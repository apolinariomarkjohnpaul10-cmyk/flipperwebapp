"""
recon.py — Active host discovery, stealth port scanning, and passive OS fingerprinting.

All three features require root / Administrator privileges:
  - ARP sweep uses raw Layer 2 sockets (Scapy)
  - TCP SYN scan crafts raw TCP packets (Scapy)
  - OS fingerprinting sniffs raw traffic off the wire (Scapy AsyncSniffer)

Registered in main.py via:
    from recon import recon_router
    app.include_router(recon_router)
"""

from __future__ import annotations

import asyncio
import json
import logging
import random
import re
import socket
import subprocess
from typing import Optional

from fastapi import APIRouter, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.websockets import WebSocketState
from pydantic import BaseModel, field_validator, model_validator
from scapy.all import (
    ARP,
    DNS,
    DNSQR,
    Ether,
    ICMPv6EchoRequest,
    IP,
    IPv6,
    TCP,
    UDP,
    AsyncSniffer,
    conf,
    sr,
    sr1,
    srp,
)
from starlette.websockets import WebSocketDisconnect as StarletteDisconnect

logger = logging.getLogger(__name__)

recon_router = APIRouter(prefix="/api/recon", tags=["recon"])

ALLOWED_ORIGIN = "https://flipperwebapp.vercel.app"

conf.verb = 0

_PORT_TOKEN_RE = re.compile(r"^(\d{1,5})(?:-(\d{1,5}))?$")
_MAX_PORTS = 1000


class ArpSweepRequest(BaseModel):
    target_cidr: str
    timeout: float = 2.0
    include_ipv6: bool = False

    @field_validator("target_cidr")
    @classmethod
    def validate_cidr(cls, v: str) -> str:
        import ipaddress
        try:
            ipaddress.IPv4Network(v, strict=False)
        except ValueError:
            raise ValueError(f"Invalid IPv4 CIDR: {v!r}")
        return v

    @field_validator("timeout")
    @classmethod
    def validate_timeout(cls, v: float) -> float:
        if not (0.1 <= v <= 30.0):
            raise ValueError("timeout must be between 0.1 and 30.0 seconds")
        return v


class SynScanRequest(BaseModel):
    target: str
    ports: str
    timeout: float = 1.0

    @field_validator("target")
    @classmethod
    def validate_target(cls, v: str) -> str:
        import ipaddress
        try:
            ipaddress.IPv4Address(v)
            return v
        except ValueError:
            pass
        hostname_re = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9\-\.]{0,253}[a-zA-Z0-9]$")
        if hostname_re.match(v):
            return v
        raise ValueError(f"Invalid target: {v!r}. Must be an IPv4 address or hostname.")

    @field_validator("ports")
    @classmethod
    def validate_ports(cls, v: str) -> str:
        _parse_port_list(v)
        return v

    @field_validator("timeout")
    @classmethod
    def validate_timeout(cls, v: float) -> float:
        if not (0.1 <= v <= 30.0):
            raise ValueError("timeout must be between 0.1 and 30.0 seconds")
        return v


def _parse_port_list(port_str: str) -> list[int]:
    ports: set[int] = set()
    for token in port_str.split(","):
        token = token.strip()
        if not token:
            continue
        m = _PORT_TOKEN_RE.match(token)
        if not m:
            raise ValueError(f"Invalid port token: {token!r}")
        start = int(m.group(1))
        end = int(m.group(2)) if m.group(2) else start
        if start < 1 or end > 65535:
            raise ValueError(f"Port out of range 1-65535: {token!r}")
        if start > end:
            raise ValueError(f"Range start > end: {token!r}")
        ports.update(range(start, end + 1))
    if len(ports) > _MAX_PORTS:
        raise ValueError(f"Too many ports ({len(ports)}). Maximum is {_MAX_PORTS}.")
    if not ports:
        raise ValueError("Port list is empty.")
    return sorted(ports)


def _resolve_hostname(ip: str, timeout: float = 0.8) -> Optional[str]:
    """
    Try four resolution methods in order, return the first name found.

    1. Reverse DNS  — fast, works for routers and DHCP-registered devices.
    2. mDNS PTR     — Apple/Android/Chromecasts that broadcast *.local names.
    3. NetBIOS NBNS — Windows machines that advertise a NetBIOS hostname.
    4. Nmap         — DNS lookup via Google DNS (8.8.8.8) as final fallback.
    """

    # 1. Reverse DNS
    old_timeout = socket.getdefaulttimeout()
    try:
        socket.setdefaulttimeout(timeout)
        name, _, _ = socket.gethostbyaddr(ip)
        return name
    except (socket.herror, socket.gaierror, OSError):
        pass
    finally:
        socket.setdefaulttimeout(old_timeout)

    # 2. mDNS PTR query
    try:
        reversed_ip = ".".join(reversed(ip.split("."))) + ".in-addr.arpa."
        pkt = (
            IP(dst=ip)
            / UDP(dport=5353)
            / DNS(rd=1, qd=DNSQR(qname=reversed_ip, qtype="PTR"))
        )
        reply = sr1(pkt, timeout=timeout, verbose=0)
        if reply and reply.haslayer(DNS):
            dns_layer = reply[DNS]
            if dns_layer.ancount > 0 and dns_layer.an:
                rdata = dns_layer.an.rdata
                if isinstance(rdata, bytes):
                    rdata = rdata.decode(errors="ignore")
                name = rdata.rstrip(".")
                if name:
                    return name
    except Exception:
        pass

    # 3. NetBIOS Name Service (NBNS)
    try:
        tx_id = random.randint(0, 0xFFFF)
        nbns_request = (
            tx_id.to_bytes(2, "big")
            + b"\x00\x10"
            + b"\x00\x01"
            + b"\x00\x00"
            + b"\x00\x00"
            + b"\x00\x00"
            + b"\x20"
            + b"CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
            + b"\x00"
            + b"\x00\x21"
            + b"\x00\x01"
        )
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(timeout)
            sock.sendto(nbns_request, (ip, 137))
            data, _ = sock.recvfrom(1024)
        if len(data) > 56:
            num_names = data[56]
            if num_names > 0 and len(data) > 57 + 18:
                raw_name = data[57:72].decode("ascii", errors="ignore").rstrip()
                if raw_name:
                    return raw_name
    except Exception:
        pass

    # 4. Nmap hostname lookup
    try:
        result = subprocess.run(
            ["nmap", "-sn", "-Pn", "--dns-servers", "8.8.8.8", ip],
            capture_output=True, text=True, timeout=5
        )
        for line in result.stdout.splitlines():
            if "Nmap scan report for" in line:
                parts = line.split("for")[-1].strip()
                if "(" in parts:
                    name = parts.split("(")[0].strip()
                    if name and name != ip:
                        return name
    except Exception:
        pass

    return None


async def _enrich_hostnames(
    hosts: list[dict], resolve_timeout: float
) -> list[dict]:
    async def resolve_one(host: dict) -> dict:
        name = await asyncio.to_thread(_resolve_hostname, host["ip"], resolve_timeout)
        return {**host, "hostname": name}
    return list(await asyncio.gather(*[resolve_one(h) for h in hosts]))


_OS_DB: list[dict] = [
    {
        "label": "Linux 4.x / 5.x / 6.x",
        "ttl_range": (54, 64),
        "window_sizes": {29200},
        "df": True,
        "option_names": ["MSS", "SAckOK", "Timestamp", "NOP", "WScale"],
    },
    {
        "label": "Linux 2.6 / Android",
        "ttl_range": (54, 64),
        "window_sizes": {5840},
        "df": True,
        "option_names": ["MSS", "SAckOK", "Timestamp", "NOP", "WScale"],
    },
    {
        "label": "Windows 10 / Windows 11",
        "ttl_range": (118, 128),
        "window_sizes": {65535, 64240},
        "df": True,
        "option_names": ["MSS", "NOP", "WScale", "NOP", "NOP", "SAckOK"],
    },
    {
        "label": "Windows Server 2019 / 2022 / 2025",
        "ttl_range": (118, 128),
        "window_sizes": {64240},
        "df": True,
        "option_names": ["MSS", "NOP", "WScale", "NOP", "NOP", "SAckOK"],
    },
    {
        "label": "macOS (Ventura / Sonoma / Sequoia)",
        "ttl_range": (54, 64),
        "window_sizes": {65535},
        "df": True,
        "option_names": ["MSS", "NOP", "WScale", "NOP", "NOP", "Timestamp", "SAckOK", "EOL"],
    },
    {
        "label": "FreeBSD / OpenBSD",
        "ttl_range": (54, 64),
        "window_sizes": {65535},
        "df": True,
        "option_names": ["MSS", "NOP", "WScale", "SAckOK", "Timestamp"],
    },
    {
        "label": "Cisco IOS",
        "ttl_range": (245, 255),
        "window_sizes": {4128},
        "df": False,
        "option_names": ["MSS"],
    },
    {
        "label": "Embedded / IoT",
        "ttl_range": (54, 64),
        "window_sizes": {1024, 2048, 512},
        "df": False,
        "option_names": ["MSS"],
    },
]


def _score_fingerprint(ttl: int, window: int, df: bool, option_names: list[str]) -> dict:
    best_label = "Unknown"
    best_score = -1
    for entry in _OS_DB:
        score = 0
        lo, hi = entry["ttl_range"]
        if lo <= ttl <= hi:
            score += 4
        if window in entry["window_sizes"]:
            score += 3
        if df == entry["df"]:
            score += 2
        observed_set = set(option_names)
        expected_set = set(entry["option_names"])
        score += len(observed_set & expected_set)
        if score > best_score:
            best_score = score
            best_label = entry["label"]
    return {"os_guess": best_label, "confidence": best_score}


def _extract_tcp_option_names(pkt_options: list) -> list[str]:
    names = []
    for opt in pkt_options:
        if isinstance(opt, tuple):
            names.append(str(opt[0]))
        else:
            names.append(str(opt))
    return names


def _arp_sweep(target_cidr: str, timeout: float) -> list[dict]:
    pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=target_cidr)
    answered, _ = srp(pkt, timeout=timeout, verbose=0)
    return [
        {"ip": rcv.psrc, "mac": rcv.hwsrc, "method": "arp"}
        for _, rcv in answered
    ]


def _icmpv6_sweep(timeout: float) -> list[dict]:
    pkt = IPv6(dst="ff02::1") / ICMPv6EchoRequest()
    answered, _ = sr(pkt, timeout=timeout, verbose=0)
    seen: set[str] = set()
    results = []
    for _, rcv in answered:
        src = rcv[IPv6].src
        if src not in seen:
            seen.add(src)
            results.append({"ip": src, "mac": None, "method": "icmpv6"})
    return results


@recon_router.post("/arp-sweep")
async def arp_sweep(payload: ArpSweepRequest) -> dict:
    hosts: list[dict] = await asyncio.to_thread(
        _arp_sweep, payload.target_cidr, payload.timeout
    )
    if payload.include_ipv6:
        v6_hosts = await asyncio.to_thread(_icmpv6_sweep, payload.timeout)
        hosts.extend(v6_hosts)
    resolve_timeout = min(payload.timeout * 0.5, 1.5)
    hosts = await _enrich_hostnames(hosts, resolve_timeout)
    return {
        "target": payload.target_cidr,
        "hosts_found": len(hosts),
        "hosts": hosts,
    }


@recon_router.post("/syn-scan")
async def syn_scan(payload: SynScanRequest) -> dict:
    ports = _parse_port_list(payload.ports)
    result = await asyncio.to_thread(
        _tcp_syn_scan, payload.target, ports, payload.timeout
    )
    return result


def _tcp_syn_scan(target: str, ports: list[int], timeout: float) -> dict:
    src_port = random.randint(1024, 65535)
    pkts = [
        IP(dst=target) / TCP(sport=src_port, dport=port, flags="S")
        for port in ports
    ]
    answered, unanswered = sr(pkts, timeout=timeout, verbose=0)
    open_ports: list[dict] = []
    closed_count = 0
    filtered_count = len(unanswered)
    rst_pkts = []
    for sent, received in answered:
        tcp_layer = received.getlayer(TCP)
        if tcp_layer is None:
            filtered_count += 1
            continue
        flags = tcp_layer.flags
        if flags & 0x12 == 0x12:
            dport = sent[TCP].dport
            open_ports.append({"port": dport, "state": "open", "banner": None})
            rst_pkts.append(
                IP(dst=target)
                / TCP(sport=src_port, dport=dport, flags="R", seq=tcp_layer.ack)
            )
        elif flags & 0x14 == 0x14:
            closed_count += 1
        else:
            filtered_count += 1
    if rst_pkts:
        try:
            sr(rst_pkts, timeout=0.5, verbose=0)
        except Exception:
            pass
    return {
        "target": target,
        "ports_scanned": len(ports),
        "open": sorted(open_ports, key=lambda x: x["port"]),
        "closed_count": closed_count,
        "filtered_count": filtered_count,
    }


@recon_router.websocket("/ws/fingerprint")
async def ws_fingerprint(websocket: WebSocket) -> None:
    origin = websocket.headers.get("origin", "")
    if origin != ALLOWED_ORIGIN:
        await websocket.close(code=1008, reason="Policy Violation: untrusted origin")
        return
    await websocket.accept()
    await websocket.send_text(json.dumps({"event": "fingerprint_started"}))
    loop = asyncio.get_running_loop()
    queue: asyncio.Queue[Optional[str]] = asyncio.Queue(maxsize=500)
    stop_event = asyncio.Event()

    def packet_callback(pkt) -> None:
        if stop_event.is_set():
            return
        if not pkt.haslayer(IP) or not pkt.haslayer(TCP):
            return
        tcp = pkt[TCP]
        ip = pkt[IP]
        is_syn = (tcp.flags & 0x02) and not (tcp.flags & 0x10)
        is_syn_ack = (tcp.flags & 0x12) == 0x12
        if not (is_syn or is_syn_ack):
            return
        pkt_type = "SYN-ACK" if is_syn_ack else "SYN"
        ttl = ip.ttl
        window = tcp.window
        df = bool(ip.flags & 0x02)
        option_names = _extract_tcp_option_names(tcp.options)
        result = _score_fingerprint(ttl, window, df, option_names)
        msg = json.dumps({
            "event": "os_fingerprint",
            "src_ip": ip.src,
            "os_guess": result["os_guess"],
            "confidence": result["confidence"],
            "ttl": ttl,
            "window": window,
            "df": df,
            "options": option_names,
            "pkt_type": pkt_type,
        })
        loop.call_soon_threadsafe(queue.put_nowait, msg)

    sniffer = AsyncSniffer(
        filter="tcp",
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
    except Exception as exc:
        logger.error("ws_fingerprint error: %s", exc)
    finally:
        stop_event.set()
        sniffer.stop()
        logger.info("ws/fingerprint: sniffer stopped")


# ---------------------------------------------------------------------------
# Feature 4: DHCP Hostname Sniffer (WebSocket)
# ---------------------------------------------------------------------------

@recon_router.websocket("/ws/dhcp-sniff")
async def ws_dhcp_sniff(websocket: WebSocket) -> None:
    """
    Passively sniffs DHCP packets on the LAN and extracts device hostnames.
    Catches Option 12 (Hostname) and Option 60 (Vendor Class) from DHCP
    Discover and Request packets broadcast by devices joining the network.
    """
    origin = websocket.headers.get("origin", "")
    if origin != ALLOWED_ORIGIN:
        await websocket.close(code=1008, reason="Policy Violation: untrusted origin")
        return

    await websocket.accept()
    await websocket.send_text(json.dumps({"event": "dhcp_sniffer_started"}))

    loop = asyncio.get_running_loop()
    queue: asyncio.Queue[Optional[str]] = asyncio.Queue(maxsize=500)
    stop_event = asyncio.Event()

    def packet_callback(pkt) -> None:
        if stop_event.is_set():
            return
        if not pkt.haslayer("DHCP"):
            return

        dhcp_options = {
            opt[0]: opt[1]
            for opt in pkt["DHCP"].options
            if isinstance(opt, tuple)
        }

        msg_type = dhcp_options.get("message-type")
        if msg_type not in (1, 3):
            return

        hostname = dhcp_options.get("hostname", b"")
        if isinstance(hostname, bytes):
            hostname = hostname.decode(errors="ignore")

        vendor = dhcp_options.get("vendor_class_id", b"")
        if isinstance(vendor, bytes):
            vendor = vendor.decode(errors="ignore")

        src_mac = pkt["Ether"].src if pkt.haslayer("Ether") else "unknown"
        src_ip  = pkt["IP"].src   if pkt.haslayer("IP")    else "0.0.0.0"

        if not hostname and not vendor:
            return

        msg = json.dumps({
            "event":    "dhcp_hostname",
            "mac":      src_mac,
            "ip":       src_ip,
            "hostname": hostname or None,
            "vendor":   vendor   or None,
            "type":     "Discover" if msg_type == 1 else "Request",
        })
        loop.call_soon_threadsafe(queue.put_nowait, msg)

    sniffer = AsyncSniffer(
        filter="udp port 67 or udp port 68",
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
    except Exception as exc:
        logger.error("ws_dhcp_sniff error: %s", exc)
    finally:
        stop_event.set()
        sniffer.stop()
        logger.info("ws/dhcp-sniff: sniffer stopped")