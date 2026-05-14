"""
main.py — FastAPI application entry point.

Initializes the app, configures CORS and security middleware,
registers sub-routers, and defines the core Nmap scanning
and live packet sniffing features.
"""

from __future__ import annotations

import asyncio
import json
import logging
import uuid
from typing import Optional

from fastapi import BackgroundTasks, FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.websockets import WebSocketState
from pydantic import BaseModel, field_validator
from scapy.all import AsyncSniffer, IP, TCP, UDP, ICMP, conf
from starlette.websockets import WebSocketDisconnect as StarletteDisconnect
import nmap

from recon import recon_router
from pcap_analyzer import pcap_router
from fuzzer import fuzz_router
from control import control_router

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

ALLOWED_ORIGIN = "http://localhost:3000"

ALLOWED_SCAN_TYPES = {"syn", "ping", "ports"}

NMAP_ARGS = {
    "syn":   "-sS -T4 --open",
    "ping":  "-sn -T4",
    "ports": "-sT -T4 --top-ports 1000",
}

# ---------------------------------------------------------------------------
# App setup
# ---------------------------------------------------------------------------

app = FastAPI(title="Flipper Zero Web App", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=[ALLOWED_ORIGIN],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(recon_router)
app.include_router(pcap_router)
app.include_router(fuzz_router)
app.include_router(control_router)

conf.verb = 0

# In-memory job store
scan_jobs: dict[str, dict] = {}

# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------

import ipaddress
import re

HOSTNAME_REGEX = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9\-\.]{0,253}[a-zA-Z0-9]$")


class ScanTarget(BaseModel):
    target: str
    scan_type: str

    @field_validator("target")
    @classmethod
    def validate_target(cls, v: str) -> str:
        try:
            ipaddress.IPv4Address(v)
            return v
        except ValueError:
            pass
        try:
            ipaddress.IPv4Network(v, strict=False)
            return v
        except ValueError:
            pass
        if HOSTNAME_REGEX.match(v):
            return v
        raise ValueError(f"Invalid target: {v!r}")

    @field_validator("scan_type")
    @classmethod
    def validate_scan_type(cls, v: str) -> str:
        if v not in ALLOWED_SCAN_TYPES:
            raise ValueError(f"scan_type must be one of {ALLOWED_SCAN_TYPES}")
        return v


# ---------------------------------------------------------------------------
# Nmap scanning
# ---------------------------------------------------------------------------

def run_nmap_scan(job_id: str, target: str, arguments: str) -> None:
    """Blocking Nmap scan — runs in a background thread."""
    scan_jobs[job_id]["status"] = "running"
    try:
        nm = nmap.PortScanner()
        nm.scan(hosts=target, arguments=arguments)

        hosts = []
        for host in nm.all_hosts():
            host_info = {
                "ip": host,
                "hostname": nm[host].hostname() or None,
                "state": nm[host].state(),
                "protocols": {},
            }
            for proto in nm[host].all_protocols():
                ports = []
                for port, data in nm[host][proto].items():
                    ports.append({
                        "port": port,
                        "state": data["state"],
                        "name": data.get("name", ""),
                        "product": data.get("product", ""),
                        "version": data.get("version", ""),
                    })
                host_info["protocols"][proto] = ports
            hosts.append(host_info)

        scan_jobs[job_id].update({
            "status": "completed",
            "hosts": hosts,
        })
    except Exception as exc:
        scan_jobs[job_id].update({"status": "error", "message": str(exc)})


@app.get("/api/health")
async def health():
    return {"status": "ok", "message": "Flipper Zero backend is running."}


@app.post("/api/scan", status_code=202)
async def start_scan(payload: ScanTarget, background_tasks: BackgroundTasks):
    job_id = str(uuid.uuid4())
    scan_jobs[job_id] = {
        "status": "queued",
        "target": payload.target,
        "scan_type": payload.scan_type,
    }
    arguments = NMAP_ARGS[payload.scan_type]
    background_tasks.add_task(run_nmap_scan, job_id, payload.target, arguments)
    return {
        "job_id": job_id,
        "status": "queued",
        "message": f"Scan started. Poll GET /api/scan/{job_id} for results.",
    }


@app.get("/api/scan/{job_id}")
async def get_scan(job_id: str):
    job = scan_jobs.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found.")
    return job


# ---------------------------------------------------------------------------
# Live packet sniffer (WebSocket)
# ---------------------------------------------------------------------------

@app.websocket("/ws/sniff")
async def ws_sniff(websocket: WebSocket) -> None:
    origin = websocket.headers.get("origin", "")
    if origin != ALLOWED_ORIGIN:
        await websocket.close(code=1008, reason="Policy Violation: untrusted origin")
        return

    await websocket.accept()
    await websocket.send_text(json.dumps({"event": "sniffer_started"}))

    loop = asyncio.get_running_loop()
    queue: asyncio.Queue[Optional[str]] = asyncio.Queue(maxsize=500)
    stop_event = asyncio.Event()

    def packet_callback(pkt) -> None:
        if stop_event.is_set():
            return
        if not pkt.haslayer(IP):
            return

        ip = pkt[IP]
        proto = "OTHER"
        src_port = dst_port = flags = None

        if pkt.haslayer(TCP):
            proto = "TCP"
            src_port = pkt[TCP].sport
            dst_port = pkt[TCP].dport
            flags = str(pkt[TCP].flags)
        elif pkt.haslayer(UDP):
            proto = "UDP"
            src_port = pkt[UDP].sport
            dst_port = pkt[UDP].dport
        elif pkt.haslayer(ICMP):
            proto = "ICMP"

        msg = json.dumps({
            "src": ip.src,
            "dst": ip.dst,
            "proto": proto,
            "len": len(pkt),
            "src_port": src_port,
            "dst_port": dst_port,
            "flags": flags,
        })
        loop.call_soon_threadsafe(queue.put_nowait, msg)

    sniffer = AsyncSniffer(
        filter="ip",
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
        logger.error("ws_sniff error: %s", exc)
    finally:
        stop_event.set()
        sniffer.stop()
        logger.info("ws/sniff: sniffer stopped")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)