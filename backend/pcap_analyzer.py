"""
pcap_analyzer.py — Offline PCAP file analysis using dpkt.

Registered in main.py via:
    from pcap_analyzer import pcap_router
    app.include_router(pcap_router)
"""

from __future__ import annotations

import io
import socket
from collections import Counter
from dataclasses import dataclass
from typing import Optional

import dpkt
from fastapi import APIRouter, HTTPException, UploadFile, File
from fastapi.responses import JSONResponse

pcap_router = APIRouter(prefix="/api/pcap", tags=["pcap"])

MAX_PCAP_SIZE_BYTES = 100 * 1024 * 1024  # 100 MB


@dataclass(frozen=True)
class ConversationKey:
    """Normalises A→B and B→A into the same key for unique flow counting."""
    proto: str
    pair: tuple

    @classmethod
    def make(cls, proto: str, src: str, dst: str) -> "ConversationKey":
        return cls(proto=proto, pair=tuple(sorted([src, dst])))


def _parse_pcap(raw: bytes, top_n: int) -> dict:
    buf = io.BytesIO(raw)
    try:
        reader = dpkt.pcap.Reader(buf)
    except Exception as exc:
        raise ValueError(f"Could not parse PCAP: {exc}") from exc

    total_packets = 0
    total_bytes = 0
    first_ts: Optional[float] = None
    last_ts: Optional[float] = None

    proto_counter: Counter = Counter()
    src_ip_counter: Counter = Counter()
    dst_ip_counter: Counter = Counter()
    dst_port_counter: Counter = Counter()
    conversations: set = set()
    warnings: list[str] = []

    for ts, raw_buf in reader:
        total_packets += 1
        total_bytes += len(raw_buf)

        if first_ts is None:
            first_ts = ts
        last_ts = ts

        try:
            eth = dpkt.ethernet.Ethernet(raw_buf)
        except Exception:
            proto_counter["other"] += 1
            continue

        ip = eth.data
        if not isinstance(ip, dpkt.ip.IP):
            proto_counter["other"] += 1
            continue

        src = socket.inet_ntoa(ip.src)
        dst = socket.inet_ntoa(ip.dst)
        src_ip_counter[src] += 1
        dst_ip_counter[dst] += 1

        transport = ip.data
        if isinstance(transport, dpkt.tcp.TCP):
            proto_counter["tcp"] += 1
            dst_port_counter[str(transport.dport)] += 1
            conversations.add(ConversationKey.make("tcp", src, dst))
        elif isinstance(transport, dpkt.udp.UDP):
            proto_counter["udp"] += 1
            dst_port_counter[str(transport.dport)] += 1
            conversations.add(ConversationKey.make("udp", src, dst))
        elif isinstance(transport, dpkt.icmp.ICMP):
            proto_counter["icmp"] += 1
            conversations.add(ConversationKey.make("icmp", src, dst))
        else:
            proto_counter["other"] += 1

    duration = round((last_ts - first_ts), 2) if first_ts and last_ts else 0.0

    return {
        "total_packets": total_packets,
        "total_bytes": total_bytes,
        "capture_duration_s": duration,
        "protocols": dict(proto_counter),
        "top_src_ips": dict(src_ip_counter.most_common(top_n)),
        "top_dst_ips": dict(dst_ip_counter.most_common(top_n)),
        "top_dst_ports": dict(dst_port_counter.most_common(top_n)),
        "unique_conversations": len(conversations),
        "warnings": warnings,
    }


@pcap_router.post("/analyze")
async def analyze_pcap(file: UploadFile = File(...), top_n: int = 10):
    if not file.filename or not file.filename.endswith(".pcap"):
        raise HTTPException(status_code=400, detail="File must be a .pcap file.")

    raw = await file.read()

    if len(raw) > MAX_PCAP_SIZE_BYTES:
        raise HTTPException(
            status_code=413,
            detail=f"File too large. Maximum size is {MAX_PCAP_SIZE_BYTES // (1024*1024)} MB.",
        )

    try:
        import asyncio
        analysis = await asyncio.to_thread(_parse_pcap, raw, top_n)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))

    return JSONResponse(content={"filename": file.filename, "analysis": analysis})