"""
fuzzer.py — HTTP payload fuzzer and application architecture mapper.

Registered in main.py via:
    from fuzzer import fuzz_router
    app.include_router(fuzz_router)
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
import re
import socket
import statistics
import time
from typing import AsyncGenerator, Optional

import httpx
from fastapi import APIRouter, HTTPException, WebSocket, WebSocketDisconnect
from pydantic import BaseModel, field_validator
from starlette.websockets import WebSocketDisconnect as StarletteDisconnect

logger = logging.getLogger(__name__)

fuzz_router = APIRouter(prefix="/api/fuzz", tags=["fuzz"])

ALLOWED_ORIGIN = "http://localhost:3000"

# ---------------------------------------------------------------------------
# SSRF protection
# ---------------------------------------------------------------------------

def _validate_local_url(url: str) -> str:
    match = re.match(r"https?://([^/:]+)", url)
    if not match:
        raise ValueError(f"Invalid URL: {url!r}")
    host = match.group(1)
    try:
        resolved = socket.gethostbyname(host)
        addr = ipaddress.ip_address(resolved)
        if not (
            addr.is_loopback
            or addr.is_private
            or not addr.is_global
        ):
            raise ValueError(f"Target must be a local/LAN address. Got: {resolved}")
    except socket.gaierror:
        if "." in host:
            raise ValueError(f"Could not resolve host: {host!r}")
    return url


# ---------------------------------------------------------------------------
# Fuzz payloads
# ---------------------------------------------------------------------------

REPLACIVE_VECTORS: list[tuple[str, str]] = [
    # Buffer overflow
    ("A" * 256,              "Buffer overflow - 256 bytes"),
    ("A" * 1024,             "Buffer overflow - 1024 bytes"),
    ("A" * 8192,             "Buffer overflow - 8192 bytes"),
    # SQL injection
    ("' OR '1'='1",          "SQL injection - always-true"),
    ("' OR '1'='1'--",       "SQL injection - comment terminator"),
    ("'; DROP TABLE users;--","SQL table drop (canary)"),
    ("1 UNION SELECT NULL--", "SQL UNION probe"),
    # NoSQL injection
    ('{"$gt": ""}',          "NoSQL injection - $gt operator"),
    ('{"$where": "1==1"}',   "NoSQL injection - $where operator"),
    # Path traversal
    ("../../../etc/passwd",  "Path traversal - Unix"),
    ("..\\..\\..\\windows\\win.ini", "Path traversal - Windows"),
    ("%2e%2e%2fetc%2fpasswd","Path traversal - URL encoded"),
    # SSTI
    ("{{7*7}}",              "SSTI - Jinja2/Twig probe"),
    ("${7*7}",               "SSTI - Freemarker/Spring probe"),
    ("<%= 7*7 %>",           "SSTI - ERB/EJS probe"),
    ("#{7*7}",               "SSTI - Ruby probe"),
    # Command injection
    ("; ls -la",             "Command injection - semicolon"),
    ("| cat /etc/passwd",    "Command injection - pipe"),
    ("$(id)",                "Command injection - subshell"),
    ("`id`",                 "Command injection - backtick"),
    # CRLF injection
    ("\r\nX-Injected: true", "CRLF injection"),
    # Integer edge cases
    ("0",                    "Integer edge - zero"),
    ("-1",                   "Integer edge - negative"),
    ("2147483647",           "Integer edge - INT32_MAX"),
    ("2147483648",           "Integer edge - INT32_MAX+1"),
    ("9999999999999999",     "Integer edge - very large"),
    # Malformed JSON
    ("{",                    "Malformed JSON - truncated"),
    ('{"a":' + "{"*50,       "Malformed JSON - deep nesting"),
    # XSS
    ("<script>alert(1)</script>", "XSS probe"),
    ('"><img src=x onerror=alert(1)>', "XSS - attribute breakout"),
    # Null bytes
    ("\x00",                 "Null byte injection"),
    ("%00",                  "Null byte - URL encoded"),
    # Format strings
    ("%s%s%s%s",             "Format string probe"),
    ("%x%x%x%x",             "Format string - hex"),
]


def _generate_recursive(length: int) -> list[tuple[str, str]]:
    """Generate all hex combinations of given length."""
    max_val = 16 ** length
    return [
        (format(i, f"0{length}x"), f"Recursive hex {format(i, f'0{length}x')}")
        for i in range(max_val)
    ]


# ---------------------------------------------------------------------------
# Interesting response detection
# ---------------------------------------------------------------------------

STACK_TRACE_PATTERNS = re.compile(
    r"(Traceback|NullPointerException|SQLException|SyntaxError"
    r"|undefined method|stack trace|at [a-zA-Z]+\.[a-zA-Z]+\()",
    re.IGNORECASE,
)

SENSITIVE_PATTERNS = re.compile(
    r"(root:|admin|dashboard|password|secret|token)",
    re.IGNORECASE,
)


def _is_interesting(
    status: int,
    body: str,
    response_ms: float,
    baseline_ms: float,
    timed_out: bool,
) -> tuple[bool, str]:
    if status >= 500:
        return True, f"HTTP {status} server error"
    if STACK_TRACE_PATTERNS.search(body):
        return True, "Stack trace / debug info in response"
    if "root:" in body:
        return True, "Possible /etc/passwd content in response"
    if status == 200 and SENSITIVE_PATTERNS.search(body):
        return True, f"Sensitive content on HTTP 200"
    if baseline_ms > 0 and response_ms > baseline_ms * 3:
        return True, f"Timing anomaly ({response_ms:.0f}ms vs baseline {baseline_ms:.0f}ms)"
    if timed_out and baseline_ms > 0 and response_ms > baseline_ms * 2:
        return True, "Possible blind injection (request timeout)"
    return False, ""


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------

ALLOWED_METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD"}


class FuzzRequest(BaseModel):
    target_url: str
    method: str = "GET"
    headers: dict = {}
    body_template: Optional[str] = None
    mode: str = "replacive"
    recursive_length: int = 2
    concurrency: int = 10
    timeout: float = 5.0

    @field_validator("target_url")
    @classmethod
    def validate_url(cls, v: str) -> str:
        return _validate_local_url(v)

    @field_validator("method")
    @classmethod
    def validate_method(cls, v: str) -> str:
        v = v.upper()
        if v not in ALLOWED_METHODS:
            raise ValueError(f"method must be one of {ALLOWED_METHODS}")
        return v

    @field_validator("concurrency")
    @classmethod
    def validate_concurrency(cls, v: int) -> int:
        if not (1 <= v <= 50):
            raise ValueError("concurrency must be between 1 and 50")
        return v

    @field_validator("timeout")
    @classmethod
    def validate_timeout(cls, v: float) -> float:
        if not (0.5 <= v <= 60.0):
            raise ValueError("timeout must be between 0.5 and 60.0")
        return v

    @field_validator("recursive_length")
    @classmethod
    def validate_length(cls, v: int) -> int:
        if not (1 <= v <= 8):
            raise ValueError("recursive_length must be between 1 and 8")
        return v


class ArchMapRequest(BaseModel):
    target_url: str
    probe_count: int = 5
    timeout: float = 5.0

    @field_validator("target_url")
    @classmethod
    def validate_url(cls, v: str) -> str:
        return _validate_local_url(v)


# ---------------------------------------------------------------------------
# Fuzzer core
# ---------------------------------------------------------------------------

async def _fuzz_one(
    client: httpx.AsyncClient,
    method: str,
    url: str,
    payload: str,
    description: str,
    headers: dict,
    body_template: Optional[str],
    timeout: float,
    baseline_ms: float,
    sem: asyncio.Semaphore,
) -> Optional[dict]:
    async with sem:
        target_url = url.replace("{FUZZ}", payload)
        body = body_template.replace("{FUZZ}", payload) if body_template else None
        timed_out = False
        start = time.monotonic()
        try:
            resp = await client.request(
                method,
                target_url,
                headers=headers,
                content=body,
                timeout=timeout,
            )
            status = resp.status_code
            body_text = resp.text[:2000]
        except httpx.TimeoutException:
            timed_out = True
            status = 0
            body_text = ""
        except Exception:
            return None
        finally:
            response_ms = (time.monotonic() - start) * 1000

        interesting, reason = _is_interesting(
            status, body_text, response_ms, baseline_ms, timed_out
        )
        if not interesting:
            return None

        return {
            "event": "fuzz_hit",
            "payload": payload,
            "description": description,
            "url": target_url,
            "status_code": status,
            "response_ms": round(response_ms, 1),
            "interesting": True,
            "reason": reason,
            "body_snippet": body_text[:500],
        }


async def fuzz_stream(req: FuzzRequest) -> AsyncGenerator[str, None]:
    vectors = (
        REPLACIVE_VECTORS
        if req.mode == "replacive"
        else _generate_recursive(req.recursive_length)
    )

    async with httpx.AsyncClient(verify=False) as client:
        # Baseline measurement
        baseline_ms = 0.0
        try:
            start = time.monotonic()
            await client.get(
                req.target_url.replace("{FUZZ}", "baseline"),
                timeout=req.timeout,
            )
            baseline_ms = (time.monotonic() - start) * 1000
        except Exception:
            pass

        yield json.dumps({
            "event": "baseline_measured",
            "baseline_ms": round(baseline_ms, 1),
            "mode": req.mode,
        })

        yield json.dumps({
            "event": "fuzz_started",
            "total_payloads": str(len(vectors)),
        })

        sem = asyncio.Semaphore(req.concurrency)
        tasks = [
            _fuzz_one(
                client, req.method, req.target_url,
                payload, desc,
                req.headers, req.body_template,
                req.timeout, baseline_ms, sem,
            )
            for payload, desc in vectors
        ]

        hits = 0
        for coro in asyncio.as_completed(tasks):
            result = await coro
            if result:
                hits += 1
                yield json.dumps(result)

        yield json.dumps({"event": "fuzz_complete", "total_hits": hits})


# ---------------------------------------------------------------------------
# WebSocket fuzzer endpoint
# ---------------------------------------------------------------------------

@fuzz_router.websocket("/ws/fuzz")
async def ws_fuzz(websocket: WebSocket) -> None:
    origin = websocket.headers.get("origin", "")
    if origin != ALLOWED_ORIGIN:
        await websocket.close(code=1008, reason="Policy Violation: untrusted origin")
        return

    await websocket.accept()

    try:
        raw = await websocket.receive_text()
        req = FuzzRequest.model_validate_json(raw)
    except Exception as exc:
        await websocket.send_text(json.dumps({"event": "error", "message": str(exc)}))
        await websocket.close()
        return

    try:
        async for msg in fuzz_stream(req):
            await websocket.send_text(msg)
    except (WebSocketDisconnect, StarletteDisconnect):
        pass
    except Exception as exc:
        logger.error("ws_fuzz error: %s", exc)


# ---------------------------------------------------------------------------
# Architecture mapper
# ---------------------------------------------------------------------------

ALL_METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH",
               "HEAD", "OPTIONS", "TRACE", "CONNECT", "PROPFIND", "PURGE"]

HEADER_LABELS = {
    "server":                    "Web Server / OS",
    "x-powered-by":              "Application Framework",
    "via":                       "Proxy / Load Balancer",
    "x-cache":                   "Cache Status",
    "cf-ray":                    "Cloudflare CDN",
    "x-amz-cf-id":               "AWS CloudFront",
    "x-azure-ref":               "Azure Front Door",
    "x-kong-upstream-latency":   "Kong API Gateway",
    "x-forwarded-for":           "Proxy Forwarding Chain",
    "x-request-id":              "Request Tracing (Framework)",
    "x-frame-options":           "Security Header",
    "strict-transport-security": "HSTS",
    "content-security-policy":   "CSP",
    "x-cache-status":            "Nginx Cache Status",
}


@fuzz_router.post("/arch-map")
async def arch_map(payload: ArchMapRequest) -> dict:
    waf_indicators: list[str] = []
    headers_found: dict = {}
    method_map: dict = {}
    timing_samples: list[float] = []
    topology_clues: list[str] = []

    async with httpx.AsyncClient(verify=False) as client:
        # Phase 1 — HTTP method probing
        for method in ALL_METHODS:
            try:
                resp = await client.request(
                    method, payload.target_url, timeout=payload.timeout
                )
                allowed = resp.status_code not in (405, 501)
                method_map[method] = {"status": resp.status_code, "allowed": allowed}
                if method == "TRACE" and resp.status_code == 200:
                    waf_indicators.append(
                        "⚠ TRACE method allowed — potential Cross-Site Tracing (XST) vulnerability"
                    )
            except Exception:
                method_map[method] = {"status": None, "allowed": False}

        # Phase 2 — Header analysis
        try:
            resp = await client.get(payload.target_url, timeout=payload.timeout)
            for header, label in HEADER_LABELS.items():
                value = resp.headers.get(header)
                if value:
                    headers_found[header] = {"label": label, "value": value}
                    topology_clues.append(f"[Header] {label}: '{header}: {value}'")
        except Exception:
            pass

        # Phase 3 — Timing analysis
        for _ in range(payload.probe_count):
            try:
                start = time.monotonic()
                await client.get(payload.target_url, timeout=payload.timeout)
                timing_samples.append((time.monotonic() - start) * 1000)
            except Exception:
                pass

        # Phase 4 — Malformed request probe
        try:
            malformed_resp = await client.post(
                payload.target_url,
                headers={"Content-Length": "99999"},
                content=b"x" * 10,
                timeout=payload.timeout,
            )
            if malformed_resp.status_code in (400, 408, 413):
                topology_clues.append(
                    f"[Malformed] Proxy/WAF handled malformed request ({malformed_resp.status_code})"
                )
        except Exception:
            pass

    # Timing analysis
    timing_analysis: dict = {}
    if timing_samples:
        avg = statistics.mean(timing_samples)
        stddev = statistics.stdev(timing_samples) if len(timing_samples) > 1 else 0.0
        cv = (stddev / avg * 100) if avg > 0 else 0.0
        interpretation = "Consistent response time"
        if cv > 30:
            interpretation = "High variance — possible load balancer distributing requests"
        if len(timing_samples) > 1 and timing_samples[0] > timing_samples[1] * 2:
            interpretation = "Cache behavior detected: First request slower than subsequent"
        timing_analysis = {
            "samples": [round(t, 1) for t in timing_samples],
            "avg_ms": round(avg, 1),
            "stddev_ms": round(stddev, 1),
            "cv_percent": round(cv, 1),
            "interpretation": interpretation,
        }
        topology_clues.append(
            f"[Timing] Avg={avg:.0f}ms, StdDev={stddev:.0f}ms, CV={cv:.1f}% → {interpretation}"
        )

    # Topology guess
    topology_guess = "Direct connection"
    h = headers_found
    if any(k in h for k in ("via", "x-cache", "cf-ray", "x-amz-cf-id", "x-azure-ref")):
        topology_guess = "Reverse Proxy / Load Balancer detected"
    elif "x-powered-by" in h:
        topology_guess = f"Direct app server ({h['x-powered-by']['value']})"

    return {
        "target": payload.target_url,
        "method_map": method_map,
        "headers_found": headers_found,
        "waf_indicators": waf_indicators,
        "timing_analysis": timing_analysis,
        "topology_guess": topology_guess,
        "topology_summary": topology_clues,
    }