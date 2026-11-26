"""Authenticated & TLS-Backed Hackathon Studio Server for COMET × Synapse."""

from __future__ import annotations

import asyncio
import os
import secrets
import time
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, Dict, List
from urllib.parse import urlparse

import httpx
import jwt
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from copilot.agent import CometCopilot
from copilot.live_discover import (
    disable_live_endpoint_and_rebuild,
    enable_live_endpoint_and_rebuild,
    is_live_endpoint_enabled,
)
from copilot.mcp_bridge import MultiSystemMCPBridge
from copilot.service_manager import (
    CA_CERT_PATH,
    INTERNAL_ADMIN_TOKEN,
    ISSUER_PRIVATE_KEY_PEM,
    ISSUER_PUBLIC_KEY_PEM,
    SERVICES,
    BackendServiceManager,
    build_signed_service_headers,
    create_verified_ssl_context,
)
from security.auth_guard import (
    ISSUER,
    compute_request_hmac,
    generate_es256_keypair_pem,
    issue_scoped_es256_jwt,
)

STATIC_DIR = Path(__file__).resolve().parent / "static"
ALLOWED_LOOPBACK_HOSTS = {"127.0.0.1", "localhost", "::1", "[::1]", "testserver"}
STUDIO_AUDIENCE = "comet_studio_ui"
STUDIO_COOKIE_NAME = "comet_studio_session"

manager = BackendServiceManager()
mcp_pool = MultiSystemMCPBridge(persistent=True)
copilot = CometCopilot()
_mutation_lock = asyncio.Lock()
_http_client: httpx.AsyncClient | None = None
_studio_false_auth_events: List[Dict[str, Any]] = []


def _is_demo_harness_enabled() -> bool:
    return os.environ.get("DEMO_HARNESS_ENABLED", "1").strip() not in ("0", "false", "False")


def _mint_studio_session_jwt() -> str:
    return issue_scoped_es256_jwt(
        issuer_private_key_pem=ISSUER_PRIVATE_KEY_PEM,
        audience=STUDIO_AUDIENCE,
        subject="studio-browser-operator",
        scope="studio:operator",
        ttl_seconds=43200,
    )


def _verify_studio_session(request: Request) -> None:
    """Enforces asymmetric ES256 Studio Session JWT via HttpOnly cookie or Authorization Bearer header."""
    token = ""
    auth_hdr = request.headers.get("authorization", "").strip()
    if auth_hdr.lower().startswith("bearer "):
        token = auth_hdr[7:].strip()
    elif STUDIO_COOKIE_NAME in request.cookies:
        token = request.cookies[STUDIO_COOKIE_NAME]

    if not token:
        _studio_false_auth_events.insert(
            0,
            {
                "service": STUDIO_AUDIENCE,
                "category": "MISSING_STUDIO_SESSION",
                "method": request.method,
                "path": request.url.path,
                "status_code": 401,
                "detail": "API call attempted without signed ES256 Studio Session JWT cookie or Bearer token.",
            },
        )
        raise HTTPException(status_code=401, detail="Studio authentication required: missing session token.")

    try:
        jwt.decode(
            token,
            ISSUER_PUBLIC_KEY_PEM,
            algorithms=["ES256"],
            audience=STUDIO_AUDIENCE,
            issuer=ISSUER,
        )
    except jwt.PyJWTError as exc:
        _studio_false_auth_events.insert(
            0,
            {
                "service": STUDIO_AUDIENCE,
                "category": "FORGED_STUDIO_SESSION",
                "method": request.method,
                "path": request.url.path,
                "status_code": 401,
                "detail": f"Forged or wrong-audience Studio Session JWT rejected ({type(exc).__name__}).",
            },
        )
        raise HTTPException(status_code=401, detail="Invalid or forged Studio session token.") from exc


@asynccontextmanager
async def lifespan(app: FastAPI):
    global _http_client
    manager.start_all()
    _http_client = httpx.AsyncClient(verify=create_verified_ssl_context(), timeout=4.0)
    await mcp_pool.ensure_connected()
    try:
        yield
    finally:
        await mcp_pool.close()
        if _http_client is not None:
            await _http_client.aclose()
            _http_client = None
        manager.stop_all()


app = FastAPI(title="COMET × Synapse Hackathon Studio", lifespan=lifespan)
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


@app.middleware("http")
async def security_and_session_auth_middleware(request: Request, call_next):
    host_header = (request.headers.get("host") or "").split(":")[0].strip().lower()
    if host_header and host_header not in ALLOWED_LOOPBACK_HOSTS:
        return JSONResponse(status_code=403, content={"detail": "Forbidden Host header."})

    if request.url.path.startswith("/api/"):
        if request.method in ("POST", "PUT", "PATCH", "DELETE"):
            origin = request.headers.get("origin")
            if origin:
                parsed = urlparse(origin)
                if (parsed.hostname or "").lower() not in ALLOWED_LOOPBACK_HOSTS:
                    return JSONResponse(
                        status_code=403,
                        content={"detail": "Cross-origin POST blocked by loopback CSRF policy."},
                    )
        try:
            _verify_studio_session(request)
        except HTTPException as exc:
            return JSONResponse(status_code=exc.status_code, content={"detail": exc.detail})

    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline'; "
        "connect-src 'self'; "
        "img-src 'self' data:; "
        "frame-ancestors 'none';"
    )
    return response


class AskRequest(BaseModel):
    question: str = Field(..., min_length=2, max_length=1000)
    bla_enabled: bool = Field(default=True)


async def _get_http_client() -> httpx.AsyncClient:
    global _http_client
    if _http_client is None or _http_client.is_closed:
        _http_client = httpx.AsyncClient(verify=create_verified_ssl_context(), timeout=4.0)
    return _http_client


def _probe_tls_cipher() -> Dict[str, str]:
    import socket

    ctx = create_verified_ssl_context()
    with socket.create_connection(("127.0.0.1", SERVICES["orders"]["port"]), timeout=1.5) as sock:
        with ctx.wrap_socket(sock, server_hostname="127.0.0.1") as ssock:
            cipher_name, tls_ver, bits = ssock.cipher() or ("UNKNOWN", "TLS", 0)
            return {
                "protocol": tls_ver,
                "cipher": cipher_name,
                "key_bits": str(bits),
                "ca_file": CA_CERT_PATH.name,
            }


@app.get("/")
def serve_index(request: Request):
    resp = FileResponse(str(STATIC_DIR / "index.html"))
    resp.set_cookie(
        key=STUDIO_COOKIE_NAME,
        value=_mint_studio_session_jwt(),
        httponly=True,
        secure=(request.url.scheme == "https"),
        samesite="strict",
        max_age=43200,
    )
    return resp


@app.get("/api/status")
async def get_system_status(request: Request) -> Dict[str, Any]:
    await manager.ensure_running_async()
    await mcp_pool.ensure_connected()

    orders_tools = [t for t in mcp_pool.tools_catalog if "orders" in t["server"]]
    support_tools = [t for t in mcp_pool.tools_catalog if "support" in t["server"]]

    client = await _get_http_client()
    ord_headers = build_signed_service_headers("orders", "GET", "/shipments/delayed")
    sup_headers = build_signed_service_headers("support", "GET", "/tickets")
    admin_headers = {"X-Internal-Token": INTERNAL_ADMIN_TOKEN}

    delayed_resp, tickets_resp, ord_sec_resp, sup_sec_resp = await asyncio.gather(
        client.get(f"{SERVICES['orders']['url']}/shipments/delayed", headers=ord_headers),
        client.get(f"{SERVICES['support']['url']}/tickets", headers=sup_headers),
        client.get(f"{SERVICES['orders']['url']}/internal/security-telemetry", headers=admin_headers),
        client.get(f"{SERVICES['support']['url']}/internal/security-telemetry", headers=admin_headers),
    )
    tls_info = await asyncio.to_thread(_probe_tls_cipher)

    ord_sec = ord_sec_resp.json()
    sup_sec = sup_sec_resp.json()
    combined_events = (
        list(_studio_false_auth_events[:8])
        + ord_sec.get("recent_events", [])
        + sup_sec.get("recent_events", [])
    )
    combined_events.sort(key=lambda e: e.get("timestamp", ""), reverse=True)

    return {
        "live_endpoint_enabled": is_live_endpoint_enabled(),
        "demo_harness_enabled": _is_demo_harness_enabled(),
        "security": {
            "tls": tls_info,
            "browser_to_studio_scheme": request.url.scheme.upper(),
            "copilot_to_mcp_transport": "OS Anonymous Kernel Pipe (stdio)",
            "mcp_to_backend_auth": "TLS 1.3 + Asymmetric ES256 JWT (Public-Key Verified) + Service-Isolated HMAC-SHA256",
            "authenticated_calls_total": ord_sec.get("authenticated_requests", 0) + sup_sec.get("authenticated_requests", 0),
            "blocked_false_auth_total": (
                len(_studio_false_auth_events)
                + ord_sec.get("blocked_false_auth", 0)
                + sup_sec.get("blocked_false_auth", 0)
            ),
            "orders_telemetry": ord_sec,
            "support_telemetry": sup_sec,
            "recent_false_auth_events": combined_events[:12],
        },
        "orders_service": {
            "url": SERVICES["orders"]["url"],
            "mcp_server": "orders_logistics_service/synapse_auto_server.py",
            "tools_count": len(orders_tools),
            "tools": orders_tools,
            "delayed_shipments": delayed_resp.json().get("shipments", []),
        },
        "support_service": {
            "url": SERVICES["support"]["url"],
            "mcp_server": "support_ticketing_service/synapse_auto_server.py",
            "tools_count": len(support_tools),
            "tools": support_tools,
            "open_tickets": tickets_resp.json().get("tickets", []),
        },
    }


@app.post("/api/security/simulate-attacks")
async def simulate_false_auth_attacks() -> Dict[str, Any]:
    """Fires 4 real false-auth & lateral-movement attack vectors over HTTPS to prove ES256 detection."""
    await manager.ensure_running_async()
    client = await _get_http_client()
    actor_headers = {"X-Actor-Id": "redteam-simulator"}
    results = []

    # Attack 1: Unauthenticated direct HTTPS call (Missing Bearer Token)
    r1 = await client.get(f"{SERVICES['orders']['url']}/shipments/SHP-402", headers=actor_headers)
    results.append(
        {
            "attack": "1. Unauthenticated Probe (No Bearer Token)",
            "target": "GET https://127.0.0.1:8101/shipments/SHP-402",
            "status_code": r1.status_code,
            "blocked": r1.status_code == 401,
            "response": r1.json().get("detail"),
        }
    )

    # Attack 2: Forged ES256 JWT signed with an attacker's rogue ECDSA P-256 private key!
    rogue_priv_pem, _ = generate_es256_keypair_pem()
    forged_jwt = issue_scoped_es256_jwt(
        issuer_private_key_pem=rogue_priv_pem,
        audience="support_ticketing_service",
        subject="malicious-agent",
    )
    r2 = await client.get(
        f"{SERVICES['support']['url']}/tickets",
        headers={**actor_headers, "Authorization": f"Bearer {forged_jwt}"},
    )
    results.append(
        {
            "attack": "2. Forged ES256 JWT Signature (Rogue ECDSA P-256 Private Key)",
            "target": "GET https://127.0.0.1:8102/tickets",
            "status_code": r2.status_code,
            "blocked": r2.status_code == 401,
            "response": r2.json().get("detail"),
        }
    )

    # Attack 3: Cross-Service Token Replay (Genuine CareDesk ES256 JWT replayed against SupplyPulse!)
    # SupplyPulse verifies the ES256 signature using ONLY ISSUER_PUBLIC_KEY_PEM (zero shared secrets!)
    # and rejects aud='support_ticketing_service' with 403 CROSS_SERVICE_AUDIENCE_SPOOF.
    caredesk_valid_jwt = issue_scoped_es256_jwt(
        issuer_private_key_pem=ISSUER_PRIVATE_KEY_PEM,
        audience="support_ticketing_service",
        subject="mcp-worker:support_ticketing_service",
    )
    r3 = await client.get(
        f"{SERVICES['orders']['url']}/orders/ORD-7801",
        headers={**actor_headers, "Authorization": f"Bearer {caredesk_valid_jwt}"},
    )
    results.append(
        {
            "attack": "3. Cross-Service Token Replay (CareDesk ES256 JWT -> SupplyPulse)",
            "target": "GET https://127.0.0.1:8101/orders/ORD-7801",
            "status_code": r3.status_code,
            "blocked": r3.status_code == 403,
            "response": r3.json().get("detail"),
        }
    )

    # Attack 4: Stale Timestamp Replay Attack (Valid SupplyPulse ES256 JWT, 10-minute-old signed envelope)
    valid_supply_jwt = issue_scoped_es256_jwt(
        issuer_private_key_pem=ISSUER_PRIVATE_KEY_PEM,
        audience="orders_logistics_service",
    )
    stale_ts = str(int(time.time()) - 600)
    nonce = secrets.token_hex(10)
    stale_sig = compute_request_hmac(
        SERVICES["orders"]["hmac_secret"], "GET", "/inventory/SKU-GPU-H200", stale_ts, nonce
    )
    r4 = await client.get(
        f"{SERVICES['orders']['url']}/inventory/SKU-GPU-H200",
        headers={
            **actor_headers,
            "Authorization": f"Bearer {valid_supply_jwt}",
            "X-Request-Timestamp": stale_ts,
            "X-Request-Nonce": nonce,
            "X-Request-Signature": stale_sig,
        },
    )
    results.append(
        {
            "attack": "4. Captured Packet Replay (10m Stale HMAC Timestamp)",
            "target": "GET https://127.0.0.1:8101/inventory/SKU-GPU-H200",
            "status_code": r4.status_code,
            "blocked": r4.status_code == 401,
            "response": r4.json().get("detail"),
        }
    )

    return {
        "all_attacks_blocked": all(item["blocked"] for item in results),
        "simulations": results,
    }


@app.post("/api/ask")
async def ask_copilot(req: AskRequest) -> Dict[str, Any]:
    async with _mutation_lock:
        await manager.ensure_running_async()
        try:
            return await copilot.ask(req.question, shared_bridge=mcp_pool, bla_enabled=req.bla_enabled)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post("/api/live-discover/enable")
async def api_enable_live_discover() -> Dict[str, Any]:
    if not _is_demo_harness_enabled():
        raise HTTPException(
            status_code=403,
            detail="Live code-mutation harness is disabled when DEMO_HARNESS_ENABLED=0.",
        )
    async with _mutation_lock:
        build_res = await asyncio.to_thread(enable_live_endpoint_and_rebuild)
        await manager.restart_orders_service_async(expect_expedite_route=True)
        await mcp_pool.reload_server("orders_logistics_service")
        tools = [t["name"] for t in mcp_pool.tools_catalog if "orders" in t["server"]]
        return {**build_res, "updated_orders_mcp_tools": tools}


@app.post("/api/live-discover/reset")
async def api_reset_demo() -> Dict[str, Any]:
    if not _is_demo_harness_enabled():
        raise HTTPException(
            status_code=403,
            detail="Live code-mutation harness is disabled when DEMO_HARNESS_ENABLED=0.",
        )
    async with _mutation_lock:
        _studio_false_auth_events.clear()
        build_res = await asyncio.to_thread(disable_live_endpoint_and_rebuild)
        await manager.restart_orders_service_async(expect_expedite_route=False)
        await manager.reset_demo_data_async()
        await mcp_pool.reload_server("orders_logistics_service")
        tools = [t["name"] for t in mcp_pool.tools_catalog if "orders" in t["server"]]
        return {**build_res, "updated_orders_mcp_tools": tools}
