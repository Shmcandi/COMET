"""Manages both TLS (`HTTPS`) FastAPI backends with asymmetric ES256 public-key verification."""

from __future__ import annotations

import asyncio
import os
import secrets
import ssl
import subprocess
import sys
import time
from pathlib import Path
from typing import Dict, Optional

import httpx

from security.auth_guard import (
    compute_request_hmac,
    generate_es256_keypair_pem,
    issue_scoped_es256_jwt,
)
from security.pki import ensure_tls_certificates

PROJECT_ROOT = Path(__file__).resolve().parent.parent
VENV_PYTHON = PROJECT_ROOT / ".venv" / "Scripts" / "python.exe"
PYTHON_CMD = str(VENV_PYTHON if VENV_PYTHON.exists() else Path(sys.executable))

CA_CERT_PATH, SERVER_CERT_PATH, SERVER_KEY_PATH = ensure_tls_certificates()

# Control-plane holds the ES256 private key; backends ONLY ever receive ISSUER_PUBLIC_KEY_PEM!
ISSUER_PRIVATE_KEY_PEM, ISSUER_PUBLIC_KEY_PEM = generate_es256_keypair_pem()

INTERNAL_ADMIN_TOKEN = os.environ.get("NEXUSOPS_INTERNAL_TOKEN") or secrets.token_urlsafe(32)
SUPPLYPULSE_HMAC_SECRET = os.environ.get("SUPPLYPULSE_HMAC_SECRET") or secrets.token_urlsafe(32)
CAREDESK_HMAC_SECRET = os.environ.get("CAREDESK_HMAC_SECRET") or secrets.token_urlsafe(32)

os.environ["NEXUSOPS_INTERNAL_TOKEN"] = INTERNAL_ADMIN_TOKEN

SERVICES = {
    "orders": {
        "name": "orders_logistics_service",
        "dir": PROJECT_ROOT / "services" / "orders_logistics_service",
        "port": 8101,
        "url": "https://127.0.0.1:8101",
        "hmac_env_name": "SUPPLYPULSE_HMAC_SECRET",
        "hmac_secret": SUPPLYPULSE_HMAC_SECRET,
    },
    "support": {
        "name": "support_ticketing_service",
        "dir": PROJECT_ROOT / "services" / "support_ticketing_service",
        "port": 8102,
        "url": "https://127.0.0.1:8102",
        "hmac_env_name": "CAREDESK_HMAC_SECRET",
        "hmac_secret": CAREDESK_HMAC_SECRET,
    },
}

_SAFE_ENV_KEYS = (
    "SYSTEMROOT",
    "WINDIR",
    "COMSPEC",
    "PATHEXT",
    "TEMP",
    "TMP",
    "USERPROFILE",
    "HOME",
    "PATH",
)


def create_verified_ssl_context() -> ssl.SSLContext:
    """Returns a strict RFC 5280 TLS verification context pinned to our NexusOps Root CA."""
    ensure_tls_certificates()
    ctx = ssl.create_default_context(cafile=str(CA_CERT_PATH))
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    return ctx


def build_signed_service_headers(key: str, method: str, path: str, subject: str = "studio-control-plane") -> Dict[str, str]:
    """Builds an asymmetric ES256 Bearer JWT + service-isolated HMAC-SHA256 anti-replay envelope."""
    cfg = SERVICES[key]
    token = issue_scoped_es256_jwt(
        issuer_private_key_pem=ISSUER_PRIVATE_KEY_PEM,
        audience=cfg["name"],
        subject=subject,
        ttl_seconds=900,
    )
    ts = str(int(time.time()))
    nonce = secrets.token_hex(12)
    sig = compute_request_hmac(cfg["hmac_secret"], method.upper(), path, ts, nonce)
    return {
        "Authorization": f"Bearer {token}",
        "X-Request-Timestamp": ts,
        "X-Request-Nonce": nonce,
        "X-Request-Signature": sig,
    }


class BackendServiceManager:
    """Starts, health-checks, and hot-restarts both HTTPS backends with compartmentalized secrets."""

    def __init__(self) -> None:
        self.procs: Dict[str, subprocess.Popen] = {}
        self._verified_healthy: Dict[str, bool] = {"orders": False, "support": False}
        self.ssl_ctx = create_verified_ssl_context()

    def _spawn_process(self, key: str) -> None:
        ensure_tls_certificates()
        cfg = SERVICES[key]
        env = {k: os.environ[k] for k in _SAFE_ENV_KEYS if k in os.environ}
        env["NEXUSOPS_INTERNAL_TOKEN"] = INTERNAL_ADMIN_TOKEN
        # Strict compartmentalization: ONLY the public key + THIS service's own HMAC secret!
        env["ISSUER_PUBLIC_KEY_PEM"] = ISSUER_PUBLIC_KEY_PEM
        env[cfg["hmac_env_name"]] = cfg["hmac_secret"]
        env["PYTHONIOENCODING"] = "utf-8"

        cmd = [
            PYTHON_CMD,
            "-m",
            "uvicorn",
            "app:app",
            "--host",
            "127.0.0.1",
            "--port",
            str(cfg["port"]),
            "--ssl-certfile",
            str(SERVER_CERT_PATH),
            "--ssl-keyfile",
            str(SERVER_KEY_PATH),
            "--timeout-graceful-shutdown",
            "2",
            "--log-level",
            "warning",
        ]
        creationflags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
        proc = subprocess.Popen(
            cmd,
            cwd=str(cfg["dir"]),
            env=env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            creationflags=creationflags,
        )
        self.procs[key] = proc
        self._verified_healthy[key] = False

    def _is_proc_alive(self, key: str) -> bool:
        proc = self.procs.get(key)
        return proc is not None and proc.poll() is None

    def _is_healthy_sync(self, key: str) -> bool:
        url = f"{SERVICES[key]['url']}/health"
        try:
            r = httpx.get(url, verify=self.ssl_ctx, timeout=0.9)
            return r.status_code == 200 and r.json().get("tls_auth") == "JWT_ES256+HMAC_SHA256"
        except Exception:
            return False

    async def _is_healthy_async(self, client: httpx.AsyncClient, key: str) -> bool:
        url = f"{SERVICES[key]['url']}/health"
        try:
            r = await client.get(url)
            return r.status_code == 200 and r.json().get("tls_auth") == "JWT_ES256+HMAC_SHA256"
        except Exception:
            return False

    def start_service(self, key: str, force_restart: bool = False) -> None:
        if force_restart:
            self.stop_service(key)
        elif self._is_proc_alive(key) and self._verified_healthy.get(key):
            return
        elif not force_restart:
            if not self._is_proc_alive(key):
                self._kill_port_owner(SERVICES[key]["port"])
            elif self._is_healthy_sync(key):
                self._verified_healthy[key] = True
                return

        self._spawn_process(key)
        deadline = time.perf_counter() + 12.0
        while time.perf_counter() < deadline:
            if self._is_healthy_sync(key):
                self._verified_healthy[key] = True
                return
            time.sleep(0.06)
        raise RuntimeError(f"HTTPS service '{key}' failed to become healthy on {SERVICES[key]['url']}")

    async def ensure_running_async(self) -> None:
        if all(self._is_proc_alive(k) and self._verified_healthy.get(k) for k in ("orders", "support")):
            return

        async with httpx.AsyncClient(verify=self.ssl_ctx, timeout=1.0) as client:
            for key in ("orders", "support"):
                if self._is_proc_alive(key) and await self._is_healthy_async(client, key):
                    self._verified_healthy[key] = True
                    continue
                self.stop_service(key)
                self._kill_port_owner(SERVICES[key]["port"])
                self._spawn_process(key)

            deadline = time.perf_counter() + 12.0
            while time.perf_counter() < deadline:
                checks = await asyncio.gather(
                    self._is_healthy_async(client, "orders"),
                    self._is_healthy_async(client, "support"),
                )
                if all(checks):
                    self._verified_healthy["orders"] = True
                    self._verified_healthy["support"] = True
                    return
                await asyncio.sleep(0.05)
        raise RuntimeError("HTTPS backend microservices failed async readiness check.")

    def start_all(self) -> None:
        for key in ("orders", "support"):
            self.start_service(key)

    async def restart_orders_service_async(self, expect_expedite_route: Optional[bool] = None) -> None:
        """Called inside Studio's `_mutation_lock` after all in-flight Copilot queries have drained."""
        self.stop_service("orders")
        self._spawn_process("orders")
        async with httpx.AsyncClient(verify=self.ssl_ctx, timeout=1.2) as client:
            deadline = time.perf_counter() + 12.0
            while time.perf_counter() < deadline:
                try:
                    headers = build_signed_service_headers("orders", "GET", "/openapi.json")
                    resp = await client.get(f"{SERVICES['orders']['url']}/openapi.json", headers=headers)
                    if resp.status_code == 200:
                        has_route = "/shipments/{shipment_id}/expedite-reroute" in resp.json().get("paths", {})
                        if expect_expedite_route is None or has_route == expect_expedite_route:
                            self._verified_healthy["orders"] = True
                            return
                except Exception:
                    pass
                await asyncio.sleep(0.05)
        raise RuntimeError("Orders HTTPS service did not reload expected OpenAPI routes in time.")

    def restart_orders_service(self, expect_expedite_route: Optional[bool] = None) -> None:
        self.start_service("orders", force_restart=True)
        if expect_expedite_route is not None:
            deadline = time.perf_counter() + 10.0
            while time.perf_counter() < deadline:
                try:
                    headers = build_signed_service_headers("orders", "GET", "/openapi.json")
                    spec = httpx.get(
                        f"{SERVICES['orders']['url']}/openapi.json",
                        headers=headers,
                        verify=self.ssl_ctx,
                        timeout=1.2,
                    ).json()
                    has_route = "/shipments/{shipment_id}/expedite-reroute" in spec.get("paths", {})
                    if has_route == expect_expedite_route:
                        return
                except Exception:
                    pass
                time.sleep(0.05)

    async def reset_demo_data_async(self) -> None:
        headers = {"X-Internal-Token": INTERNAL_ADMIN_TOKEN}
        async with httpx.AsyncClient(verify=self.ssl_ctx, timeout=3.0) as client:
            await asyncio.gather(
                client.post(f"{SERVICES['orders']['url']}/internal/reset-demo-state", headers=headers),
                client.post(f"{SERVICES['support']['url']}/internal/reset-demo-state", headers=headers),
            )

    def reset_demo_data(self) -> None:
        headers = {"X-Internal-Token": INTERNAL_ADMIN_TOKEN}
        for key in ("orders", "support"):
            if self._is_healthy_sync(key):
                r = httpx.post(
                    f"{SERVICES[key]['url']}/internal/reset-demo-state",
                    headers=headers,
                    verify=self.ssl_ctx,
                    timeout=3.0,
                )
                r.raise_for_status()

    @staticmethod
    def _kill_port_owner(port: int) -> None:
        if os.name != "nt":
            return
        try:
            out = subprocess.check_output(
                ["netstat", "-ano", "-p", "tcp"], text=True, encoding="utf-8", errors="ignore"
            )
            for line in out.splitlines():
                if f"127.0.0.1:{port}" in line and "LISTENING" in line:
                    pid = int(line.strip().split()[-1])
                    if pid > 0 and pid != os.getpid():
                        subprocess.run(
                            ["taskkill", "/F", "/PID", str(pid)],
                            stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL,
                        )
        except Exception:
            pass

    def stop_service(self, key: str) -> None:
        self._verified_healthy[key] = False
        proc = self.procs.pop(key, None)
        if proc is not None and proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=2.0)
            except subprocess.TimeoutExpired:
                proc.kill()

    def stop_all(self) -> None:
        for key in list(self.procs.keys()):
            self.stop_service(key)
