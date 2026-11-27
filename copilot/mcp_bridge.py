"""Persistent, Compartment-Isolated MCP Bridge using Explicit Authenticated Runner + ES256 JWTs."""

from __future__ import annotations

import asyncio
import json
import os
import re
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from copilot.service_manager import CA_CERT_PATH, ISSUER_PRIVATE_KEY_PEM, SERVICES
from security.auth_guard import issue_scoped_es256_jwt

PROJECT_ROOT = Path(__file__).resolve().parent.parent
_WIN_PY = PROJECT_ROOT / ".venv" / "Scripts" / "python.exe"
_POSIX_PY = PROJECT_ROOT / ".venv" / "bin" / "python"
PYTHON_CMD = str(_WIN_PY if _WIN_PY.exists() else (_POSIX_PY if _POSIX_PY.exists() else Path(sys.executable)))
AUTH_RUNNER_SCRIPT = PROJECT_ROOT / "security" / "authenticated_mcp_runner.py"

ORDERS_SERVER_SCRIPT = PROJECT_ROOT / "services" / "orders_logistics_service" / "synapse_auto_server.py"
SUPPORT_SERVER_SCRIPT = PROJECT_ROOT / "services" / "support_ticketing_service" / "synapse_auto_server.py"

SERVER_CONFIGS: Dict[str, Tuple[Path, str, str]] = {
    "orders_logistics_service": (
        ORDERS_SERVER_SCRIPT,
        SERVICES["orders"]["url"],
        SERVICES["orders"]["hmac_secret"],
    ),
    "support_ticketing_service": (
        SUPPORT_SERVER_SCRIPT,
        SERVICES["support"]["url"],
        SERVICES["support"]["hmac_secret"],
    ),
}

_SAFE_SUBPROCESS_ENV_KEYS = (
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

_PATH_ID_FIELDS = {"shipment_id", "order_id", "customer_id", "ticket_id", "sku", "priority"}
_SAFE_ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,32}$")


def validate_tool_arguments(
    tool_name: str,
    arguments: Dict[str, Any],
    input_schema: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Enforces schema property allowlists (hallucination guard) and path-traversal checks."""
    allowed_props: Optional[set[str]] = None
    if input_schema and isinstance(input_schema.get("properties"), dict):
        allowed_props = set(input_schema["properties"].keys())

    sanitized: Dict[str, Any] = {}
    for key, val in (arguments or {}).items():
        if allowed_props is not None and key not in allowed_props:
            raise ValueError(
                f"Hallucinated or unsupported argument '{key}' rejected for tool '{tool_name}'. "
                f"Allowed parameters: {sorted(allowed_props)}"
            )
        if val is None:
            sanitized[key] = None
            continue
        if key in _PATH_ID_FIELDS:
            s_val = str(val).strip()
            if not _SAFE_ID_RE.match(s_val) or ".." in s_val:
                raise ValueError(
                    f"Blocked unsafe path parameter '{key}={s_val!r}' for tool '{tool_name}'."
                )
            sanitized[key] = s_val.upper()
        elif isinstance(val, str):
            if len(val) > 2000:
                raise ValueError(f"Argument '{key}' exceeds maximum allowed length (2000 chars).")
            sanitized[key] = val
        elif isinstance(val, (int, float, bool)):
            sanitized[key] = val
        else:
            raise ValueError(f"Unsupported nested argument type for '{key}' in tool '{tool_name}'.")
    return sanitized


class _MCPServerWorker:
    """Dedicated single-task owner of one explicit `authenticated_mcp_runner.py` stdio session."""

    def __init__(
        self,
        server_name: str,
        script_path: Path,
        base_url: str,
        hmac_secret: str,
    ) -> None:
        self.server_name = server_name
        self.script_path = script_path
        self.base_url = base_url
        self.hmac_secret = hmac_secret
        self.tools: List[Dict[str, Any]] = []
        self._queue: asyncio.Queue = asyncio.Queue()
        self._ready = asyncio.Event()
        self._startup_error: Optional[BaseException] = None
        self._task: Optional[asyncio.Task] = None

    async def start(self) -> None:
        if self._task is not None and not self._task.done():
            await self._ready.wait()
            return
        self._ready.clear()
        self._startup_error = None
        self._queue = asyncio.Queue()
        self._task = asyncio.create_task(self._run_loop(), name=f"mcp-worker-{self.server_name}")
        await self._ready.wait()
        if self._startup_error is not None:
            raise RuntimeError(
                f"Failed to start MCP server '{self.server_name}': {self._startup_error}"
            ) from self._startup_error

    async def _run_loop(self) -> None:
        # Mint an asymmetric ES256 JWT; child worker NEVER receives ISSUER_PRIVATE_KEY_PEM!
        scoped_jwt = issue_scoped_es256_jwt(
            issuer_private_key_pem=ISSUER_PRIVATE_KEY_PEM,
            audience=self.server_name,
            subject=f"mcp-worker:{self.server_name}",
            ttl_seconds=86400,
        )
        env = {k: os.environ[k] for k in _SAFE_SUBPROCESS_ENV_KEYS if k in os.environ}
        env["ENDPOINT_BASE_URL"] = self.base_url
        env["PYTHONIOENCODING"] = "utf-8"
        env["REQUESTS_CA_BUNDLE"] = str(CA_CERT_PATH)
        env["SSL_CERT_FILE"] = str(CA_CERT_PATH)
        env["MCP_SERVICE_JWT"] = scoped_jwt
        env["MCP_HMAC_SECRET"] = self.hmac_secret

        params = StdioServerParameters(
            command=PYTHON_CMD,
            args=[str(AUTH_RUNNER_SCRIPT), str(self.script_path)],
            env=env,
        )
        try:
            async with stdio_client(params) as (read_stream, write_stream):
                async with ClientSession(read_stream, write_stream) as session:
                    await session.initialize()
                    listed = await session.list_tools()
                    self.tools = [
                        {
                            "name": t.name,
                            "server": self.server_name,
                            "description": t.description or "",
                            "inputSchema": t.inputSchema,
                        }
                        for t in listed.tools
                    ]
                    self._ready.set()

                    while True:
                        op, payload, fut = await self._queue.get()
                        if op == "STOP":
                            if not fut.done():
                                fut.set_result(True)
                            break
                        elif op == "CALL":
                            tool_name, args = payload
                            try:
                                res = await asyncio.wait_for(
                                    session.call_tool(tool_name, arguments=args),
                                    timeout=15.0,
                                )
                                if not fut.done():
                                    fut.set_result(res)
                            except BaseException as exc:
                                if not fut.done():
                                    fut.set_exception(exc)
        except BaseException as exc:
            self._startup_error = exc
            self._ready.set()
            while not self._queue.empty():
                _, _, fut = self._queue.get_nowait()
                if not fut.done():
                    fut.set_exception(exc)

    @property
    def is_alive(self) -> bool:
        return self._task is not None and not self._task.done() and self._startup_error is None

    async def call_tool(self, tool_name: str, arguments: Dict[str, Any]):
        if not self.is_alive:
            await self.start()
        loop = asyncio.get_running_loop()
        fut = loop.create_future()
        await self._queue.put(("CALL", (tool_name, arguments), fut))
        return await fut

    async def stop(self) -> None:
        if self._task is None or self._task.done():
            self._task = None
            return
        loop = asyncio.get_running_loop()
        fut = loop.create_future()
        await self._queue.put(("STOP", None, fut))
        try:
            await asyncio.wait_for(self._task, timeout=3.0)
        except Exception:
            self._task.cancel()
        finally:
            self._task = None


class MultiSystemMCPBridge:
    """Warm, compartment-isolated MCP client bridge across both Synapse-generated servers."""

    def __init__(self, persistent: bool = False) -> None:
        self._persistent = persistent
        self._workers: Dict[str, _MCPServerWorker] = {}
        self._lifecycle_lock = asyncio.Lock()
        self.tool_to_server: Dict[str, str] = {}
        self.tool_schemas: Dict[str, Dict[str, Any]] = {}
        self.tools_catalog: List[Dict[str, Any]] = []

    async def __aenter__(self) -> "MultiSystemMCPBridge":
        await self.ensure_connected()
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        if not self._persistent:
            await self.close()

    def _rebuild_catalog(self) -> None:
        self.tool_to_server = {}
        self.tool_schemas = {}
        self.tools_catalog = []
        for server_name, worker in self._workers.items():
            for tool in worker.tools:
                self.tool_to_server[tool["name"]] = server_name
                self.tool_schemas[tool["name"]] = tool.get("inputSchema") or {}
                self.tools_catalog.append(tool)

    async def ensure_connected(self) -> None:
        if self._workers and all(w.is_alive for w in self._workers.values()):
            return
        async with self._lifecycle_lock:
            to_start = []
            for server_name, (script_path, base_url, hmac_sec) in SERVER_CONFIGS.items():
                worker = self._workers.get(server_name)
                if worker is None or not worker.is_alive:
                    worker = _MCPServerWorker(server_name, script_path, base_url, hmac_sec)
                    self._workers[server_name] = worker
                    to_start.append(worker.start())
            if to_start:
                await asyncio.gather(*to_start)
            self._rebuild_catalog()

    async def reload_server(self, server_name: str = "orders_logistics_service") -> List[Dict[str, Any]]:
        async with self._lifecycle_lock:
            old = self._workers.get(server_name)
            if old is not None:
                await old.stop()
            script_path, base_url, hmac_sec = SERVER_CONFIGS[server_name]
            fresh = _MCPServerWorker(server_name, script_path, base_url, hmac_sec)
            self._workers[server_name] = fresh
            await fresh.start()
            self._rebuild_catalog()
            return list(self.tools_catalog)

    async def close(self) -> None:
        async with self._lifecycle_lock:
            stops = [w.stop() for w in self._workers.values()]
            if stops:
                await asyncio.gather(*stops, return_exceptions=True)
            self._workers.clear()
            self.tool_to_server.clear()
            self.tool_schemas.clear()
            self.tools_catalog.clear()

    def has_tool(self, tool_name: str) -> bool:
        return tool_name in self.tool_to_server

    async def call_tool(
        self,
        tool_name: str,
        arguments: Optional[Dict[str, Any]] = None,
        trace_log: Optional[List[Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        await self.ensure_connected()
        if tool_name not in self.tool_to_server:
            raise KeyError(f"Tool '{tool_name}' is not registered in any connected MCP server.")

        schema = self.tool_schemas.get(tool_name)
        clean_args = validate_tool_arguments(tool_name, arguments or {}, input_schema=schema)
        server_name = self.tool_to_server[tool_name]
        worker = self._workers[server_name]

        started = time.perf_counter()
        result = await worker.call_tool(tool_name, clean_args)
        elapsed_ms = round((time.perf_counter() - started) * 1000, 1)

        is_error = bool(getattr(result, "isError", False))
        raw_texts: List[str] = []
        for item in getattr(result, "content", []) or []:
            text = getattr(item, "text", None)
            if text is not None:
                raw_texts.append(text)

        joined = "\n".join(raw_texts).strip()
        if joined:
            try:
                parsed_payload = json.loads(joined)
                if not isinstance(parsed_payload, dict):
                    parsed_payload = {"data": parsed_payload}
            except json.JSONDecodeError:
                parsed_payload = {"error" if is_error else "raw": joined}
        else:
            parsed_payload = {"error": "Empty MCP response"} if is_error else {}

        if is_error and "error" not in parsed_payload:
            parsed_payload["error"] = joined or "MCP tool execution returned an error."

        if trace_log is not None:
            trace_log.append(
                {
                    "server": server_name,
                    "system_badge": "SupplyPulse ERP (TLS)" if "orders" in server_name else "CareDesk CRM (TLS)",
                    "tool": tool_name,
                    "arguments": clean_args,
                    "latency_ms": elapsed_ms,
                    "is_error": is_error,
                    "transport_security": "stdio -> HTTPS TLS 1.3 + JWT(ES256) + HMAC-SHA256",
                    "output": parsed_payload,
                }
            )
        return parsed_payload
