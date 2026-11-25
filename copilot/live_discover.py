"""Live endpoint hot-injection + `synapse build --discover` runner for Track 3 Demo."""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Dict

PROJECT_ROOT = Path(__file__).resolve().parent.parent
ORDERS_SERVICE_DIR = PROJECT_ROOT / "services" / "orders_logistics_service"
ORDERS_APP_FILE = ORDERS_SERVICE_DIR / "app.py"
ORDERS_MCP_FILE = ORDERS_SERVICE_DIR / "synapse_auto_server.py"

MARKER = "# --- LIVE_DISCOVER_ENDPOINT_MARKER ---"

BASE_ENDPOINTS = [
    "GET /shipments/delayed",
    "GET /shipments/{shipment_id}",
    "GET /orders/{order_id}",
    "GET /orders/by-shipment/{shipment_id}",
    "GET /inventory/{sku}",
]

LIVE_ENDPOINT_ROUTE = "POST /shipments/{shipment_id}/expedite-reroute"

LIVE_ENDPOINT_CODE = '''# --- LIVE_DISCOVER_ENDPOINT_MARKER ---


class ExpediteRerouteRequest(BaseModel):
    dispatch_hub: str = Field(default="WH-BLR-02", description="Regional warehouse hub to dispatch backup stock from")
    transport_mode: str = Field(default="NEXT_FLIGHT_AIR", description="Expedited air or courier mode")


@app.post("/shipments/{shipment_id}/expedite-reroute")
def expedite_reroute_shipment(shipment_id: str, payload: ExpediteRerouteRequest):
    """Emergency reroute for a delayed shipment: dispatches regional hub inventory via next-flight air freight and issues a 6-hour express ETA."""
    sid = _clean_id(shipment_id, "shipment")
    hub = (payload.dispatch_hub or "WH-BLR-02").strip().upper()
    mode = (payload.transport_mode or "NEXT_FLIGHT_AIR").strip().upper()

    if hub not in VALID_HUBS:
        raise HTTPException(status_code=400, detail=f"Unknown dispatch_hub '{hub}'. Valid hubs: {sorted(VALID_HUBS)}")
    if mode not in VALID_TRANSPORT_MODES:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid transport_mode '{mode}'. Valid modes: {sorted(VALID_TRANSPORT_MODES)}",
        )

    with _STATE_LOCK:
        if sid not in SHIPMENTS:
            raise HTTPException(status_code=404, detail=f"Shipment {sid} not found")
        shipment = SHIPMENTS[sid]

        # Idempotency guard: prevent double inventory deduction on repeated calls!
        if shipment.get("expedited") and shipment.get("expedited_result"):
            return {**deepcopy(shipment["expedited_result"]), "already_expedited": True}

        if shipment["status"] == "DELIVERED":
            raise HTTPException(status_code=409, detail=f"Shipment {sid} is already DELIVERED and cannot be rerouted.")

        dispatched_orders = []
        partial_orders = []
        for oid in shipment["affected_orders"]:
            order = ORDERS.get(oid)
            if not order:
                continue
            can_fulfill = True
            for item in order["items"]:
                inv = INVENTORY.get(item["sku"])
                hub_qty = inv["warehouses"].get(hub, 0) if inv else 0
                if hub_qty < item["quantity"]:
                    can_fulfill = False
            if can_fulfill:
                for item in order["items"]:
                    inv = INVENTORY[item["sku"]]
                    inv["warehouses"][hub] -= item["quantity"]
                    inv["total_available"] -= item["quantity"]
                dispatched_orders.append(oid)
            else:
                partial_orders.append(oid)

        shipment["status"] = "EXPEDITED_REROUTE"
        shipment["expedited"] = True
        shipment["delay_hours"] = 0 if not partial_orders else 6
        shipment["revised_eta"] = "2026-11-25T23:30:00Z (Express 6h Air Dispatch)"
        result = {
            "shipment_id": sid,
            "new_status": shipment["status"],
            "dispatch_hub": hub,
            "transport_mode": mode,
            "air_waybill": f"AWB-AIR-{sid.split('-')[-1]}-99X",
            "express_eta": shipment["revised_eta"],
            "fulfilled_immediately_orders": dispatched_orders,
            "backordered_orders": partial_orders,
            "already_expedited": False,
        }
        shipment["expedited_result"] = deepcopy(result)
        return result
'''


def _find_node_dir() -> str | None:
    hermes_node = Path.home() / "AppData" / "Local" / "hermes" / "tools" / "node-26.7.0-win32-x64"
    if (hermes_node / "node.exe").exists():
        return str(hermes_node)
    found = shutil.which("node")
    return str(Path(found).parent) if found else None


def _atomic_write_text(target: Path, content: str) -> None:
    fd, tmp_name = tempfile.mkstemp(dir=str(target.parent), prefix=".tmp_", suffix=target.suffix)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(content)
        os.replace(tmp_name, target)
    except Exception:
        Path(tmp_name).unlink(missing_ok=True)
        raise


def is_live_endpoint_enabled() -> bool:
    content = ORDERS_APP_FILE.read_text(encoding="utf-8")
    return "def expedite_reroute_shipment" in content


def _run_synapse_discover(endpoints: list[str]) -> Dict[str, Any]:
    synapse_bin = PROJECT_ROOT / "node_modules" / ".bin" / ("synapse.cmd" if os.name == "nt" else "synapse")
    # Pass only safe OS/PATH vars to CLI subprocess (least privilege)
    safe_keys = ("SYSTEMROOT", "WINDIR", "COMSPEC", "PATHEXT", "TEMP", "TMP", "USERPROFILE", "HOME", "APPDATA", "LOCALAPPDATA", "PATH")
    env = {k: os.environ[k] for k in safe_keys if k in os.environ}
    env["SYNAPSE_TELEMETRY"] = "0"
    node_dir = _find_node_dir()
    if node_dir:
        env["PATH"] = f"{node_dir}{os.pathsep}{env.get('PATH', '')}"

    # Keep backup of current MCP server so active readers never see a missing file if build fails
    backup_bytes = ORDERS_MCP_FILE.read_bytes() if ORDERS_MCP_FILE.exists() else None
    for existing in ORDERS_SERVICE_DIR.glob("synapse_auto_server*.py"):
        existing.unlink(missing_ok=True)

    cmd = [
        str(synapse_bin),
        "build",
        "--discover",
        "--auto",
        "--local",
        "--provider",
        "ollama",
        "--endpoints",
        ",".join(endpoints),
    ]
    proc = subprocess.run(
        cmd,
        cwd=str(ORDERS_SERVICE_DIR),
        env=env,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=60,
    )
    if proc.returncode != 0 and backup_bytes is not None and not ORDERS_MCP_FILE.exists():
        ORDERS_MCP_FILE.write_bytes(backup_bytes)

    clean_stdout = re.sub(r"\x1b\[[0-9;]*m", "", proc.stdout or "")
    clean_stderr = re.sub(r"\x1b\[[0-9;]*m", "", proc.stderr or "")
    return {
        "command": f'synapse build --discover --auto --local --endpoints "{",".join(endpoints)}"',
        "returncode": proc.returncode,
        "stdout": clean_stdout.strip(),
        "stderr": clean_stderr.strip(),
        "server_file": str(ORDERS_MCP_FILE),
    }


def enable_live_endpoint_and_rebuild() -> Dict[str, Any]:
    """Injects `POST /shipments/{shipment_id}/expedite-reroute` atomically and rebuilds via `synapse build --discover`."""
    content = ORDERS_APP_FILE.read_text(encoding="utf-8")
    if "def expedite_reroute_shipment" not in content:
        if MARKER not in content:
            raise RuntimeError(f"Marker '{MARKER}' missing in {ORDERS_APP_FILE}")
        updated = content.replace(MARKER, LIVE_ENDPOINT_CODE, 1)
        _atomic_write_text(ORDERS_APP_FILE, updated)

    build_info = _run_synapse_discover(BASE_ENDPOINTS + [LIVE_ENDPOINT_ROUTE])
    if build_info["returncode"] != 0:
        raise RuntimeError(f"Synapse build failed: {build_info['stderr'] or build_info['stdout']}")
    return {
        "enabled": True,
        "added_endpoint": LIVE_ENDPOINT_ROUTE,
        "added_tool": "expedite_reroute_shipment",
        **build_info,
    }


def disable_live_endpoint_and_rebuild() -> Dict[str, Any]:
    """Restores `orders_logistics_service/app.py` to its baseline routes and runs `synapse build --discover`."""
    content = ORDERS_APP_FILE.read_text(encoding="utf-8")
    if MARKER in content:
        head = content.split(MARKER)[0].rstrip() + f"\n\n{MARKER}\n"
        _atomic_write_text(ORDERS_APP_FILE, head)

    build_info = _run_synapse_discover(BASE_ENDPOINTS)
    if build_info["returncode"] != 0:
        raise RuntimeError(f"Synapse rebuild failed: {build_info['stderr'] or build_info['stdout']}")
    return {
        "enabled": False,
        "removed_endpoint": LIVE_ENDPOINT_ROUTE,
        **build_info,
    }
