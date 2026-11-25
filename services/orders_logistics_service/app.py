"""SupplyPulse Legacy ERP Service — Orders, Freight Shipments & Warehouse Inventory API."""

import os
import re
import secrets
import sys
import threading
from copy import deepcopy
from pathlib import Path
from typing import Dict, List
from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from security.auth_guard import FalseAuthRecognitionGuard

app = FastAPI(
    title="SupplyPulse Orders & Logistics API",
    description="Enterprise orders, freight shipments, and warehouse stock service.",
    version="2.6.0",
)

_STATE_LOCK = threading.RLock()
_ID_PATTERN = re.compile(r"^[A-Z0-9-]{2,32}$")
_INTERNAL_TOKEN = os.environ.get("NEXUSOPS_INTERNAL_TOKEN", "")
_AUTH_GUARD = FalseAuthRecognitionGuard(
    service_name="orders_logistics_service",
    issuer_public_key_pem=os.environ.get("ISSUER_PUBLIC_KEY_PEM", ""),
    hmac_secret=os.environ.get("SUPPLYPULSE_HMAC_SECRET", "dev-supplypulse-hmac-secret"),
)


@app.middleware("http")
async def enforce_service_auth_middleware(request: Request, call_next):
    path = request.url.path
    if path == "/health":
        return await call_next(request)
    if path.startswith("/internal/"):
        token = request.headers.get("x-internal-token", "")
        if not _INTERNAL_TOKEN or not secrets.compare_digest(token, _INTERNAL_TOKEN):
            actor = request.headers.get("x-actor-id", request.client.host if request.client else "unknown")
            _AUTH_GUARD._record_false_auth(
                actor,
                "PRIVILEGE_ESCALATION_ATTEMPT",
                path,
                request.method,
                "Unauthorized attempt to invoke internal admin endpoint without valid X-Internal-Token.",
                403,
            )
            return JSONResponse(status_code=403, content={"detail": "Forbidden: valid X-Internal-Token required."})
        return await call_next(request)

    try:
        _AUTH_GUARD.verify_request(request)
    except HTTPException as exc:
        return JSONResponse(status_code=exc.status_code, content={"detail": exc.detail})
    return await call_next(request)

INITIAL_SHIPMENTS: Dict[str, dict] = {
    "SHP-402": {
        "shipment_id": "SHP-402",
        "status": "DELAYED",
        "corridor": "Shenzhen -> Bengaluru Tech Hub",
        "carrier": "BlueDart Freight Express",
        "delay_hours": 54,
        "delay_reason": "Customs clearance hold and port congestion at Nhava Sheva",
        "original_eta": "2026-11-24T14:00:00Z",
        "revised_eta": "2026-11-26T20:00:00Z",
        "affected_orders": ["ORD-7801", "ORD-7804", "ORD-7809"],
        "expedited": False,
        "expedited_result": None,
    },
    "SHP-409": {
        "shipment_id": "SHP-409",
        "status": "DELAYED",
        "corridor": "Pune -> Hyderabad Pharma Park",
        "carrier": "Delhivery ColdChain",
        "delay_hours": 28,
        "delay_reason": "Reefer compressor fault at Solapur highway checkpoint",
        "original_eta": "2026-11-25T09:00:00Z",
        "revised_eta": "2026-11-26T13:00:00Z",
        "affected_orders": ["ORD-7812", "ORD-7815"],
        "expedited": False,
        "expedited_result": None,
    },
    "SHP-415": {
        "shipment_id": "SHP-415",
        "status": "DELIVERED",
        "corridor": "Mumbai -> Gurugram CyberCity",
        "carrier": "BlueDart Air",
        "delay_hours": 0,
        "delay_reason": None,
        "original_eta": "2026-11-23T11:00:00Z",
        "revised_eta": "2026-11-23T10:45:00Z",
        "affected_orders": ["ORD-7820"],
        "expedited": False,
        "expedited_result": None,
    },
}

INITIAL_ORDERS: Dict[str, dict] = {
    "ORD-7801": {
        "order_id": "ORD-7801",
        "customer_id": "CUST-101",
        "customer_name": "Apex BioLabs Pvt Ltd",
        "account_tier": "Enterprise",
        "annual_contract_usd": 240000,
        "order_total_usd": 48500,
        "shipment_id": "SHP-402",
        "nearest_hub": "WH-BLR-02",
        "items": [
            {"sku": "SKU-GPU-H200", "product_name": "Edge AI Inference Server Blade", "quantity": 4}
        ],
    },
    "ORD-7804": {
        "order_id": "ORD-7804",
        "customer_id": "CUST-102",
        "customer_name": "Vanguard Robotics",
        "account_tier": "Enterprise",
        "annual_contract_usd": 185000,
        "order_total_usd": 31200,
        "shipment_id": "SHP-402",
        "nearest_hub": "WH-BLR-02",
        "items": [
            {"sku": "SKU-LIDAR-X4", "product_name": "Solid-State 3D LiDAR Array", "quantity": 12}
        ],
    },
    "ORD-7809": {
        "order_id": "ORD-7809",
        "customer_id": "CUST-103",
        "customer_name": "Nova Retail Systems",
        "account_tier": "Growth",
        "annual_contract_usd": 36000,
        "order_total_usd": 6400,
        "shipment_id": "SHP-402",
        "nearest_hub": "WH-BLR-02",
        "items": [
            {"sku": "SKU-POS-TERM", "product_name": "Smart RFID Checkout Terminal", "quantity": 8}
        ],
    },
    "ORD-7812": {
        "order_id": "ORD-7812",
        "customer_id": "CUST-104",
        "customer_name": "MedCore Diagnostics",
        "account_tier": "Enterprise",
        "annual_contract_usd": 310000,
        "order_total_usd": 62000,
        "shipment_id": "SHP-409",
        "nearest_hub": "WH-HYD-01",
        "items": [
            {"sku": "SKU-CRYO-SENS", "product_name": "Ultra-Low Temp Telemetry Probe", "quantity": 20}
        ],
    },
    "ORD-7815": {
        "order_id": "ORD-7815",
        "customer_id": "CUST-105",
        "customer_name": "Zenith AgroTech",
        "account_tier": "Mid-Market",
        "annual_contract_usd": 52000,
        "order_total_usd": 9800,
        "shipment_id": "SHP-409",
        "nearest_hub": "WH-HYD-01",
        "items": [
            {"sku": "SKU-SOIL-NODE", "product_name": "LoRaWAN Multi-Depth Soil Node", "quantity": 35}
        ],
    },
    "ORD-7820": {
        "order_id": "ORD-7820",
        "customer_id": "CUST-106",
        "customer_name": "Orbit FinServe",
        "account_tier": "Enterprise",
        "annual_contract_usd": 290000,
        "order_total_usd": 22000,
        "shipment_id": "SHP-415",
        "nearest_hub": "WH-MUM-01",
        "items": [
            {"sku": "SKU-HSM-CARD", "product_name": "PCIe Hardware Security Module", "quantity": 2}
        ],
    },
}

INITIAL_INVENTORY: Dict[str, dict] = {
    "SKU-GPU-H200": {
        "sku": "SKU-GPU-H200",
        "product_name": "Edge AI Inference Server Blade",
        "total_available": 6,
        "reorder_threshold": 5,
        "unit_price_usd": 12125,
        "warehouses": {"WH-BLR-02": 6, "WH-MUM-01": 0, "WH-HYD-01": 0},
    },
    "SKU-LIDAR-X4": {
        "sku": "SKU-LIDAR-X4",
        "product_name": "Solid-State 3D LiDAR Array",
        "total_available": 18,
        "reorder_threshold": 10,
        "unit_price_usd": 2600,
        "warehouses": {"WH-BLR-02": 14, "WH-MUM-01": 4, "WH-HYD-01": 0},
    },
    "SKU-POS-TERM": {
        "sku": "SKU-POS-TERM",
        "product_name": "Smart RFID Checkout Terminal",
        "total_available": 3,
        "reorder_threshold": 10,
        "unit_price_usd": 800,
        "warehouses": {"WH-BLR-02": 3, "WH-MUM-01": 0, "WH-HYD-01": 0},
    },
    "SKU-CRYO-SENS": {
        "sku": "SKU-CRYO-SENS",
        "product_name": "Ultra-Low Temp Telemetry Probe",
        "total_available": 25,
        "reorder_threshold": 15,
        "unit_price_usd": 3100,
        "warehouses": {"WH-BLR-02": 0, "WH-MUM-01": 5, "WH-HYD-01": 20},
    },
    "SKU-SOIL-NODE": {
        "sku": "SKU-SOIL-NODE",
        "product_name": "LoRaWAN Multi-Depth Soil Node",
        "total_available": 50,
        "reorder_threshold": 20,
        "unit_price_usd": 280,
        "warehouses": {"WH-BLR-02": 10, "WH-MUM-01": 0, "WH-HYD-01": 40},
    },
    "SKU-HSM-CARD": {
        "sku": "SKU-HSM-CARD",
        "product_name": "PCIe Hardware Security Module",
        "total_available": 1,
        "reorder_threshold": 4,
        "unit_price_usd": 11000,
        "warehouses": {"WH-BLR-02": 0, "WH-MUM-01": 1, "WH-HYD-01": 0},
    },
}

VALID_HUBS = {"WH-BLR-02", "WH-MUM-01", "WH-HYD-01"}
VALID_TRANSPORT_MODES = {"NEXT_FLIGHT_AIR", "DEDICATED_COURIER", "EXPRESS_SURFACE"}

SHIPMENTS = deepcopy(INITIAL_SHIPMENTS)
ORDERS = deepcopy(INITIAL_ORDERS)
INVENTORY = deepcopy(INITIAL_INVENTORY)


def _clean_id(raw: str, label: str) -> str:
    cleaned = (raw or "").strip().upper()
    if not _ID_PATTERN.match(cleaned):
        raise HTTPException(status_code=400, detail=f"Invalid {label} identifier format.")
    return cleaned


@app.get("/health")
def health_check():
    """Internal liveness probe (not exposed to AI agents)."""
    return {"status": "ok", "service": "orders_logistics_service", "tls_auth": "JWT_ES256+HMAC_SHA256"}


@app.get("/internal/security-telemetry")
def internal_security_telemetry():
    """Internal protected endpoint returning false-auth intrusion detection metrics."""
    return _AUTH_GUARD.get_telemetry_snapshot()


@app.post("/internal/reset-demo-state")
def reset_demo_state():
    """Internal protected helper to reset in-memory state between hackathon demo runs."""
    global SHIPMENTS, ORDERS, INVENTORY
    with _STATE_LOCK:
        SHIPMENTS = deepcopy(INITIAL_SHIPMENTS)
        ORDERS = deepcopy(INITIAL_ORDERS)
        INVENTORY = deepcopy(INITIAL_INVENTORY)
    _AUTH_GUARD.reset_telemetry()
    return {"reset": True}


@app.get("/shipments/delayed")
def list_delayed_shipments():
    """List all unmitigated delayed freight shipments, including delay hours, reason, carrier, and affected order IDs."""
    with _STATE_LOCK:
        delayed = [deepcopy(s) for s in SHIPMENTS.values() if s["status"] == "DELAYED"]
    return {"count": len(delayed), "shipments": delayed}


@app.get("/shipments/{shipment_id}")
def get_shipment_details(shipment_id: str):
    """Get detailed status, delay reason, ETA, and affected order IDs for a specific shipment ID (e.g. SHP-402)."""
    key = _clean_id(shipment_id, "shipment")
    with _STATE_LOCK:
        if key not in SHIPMENTS:
            raise HTTPException(status_code=404, detail=f"Shipment {key} not found")
        return deepcopy(SHIPMENTS[key])


@app.get("/orders/{order_id}")
def get_order_by_id(order_id: str):
    """Fetch customer details, account tier, contract value, SKUs, and quantities for a specific order ID (e.g. ORD-7801)."""
    key = _clean_id(order_id, "order")
    with _STATE_LOCK:
        if key not in ORDERS:
            raise HTTPException(status_code=404, detail=f"Order {key} not found")
        return deepcopy(ORDERS[key])


@app.get("/orders/by-shipment/{shipment_id}")
def get_orders_by_shipment(shipment_id: str):
    """Fetch all customer orders travelling inside a specific freight shipment ID (e.g. SHP-402)."""
    sid = _clean_id(shipment_id, "shipment")
    with _STATE_LOCK:
        results: List[dict] = [deepcopy(o) for o in ORDERS.values() if o["shipment_id"].upper() == sid]
    return {"shipment_id": sid, "count": len(results), "orders": results}


@app.get("/inventory/{sku}")
def get_inventory_by_sku(sku: str):
    """Check real-time warehouse stock levels, regional breakdown, and reorder status for a product SKU."""
    key = _clean_id(sku, "SKU")
    with _STATE_LOCK:
        if key not in INVENTORY:
            raise HTTPException(status_code=404, detail=f"SKU {key} not found")
        item = deepcopy(INVENTORY[key])
    return {
        **item,
        "below_reorder_threshold": item["total_available"] <= item["reorder_threshold"],
    }

# --- LIVE_DISCOVER_ENDPOINT_MARKER ---
