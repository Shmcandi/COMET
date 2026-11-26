"""CareDesk Legacy CRM Service — Support Ticketing, Escalations & SLA Tracking API."""

import os
import re
import secrets
import sys
import threading
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional
from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, field_validator

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from security.auth_guard import FalseAuthRecognitionGuard

app = FastAPI(
    title="CareDesk Support & SLA Ticketing API",
    description="Customer support tickets, SLA breach tracking, and incident escalation service.",
    version="3.3.0",
)

_STATE_LOCK = threading.RLock()
_ID_PATTERN = re.compile(r"^[A-Z0-9-]{2,32}$")
_VALID_PRIORITIES = {"P1", "P2", "P3"}
_VALID_STATUSES = {"open", "mitigated", "resolved"}
_INTERNAL_TOKEN = os.environ.get("COMET_INTERNAL_TOKEN", "")
_AUTH_GUARD = FalseAuthRecognitionGuard(
    service_name="support_ticketing_service",
    issuer_public_key_pem=os.environ.get("ISSUER_PUBLIC_KEY_PEM", ""),
    hmac_secret=os.environ.get("CAREDESK_HMAC_SECRET", "dev-caredesk-hmac-secret"),
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

INITIAL_TICKETS: Dict[str, dict] = {
    "TCK-901": {
        "ticket_id": "TCK-901",
        "customer_id": "CUST-101",
        "customer_name": "Apex BioLabs Pvt Ltd",
        "order_id": "ORD-7801",
        "priority": "P1",
        "status": "open",
        "sla_minutes_remaining": 38,
        "sla_breach_risk": "HIGH",
        "subject": "URGENT: Production lab cluster installation blocked — where is ORD-7801?",
        "sentiment": "critical_frustrated",
        "assigned_to": "Priya Nair",
        "notes": [
            "Customer has field engineers waiting onsite in Bengaluru; needs ETA or local replacement dispatch."
        ],
    },
    "TCK-902": {
        "ticket_id": "TCK-902",
        "customer_id": "CUST-104",
        "customer_name": "MedCore Diagnostics",
        "order_id": "ORD-7812",
        "priority": "P1",
        "status": "open",
        "sla_minutes_remaining": 22,
        "sla_breach_risk": "CRITICAL",
        "subject": "Cold-chain validation deadline today for ORD-7812 telemetry probes",
        "sentiment": "critical_urgent",
        "assigned_to": "Priya Nair",
        "notes": [
            "Audit team scheduled at 17:00 IST; customer asking whether Hyderabad hub can dispatch backup probes."
        ],
    },
    "TCK-903": {
        "ticket_id": "TCK-903",
        "customer_id": "CUST-106",
        "customer_name": "Orbit FinServe",
        "order_id": "ORD-7820",
        "priority": "P1",
        "status": "open",
        "sla_minutes_remaining": 55,
        "sla_breach_risk": "HIGH",
        "subject": "DOA PCIe HSM cards on ORD-7820 — need 2 immediate replacement units",
        "sentiment": "escalated",
        "assigned_to": "Ananya Rao",
        "notes": [
            "Both HSM cards failed POST checksums; customer requests immediate RMA replacement stock check."
        ],
    },
    "TCK-904": {
        "ticket_id": "TCK-904",
        "customer_id": "CUST-103",
        "customer_name": "Nova Retail Systems",
        "order_id": "ORD-7809",
        "priority": "P2",
        "status": "open",
        "sla_minutes_remaining": 195,
        "sla_breach_risk": "MODERATE",
        "subject": "Store launch delayed waiting on RFID checkout terminals (ORD-7809)",
        "sentiment": "concerned",
        "assigned_to": "Rohan Verma",
        "notes": [
            "Customer asked for updated delivery schedule before weekend store opening."
        ],
    },
}

TICKETS = deepcopy(INITIAL_TICKETS)
NEXT_TICKET_SEQ = 905


def _clean_id(raw: str, label: str) -> str:
    cleaned = (raw or "").strip().upper()
    if not _ID_PATTERN.match(cleaned):
        raise HTTPException(status_code=400, detail=f"Invalid {label} identifier format.")
    return cleaned


class CreateTicketRequest(BaseModel):
    customer_id: str = Field(..., min_length=2, max_length=32, description="Customer identifier such as CUST-102")
    customer_name: str = Field(..., min_length=2, max_length=120, description="Customer organization name")
    order_id: str = Field(..., min_length=2, max_length=32, description="Associated order ID such as ORD-7804")
    priority: str = Field(default="P2", description="Ticket priority: P1, P2, or P3")
    subject: str = Field(..., min_length=3, max_length=200, description="Concise summary of the support ticket")
    initial_note: str = Field(..., min_length=3, max_length=1000, description="Initial message or cross-system context")

    @field_validator("customer_id", "order_id")
    @classmethod
    def validate_ids(cls, v: str) -> str:
        cleaned = v.strip().upper()
        if not _ID_PATTERN.match(cleaned):
            raise ValueError("Identifier must match ^[A-Z0-9-]{2,32}$")
        return cleaned

    @field_validator("priority")
    @classmethod
    def validate_priority(cls, v: str) -> str:
        cleaned = (v or "P2").strip().upper()
        if cleaned not in _VALID_PRIORITIES:
            raise ValueError(f"Priority must be one of {sorted(_VALID_PRIORITIES)}")
        return cleaned


class UpdateTicketNoteRequest(BaseModel):
    priority: Optional[str] = Field(default=None, description="Optional updated priority (P1, P2, P3)")
    status: Optional[str] = Field(default=None, description="Optional updated status (open, mitigated, resolved)")
    resolution_note: str = Field(..., min_length=3, max_length=1000, description="Action or logistics update to append")

    @field_validator("priority")
    @classmethod
    def validate_opt_priority(cls, v: Optional[str]) -> Optional[str]:
        if v is None or v == "":
            return None
        cleaned = v.strip().upper()
        if cleaned not in _VALID_PRIORITIES:
            raise ValueError(f"Priority must be one of {sorted(_VALID_PRIORITIES)}")
        return cleaned

    @field_validator("status")
    @classmethod
    def validate_opt_status(cls, v: Optional[str]) -> Optional[str]:
        if v is None or v == "":
            return None
        cleaned = v.strip().lower()
        if cleaned not in _VALID_STATUSES:
            raise ValueError(f"Status must be one of {sorted(_VALID_STATUSES)}")
        return cleaned


@app.get("/health")
def health_check():
    """Internal liveness probe (not exposed to AI agents)."""
    return {"status": "ok", "service": "support_ticketing_service", "tls_auth": "JWT_ES256+HMAC_SHA256"}


@app.get("/internal/security-telemetry")
def internal_security_telemetry():
    """Internal protected endpoint returning false-auth intrusion detection metrics."""
    return _AUTH_GUARD.get_telemetry_snapshot()


@app.post("/internal/reset-demo-state")
def reset_demo_state():
    """Internal protected helper to reset in-memory tickets between hackathon demo runs."""
    global TICKETS, NEXT_TICKET_SEQ
    with _STATE_LOCK:
        TICKETS = deepcopy(INITIAL_TICKETS)
        NEXT_TICKET_SEQ = 905
    _AUTH_GUARD.reset_telemetry()
    return {"reset": True}


@app.get("/tickets")
def list_all_open_tickets():
    """List all active customer support tickets with SLA breach countdowns, priorities, and linked order IDs."""
    with _STATE_LOCK:
        items = [deepcopy(t) for t in TICKETS.values() if t["status"] != "resolved"]
    return {"count": len(items), "tickets": items}


@app.get("/tickets/by-customer/{customer_id}")
def get_tickets_by_customer(customer_id: str):
    """Find all support tickets raised by a specific customer ID (e.g. CUST-101) to check if they reported an issue."""
    cid = _clean_id(customer_id, "customer")
    with _STATE_LOCK:
        items = [deepcopy(t) for t in TICKETS.values() if t["customer_id"].upper() == cid]
    return {
        "customer_id": cid,
        "has_open_ticket": any(t["status"] in ("open", "mitigated") for t in items),
        "count": len(items),
        "tickets": items,
    }


@app.get("/tickets/by-order/{order_id}")
def get_tickets_by_order(order_id: str):
    """Find all support tickets linked to a specific order ID (e.g. ORD-7801)."""
    oid = _clean_id(order_id, "order")
    with _STATE_LOCK:
        items = [deepcopy(t) for t in TICKETS.values() if t["order_id"].upper() == oid]
    return {"order_id": oid, "has_ticket": len(items) > 0, "count": len(items), "tickets": items}


@app.get("/tickets/by-priority/{priority}")
def get_tickets_by_priority(priority: str):
    """Fetch all open support tickets at a given priority tier (e.g. P1, P2, P3)."""
    prio = _clean_id(priority, "priority")
    if prio not in _VALID_PRIORITIES:
        raise HTTPException(status_code=400, detail=f"Priority must be one of {sorted(_VALID_PRIORITIES)}")
    with _STATE_LOCK:
        items: List[dict] = [
            deepcopy(t) for t in TICKETS.values() if t["priority"].upper() == prio and t["status"] == "open"
        ]
    return {"priority": prio, "count": len(items), "tickets": items}


@app.get("/tickets/{ticket_id}")
def get_ticket_by_id(ticket_id: str):
    """Retrieve full support ticket details, SLA countdown, sentiment, and notes for a ticket ID (e.g. TCK-901)."""
    key = _clean_id(ticket_id, "ticket")
    with _STATE_LOCK:
        if key not in TICKETS:
            raise HTTPException(status_code=404, detail=f"Ticket {key} not found")
        return deepcopy(TICKETS[key])


@app.post("/tickets")
def create_proactive_ticket(payload: CreateTicketRequest):
    """Create a new support or proactive outreach ticket for an impacted customer order (idempotent per active order)."""
    global NEXT_TICKET_SEQ
    with _STATE_LOCK:
        for existing in TICKETS.values():
            if (
                existing["customer_id"] == payload.customer_id
                and existing["order_id"] == payload.order_id
                and existing["status"] in ("open", "mitigated")
            ):
                return {**deepcopy(existing), "deduplicated": True}

        ticket_id = f"TCK-{NEXT_TICKET_SEQ}"
        NEXT_TICKET_SEQ += 1
        record = {
            "ticket_id": ticket_id,
            "customer_id": payload.customer_id,
            "customer_name": payload.customer_name.strip(),
            "order_id": payload.order_id,
            "priority": payload.priority,
            "status": "open",
            "sla_minutes_remaining": 60 if payload.priority == "P1" else 240,
            "sla_breach_risk": "HIGH" if payload.priority == "P1" else "LOW",
            "subject": payload.subject.strip(),
            "sentiment": "proactive_outreach",
            "assigned_to": "Auto-Triage Bot -> Priya Nair",
            "created_at": datetime.now(timezone.utc).isoformat(),
            "notes": [payload.initial_note.strip()],
            "deduplicated": False,
        }
        TICKETS[ticket_id] = record
        return deepcopy(record)


@app.patch("/tickets/{ticket_id}/escalate")
def update_or_escalate_ticket(ticket_id: str, payload: UpdateTicketNoteRequest):
    """Escalate or update an existing support ticket with cross-system shipment/inventory resolution notes."""
    key = _clean_id(ticket_id, "ticket")
    with _STATE_LOCK:
        if key not in TICKETS:
            raise HTTPException(status_code=404, detail=f"Ticket {key} not found")
        ticket = TICKETS[key]
        if payload.priority:
            ticket["priority"] = payload.priority
        if payload.status:
            ticket["status"] = payload.status
            if ticket["status"] == "mitigated":
                ticket["sla_breach_risk"] = "MITIGATED"
            elif ticket["status"] == "resolved":
                ticket["sla_breach_risk"] = "NONE"
                ticket["sla_minutes_remaining"] = 0
        note_clean = payload.resolution_note.strip()
        if not ticket["notes"] or ticket["notes"][-1] != note_clean:
            ticket["notes"].append(note_clean)
        return deepcopy(ticket)
