"""Blind LLM Agent (BLA) Privacy-Preserving Tokenization & De-Tokenization Vault.

Ensures the reasoning LLM operates completely *blind* to sensitive enterprise PII and
customer/employee identities while preserving cross-system relational join consistency:
1. Outbound to LLM (`blind_payload` / `blind_text`):
   Replaces sensitive fields (`customer_name`, `assigned_to`, emails, phone numbers) with
   deterministic, session-keyed HMAC-SHA256 pseudonyms (e.g., `[ORG_BLIND_9A4F]`,
   `[STAFF_BLIND_2C81]`). Identical entities from `SupplyPulse ERP` and `CareDesk CRM`
   map to the exact same blind token so the LLM can still join records across systems.
2. Tool-Call Boundary (`unblind_payload`):
   Automatically restores real values when a Blind LLM passes a blind token back into a
   write tool (such as `create_proactive_ticket` or `update_or_escalate_ticket`).
3. Operator Presentation (`unblind_text`):
   Restores human-readable identities locally for the authenticated Studio operator, while
   exposing the blinded transcript so judges can inspect exact Zero-PII LLM context.
"""

from __future__ import annotations

import hashlib
import hmac
import re
import secrets
from typing import Any, Dict, List

_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
_PHONE_RE = re.compile(r"\b(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b")

_SENSITIVE_FIELD_PREFIXES = {
    "customer_name": "ORG_BLIND",
    "organization": "ORG_BLIND",
    "company_name": "ORG_BLIND",
    "assigned_to": "STAFF_BLIND",
    "contact_email": "EMAIL_BLIND",
    "email": "EMAIL_BLIND",
    "phone": "PHONE_BLIND",
}


class BlindLLMVault:
    """Session-scoped bidirectional pseudonymization vault for Blind LLM Agents (BLA)."""

    def __init__(self, session_key: bytes | None = None) -> None:
        self._key = session_key or secrets.token_bytes(32)
        self._token_to_raw: Dict[str, str] = {}
        self._raw_to_token: Dict[str, str] = {}
        self._category_by_token: Dict[str, str] = {}
        self.tool_outputs_blinded = 0
        self.tool_args_unblinded = 0

    def _mint_token(self, raw_value: str, prefix: str) -> str:
        clean = raw_value.strip()
        if not clean:
            return raw_value
        # Already a blind token
        if clean.startswith("[") and clean.endswith("]") and "_BLIND_" in clean:
            return clean
        if clean in self._raw_to_token:
            return self._raw_to_token[clean]

        digest = hmac.new(
            self._key, f"{prefix}:{clean.lower()}".encode("utf-8"), hashlib.sha256
        ).hexdigest()[:6].upper()
        token = f"[{prefix}_{digest}]"

        self._raw_to_token[clean] = token
        self._token_to_raw[token] = clean
        self._category_by_token[token] = prefix
        return token

    def blind_text(self, text: str) -> str:
        """Replaces known registered entities plus inline emails/phones in free-form text."""
        if not text:
            return text
        out = text
        out = _EMAIL_RE.sub(lambda m: self._mint_token(m.group(0), "EMAIL_BLIND"), out)
        out = _PHONE_RE.sub(lambda m: self._mint_token(m.group(0), "PHONE_BLIND"), out)
        # Replace longest raw strings first to avoid partial substring collisions
        for raw in sorted(self._raw_to_token.keys(), key=len, reverse=True):
            out = out.replace(raw, self._raw_to_token[raw])
        return out

    def blind_payload(self, data: Any) -> Any:
        """Recursively blinds sensitive identity fields in MCP JSON responses before LLM ingestion."""
        if isinstance(data, dict):
            blinded_dict: Dict[str, Any] = {}
            # First pass: register structured identity fields
            for k, v in data.items():
                prefix = _SENSITIVE_FIELD_PREFIXES.get(k.lower())
                if prefix and isinstance(v, str) and v.strip():
                    self.tool_outputs_blinded += 1
                    blinded_dict[k] = self._mint_token(v, prefix)
                else:
                    blinded_dict[k] = v
            # Second pass: recurse and scrub free-text notes/subjects against registered entities
            for k, v in list(blinded_dict.items()):
                if k.lower() not in _SENSITIVE_FIELD_PREFIXES:
                    blinded_dict[k] = self.blind_payload(v)
            return blinded_dict
        if isinstance(data, list):
            return [self.blind_payload(item) for item in data]
        if isinstance(data, str):
            return self.blind_text(data)
        return data

    def unblind_text(self, text: str) -> str:
        """Restores real entity names locally for authorized human operators or backend writebacks."""
        if not text:
            return text
        out = text
        for token, raw in self._token_to_raw.items():
            if token in out:
                out = out.replace(token, raw)
        return out

    def unblind_payload(self, data: Any) -> Any:
        """Recursively restores blind tokens in LLM tool-call arguments before hitting backend APIs."""
        if isinstance(data, dict):
            out: Dict[str, Any] = {}
            for k, v in data.items():
                out[k] = self.unblind_payload(v)
            return out
        if isinstance(data, list):
            return [self.unblind_payload(item) for item in data]
        if isinstance(data, str):
            restored = self.unblind_text(data)
            if restored != data:
                self.tool_args_unblinded += 1
            return restored
        return data

    def contains_any_raw_pii(self, text: str) -> bool:
        """Audit helper verifying zero registered raw PII strings appear in a blinded LLM transcript."""
        if not text:
            return False
        return any(raw in text for raw in self._raw_to_token.keys())

    def summary(self) -> Dict[str, Any]:
        mappings: List[Dict[str, str]] = [
            {"blind_token": tok, "category": self._category_by_token.get(tok, "ENTITY"), "redacted_preview": f"{raw[:3]}***"}
            for tok, raw in list(self._token_to_raw.items())[:20]
        ]
        return {
            "bla_enabled": True,
            "unique_entities_blinded": len(self._token_to_raw),
            "field_redactions_count": self.tool_outputs_blinded,
            "writeback_args_unblinded": self.tool_args_unblinded,
            "mappings": mappings,
        }
