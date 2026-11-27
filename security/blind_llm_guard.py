"""Blind LLM Agent (BLA) Identity-Blinding & Canonical Alias Tokenization Vault.

Hardened properties:
- Case-insensitive word-boundary regex matching (`re.IGNORECASE`) so lowercase or mixed-case
  operator prompts (e.g. `"check apex biolabs ticket"`) are caught on Turn 1.
- Canonical alias unification so short names (`"Apex BioLabs"`) and legal names
  (`"Apex BioLabs Pvt Ltd"`) resolve to the EXACT same `[ORG_BLIND_XXXXXX]` token across
  user prompts, SupplyPulse ERP, and CareDesk CRM.
"""

from __future__ import annotations

import hashlib
import hmac
import re
import secrets
from typing import Any, Dict, List

_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
_PHONE_RE = re.compile(r"(?<!\w)(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}(?!\w)")

_SENSITIVE_FIELD_PREFIXES = {
    "customer_name": "ORG_BLIND",
    "organization": "ORG_BLIND",
    "company_name": "ORG_BLIND",
    "assigned_to": "STAFF_BLIND",
    "contact_email": "EMAIL_BLIND",
    "email": "EMAIL_BLIND",
    "phone": "PHONE_BLIND",
}

# Maps lowercase variants/aliases to their canonical display name so aliases share one blind token
_CANONICAL_ORG_ALIASES: Dict[str, str] = {
    "apex biolabs pvt ltd": "Apex BioLabs Pvt Ltd",
    "apex biolabs": "Apex BioLabs Pvt Ltd",
    "vanguard robotics": "Vanguard Robotics",
    "nova retail systems": "Nova Retail Systems",
    "nova retail": "Nova Retail Systems",
    "medcore diagnostics": "MedCore Diagnostics",
    "medcore": "MedCore Diagnostics",
    "zenith agrotech": "Zenith AgroTech",
    "orbit finserve": "Orbit FinServe",
}

_DEFAULT_KNOWN_STAFF = (
    "Priya Nair",
    "Ananya Rao",
    "Rohan Verma",
)


class BlindLLMVault:
    """Session-scoped bidirectional pseudonymization vault for Blind LLM Agents (BLA)."""

    def __init__(self, session_key: bytes | None = None, preseed_directory: bool = True) -> None:
        self._key = session_key or secrets.token_bytes(32)
        self._token_to_raw: Dict[str, str] = {}
        self._alias_lower_to_token: Dict[str, str] = {}
        self._category_by_token: Dict[str, str] = {}
        self._compiled_matcher: re.Pattern[str] | None = None
        self.tool_outputs_blinded = 0
        self.tool_args_unblinded = 0

        if preseed_directory:
            for alias_lower, canonical_org in _CANONICAL_ORG_ALIASES.items():
                tok = self._mint_token(canonical_org, "ORG_BLIND")
                self._alias_lower_to_token[alias_lower] = tok
            for staff in _DEFAULT_KNOWN_STAFF:
                self._mint_token(staff, "STAFF_BLIND")
            self._rebuild_matcher()

    def _canonicalize(self, raw_value: str, prefix: str) -> str:
        clean = raw_value.strip()
        if prefix == "ORG_BLIND":
            return _CANONICAL_ORG_ALIASES.get(clean.lower(), clean)
        return clean

    def _rebuild_matcher(self) -> None:
        if not self._alias_lower_to_token:
            self._compiled_matcher = None
            return
        # Longest phrases first so "Apex BioLabs Pvt Ltd" matches as a whole before "Apex BioLabs"
        ordered = sorted(self._alias_lower_to_token.keys(), key=len, reverse=True)
        escaped = "|".join(re.escape(k) for k in ordered)
        self._compiled_matcher = re.compile(
            rf"(?<![A-Za-z0-9])(?:{escaped})(?![A-Za-z0-9])",
            re.IGNORECASE,
        )

    def _mint_token(self, raw_value: str, prefix: str) -> str:
        clean = raw_value.strip()
        if not clean:
            return raw_value
        if clean.startswith("[") and clean.endswith("]") and "_BLIND_" in clean:
            return clean

        canonical = self._canonicalize(clean, prefix)
        canon_lower = canonical.lower()
        if canon_lower in self._alias_lower_to_token:
            tok = self._alias_lower_to_token[canon_lower]
            if clean.lower() not in self._alias_lower_to_token:
                self._alias_lower_to_token[clean.lower()] = tok
                self._rebuild_matcher()
            return tok

        digest = hmac.new(
            self._key, f"{prefix}:{canon_lower}".encode("utf-8"), hashlib.sha256
        ).hexdigest()[:6].upper()
        token = f"[{prefix}_{digest}]"

        self._token_to_raw[token] = canonical
        self._alias_lower_to_token[canon_lower] = token
        self._alias_lower_to_token[clean.lower()] = token
        self._category_by_token[token] = prefix
        self._rebuild_matcher()
        return token

    def blind_text(self, text: str) -> str:
        """Case-insensitively replaces registered entities, aliases, emails, and phones."""
        if not text:
            return text
        out = _EMAIL_RE.sub(lambda m: self._mint_token(m.group(0), "EMAIL_BLIND"), text)
        out = _PHONE_RE.sub(lambda m: self._mint_token(m.group(0), "PHONE_BLIND"), out)
        if self._compiled_matcher is not None:
            out = self._compiled_matcher.sub(
                lambda m: self._alias_lower_to_token[m.group(0).lower()],
                out,
            )
        return out

    def blind_payload(self, data: Any) -> Any:
        """Recursively blinds sensitive identity fields in MCP JSON responses before LLM ingestion."""
        if isinstance(data, dict):
            blinded_dict: Dict[str, Any] = {}
            for k, v in data.items():
                prefix = _SENSITIVE_FIELD_PREFIXES.get(k.lower())
                if prefix and isinstance(v, str) and v.strip():
                    self.tool_outputs_blinded += 1
                    blinded_dict[k] = self._mint_token(v, prefix)
                else:
                    blinded_dict[k] = v
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
        """Restores canonical entity names locally for authorized operators or backend writebacks."""
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
            return {k: self.unblind_payload(v) for k, v in data.items()}
        if isinstance(data, list):
            return [self.unblind_payload(item) for item in data]
        if isinstance(data, str):
            restored = self.unblind_text(data)
            if restored != data:
                self.tool_args_unblinded += 1
            return restored
        return data

    def contains_any_raw_pii(self, text: str) -> bool:
        """Audit helper verifying zero registered entities/aliases appear (case-insensitively) in text."""
        if not text:
            return False
        if _EMAIL_RE.search(text) or _PHONE_RE.search(text):
            return True
        if self._compiled_matcher is not None and self._compiled_matcher.search(text):
            return True
        return False

    def summary(self) -> Dict[str, Any]:
        mappings: List[Dict[str, str]] = [
            {
                "blind_token": tok,
                "category": self._category_by_token.get(tok, "ENTITY"),
                "redacted_preview": f"{raw[:3]}***",
            }
            for tok, raw in list(self._token_to_raw.items())[:20]
        ]
        return {
            "bla_enabled": True,
            "unique_entities_blinded": len(self._token_to_raw),
            "field_redactions_count": self.tool_outputs_blinded,
            "writeback_args_unblinded": self.tool_args_unblinded,
            "mappings": mappings,
        }
