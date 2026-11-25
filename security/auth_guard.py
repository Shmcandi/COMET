"""Asymmetric ES256 (ECDSA P-256) JWT + Per-Service HMAC-SHA256 + False-Auth Intrusion Guard.

Zero-Trust Compartmentalization:
- Only the control-plane token authority holds the ECDSA P-256 PRIVATE key.
- Backend microservices (`orders_logistics_service`, `support_ticketing_service`) receive ONLY
  the ECDSA P-256 PUBLIC key (`ISSUER_PUBLIC_KEY_PEM`) and their own isolated HMAC secret.
- Compromising one backend service yields zero ability to forge JWTs for any service, while
  still allowing public-key signature verification to distinguish a forged token from a genuine
  cross-service token replayed against the wrong audience (`CROSS_SERVICE_AUDIENCE_SPOOF`).
"""

from __future__ import annotations

import collections
import hashlib
import hmac
import secrets
import threading
import time
from datetime import datetime, timezone
from typing import Any, Deque, Dict, Optional, Tuple

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from fastapi import HTTPException, Request

ISSUER = "nexusops-security-authority"
MAX_CLOCK_SKEW_SECONDS = 60
BRUTE_FORCE_WINDOW_SECONDS = 30
BRUTE_FORCE_THRESHOLD = 6
LOCKOUT_DURATION_SECONDS = 15


def generate_es256_keypair_pem() -> Tuple[str, str]:
    """Generates an ephemeral ECDSA P-256 keypair (private PEM for issuer, public PEM for verifiers)."""
    priv = ec.generate_private_key(ec.SECP256R1())
    priv_pem = priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")
    pub_pem = priv.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")
    return priv_pem, pub_pem


def issue_scoped_es256_jwt(
    issuer_private_key_pem: str,
    audience: str,
    subject: str = "synapse-mcp-bridge",
    scope: str = "mcp:tools",
    ttl_seconds: int = 3600,
) -> str:
    """Signs an asymmetric ES256 JWT bound to a single target backend (`aud`)."""
    now = int(time.time())
    payload = {
        "iss": ISSUER,
        "sub": subject,
        "aud": audience,
        "scope": scope,
        "iat": now,
        "exp": now + ttl_seconds,
        "jti": secrets.token_hex(12),
    }
    return jwt.encode(payload, issuer_private_key_pem, algorithm="ES256")


def compute_request_hmac(
    hmac_secret: str,
    method: str,
    path: str,
    timestamp: str,
    nonce: str,
) -> str:
    """Computes HMAC-SHA256 over HTTP method, path, timestamp, and unique request nonce."""
    canonical = f"{method.upper()}:{path}:{timestamp}:{nonce}".encode("utf-8")
    return hmac.new(hmac_secret.encode("utf-8"), canonical, hashlib.sha256).hexdigest()


class FalseAuthRecognitionGuard:
    """Verifies asymmetric ES256 JWTs (public key only) + per-service HMAC request signatures."""

    def __init__(
        self,
        service_name: str,
        issuer_public_key_pem: str,
        hmac_secret: str,
    ) -> None:
        self.service_name = service_name
        self.issuer_public_key_pem = issuer_public_key_pem
        self.hmac_secret = hmac_secret

        self._lock = threading.RLock()
        self._seen_nonces: Dict[str, float] = {}
        self._failure_timestamps: Dict[str, Deque[float]] = collections.defaultdict(collections.deque)
        self._lockout_until: Dict[str, float] = {}
        self._audit_events: Deque[Dict[str, Any]] = collections.deque(maxlen=100)
        self.stats = {
            "authenticated_requests": 0,
            "blocked_false_auth": 0,
            "by_category": collections.Counter(),
        }

    def _record_false_auth(
        self,
        client_id: str,
        category: str,
        path: str,
        method: str,
        detail: str,
        status_code: int,
    ) -> None:
        now = time.time()
        with self._lock:
            self.stats["blocked_false_auth"] += 1
            self.stats["by_category"][category] += 1

            window = self._failure_timestamps[client_id]
            window.append(now)
            while window and (now - window[0]) > BRUTE_FORCE_WINDOW_SECONDS:
                window.popleft()

            if len(window) >= BRUTE_FORCE_THRESHOLD:
                self._lockout_until[client_id] = now + LOCKOUT_DURATION_SECONDS

            self._audit_events.appendleft(
                {
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "service": self.service_name,
                    "client": client_id,
                    "method": method,
                    "path": path,
                    "category": category,
                    "status_code": status_code,
                    "detail": detail,
                }
            )

    def _prune_nonces(self, now: float) -> None:
        expired = [n for n, exp in self._seen_nonces.items() if exp < now]
        for n in expired:
            self._seen_nonces.pop(n, None)

    def verify_request(self, request: Request) -> Dict[str, Any]:
        """Validates ES256 Bearer JWT (via public key) + HMAC headers; logs & blocks anomalies."""
        path = request.url.path
        method = request.method.upper()
        client_ip = request.client.host if request.client else "unknown"
        probe_actor = request.headers.get("x-actor-id", client_ip)[:48]
        now = time.time()

        with self._lock:
            locked_until = self._lockout_until.get(probe_actor, 0.0)
            if locked_until > now:
                rem = round(locked_until - now, 1)
                self._record_false_auth(
                    probe_actor,
                    "BRUTE_FORCE_LOCKOUT",
                    path,
                    method,
                    f"Actor temporarily locked out ({rem}s left) after repeated false-auth attempts.",
                    429,
                )
                raise HTTPException(
                    status_code=429,
                    detail=f"False-Auth Lockout Active: retry after {rem}s.",
                )

        auth_header = request.headers.get("authorization", "").strip()
        if not auth_header or not auth_header.lower().startswith("bearer "):
            self._record_false_auth(
                probe_actor,
                "MISSING_CREDENTIALS",
                path,
                method,
                "Missing Authorization Bearer token on protected endpoint.",
                401,
            )
            raise HTTPException(status_code=401, detail="Authentication required: missing Bearer token.")

        raw_token = auth_header[7:].strip()

        # 1. Verify Asymmetric ES256 Signature using ONLY the Issuer's Public Key (no shared secrets!)
        try:
            unverified_aud_claims = jwt.decode(
                raw_token,
                self.issuer_public_key_pem,
                algorithms=["ES256"],
                issuer=ISSUER,
                options={"verify_aud": False, "require": ["exp", "iat", "iss", "aud", "jti"]},
            )
        except jwt.ExpiredSignatureError as exc:
            self._record_false_auth(
                probe_actor,
                "EXPIRED_TOKEN",
                path,
                method,
                "Presented an expired ES256 Bearer JWT.",
                401,
            )
            raise HTTPException(status_code=401, detail="Bearer token has expired.") from exc
        except jwt.PyJWTError as exc:
            self._record_false_auth(
                probe_actor,
                "TAMPERED_OR_FORGED_TOKEN",
                path,
                method,
                f"Asymmetric ES256 public-key signature check failed ({type(exc).__name__}).",
                401,
            )
            raise HTTPException(status_code=401, detail="Invalid or forged ES256 Bearer token signature.") from exc

        # 2. Enforce Strict Audience Compartment (`aud` must equal this service!)
        token_aud = unverified_aud_claims.get("aud")
        if token_aud != self.service_name:
            self._record_false_auth(
                probe_actor,
                "CROSS_SERVICE_AUDIENCE_SPOOF",
                path,
                method,
                f"Cross-service token replay detected via ES256 public key: token aud='{token_aud}' rejected by '{self.service_name}'.",
                403,
            )
            raise HTTPException(
                status_code=403,
                detail=f"Cross-service false auth blocked: '{token_aud}' token rejected by '{self.service_name}'.",
            )

        # 3. Verify Per-Request Anti-Replay Timestamp + Nonce + Service-Isolated HMAC-SHA256
        req_ts = request.headers.get("x-request-timestamp", "").strip()
        req_nonce = request.headers.get("x-request-nonce", "").strip()
        req_sig = request.headers.get("x-request-signature", "").strip()

        if not req_ts or not req_nonce or not req_sig:
            self._record_false_auth(
                probe_actor,
                "MISSING_HMAC_ENVELOPE",
                path,
                method,
                "Valid ES256 JWT presented without per-request HMAC timestamp/nonce/signature headers.",
                401,
            )
            raise HTTPException(status_code=401, detail="Missing X-Request-Timestamp/Nonce/Signature headers.")

        try:
            ts_int = int(req_ts)
        except ValueError as exc:
            self._record_false_auth(
                probe_actor,
                "TAMPERED_HMAC_ENVELOPE",
                path,
                method,
                "Non-integer X-Request-Timestamp header.",
                401,
            )
            raise HTTPException(status_code=401, detail="Malformed X-Request-Timestamp.") from exc

        if abs(now - ts_int) > MAX_CLOCK_SKEW_SECONDS:
            self._record_false_auth(
                probe_actor,
                "REPLAY_TIMESTAMP_SKEW",
                path,
                method,
                f"Stale/replayed request timestamp skew={round(abs(now - ts_int))}s (> {MAX_CLOCK_SKEW_SECONDS}s).",
                401,
            )
            raise HTTPException(status_code=401, detail="Request timestamp outside allowed anti-replay window.")

        expected_sig = compute_request_hmac(self.hmac_secret, method, path, req_ts, req_nonce)
        if not secrets.compare_digest(req_sig, expected_sig):
            self._record_false_auth(
                probe_actor,
                "TAMPERED_HMAC_SIGNATURE",
                path,
                method,
                "HMAC-SHA256 request signature mismatch.",
                401,
            )
            raise HTTPException(status_code=401, detail="Invalid X-Request-Signature.")

        with self._lock:
            self._prune_nonces(now)
            if req_nonce in self._seen_nonces:
                self._record_false_auth(
                    probe_actor,
                    "REPLAY_NONCE_DETECTED",
                    path,
                    method,
                    f"Duplicate request nonce '{req_nonce[:16]}' replayed within window.",
                    401,
                )
                raise HTTPException(status_code=401, detail="Replay attack blocked: duplicate nonce.")
            self._seen_nonces[req_nonce] = now + MAX_CLOCK_SKEW_SECONDS + 5
            self.stats["authenticated_requests"] += 1

        return unverified_aud_claims

    def get_telemetry_snapshot(self) -> Dict[str, Any]:
        with self._lock:
            now = time.time()
            active_lockouts = {
                actor: round(exp - now, 1)
                for actor, exp in self._lockout_until.items()
                if exp > now
            }
            return {
                "service": self.service_name,
                "jwt_algorithm": "ES256 (Public-Key Verified Only — Zero Shared JWT Secrets)",
                "authenticated_requests": self.stats["authenticated_requests"],
                "blocked_false_auth": self.stats["blocked_false_auth"],
                "by_category": dict(self.stats["by_category"]),
                "active_lockouts": active_lockouts,
                "recent_events": list(self._audit_events)[:20],
            }

    def reset_telemetry(self) -> None:
        with self._lock:
            self._seen_nonces.clear()
            self._failure_timestamps.clear()
            self._lockout_until.clear()
            self._audit_events.clear()
            self.stats["authenticated_requests"] = 0
            self.stats["blocked_false_auth"] = 0
            self.stats["by_category"].clear()
