"""Asymmetric ES256 (ECDSA P-256) JWT + Full-Body HMAC-SHA256 + Anti-DoS Intrusion Guard."""

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

ISSUER = "comet-security-authority"
MAX_CLOCK_SKEW_SECONDS = 60
BRUTE_FORCE_WINDOW_SECONDS = 30
BRUTE_FORCE_THRESHOLD = 6
LOCKOUT_DURATION_SECONDS = 15
MAX_TRACKED_NONCES = 4096
MAX_TRACKED_ACTORS = 1024


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
    body_bytes: bytes = b"",
    query: str = "",
) -> str:
    """Computes HMAC-SHA256 over method, path, query, timestamp, nonce, and SHA-256(body)."""
    body_hash = hashlib.sha256(body_bytes or b"").hexdigest()
    canonical = f"{method.upper()}:{path}:{query}:{timestamp}:{nonce}:{body_hash}".encode("utf-8")
    return hmac.new(hmac_secret.encode("utf-8"), canonical, hashlib.sha256).hexdigest()


class FalseAuthRecognitionGuard:
    """Verifies ES256 JWTs + full-body HMAC signatures with unspoofable, bounded rate-limiting."""

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
        self._seen_nonces: collections.OrderedDict[str, float] = collections.OrderedDict()
        self._failure_timestamps: collections.OrderedDict[str, Deque[float]] = collections.OrderedDict()
        self._lockout_until: collections.OrderedDict[str, float] = collections.OrderedDict()
        self._audit_events: Deque[Dict[str, Any]] = collections.deque(maxlen=100)
        self.stats = {
            "authenticated_requests": 0,
            "blocked_false_auth": 0,
            "by_category": collections.Counter(),
        }

    def ensure_configured(self) -> None:
        """Fail-closed guard preventing accidental startup with empty or weak fallback secrets."""
        if not self.issuer_public_key_pem or "BEGIN PUBLIC KEY" not in self.issuer_public_key_pem:
            raise HTTPException(status_code=503, detail="Service misconfigured: ISSUER_PUBLIC_KEY_PEM missing.")
        if not self.hmac_secret or len(self.hmac_secret) < 16:
            raise HTTPException(status_code=503, detail="Service misconfigured: HMAC secret missing or too short.")

    def _evict_bounded_maps(self, now: float) -> None:
        # Prune expired nonces from front of OrderedDict, then enforce hard cap
        while self._seen_nonces:
            oldest_nonce, exp = next(iter(self._seen_nonces.items()))
            if exp < now or len(self._seen_nonces) > MAX_TRACKED_NONCES:
                self._seen_nonces.pop(oldest_nonce, None)
            else:
                break
        while len(self._failure_timestamps) > MAX_TRACKED_ACTORS:
            self._failure_timestamps.popitem(last=False)
        while len(self._lockout_until) > MAX_TRACKED_ACTORS:
            self._lockout_until.popitem(last=False)

    def _record_false_auth(
        self,
        actor_bucket: str,
        category: str,
        path: str,
        method: str,
        detail: str,
        status_code: int,
    ) -> Optional[float]:
        """Records failure and returns active lockout seconds remaining if threshold is exceeded."""
        now = time.time()
        with self._lock:
            self._evict_bounded_maps(now)
            self.stats["blocked_false_auth"] += 1
            self.stats["by_category"][category] += 1

            window = self._failure_timestamps.get(actor_bucket)
            if window is None:
                window = collections.deque()
                self._failure_timestamps[actor_bucket] = window
            else:
                self._failure_timestamps.move_to_end(actor_bucket)

            window.append(now)
            while window and (now - window[0]) > BRUTE_FORCE_WINDOW_SECONDS:
                window.popleft()

            if len(window) >= BRUTE_FORCE_THRESHOLD:
                self._lockout_until[actor_bucket] = now + LOCKOUT_DURATION_SECONDS
                self._lockout_until.move_to_end(actor_bucket)

            self._audit_events.appendleft(
                {
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "service": self.service_name,
                    "client": actor_bucket,
                    "method": method,
                    "path": path,
                    "category": category,
                    "status_code": status_code,
                    "detail": detail,
                }
            )
            locked_until = self._lockout_until.get(actor_bucket, 0.0)
            return round(locked_until - now, 1) if locked_until > now else None

    def _fail_or_lockout(
        self,
        actor_bucket: str,
        category: str,
        path: str,
        method: str,
        detail: str,
        status_code: int,
        public_msg: str,
    ) -> None:
        now = time.time()
        with self._lock:
            existing_lock = self._lockout_until.get(actor_bucket, 0.0)
            if existing_lock > now:
                rem = round(existing_lock - now, 1)
                self._record_false_auth(
                    actor_bucket,
                    "BRUTE_FORCE_LOCKOUT",
                    path,
                    method,
                    f"Source IP locked out ({rem}s left) after repeated false-auth attempts.",
                    429,
                )
                raise HTTPException(
                    status_code=429,
                    detail=f"False-Auth Lockout Active: retry after {rem}s.",
                )

        self._record_false_auth(actor_bucket, category, path, method, detail, status_code)
        raise HTTPException(status_code=status_code, detail=public_msg)

    async def verify_request(self, request: Request) -> Dict[str, Any]:
        """Validates ES256 JWT + full-body HMAC.

        Anti-DoS Design:
        - Rate-limit buckets are keyed strictly by network peer IP (never untrusted X-Actor-Id!).
        - Legitimate requests carrying a valid ES256 JWT + valid HMAC signature succeed even if
          an unauthenticated attacker on the same host/IP triggered a brute-force lockout!
        """
        self.ensure_configured()
        path = request.url.path
        query = request.url.query or ""
        method = request.method.upper()
        # Never trust unauthenticated X-Actor-Id header for rate-limit bucketing!
        actor_bucket = request.client.host if request.client else "unknown"
        now = time.time()

        auth_header = request.headers.get("authorization", "").strip()
        if not auth_header or not auth_header.lower().startswith("bearer "):
            self._fail_or_lockout(
                actor_bucket,
                "MISSING_CREDENTIALS",
                path,
                method,
                "Missing Authorization Bearer token on protected endpoint.",
                401,
                "Authentication required: missing Bearer token.",
            )

        raw_token = auth_header[7:].strip()

        # 1. Verify Asymmetric ES256 Signature via Public Key Only
        try:
            unverified_aud_claims = jwt.decode(
                raw_token,
                self.issuer_public_key_pem,
                algorithms=["ES256"],
                issuer=ISSUER,
                options={"verify_aud": False, "require": ["exp", "iat", "iss", "aud", "jti"]},
            )
        except jwt.ExpiredSignatureError:
            self._fail_or_lockout(
                actor_bucket,
                "EXPIRED_TOKEN",
                path,
                method,
                "Presented an expired ES256 Bearer JWT.",
                401,
                "Bearer token has expired.",
            )
        except jwt.PyJWTError as exc:
            self._fail_or_lockout(
                actor_bucket,
                "TAMPERED_OR_FORGED_TOKEN",
                path,
                method,
                f"Asymmetric ES256 public-key signature check failed ({type(exc).__name__}).",
                401,
                "Invalid or forged ES256 Bearer token signature.",
            )

        # 2. Enforce Strict Audience Compartment (`aud` must equal this service!)
        token_aud = unverified_aud_claims.get("aud")
        if token_aud != self.service_name:
            self._fail_or_lockout(
                actor_bucket,
                "CROSS_SERVICE_AUDIENCE_SPOOF",
                path,
                method,
                f"Cross-service token replay detected via ES256 public key: token aud='{token_aud}' rejected by '{self.service_name}'.",
                403,
                f"Cross-service false auth blocked: '{token_aud}' token rejected by '{self.service_name}'.",
            )

        # 3. Verify Per-Request Timestamp + Nonce + Full-Body/Query HMAC-SHA256
        req_ts = request.headers.get("x-request-timestamp", "").strip()
        req_nonce = request.headers.get("x-request-nonce", "").strip()
        req_sig = request.headers.get("x-request-signature", "").strip()

        if not req_ts or not req_nonce or not req_sig:
            self._fail_or_lockout(
                actor_bucket,
                "MISSING_HMAC_ENVELOPE",
                path,
                method,
                "Valid ES256 JWT presented without per-request HMAC timestamp/nonce/signature headers.",
                401,
                "Missing X-Request-Timestamp/Nonce/Signature headers.",
            )

        try:
            ts_int = int(req_ts)
        except ValueError:
            self._fail_or_lockout(
                actor_bucket,
                "TAMPERED_HMAC_ENVELOPE",
                path,
                method,
                "Non-integer X-Request-Timestamp header.",
                401,
                "Malformed X-Request-Timestamp.",
            )

        if abs(now - ts_int) > MAX_CLOCK_SKEW_SECONDS:
            self._fail_or_lockout(
                actor_bucket,
                "REPLAY_TIMESTAMP_SKEW",
                path,
                method,
                f"Stale/replayed request timestamp skew={round(abs(now - ts_int))}s (> {MAX_CLOCK_SKEW_SECONDS}s).",
                401,
                "Request timestamp outside allowed anti-replay window.",
            )

        body_bytes = await request.body()
        expected_sig = compute_request_hmac(
            self.hmac_secret, method, path, req_ts, req_nonce, body_bytes=body_bytes, query=query
        )
        if not secrets.compare_digest(req_sig, expected_sig):
            self._fail_or_lockout(
                actor_bucket,
                "TAMPERED_HMAC_SIGNATURE",
                path,
                method,
                "HMAC-SHA256 request/body/query signature mismatch (payload or header tampering detected).",
                401,
                "Invalid X-Request-Signature (header, query, or body tampered).",
            )

        with self._lock:
            self._evict_bounded_maps(now)
            if req_nonce in self._seen_nonces:
                self._fail_or_lockout(
                    actor_bucket,
                    "REPLAY_NONCE_DETECTED",
                    path,
                    method,
                    f"Duplicate request nonce '{req_nonce[:16]}' replayed within window.",
                    401,
                    "Replay attack blocked: duplicate nonce.",
                )
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
                "jwt_algorithm": "ES256 (Public-Key Verified) + Full-Body/Query HMAC-SHA256",
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
