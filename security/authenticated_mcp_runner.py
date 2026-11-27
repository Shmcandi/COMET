"""Explicit, Auditable TLS + ES256 JWT + Full-Body HMAC Wrapper for Synapse MCP Servers."""

from __future__ import annotations

import hashlib
import hmac
import os
import runpy
import secrets
import sys
import time
from pathlib import Path
from urllib.parse import urlsplit

import requests
from requests.auth import AuthBase


class ScopedES256AndHMACAuth(AuthBase):
    """Explicit requests AuthBase signing method, path, query, timestamp, nonce, and SHA256(body)."""

    def __init__(self, bearer_jwt: str, hmac_secret: str) -> None:
        self.bearer_jwt = bearer_jwt
        self.hmac_secret = hmac_secret

    def __call__(self, r: requests.PreparedRequest) -> requests.PreparedRequest:
        if self.bearer_jwt and "Authorization" not in r.headers:
            r.headers["Authorization"] = f"Bearer {self.bearer_jwt}"
        if self.hmac_secret:
            parsed = urlsplit(r.url or "/")
            parsed_path = parsed.path or "/"
            parsed_query = parsed.query or ""
            raw_body = r.body
            if isinstance(raw_body, str):
                body_bytes = raw_body.encode("utf-8")
            elif isinstance(raw_body, (bytes, bytearray)):
                body_bytes = bytes(raw_body)
            else:
                body_bytes = b""

            body_hash = hashlib.sha256(body_bytes).hexdigest()
            ts = str(int(time.time()))
            nonce = secrets.token_hex(12)
            canonical = (
                f"{(r.method or 'GET').upper()}:{parsed_path}:{parsed_query}:{ts}:{nonce}:{body_hash}"
            ).encode("utf-8")
            sig = hmac.new(self.hmac_secret.encode("utf-8"), canonical, hashlib.sha256).hexdigest()
            r.headers["X-Request-Timestamp"] = ts
            r.headers["X-Request-Nonce"] = nonce
            r.headers["X-Request-Signature"] = sig
        return r


def main() -> None:
    if len(sys.argv) < 2:
        raise SystemExit("Usage: python security/authenticated_mcp_runner.py <synapse_auto_server.py>")

    target_script = Path(sys.argv[1]).resolve()
    if not target_script.exists():
        raise FileNotFoundError(f"MCP server script not found: {target_script}")

    session = requests.Session()
    ca_bundle = os.environ.get("REQUESTS_CA_BUNDLE", "").strip()
    if ca_bundle:
        session.verify = ca_bundle
    session.auth = ScopedES256AndHMACAuth(
        bearer_jwt=os.environ.get("MCP_SERVICE_JWT", ""),
        hmac_secret=os.environ.get("MCP_HMAC_SECRET", ""),
    )

    def _dispatch(method: str, url: str, **kwargs):
        kwargs.setdefault("timeout", 10.0)
        return session.request(method=method, url=url, **kwargs)

    requests.get = lambda url, **kw: _dispatch("GET", url, **kw)
    requests.post = lambda url, **kw: _dispatch("POST", url, **kw)
    requests.put = lambda url, **kw: _dispatch("PUT", url, **kw)
    requests.patch = lambda url, **kw: _dispatch("PATCH", url, **kw)
    requests.delete = lambda url, **kw: _dispatch("DELETE", url, **kw)

    sys.path.insert(0, str(target_script.parent))
    sys.argv = [str(target_script)]
    runpy.run_path(str(target_script), run_name="__main__")


if __name__ == "__main__":
    main()
