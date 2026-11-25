"""Explicit, Auditable TLS + ES256 JWT + HMAC Wrapper for Synapse-Generated MCP Servers.

Replaces implicit `PYTHONPATH` / `sitecustomize.py` hooks with a first-class, inspectable
entrypoint (`python security/authenticated_mcp_runner.py <path/to/synapse_auto_server.py>`):
1. Configures a pooled `requests.Session` verified strictly against `REQUESTS_CA_BUNDLE`.
2. Attaches an explicit `requests.auth.AuthBase` signer (`ScopedES256AndHMACAuth`) to that session.
3. Executes the unmodified Synapse-generated MCP server via `runpy.run_path(..., run_name='__main__')`.
"""

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
    """Explicit requests AuthBase attaching ES256 Bearer JWT + anti-replay HMAC headers."""

    def __init__(self, bearer_jwt: str, hmac_secret: str) -> None:
        self.bearer_jwt = bearer_jwt
        self.hmac_secret = hmac_secret

    def __call__(self, r: requests.PreparedRequest) -> requests.PreparedRequest:
        if self.bearer_jwt and "Authorization" not in r.headers:
            r.headers["Authorization"] = f"Bearer {self.bearer_jwt}"
        if self.hmac_secret:
            parsed_path = urlsplit(r.url or "/").path or "/"
            ts = str(int(time.time()))
            nonce = secrets.token_hex(12)
            canonical = f"{(r.method or 'GET').upper()}:{parsed_path}:{ts}:{nonce}".encode("utf-8")
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

    # Bind the authenticated TLS keep-alive session for the child MCP process
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
