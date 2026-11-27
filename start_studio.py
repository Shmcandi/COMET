"""Launches both HTTPS backend systems and the COMET × Synapse Studio.

Default: http://127.0.0.1:8100 (frictionless browser access with signed HttpOnly JWT session cookie;
all MCP <-> Backend traffic runs over CA-verified TLS 1.3 on https://127.0.0.1:8101 & :8102).
Pass `--https` to also serve the browser UI itself over TLS 1.3 (`https://127.0.0.1:8100`).
"""

import sys
import uvicorn
from security.pki import ensure_tls_certificates

if __name__ == "__main__":
    use_https = "--https" in sys.argv
    if use_https:
        _, cert_path, key_path = ensure_tls_certificates()
        print("\n  COMET × Synapse Studio (Full HTTPS) running at: https://127.0.0.1:8100\n")
        uvicorn.run(
            "dashboard.server:app",
            host="127.0.0.1",
            port=8100,
            ssl_certfile=str(cert_path),
            ssl_keyfile=str(key_path),
            reload=False,
        )
    else:
        print("\n  COMET × Synapse Studio running at: http://127.0.0.1:8100 (Backends on TLS 1.3 :8101/:8102)\n")
        uvicorn.run("dashboard.server:app", host="127.0.0.1", port=8100, reload=False)
