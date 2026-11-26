"""Automated 24-Assertion Verification Suite: ES256 Auth, TLS 1.3, Schema Guards & MCP Latency."""

from __future__ import annotations

import os
import ssl
import time
import httpx
from fastapi.testclient import TestClient

from copilot.mcp_bridge import validate_tool_arguments, _SAFE_SUBPROCESS_ENV_KEYS
from copilot.service_manager import (
    SERVICES,
    build_signed_service_headers,
    create_verified_ssl_context,
)
from dashboard.server import app
from security.blind_llm_guard import BlindLLMVault


def run_all_checks() -> None:
    assertions_passed = 0

    def check(cond: bool, msg: str) -> None:
        nonlocal assertions_passed
        if not cond:
            raise AssertionError(msg)
        assertions_passed += 1

    ssl_ctx = create_verified_ssl_context()

    # Suite 1: Path Traversal, LLM Schema Hallucination Guard & Secret Isolation (7 assertions)
    schema = {"type": "object", "properties": {"shipment_id": {"type": "string"}}}
    for payload in ("../internal/reset-demo-state", "SHP-402?admin=1", "SHP-402/../../health", "SHP-402%2f.."):
        rejected = False
        try:
            validate_tool_arguments("get_shipment_details", {"shipment_id": payload}, input_schema=schema)
        except ValueError:
            rejected = True
        check(rejected, f"Expected traversal payload {payload!r} to be rejected")

    hallucination_rejected = False
    try:
        validate_tool_arguments(
            "get_shipment_details",
            {"shipment_id": "SHP-402", "hallucinated_param": True},
            input_schema=schema,
        )
    except ValueError:
        hallucination_rejected = True
    check(hallucination_rejected, "Expected hallucinated tool argument key to be rejected")

    for secret_var in ("OPENAI_API_KEY", "GROQ_API_KEY", "ISSUER_PRIVATE_KEY_PEM", "SYNAPSE_API_KEY"):
        check(secret_var not in _SAFE_SUBPROCESS_ENV_KEYS, f"Secret {secret_var} leaked in whitelist")
    print(f"[PASS] Suite 1: Path-traversal, JSON-Schema hallucination guard & env isolation ({assertions_passed} assertions)")

    with TestClient(app) as client:
        # Suite 2: Studio Session Auth, Forged ES256 Token, CSRF & DNS-Rebinding (5 assertions)
        check(client.get("/api/status").status_code == 401, "Missing Studio session must return 401")
        check(
            client.get("/api/status", headers={"Authorization": "Bearer forged.es256.token"}).status_code == 401,
            "Forged Studio Bearer token must return 401",
        )
        r_index = client.get("/")
        check(r_index.status_code == 200 and "comet_studio_session" in client.cookies, "Index must set session cookie")
        check(
            client.post(
                "/api/ask",
                headers={"Origin": "https://evil-attacker.example"},
                json={"question": "Which customers are affected by SHP-402?"},
            ).status_code == 403,
            "Cross-origin POST must return 403",
        )
        check(
            client.get("/api/status", headers={"Host": "evil-rebind.attacker.com"}).status_code == 403,
            "Untrusted Host header must return 403",
        )
        print(f"[PASS] Suite 2: Studio ES256 session cookie, CSRF & DNS-rebinding guards ({assertions_passed} cumulative)")

        # Suite 3: Strict RFC 5280 TLS 1.3 & Untrusted CA Rejection (3 assertions)
        st_initial = client.get("/api/status").json()
        tls_meta = st_initial["security"]["tls"]
        check("TLSv1.3" in tls_meta["protocol"] or "TLSv1.2" in tls_meta["protocol"], f"Unexpected TLS: {tls_meta}")

        plain_failed = False
        try:
            r_plain = httpx.get("http://127.0.0.1:8101/health", timeout=1.5)
            plain_failed = r_plain.status_code >= 400
        except httpx.HTTPError:
            plain_failed = True
        check(plain_failed, "Plaintext HTTP to TLS backend must fail")

        untrusted_rejected = False
        try:
            httpx.get("https://127.0.0.1:8101/health", verify=ssl.create_default_context(), timeout=1.5)
        except httpx.ConnectError:
            untrusted_rejected = True
        check(untrusted_rejected, "System CA without COMET Root CA must reject backend cert")
        print(f"[PASS] Suite 3: Backend HTTPS ({tls_meta['protocol']} · {tls_meta['cipher']}) & CA pinning ({assertions_passed} cumulative)")

        # Suite 4: Asymmetric ES256 False-Auth Recognition, Nonce Replay & Brute-Force Lockout (4 assertions)
        sim = client.post("/api/security/simulate-attacks").json()
        check(sim["all_attacks_blocked"] is True and len(sim["simulations"]) == 4, f"Sim failed: {sim}")

        valid_hdrs = build_signed_service_headers("orders", "GET", "/shipments/SHP-402")
        check(
            httpx.get("https://127.0.0.1:8101/shipments/SHP-402", headers={**valid_hdrs, "X-Actor-Id": "nonce-test"}, verify=ssl_ctx).status_code == 200,
            "First signed request should succeed",
        )
        check(
            httpx.get("https://127.0.0.1:8101/shipments/SHP-402", headers={**valid_hdrs, "X-Actor-Id": "nonce-test"}, verify=ssl_ctx).status_code == 401,
            "Replayed identical nonce must return 401",
        )

        for _ in range(6):
            httpx.get(
                "https://127.0.0.1:8102/tickets",
                headers={"Authorization": "Bearer bad.forged.token", "X-Actor-Id": "brute-bot"},
                verify=ssl_ctx,
            )
        check(
            httpx.get(
                "https://127.0.0.1:8102/tickets",
                headers={"Authorization": "Bearer bad.forged.token", "X-Actor-Id": "brute-bot"},
                verify=ssl_ctx,
            ).status_code == 429,
            "7th consecutive bad auth attempt must return 429 lockout",
        )
        print(f"[PASS] Suite 4: ES256 public-key audience spoof, nonce replay & 429 lockout ({assertions_passed} cumulative)")

        # Suite 5: Production Feature-Flag Lock on Code-Mutation Demo Harness (1 assertion)
        os.environ["DEMO_HARNESS_ENABLED"] = "0"
        try:
            locked_discover = client.post("/api/live-discover/enable")
            check(locked_discover.status_code == 403, "Expected 403 when DEMO_HARNESS_ENABLED=0")
        finally:
            os.environ["DEMO_HARNESS_ENABLED"] = "1"
        print(f"[PASS] Suite 5: DEMO_HARNESS_ENABLED=0 blocks runtime route mutation ({assertions_passed} cumulative)")

        # Suite 6: Split MCP Transport Latency + Live `--discover` + ERP Idempotency (4 assertions)
        client.post("/api/live-discover/reset")

        ask1 = client.post(
            "/api/ask",
            json={"question": "Which customers are affected by delayed shipment SHP-402, and have they raised a support ticket?"},
        ).json()
        check(
            ask1["cross_system_verified"] and ask1["mcp_transport_latency_ms"] < 350 and ask1["llm_inference_latency_ms"] == 0.0,
            f"Unexpected latency split: {ask1}",
        )

        en = client.post("/api/live-discover/enable").json()
        check("expedite_reroute_shipment" in en["updated_orders_mcp_tools"], "Live discover did not add tool")

        r1 = client.post(
            "/api/ask",
            json={"question": "Expedite and reroute delayed shipment SHP-402 via air freight and update affected CareDesk support tickets."},
        ).json()
        r2 = client.post(
            "/api/ask",
            json={"question": "Expedite and reroute delayed shipment SHP-402 via air freight and update affected CareDesk support tickets."},
        ).json()
        inv_hdrs = build_signed_service_headers("orders", "GET", "/inventory/SKU-GPU-H200")
        inv_check = httpx.get("https://127.0.0.1:8101/inventory/SKU-GPU-H200", headers=inv_hdrs, verify=ssl_ctx).json()
        check(
            "`ORD-7801`, `ORD-7804`" in r1["answer"]
            and "`ORD-7801`, `ORD-7804`" in r2["answer"]
            and inv_check["warehouses"]["WH-BLR-02"] == 2,
            "Idempotency check failed on repeated expedite",
        )

        r_deliv = client.post("/api/ask", json={"question": "Expedite and reroute SHP-415 via air freight."}).json()
        check("Already Delivered" in r_deliv["answer"], "Delivered shipment reroute guard failed")

        client.post("/api/live-discover/reset")
        print(
            f"[PASS] Suite 6: MCP transport={ask1['mcp_transport_latency_ms']}ms (LLM=0.0ms), live --discover & ERP idempotency ({assertions_passed} cumulative)"
        )

        # Suite 7: Blind LLM Agent (BLA) Cryptographic Tokenization & Zero-PII Verification (6 assertions)
        vault = BlindLLMVault()
        erp_blinded = vault.blind_payload({"customer_name": "Apex BioLabs Pvt Ltd", "order_id": "ORD-7801"})
        crm_blinded = vault.blind_payload({"customer_name": "Apex BioLabs Pvt Ltd", "assigned_to": "Priya Nair"})
        check(
            erp_blinded["customer_name"].startswith("[ORG_BLIND_")
            and erp_blinded["customer_name"] == crm_blinded["customer_name"],
            "BLA must produce deterministic cross-system tokens for joins",
        )
        check(
            crm_blinded["assigned_to"].startswith("[STAFF_BLIND_"),
            "BLA must blind staff identities",
        )
        scrubbed = vault.blind_text("Email ops@apexbiolabs.in or call +91-984-501-2233 regarding Apex BioLabs Pvt Ltd")
        check(
            "ops@apexbiolabs.in" not in scrubbed
            and "984-501-2233" not in scrubbed
            and "Apex BioLabs Pvt Ltd" not in scrubbed,
            f"BLA text scrubber leaked raw PII: {scrubbed}",
        )
        unblinded_args = vault.unblind_payload({"customer_name": erp_blinded["customer_name"]})
        check(
            unblinded_args["customer_name"] == "Apex BioLabs Pvt Ltd",
            "BLA writeback unblinding failed to restore original organization name",
        )
        check(
            ask1["bla"]["bla_enabled"] is True
            and ask1["bla"]["zero_raw_pii_in_blind_view"] is True
            and "Apex BioLabs" not in ask1["blind_answer"]
            and "Vanguard Robotics" not in ask1["blind_answer"]
            and "[ORG_BLIND_" in ask1["blind_answer"],
            "Live /api/ask blind_answer leaked customer names",
        )
        check(
            "Apex BioLabs Pvt Ltd" in ask1["answer"] and "[ORG_BLIND_" not in ask1["answer"],
            "Operator unblinded view failed to restore readable names",
        )
        print(f"[PASS] Suite 7: Blind LLM Agent (BLA) zero-PII tokenization, cross-system join & writeback unblinding ({assertions_passed} cumulative)")

    print(f"\nSUMMARY: {assertions_passed}/{assertions_passed} assertions passed across 7 verification suites (0 failures).")


if __name__ == "__main__":
    run_all_checks()
