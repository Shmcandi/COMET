# COMET — Cross-System Supply Chain & Support Copilot (with Blind LLM Agents)

**2nd Brain Labs × Geek Room: Vibe-a-thon Submission**  
**Selected Track:** **Problem Statement 3 — *A copilot that works across two systems*** (`Synapse Auto Mode` + Live `synapse build --discover`)  
**Detailed Architecture & Verification Report:** [`./PROJECT_REPORT.md`](./PROJECT_REPORT.md)

---

## 1. The Real-World Problem

Enterprise operations teams lose critical SLA minutes switching between disconnected silos during freight disruptions:
- **System 1 — `SupplyPulse ERP` (`./services/orders_logistics_service/app.py`, `https://127.0.0.1:8101`)**: Sample FastAPI ERP tracking freight corridors, carrier delays, customer orders, ARR contract tiers, and regional warehouse stock — **with no visibility into customer support tickets or SLA timers.**
- **System 2 — `CareDesk CRM` (`./services/support_ticketing_service/app.py`, `https://127.0.0.1:8102`)**: Sample FastAPI ticketing service tracking P1–P3 escalations, SLA breach countdowns, and customer notes — **with no visibility into freight delays or nearby replacement warehouse stock.**

Using **`@2ndbrainlabs-ai/synapse-cli` (`v0.1.9`)** in **Auto Mode**, we generate standalone **Model Context Protocol (MCP)** servers (`synapse_auto_server.py`) externally from both FastAPI backends (which contain zero MCP SDK imports), and connect them through **COMET Copilot** — including **Blind LLM Agents (BLA)** identity blinding and **live hot-discovery (`synapse build --discover`)**.

---

## 2. Selective Endpoint Exposure (Judging Criterion)

Per Page 7 of the Participant Guide (*"Expose only what the agent needs. Fewer, well-named tools make agents more reliable"*), internal operational and telemetry routes are deliberately excluded during `synapse build --auto --endpoints ...`:

| Codebase | Exposed MCP Tools (`synapse_auto_server.py`) | Excluded Internal Routes |
| :--- | :--- | :--- |
| **`orders_logistics_service`** (`SupplyPulse ERP`, `:8101`) | `list_delayed_shipments`, `get_shipment_details`, `get_order_by_id`, `get_orders_by_shipment`, `get_inventory_by_sku` *(+ `expedite_reroute_shipment` added live via `--discover`)* | `GET /health`, `POST /internal/reset-demo-state`, `GET /internal/security-telemetry` |
| **`support_ticketing_service`** (`CareDesk CRM`, `:8102`) | `list_all_open_tickets`, `get_tickets_by_customer`, `get_tickets_by_order`, `get_tickets_by_priority`, `get_ticket_by_id`, `create_proactive_ticket`, `update_or_escalate_ticket` | `GET /health`, `POST /internal/reset-demo-state`, `GET /internal/security-telemetry` |

---

## 3. Quick Start (1-Command Studio & Automated Demo)

```powershell
# On macOS / Linux, replace .\.venv\Scripts\python.exe with ./.venv/bin/python

# 1. Launch Interactive Web Studio (Loopback HTTP UI on :8100 + TLS 1.3 Backends on :8101/:8102)
.\.venv\Scripts\python.exe .\start_studio.py

# 2. Optional: Serve Browser-to-Studio UI over TLS 1.3 as well (https://127.0.0.1:8100)
.\.venv\Scripts\python.exe .\start_studio.py --https

# 3. Run Automated CLI Judge Demo (Prompts 1-2 + Before/After Live `synapse build --discover`)
.\.venv\Scripts\python.exe .\run_demo.py

# 4. Run 42-Assertion Security, Red-Team Patch, BLA & Latency Verification Suite
.\.venv\Scripts\python.exe .\test_security_and_latency.py
```

Open **http://127.0.0.1:8100** to demo:
1. **Prompt 1 (`SHP-402` Blast Radius):** Correlates a 54h delay (\$86,100 across 3 orders) with support state — flags **Apex BioLabs** (`ORD-7801`, \$48.5k) at `38m` left on P1 SLA (`TCK-901`) with 6 backup units ready in `WH-BLR-02`, plus **Vanguard Robotics** (`ORD-7804`, \$31.2k Enterprise) with **no ticket filed** (*silent VIP churn risk*).
2. **Prompt 2 (P1 SLA × Warehouse Stock):** Audits all 3 open P1 tickets against regional hub stock, confirming 2 immediately fulfillable P1s and 1 critical `SKU-HSM-CARD` stockout on `TCK-903`.
3. **Prompt 3 (Proactive Rescue):** Finds delayed Enterprise orders lacking support tickets and opens idempotent proactive P1 alerts in `CareDesk`.
4. **Live `synapse build --discover` Update:** Run **Prompt 4** (*capability gap reported*) → click **Live Add Endpoint + `synapse build --discover`** → re-run **Prompt 4** (*calls `expedite_reroute_shipment` on `SupplyPulse` and updates `TCK-901` to `mitigated` in `CareDesk`*).

---

## 4. Security, Compartmentalization (`ES256`) & Blind LLM Agents (BLA)

- **Backend `TLSv1.3` & CA Pinning (`./security/pki.py`)**: Generates an RFC 5280 `VERIFY_X509_STRICT` ECDSA P-256 Root CA (`./certs/comet_ca.pem`) and SAN server cert (`127.0.0.1`, `localhost`) with owner-only private-key ACLs. Both backends run exclusively over `HTTPS` (`TLS_AES_256_GCM_SHA384`).
- **Blind LLM Agents (BLA) Identity Blinding (`./security/blind_llm_guard.py`)**: Enforced server-side (`COMET_BLA_ENFORCED=1`). Pre-seeds directory organizations/aliases & staff with case-insensitive matching (`re.IGNORECASE`) and canonical alias unification so Turn-1 user prompts and structured/unstructured MCP outputs (`customer_name`, `assigned_to`, emails, phones, `subject`/`notes`) resolve to deterministic 6-hex `HMAC-SHA256` tokens (`[ORG_BLIND_XXXXXX]`, `[STAFF_BLIND_XXXXXX]`), preserving cross-system joins while unblinding writebacks locally. Includes a live **Blind LLM Context vs. Operator View** toggle in the Studio.
- **Compartmentalized Asymmetric `ES256` JWT + Full-Body HMAC-SHA256 (`./security/auth_guard.py`, `./security/authenticated_mcp_runner.py`)**: Backends receive **only** `ISSUER_PUBLIC_KEY_PEM` (zero shared JWT secrets, zero fallback defaults) plus their own isolated HMAC secret signing `METHOD:PATH:QUERY:TIMESTAMP:NONCE:SHA256(BODY)`, wrapped explicitly via `authenticated_mcp_runner.py` while keeping `synapse_auto_server.py` untouched. Studio enforces `HttpOnly; SameSite=Strict` `ES256` cookies, mandatory `X-COMET-CSRF: 1` headers, `Sec-Fetch-Site` checks, and strict `script-src 'self'` CSP.

---

## 5. Using with Claude Desktop / Cursor & Optional LLM Keys

Paste [`./mcp_client_config.json`](./mcp_client_config.json) into your MCP client's `mcpServers` block. **COMET** works offline out-of-the-box via its deterministic rule-based workflow orchestrator and upgrades automatically to live OpenAI-compatible tool-calling when `GROQ_API_KEY`, `OPENAI_API_KEY`, `GEMINI_API_KEY`, or `OPENROUTER_API_KEY` is configured in `.env`.
