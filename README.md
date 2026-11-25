# NexusOps — Cross-System Supply Chain & Support Copilot

**2nd Brain Labs × Geek Room: Vibe-a-thon Submission**  
**Selected Track:** **Problem Statement 3 — *A copilot that works across two systems*** (`Synapse Auto Mode` + Live `synapse build --discover`)

---

## 1. The Real-World Problem

Enterprise operations teams lose hours switching between disconnected silos during logistics disruptions:
- **System 1 — `SupplyPulse ERP` (`services/orders_logistics_service`, Port `8101`)**: Knows which freight corridors are delayed, which customer orders are onboard, contract ARR tiers, and regional warehouse inventory — **but knows nothing about customer sentiment, SLA timers, or open support escalations.**
- **System 2 — `CareDesk CRM` (`services/support_ticketing_service`, Port `8102`)**: Tracks P1/P2 customer support tickets, SLA breach countdowns, and customer escalations — **but has zero visibility into freight delays or whether backup replacement inventory sits in a nearby hub.**

Using **`@2ndbrainlabs-ai/synapse-cli` (v0.1.9)** in **Auto Mode**, we turned both untouched legacy FastAPI backends into standalone **Model Context Protocol (MCP)** servers (`synapse_auto_server.py`) in seconds, and built **NexusOps Copilot** — an agent that queries and coordinates actions across both systems simultaneously, including **live hot-discovery (`synapse build --discover`)** when new backend capabilities ship.

---

## 2. Architecture & Selective Endpoint Exposure (Judging Criterion)

Per the Synapse Participant Guide (*"Expose only what the agent needs. Fewer, well-named tools make agents more reliable"*), each service includes internal operational endpoints (`/health`, `/internal/reset-demo-state`) that we **deliberately excluded** when running `synapse build --auto --endpoints ...`:

| Codebase | Exposed MCP Tools (`synapse_auto_server.py`) | Excluded Internal Routes |
| :--- | :--- | :--- |
| **`orders_logistics_service`** (`SupplyPulse ERP`, `:8101`) | `list_delayed_shipments`, `get_shipment_details`, `get_order_by_id`, `get_orders_by_shipment`, `get_inventory_by_sku` *(+ `expedite_reroute_shipment` added live via `--discover`!)* | `GET /health`, `POST /internal/reset-demo-state` |
| **`support_ticketing_service`** (`CareDesk CRM`, `:8102`) | `list_all_open_tickets`, `get_tickets_by_customer`, `get_tickets_by_order`, `get_tickets_by_priority`, `get_ticket_by_id`, `create_proactive_ticket`, `update_or_escalate_ticket` | `GET /health`, `POST /internal/reset-demo-state` |

---

## 3. Quick Start (1-Command Studio & Automated Demo)

### Run the Automated CLI Judge Demo (Questions 1 & 2 + Live `synapse build --discover`)
```powershell
.\.venv\Scripts\python.exe run_demo.py
```

### Launch the Interactive Hackathon Web Studio (`http://127.0.0.1:8100`)
```powershell
.\.venv\Scripts\python.exe start_studio.py
```
Then open **http://127.0.0.1:8100** to:
1. Run **Prompt 1** (*Delayed shipment `SHP-402` blast radius + support ticket triage — catches `$48.5k` P1 SLA risk at Apex BioLabs AND `$31.2k` silent churn risk at Vanguard Robotics who hasn't opened a ticket yet!*).
2. Run **Prompt 2** (*Cross-check all open P1 tickets in CareDesk against live regional warehouse stock in SupplyPulse — identifies 2 immediately fulfillable P1s and 1 critical HSM stockout*).
3. Run **Prompt 3** (*Proactive silent-impact rescue — reads delayed Enterprise orders in SupplyPulse and opens proactive P1 alert tickets in CareDesk*).
4. **Live `synapse build --discover` Demo**:
   - Run **Prompt 4** first (*"Expedite and reroute SHP-402..."*) → Copilot inspects both systems and notes no reroute tool is exposed yet.
   - Click **⚡ Live Add Endpoint + `synapse build --discover`** → Injects `POST /shipments/{shipment_id}/expedite-reroute`, runs `synapse build --discover`, and hot-reloads the MCP server in ~1 second.
   - Run **Prompt 4** again → Copilot immediately discovers and invokes `expedite_reroute_shipment` on SupplyPulse AND updates affected tickets in CareDesk!

---

## 4. Zero-Trust End-to-End Security & False-Auth Recognition

Every hop in **NexusOps** is hardened against eavesdropping, credential spoofing, lateral movement, and replay attacks — while keeping Synapse's generated `synapse_auto_server.py` **100% unmodified**:

- **Local X.509 PKI & Strict TLS 1.3 (`security/pki.py`)**: Automatically generates an ECDSA P-256 Root CA (`certs/nexusops_ca.pem`) and SAN server certificate (`127.0.0.1`, `localhost`). Both `SupplyPulse ERP` (`https://127.0.0.1:8101`) and `CareDesk CRM` (`https://127.0.0.1:8102`) run exclusively over HTTPS (`TLSv1.3`), verified strictly via `REQUESTS_CA_BUNDLE` (zero `verify=False`).
- **Compartmentalized Asymmetric `ES256` JWT + HMAC-SHA256 Signing (`./security/auth_guard.py`, `./security/authenticated_mcp_runner.py`)**:
  - Backends receive **only** `ISSUER_PUBLIC_KEY_PEM` (zero shared JWT secrets) plus their own isolated HMAC secret.
  - `authenticated_mcp_runner.py` wraps unmodified `synapse_auto_server.py` explicitly (no hidden `sitecustomize.py` hooks), attaching `Authorization: Bearer <ES256_JWT>`, `X-Request-Timestamp` (±60s), `X-Request-Nonce`, and `X-Request-Signature` (`HMAC-SHA256`).
  - Studio UI (`/api/*`) enforces an `HttpOnly; SameSite=Strict` `ES256` Session JWT (`Secure` when launched with `--https`), loopback CSRF/DNS-rebinding guards, and `DEMO_HARNESS_ENABLED` gating on the live-discover demo harness.
- **Live False-Auth Recognition & Brute-Force Lockout**: Classifies and blocks `MISSING_CREDENTIALS`, `TAMPERED_OR_FORGED_TOKEN`, `CROSS_SERVICE_AUDIENCE_SPOOF` (lateral movement using CareDesk's valid JWT against SupplyPulse!), `REPLAY_TIMESTAMP_SKEW`, `REPLAY_NONCE_DETECTED`, and `BRUTE_FORCE_LOCKOUT` (`429`), surfaced live in the Studio's **Zero-Trust Security Shield** panel.

```powershell
# Run full TLS 1.3 + False-Auth Recognition + Latency verification suite
.\.venv\Scripts\python.exe test_security_and_latency.py
```

---

## 5. Using with Claude Desktop / Cursor / Antigravity

Copy [`mcp_client_config.json`](./mcp_client_config.json) into your MCP client's `mcpServers` block (make sure both FastAPI backends are running via `start_studio.py`).

### Optional Live LLM Key Configuration
NexusOps works **100% out of the box with zero API keys** via its built-in Cross-System MCP ReAct Planner over real `mcp.client.stdio` sessions, and automatically upgrades to live LLM tool-calling if you set any of `GROQ_API_KEY`, `OPENAI_API_KEY`, `GEMINI_API_KEY`, or `OPENROUTER_API_KEY` in `.env`.
