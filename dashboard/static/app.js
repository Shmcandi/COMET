"use strict";

let lastAskResponse = null;
let lastAskedPrompt = "";
let showBlindLLMView = false;
let latestStatusData = null;

const CSRF_HEADERS = {
  "Content-Type": "application/json",
  "X-COMET-CSRF": "1",
};

const BLA_TOKEN_RE = /\[(?:ORG|STAFF|EMAIL|PHONE)_BLIND_[A-F0-9]{4,12}\]/g;

function escapeHtml(val) {
  return String(val ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function highlightBlaTokensInEscapedText(escapedStr) {
  return escapedStr.replace(BLA_TOKEN_RE, (match) => `<span class="bla-chip">${match}</span>`);
}

function classifyCodeChip(rawCode) {
  const clean = rawCode.trim();
  if (/^\[(?:ORG|STAFF|EMAIL|PHONE)_BLIND_[A-F0-9]{4,12}\]$/.test(clean)) {
    return `<span class="bla-chip">${escapeHtml(clean)}</span>`;
  }
  if (/^(?:SHP|ORD|SKU|WH|AWB)-[A-Z0-9-]+$/.test(clean) || clean === "SupplyPulse ERP" || clean === "orders_logistics_service") {
    return `<code class="mono-code tok-erp">${escapeHtml(clean)}</code>`;
  }
  if (/^(?:TCK|CUST)-[A-Z0-9-]+$/.test(clean) || clean === "CareDesk CRM" || clean === "support_ticketing_service") {
    return `<code class="mono-code tok-crm">${escapeHtml(clean)}</code>`;
  }
  if (/^\d+m$/.test(clean) || clean === "P1" || clean === "CRITICAL") {
    return `<code class="mono-code tok-crit">${escapeHtml(clean)}</code>`;
  }
  return `<code class="mono-code">${escapeHtml(clean)}</code>`;
}

function formatInlineMarkdown(rawText) {
  const codeSlots = [];
  const withPlaceholders = String(rawText ?? "").replace(/`([^`]+)`/g, (_, inner) => {
    const idx = codeSlots.length;
    codeSlots.push(classifyCodeChip(inner));
    return `\u0000CODE${idx}\u0000`;
  });

  let safe = escapeHtml(withPlaceholders);
  safe = highlightBlaTokensInEscapedText(safe);
  safe = safe
    .replace(/\*\*(.+?)\*\*/g, "<strong>$1</strong>")
    .replace(/\*(.+?)\*/g, "<em>$1</em>");

  safe = safe.replace(/\u0000CODE(\d+)\u0000/g, (_, idxStr) => codeSlots[Number(idxStr)] || "");
  return safe;
}

function isNumericCell(rawCell) {
  const stripped = rawCell.replace(/[*`]/g, "").trim();
  return /^\$[\d,]+(?:\.\d+)?$/.test(stripped) || /^[\d,]+(?:\.\d+)?\s*(?:ms|h|m|%)?$/.test(stripped);
}

function renderMarkdown(md) {
  const lines = String(md ?? "").split("\n");
  let html = "";
  let inTable = false;
  let tableRows = [];
  let inList = false;

  const flushTable = () => {
    if (!inTable) return;
    inTable = false;
    if (tableRows.length < 2) {
      tableRows = [];
      return;
    }
    const headers = tableRows[0]
      .split("|")
      .slice(1, -1)
      .map((c) => c.trim());
    const alignRow = tableRows[1]
      .split("|")
      .slice(1, -1)
      .map((c) => c.trim());
    const body = tableRows.slice(2);

    const rightAlignedCols = alignRow.map((a) => a.endsWith(":"));

    html += '<div class="table-scroll"><table class="md-table"><thead><tr>';
    headers.forEach((h, i) => {
      const cls = rightAlignedCols[i] ? ' class="num-col"' : "";
      html += `<th${cls}>${formatInlineMarkdown(h)}</th>`;
    });
    html += "</tr></thead><tbody>";

    for (const r of body) {
      const cols = r
        .split("|")
        .slice(1, -1)
        .map((c) => c.trim());
      html += "<tr>";
      cols.forEach((c, i) => {
        const numeric = rightAlignedCols[i] || isNumericCell(c);
        const cls = numeric ? ' class="num-col"' : "";
        html += `<td${cls}>${formatInlineMarkdown(c)}</td>`;
      });
      html += "</tr>";
    }
    html += "</tbody></table></div>";
    tableRows = [];
  };

  const flushList = () => {
    if (inList) {
      html += "</ul>";
      inList = false;
    }
  };

  for (const raw of lines) {
    const line = raw.trimEnd();
    if (line.trim().startsWith("|")) {
      flushList();
      inTable = true;
      tableRows.push(line.trim());
      continue;
    } else {
      flushTable();
    }

    if (line.startsWith("### ")) {
      flushList();
      html += `<h3>${formatInlineMarkdown(line.slice(4))}</h3>`;
    } else if (line.startsWith("#### ")) {
      flushList();
      html += `<h4>${formatInlineMarkdown(line.slice(5))}</h4>`;
    } else if (line.startsWith("- ") || /^\d+\.\s/.test(line)) {
      if (!inList) {
        html += "<ul>";
        inList = true;
      }
      const cleaned = line.replace(/^(-\s|\d+\.\s)/, "");
      const lower = cleaned.toLowerCase();
      let liClass = "";
      if (lower.includes("sla breach warning") || lower.includes("stockout") || lower.includes("stock shortage")) {
        liClass = ' class="callout-row callout-crit"';
      } else if (lower.includes("silent enterprise churn") || lower.includes("capability gap")) {
        liClass = ' class="callout-row callout-warn"';
      }
      html += `<li${liClass}>${formatInlineMarkdown(cleaned)}</li>`;
    } else if (line.trim() === "") {
      flushList();
    } else {
      flushList();
      html += `<p>${formatInlineMarkdown(line)}</p>`;
    }
  }

  flushTable();
  flushList();
  return html;
}

function setStepperState(state) {
  const s1 = document.getElementById("stepRoute");
  const s2 = document.getElementById("stepBuild");
  const s3 = document.getElementById("stepReload");
  [s1, s2, s3].forEach((el) => {
    el.classList.remove("active", "done");
  });

  if (state === "step1") {
    s1.classList.add("active");
  } else if (state === "step2") {
    s1.classList.add("done");
    s2.classList.add("active");
  } else if (state === "step3") {
    s1.classList.add("done");
    s2.classList.add("done");
    s3.classList.add("active");
  } else if (state === "live") {
    [s1, s2, s3].forEach((el) => el.classList.add("done"));
  }
}

async function refreshStatus() {
  const res = await fetch("/api/status");
  if (!res.ok) return;
  const data = await res.json();
  latestStatusData = data;

  const tls = (data.security && data.security.tls) || {};
  const protoShort = tls.protocol === "TLSv1.3" ? "TLS 1.3" : tls.protocol || "TLS 1.3";

  document.getElementById("erpTlsTag").textContent = `${protoShort} · ES256 · ${data.orders_service.tools_count}t`;
  document.getElementById("crmTlsTag").textContent = `${protoShort} · ES256 · ${data.support_service.tools_count}t`;

  const tileTlsCipher = document.getElementById("tileTlsCipher");
  if (tileTlsCipher) {
    tileTlsCipher.textContent = `${tls.protocol || "TLSv1.3"} · ${tls.key_bits || "256"}-bit`;
    document.getElementById("tileTlsDetail").textContent = `${tls.cipher || "TLS_AES_256_GCM_SHA384"} (${tls.ca_file || "comet_ca.pem"})`;
    const delayedLen = (data.orders_service.delayed_shipments || []).length;
    const openTckLen = (data.support_service.open_tickets || []).length;
    document.getElementById("tileQueueSummary").textContent = `${delayedLen} Delayed · ${openTckLen} Open Tickets`;
    document.getElementById("tileAuthStats").textContent = `${data.security.authenticated_calls_total} Verified · ${data.security.blocked_false_auth_total} Blocked`;
  }

  const blocked = data.security ? data.security.blocked_false_auth_total : 0;
  document.getElementById("btnAuditAuthLabel").textContent =
    blocked > 0 ? `Audit Guard (${blocked} Blocked)` : "Audit Guard";

  const ordCount = data.orders_service.tools_count;
  const supCount = data.support_service.tools_count;
  document.getElementById("totalToolsLabel").textContent = `${ordCount + supCount} Tools`;
  document.getElementById("railOrdersCount").textContent = `${ordCount} tools`;
  document.getElementById("railSupportCount").textContent = `${supCount} tools`;

  document.getElementById("railOrdersTools").innerHTML = data.orders_service.tools
    .map((t) => {
      const isNew = t.name === "expedite_reroute_shipment";
      return `<span class="tool-chip ${isNew ? "discovered" : ""}" title="${escapeHtml(t.description)}">${escapeHtml(t.name)}${isNew ? " [NEW]" : ""}</span>`;
    })
    .join("");

  document.getElementById("railSupportTools").innerHTML = data.support_service.tools
    .map((t) => `<span class="tool-chip" title="${escapeHtml(t.description)}">${escapeHtml(t.name)}</span>`)
    .join("");

  const panel = document.getElementById("discoverPanel");
  const countBadge = document.getElementById("discoverToolTransition");
  const sub = document.getElementById("discoverStatusSub");
  const btn = document.getElementById("btnRunDiscover");

  if (data.live_endpoint_enabled) {
    panel.classList.add("is-live");
    countBadge.classList.add("upgraded");
    countBadge.textContent = "5 -> 6 tools";
    sub.innerHTML = "Live tool <code>expedite_reroute_shipment</code> discovered and active on SupplyPulse MCP.";
    btn.classList.add("live-enabled");
    btn.textContent = "Endpoint Active (expedite_reroute_shipment)";
    setStepperState("live");
  } else {
    panel.classList.remove("is-live");
    countBadge.classList.remove("upgraded");
    countBadge.textContent = `${ordCount} tools`;
    sub.innerHTML = "Hot-add <code>POST /expedite-reroute</code> and rebuild SupplyPulse MCP without downtime.";
    btn.classList.remove("live-enabled");
    btn.textContent = "Run synapse build --discover";
    setStepperState("idle");
  }
}

function setContextMode(blindActive) {
  showBlindLLMView = Boolean(blindActive);
  const segOp = document.getElementById("segOperatorBtn");
  const segBla = document.getElementById("segBlaBtn");
  const stage = document.getElementById("centerStage");
  const banner = document.getElementById("blaBanner");

  if (showBlindLLMView) {
    segOp.classList.remove("active-operator");
    segBla.classList.add("active-bla");
    stage.classList.add("bla-mode-active");
    banner.classList.add("visible");
  } else {
    segBla.classList.remove("active-bla");
    segOp.classList.add("active-operator");
    stage.classList.remove("bla-mode-active");
    banner.classList.remove("visible");
  }

  if (lastAskResponse) {
    renderAskPayload(lastAskResponse, lastAskedPrompt);
  }
}

function renderAskPayload(data, promptText) {
  const emptyEl = document.getElementById("emptyBriefing");
  if (emptyEl) emptyEl.style.display = "none";

  const topLatency = document.getElementById("topLatencyBadge");
  topLatency.innerHTML = data.llm_used
    ? `MCP <strong>${escapeHtml(data.mcp_transport_latency_ms)} ms</strong> · LLM ${escapeHtml(data.llm_inference_latency_ms)} ms`
    : `MCP <strong>${escapeHtml(data.mcp_transport_latency_ms)} ms</strong> · ${escapeHtml(data.tool_calls_count)} RPCs`;

  const blaCount = data.bla ? data.bla.unique_entities_blinded : 0;
  const redactions = data.bla ? data.bla.field_redactions_count : 0;
  document.getElementById("blaBannerCount").textContent = `${blaCount} Entities Vaulted · ${redactions} Field Redactions`;

  const activeMarkdown = showBlindLLMView ? data.blind_answer : data.answer;
  const viewTag = showBlindLLMView ? "Blind LLM Context (Pseudonymized)" : "Operator View (Unblinded Locally)";

  const area = document.getElementById("dynamicBriefingArea");
  area.innerHTML = `
    <div class="query-header-card">
      <div class="query-prompt-row">
        <div class="query-prompt-text">${highlightBlaTokensInEscapedText(
          escapeHtml(showBlindLLMView && data.blind_question ? data.blind_question : promptText)
        )}</div>
      </div>
      <div class="query-metrics-bar">
        <span class="metric-chip erp">MCP Transport: ${escapeHtml(data.mcp_transport_latency_ms)} ms</span>
        <span class="metric-chip ok">${data.cross_system_verified ? "2-System Join Verified" : "Single-System Query"}</span>
        <span class="metric-chip ok">BLA Vault: ${escapeHtml(blaCount)} entities</span>
        <span class="metric-chip">${escapeHtml(viewTag)}</span>
      </div>
    </div>
    <article class="briefing-card md-body">
      ${renderMarkdown(activeMarkdown)}
    </article>
  `;

  renderTraceWaterfall(data);
}

function renderTraceWaterfall(data) {
  const steps = data.trace || [];
  const headerMeta = document.getElementById("traceHeaderMeta");
  const emptyState = document.getElementById("traceEmptyState");
  const listEl = document.getElementById("waterfallList");
  const vaultStrip = document.getElementById("vaultStrip");
  const vaultChipList = document.getElementById("vaultChipList");

  headerMeta.textContent = `${steps.length} RPCs · ${data.mcp_transport_latency_ms} ms`;

  if (data.bla && Array.isArray(data.bla.mappings) && data.bla.mappings.length > 0) {
    vaultStrip.classList.add("visible");
    document.getElementById("vaultCountLabel").textContent = `${data.bla.unique_entities_blinded} tokens`;
    vaultChipList.innerHTML = data.bla.mappings
      .map(
        (m) =>
          `<span class="vault-map-chip" title="${escapeHtml(m.category)}">${escapeHtml(m.blind_token)} <span>-> ${escapeHtml(
            m.redacted_preview
          )}</span></span>`
      )
      .join("");
  } else {
    vaultStrip.classList.remove("visible");
  }

  if (steps.length === 0) {
    emptyState.style.display = "block";
    listEl.style.display = "none";
    listEl.innerHTML = "";
    return;
  }

  emptyState.style.display = "none";
  listEl.style.display = "flex";

  const maxMs = Math.max(1, ...steps.map((s) => Number(s.latency_ms) || 1));

  listEl.innerHTML = steps
    .map((step, idx) => {
      const isErp = String(step.server || "").includes("orders");
      const sysKey = isErp ? "erp" : "crm";
      const sysLabel = isErp ? "SupplyPulse" : "CareDesk";
      const stepIndex = String(idx + 1).padStart(2, "0");

      const shownArgs = showBlindLLMView ? step.blinded_arguments ?? step.arguments : step.arguments;
      const shownOut = showBlindLLMView ? step.blinded_output ?? step.output : step.output;
      const hasError = shownOut && typeof shownOut === "object" && "error" in shownOut;

      const pct = Math.max(6, Math.min(100, Math.round(((Number(step.latency_ms) || 1) / maxMs) * 100)));
      const escapedArgs = highlightBlaTokensInEscapedText(escapeHtml(JSON.stringify(shownArgs, null, 2)));
      const escapedOut = highlightBlaTokensInEscapedText(escapeHtml(JSON.stringify(shownOut, null, 2)));

      return `
        <div class="wf-item sys-${sysKey}">
          <div class="wf-top">
            <div class="wf-top-left">
              <span class="wf-step-num">${stepIndex}</span>
              <span class="wf-sys-badge ${sysKey}">${sysLabel}</span>
            </div>
            <div class="wf-meta-right">
              <span class="wf-ms">${escapeHtml(step.latency_ms)} ms</span>
              <span class="wf-status ${hasError ? "err" : ""}">${hasError ? "ERR" : "OK"}</span>
            </div>
          </div>
          <div class="wf-tool-name">${escapeHtml(step.tool)}</div>
          <div class="wf-bar-track">
            <div class="wf-bar-fill ${sysKey}" style="width: ${pct}%;"></div>
          </div>
          <details class="wf-details" ${idx === 0 ? "open" : ""}>
            <summary>
              <span>Inspect JSON (${showBlindLLMView ? "BLA Blinded" : "Unblinded"})</span>
              <span>Payload</span>
            </summary>
            <div class="wf-payload-box">
              <div class="wf-payload-label">Arguments</div>
              <pre class="wf-pre">${escapedArgs}</pre>
              <div class="wf-payload-label">Response</div>
              <pre class="wf-pre">${escapedOut}</pre>
            </div>
          </details>
        </div>
      `;
    })
    .join("");
}

async function submitQuestion(optionalPrompt) {
  const input = document.getElementById("composerInput");
  if (typeof optionalPrompt === "string") {
    input.value = optionalPrompt;
  }
  const q = input.value.trim();
  if (!q) return;

  const btn = document.getElementById("btnSubmitQuery");
  const spinner = document.getElementById("runSpinner");
  const btnText = document.getElementById("runBtnText");
  if (btn.disabled) return;

  btn.disabled = true;
  spinner.style.display = "inline-block";
  btnText.textContent = "Running";

  try {
    const res = await fetch("/api/ask", {
      method: "POST",
      headers: CSRF_HEADERS,
      body: JSON.stringify({ question: q }),
    });
    const data = await res.json();
    if (!res.ok) {
      const area = document.getElementById("dynamicBriefingArea");
      area.innerHTML = `<div class="briefing-card"><p style="color: var(--crit); margin: 0;">Request rejected (${escapeHtml(
        res.status
      )}): ${escapeHtml(data.detail || "Execution error")}</p></div>`;
      return;
    }
    lastAskedPrompt = q;
    lastAskResponse = data;
    renderAskPayload(data, q);
    document.getElementById("briefingScroll").scrollTop = 0;
  } finally {
    btn.disabled = false;
    spinner.style.display = "none";
    btnText.textContent = "Run Query";
    await refreshStatus();
  }
}

async function triggerLiveDiscover() {
  const btn = document.getElementById("btnRunDiscover");
  const resetBtn = document.getElementById("btnResetState");
  if (btn.disabled) return;

  btn.disabled = true;
  resetBtn.disabled = true;
  btn.textContent = "Rebuilding MCP Surface...";
  setStepperState("step1");

  const tStep2 = setTimeout(() => setStepperState("step2"), 260);
  const tStep3 = setTimeout(() => setStepperState("step3"), 850);

  try {
    const res = await fetch("/api/live-discover/enable", {
      method: "POST",
      headers: CSRF_HEADERS,
    });
    const data = await res.json();
    clearTimeout(tStep2);
    clearTimeout(tStep3);

    const aux = document.getElementById("auxPanelArea");
    if (res.ok) {
      setStepperState("live");
      aux.innerHTML = `
        <div class="cli-log-card">
          <div class="cli-log-head">
            <span>synapse build --discover (+ ${escapeHtml(data.added_tool)})</span>
            <span style="color: var(--bla);">Rebuild Complete</span>
          </div>
          <pre class="cli-log-pre">$ ${escapeHtml(data.command)}\n\n${escapeHtml(data.stdout)}</pre>
        </div>
      `;
    } else {
      setStepperState("idle");
      aux.innerHTML = `
        <div class="cli-log-card">
          <div class="cli-log-head">
            <span>synapse build --discover</span>
            <span style="color: var(--crit);">HTTP ${escapeHtml(res.status)}</span>
          </div>
          <pre class="cli-log-pre">${escapeHtml(data.detail || "Rebuild rejected")}</pre>
        </div>
      `;
    }
    await refreshStatus();
  } finally {
    btn.disabled = false;
    resetBtn.disabled = false;
  }
}

async function simulateAuthGuard() {
  const btn = document.getElementById("btnAuditAuth");
  const label = document.getElementById("btnAuditAuthLabel");
  if (btn.disabled) return;

  btn.disabled = true;
  label.textContent = "Probing...";
  try {
    const res = await fetch("/api/security/simulate-attacks", {
      method: "POST",
      headers: CSRF_HEADERS,
    });
    const data = await res.json();
    const sims = data.simulations || [];
    const rowsHtml = sims
      .map(
        (s) => `
          <tr>
            <td><strong>${escapeHtml(s.attack)}</strong></td>
            <td><code class="mono-code">${escapeHtml(s.target)}</code></td>
            <td class="num-col"><span class="status-pill-crit">HTTP ${escapeHtml(s.status_code)}</span></td>
            <td>${escapeHtml(s.response)}</td>
          </tr>
        `
      )
      .join("");

    const aux = document.getElementById("auxPanelArea");
    aux.innerHTML = `
      <div class="briefing-card">
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px;">
          <strong style="font-size:13px;">Live Intrusion &amp; False-Auth Audit (5 Vectors over TLS 1.3)</strong>
          <span class="metric-chip ok">${escapeHtml(sims.length)}/${escapeHtml(sims.length)} Blocked</span>
        </div>
        <div class="table-scroll" style="margin:0;">
          <table class="md-table">
            <thead>
              <tr>
                <th>Vector</th>
                <th>Target Endpoint</th>
                <th class="num-col">Verdict</th>
                <th>Guard Recognition</th>
              </tr>
            </thead>
            <tbody>${rowsHtml}</tbody>
          </table>
        </div>
      </div>
    `;
    await refreshStatus();
  } finally {
    btn.disabled = false;
  }
}

async function resetBaseline() {
  const resetBtn = document.getElementById("btnResetState");
  const discoverBtn = document.getElementById("btnRunDiscover");
  if (resetBtn.disabled) return;

  resetBtn.disabled = true;
  discoverBtn.disabled = true;
  resetBtn.textContent = "Resetting...";

  try {
    const res = await fetch("/api/live-discover/reset", {
      method: "POST",
      headers: CSRF_HEADERS,
    });
    if (res.ok) {
      lastAskResponse = null;
      lastAskedPrompt = "";
      document.getElementById("dynamicBriefingArea").innerHTML = "";
      document.getElementById("auxPanelArea").innerHTML = "";
      const emptyEl = document.getElementById("emptyBriefing");
      if (emptyEl) emptyEl.style.display = "block";
      document.getElementById("topLatencyBadge").innerHTML = "MCP <strong>-- ms</strong>";
      document.getElementById("traceHeaderMeta").textContent = "0 RPCs · -- ms";
      document.getElementById("waterfallList").style.display = "none";
      document.getElementById("waterfallList").innerHTML = "";
      document.getElementById("traceEmptyState").style.display = "block";
      document.getElementById("vaultStrip").classList.remove("visible");
      document.querySelectorAll(".scenario-card").forEach((c) => c.classList.remove("active"));
    }
    await refreshStatus();
  } finally {
    resetBtn.disabled = false;
    discoverBtn.disabled = false;
    resetBtn.textContent = "Reset State";
  }
}

document.addEventListener("DOMContentLoaded", () => {
  document.getElementById("segOperatorBtn").addEventListener("click", () => setContextMode(false));
  document.getElementById("segBlaBtn").addEventListener("click", () => setContextMode(true));
  document.getElementById("btnAuditAuth").addEventListener("click", simulateAuthGuard);
  document.getElementById("btnResetState").addEventListener("click", resetBaseline);
  document.getElementById("btnRunDiscover").addEventListener("click", triggerLiveDiscover);

  document.getElementById("btnToggleTrace").addEventListener("click", () => {
    document.getElementById("rightInspector").classList.toggle("collapsed");
  });

  document.getElementById("btnSubmitQuery").addEventListener("click", () => submitQuestion());

  const input = document.getElementById("composerInput");
  input.addEventListener("keydown", (ev) => {
    if (ev.key === "Enter") {
      ev.preventDefault();
      submitQuestion();
    }
  });

  document.addEventListener("keydown", (ev) => {
    if ((ev.ctrlKey || ev.metaKey) && ev.key.toLowerCase() === "k") {
      ev.preventDefault();
      input.focus();
      input.select();
    }
  });

  document.querySelectorAll(".scenario-card").forEach((card) => {
    card.addEventListener("click", () => {
      document.querySelectorAll(".scenario-card").forEach((c) => c.classList.remove("active"));
      card.classList.add("active");
      const prompt = card.getAttribute("data-prompt");
      if (prompt) submitQuestion(prompt);
    });
  });

  refreshStatus();
});
