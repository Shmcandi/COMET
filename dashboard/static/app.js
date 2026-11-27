"use strict";

let lastAskResponse = null;
let showBlindLLMView = false;

const CSRF_HEADERS = {
  "Content-Type": "application/json",
  "X-COMET-CSRF": "1",
};

function escapeHtml(val) {
  return String(val ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function renderMarkdown(md) {
  const lines = String(md ?? "").split("\n");
  let html = "";
  let inTable = false;
  let tableRows = [];
  let inList = false;

  const inlineFmt = (s) =>
    escapeHtml(s)
      .replace(/\*\*(.+?)\*\*/g, "<strong>$1</strong>")
      .replace(/\*(.+?)\*/g, "<em>$1</em>")
      .replace(/`([^`]+)`/g, "<code>$1</code>");

  const flushTable = () => {
    if (!inTable) return;
    inTable = false;
    if (tableRows.length < 2) return;
    const headers = tableRows[0]
      .split("|")
      .slice(1, -1)
      .map((c) => c.trim());
    const body = tableRows.slice(2);
    html +=
      "<table><thead><tr>" +
      headers.map((h) => `<th>${inlineFmt(h)}</th>`).join("") +
      "</tr></thead><tbody>";
    for (const r of body) {
      const cols = r
        .split("|")
        .slice(1, -1)
        .map((c) => c.trim());
      html += "<tr>" + cols.map((c) => `<td>${inlineFmt(c)}</td>`).join("") + "</tr>";
    }
    html += "</tbody></table>";
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
      html += `<h3>${inlineFmt(line.slice(4))}</h3>`;
    } else if (line.startsWith("#### ")) {
      flushList();
      html += `<h4>${inlineFmt(line.slice(5))}</h4>`;
    } else if (line.startsWith("- ") || /^\d+\.\s/.test(line)) {
      if (!inList) {
        html += "<ul>";
        inList = true;
      }
      const cleaned = line.replace(/^(-\s|\d+\.\s)/, "");
      html += `<li>${inlineFmt(cleaned)}</li>`;
    } else if (line.trim() === "") {
      flushList();
    } else {
      flushList();
      html += `<p>${inlineFmt(line)}</p>`;
    }
  }
  flushTable();
  flushList();
  return html;
}

async function refreshStatus() {
  const res = await fetch("/api/status");
  if (!res.ok) return;
  const data = await res.json();

  if (data.security && data.security.tls) {
    const tls = data.security.tls;
    document.getElementById("tlsCipherBadge").textContent = `${tls.protocol} · ${tls.key_bits}-bit`;
    document.getElementById("tlsSummaryText").innerHTML =
      `Backend Hop: <code>${escapeHtml(tls.protocol)}</code> · <code>${escapeHtml(tls.cipher)}</code> · Studio UI: <code>${escapeHtml(data.security.browser_to_studio_scheme)}</code><br/>` +
      `Auth: <strong>Asymmetric ES256 JWT + Full-Body/Query HMAC-SHA256</strong>`;
    document.getElementById("authOkCount").textContent = data.security.authenticated_calls_total;
    document.getElementById("authBlockedCount").textContent = data.security.blocked_false_auth_total;

    const events = data.security.recent_false_auth_events || [];
    document.getElementById("falseAuthEventsBox").innerHTML = events
      .slice(0, 4)
      .map(
        (ev) => `
          <div class="event-row">
            <strong>[${escapeHtml(ev.status_code)}] ${escapeHtml(ev.category)}</strong> on <code>${escapeHtml(ev.service)}</code><br/>
            <span style="color:var(--muted);">${escapeHtml(ev.detail)}</span>
          </div>
        `
      )
      .join("");
  }

  document.getElementById("ordersCount").textContent = `${data.orders_service.tools_count} MCP Tools`;
  document.getElementById("ordersTools").innerHTML = data.orders_service.tools
    .map((t) => {
      const isNew = t.name === "expedite_reroute_shipment";
      return `<span class="tool-chip ${isNew ? "new-tool" : ""}" title="${escapeHtml(t.description)}">${escapeHtml(t.name)}${isNew ? " [NEW]" : ""}</span>`;
    })
    .join("");

  document.getElementById("supportCount").textContent = `${data.support_service.tools_count} MCP Tools`;
  document.getElementById("supportTools").innerHTML = data.support_service.tools
    .map((t) => `<span class="tool-chip" title="${escapeHtml(t.description)}">${escapeHtml(t.name)}</span>`)
    .join("");

  const btn = document.getElementById("btnLiveDiscover");
  if (data.live_endpoint_enabled) {
    btn.classList.add("active");
    btn.textContent = "Live Endpoint Active (expedite_reroute_shipment)";
  } else {
    btn.classList.remove("active");
    btn.textContent = "Live Add Endpoint + synapse build --discover";
  }
}

function toggleBlindInspector() {
  showBlindLLMView = !showBlindLLMView;
  const btn = document.getElementById("btnBlaToggle");
  if (showBlindLLMView) {
    btn.textContent = "View: Blind LLM Context (Identity-Blinded)";
    btn.style.background = "rgba(167,139,250,0.22)";
  } else {
    btn.textContent = "View: Operator (Unblinded)";
    btn.style.background = "";
  }
  if (lastAskResponse) renderAskPayload(lastAskResponse);
}

function renderAskPayload(data) {
  const strip = document.getElementById("metaStrip");
  strip.style.display = "flex";
  const latencyLabel = data.llm_used
    ? `MCP: ${escapeHtml(data.mcp_transport_latency_ms)} ms + LLM: ${escapeHtml(data.llm_inference_latency_ms)} ms`
    : `MCP Transport: ${escapeHtml(data.mcp_transport_latency_ms)} ms (Rule-Based Orchestrator, 0 LLM ms)`;
  const blaCount = data.bla ? data.bla.unique_entities_blinded : 0;
  strip.innerHTML = `
    <span class="pill ok">TLS 1.3 + ES256 + Body HMAC</span>
    <span class="pill ok">BLA Enforced (${escapeHtml(blaCount)} Entities)</span>
    <span class="pill ${data.cross_system_verified ? "ok" : ""}">
      ${data.cross_system_verified ? "Cross-System Join (2 MCP Servers)" : "1 MCP Server Used"}
    </span>
    <span class="pill fast">${latencyLabel}</span>
  `;

  if (data.bla) {
    document.getElementById("blaBadge").textContent = `${data.bla.unique_entities_blinded} Blinded`;
    document.getElementById("blaTokensBox").innerHTML = (data.bla.mappings || [])
      .map(
        (m) =>
          `<span class="tool-chip" title="Redacted entity (${escapeHtml(m.category)})">${escapeHtml(m.blind_token)} → ${escapeHtml(m.redacted_preview)}</span>`
      )
      .join("");
  }

  const activeMarkdown = showBlindLLMView ? data.blind_answer : data.answer;
  document.getElementById("answerBox").innerHTML = renderMarkdown(activeMarkdown);
  document.getElementById("traceSummary").textContent = `${data.tool_calls_count} calls in ${data.total_latency_ms} ms (${
    showBlindLLMView ? "Showing Blinded LLM Payloads" : "Showing Unblinded Operator Payloads"
  })`;
  document.getElementById("traceList").innerHTML = data.trace
    .map((step, idx) => {
      const shownArgs = showBlindLLMView ? step.blinded_arguments ?? step.arguments : step.arguments;
      const shownOut = showBlindLLMView ? step.blinded_output ?? step.output : step.output;
      return `
        <details class="trace-item">
          <summary class="trace-head">
            <span>
              <strong>#${idx + 1}</strong>
              <span class="sys-badge ${step.server.includes("orders") ? "sys-orders" : "sys-support"}">${escapeHtml(step.system_badge)}</span>
              <code style="margin-left:6px;color:#f8fafc;">${escapeHtml(step.tool)}(${escapeHtml(JSON.stringify(shownArgs))})</code>
            </span>
            <span style="color:var(--muted);">${escapeHtml(step.latency_ms)} ms · TLS + BLA</span>
          </summary>
          <pre style="margin:8px 0 0;font-size:11.5px;color:#cbd5e1;overflow-x:auto;">${escapeHtml(JSON.stringify(shownOut, null, 2))}</pre>
        </details>
      `;
    })
    .join("");
}

async function simulateAttacks() {
  const btn = document.getElementById("btnShield");
  btn.disabled = true;
  btn.textContent = "Probing Defenses...";
  try {
    const res = await fetch("/api/security/simulate-attacks", {
      method: "POST",
      headers: CSRF_HEADERS,
    });
    const data = await res.json();
    const card = document.getElementById("attackSimCard");
    card.style.display = "block";
    const sims = data.simulations || [];
    document.getElementById("attackSimBadge").textContent = data.all_attacks_blocked
      ? `${sims.length}/${sims.length} Attacks Recognized & Blocked`
      : "Check Alert";
    document.getElementById("attackSimBody").innerHTML = sims
      .map(
        (s) => `
          <div class="trace-item" style="border-color:rgba(16,185,129,0.35);">
            <div class="trace-head">
              <strong>${escapeHtml(s.attack)}</strong>
              <span class="sys-badge sys-alert">HTTP ${escapeHtml(s.status_code)} BLOCKED</span>
            </div>
            <div style="margin-top:4px;color:var(--muted);">
              Target: <code>${escapeHtml(s.target)}</code> → Recognized: <em>${escapeHtml(s.response)}</em>
            </div>
          </div>
        `
      )
      .join("");
    await refreshStatus();
  } finally {
    btn.disabled = false;
    btn.textContent = "Simulate False-Auth Attacks";
  }
}

async function submitQuestion() {
  const q = document.getElementById("questionInput").value.trim();
  if (!q) return;
  const btn = document.getElementById("askBtn");
  if (btn.disabled) return;
  btn.disabled = true;
  btn.textContent = "Running...";
  document.getElementById("answerBox").innerHTML =
    '<p style="color:var(--cyan);">Querying TLS-encrypted SupplyPulse &amp; CareDesk MCP channels through BLA Vault...</p>';

  try {
    const res = await fetch("/api/ask", {
      method: "POST",
      headers: CSRF_HEADERS,
      body: JSON.stringify({ question: q }),
    });
    const data = await res.json();
    if (!res.ok) {
      document.getElementById("answerBox").innerHTML = `<p style="color:var(--rose);">Error: ${escapeHtml(
        data.detail || "Request failed"
      )}</p>`;
      return;
    }
    lastAskResponse = data;
    renderAskPayload(data);
  } finally {
    btn.disabled = false;
    btn.textContent = "Ask Copilot →";
    await refreshStatus();
  }
}

async function triggerLiveDiscover() {
  const btn = document.getElementById("btnLiveDiscover");
  const resetBtn = document.getElementById("btnReset");
  if (btn.disabled) return;
  btn.disabled = true;
  resetBtn.disabled = true;
  btn.textContent = "Running synapse build --discover...";
  try {
    const res = await fetch("/api/live-discover/enable", {
      method: "POST",
      headers: CSRF_HEADERS,
    });
    const data = await res.json();
    document.getElementById("discoverCard").style.display = "block";
    document.getElementById("discoverBadge").textContent = res.ok ? `+ ${data.added_tool}` : "Build Error";
    document.getElementById("discoverTerminal").textContent = res.ok
      ? `$ ${data.command}\n\n${data.stdout}`
      : `Error: ${data.detail || "Rebuild failed"}`;
    await refreshStatus();
  } finally {
    btn.disabled = false;
    resetBtn.disabled = false;
  }
}

async function resetDemo() {
  const btn = document.getElementById("btnReset");
  if (btn.disabled) return;
  btn.disabled = true;
  try {
    const res = await fetch("/api/live-discover/reset", {
      method: "POST",
      headers: CSRF_HEADERS,
    });
    const data = await res.json();
    document.getElementById("attackSimCard").style.display = "none";
    document.getElementById("discoverCard").style.display = "block";
    document.getElementById("discoverBadge").textContent = "Baseline Restored";
    document.getElementById("discoverTerminal").textContent = `$ ${data.command}\n\n${data.stdout}`;
    await refreshStatus();
  } finally {
    btn.disabled = false;
  }
}

document.addEventListener("DOMContentLoaded", () => {
  document.getElementById("btnBlaToggle").addEventListener("click", toggleBlindInspector);
  document.getElementById("btnShield").addEventListener("click", simulateAttacks);
  document.getElementById("btnLiveDiscover").addEventListener("click", triggerLiveDiscover);
  document.getElementById("btnReset").addEventListener("click", resetDemo);
  document.getElementById("askBtn").addEventListener("click", submitQuestion);
  document.getElementById("questionInput").addEventListener("keydown", (ev) => {
    if (ev.key === "Enter") submitQuestion();
  });
  document.querySelectorAll(".scenario-btn").forEach((btn) => {
    btn.addEventListener("click", () => {
      const prompt = btn.getAttribute("data-prompt");
      if (prompt) {
        document.getElementById("questionInput").value = prompt;
        submitQuestion();
      }
    });
  });
  refreshStatus();
});
