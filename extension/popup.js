// popup.js - FraudShield v4.2
const API_URL = "https://fraudshield-1-pkvb.onrender.com";
const MAX_RETRIES = 3;
const RETRY_DELAY_MS = 5000;

// ── Helpers ────────────────────────────────────────────
function scoreColor(s) {
  if (s >= 85) return "#00d4aa";
  if (s >= 65) return "#f59e0b";
  if (s >= 45) return "#f97316";
  return "#ff4d6d";
}

function scoreVerdict(s) {
  if (s >= 85) return "✅ Safe";
  if (s >= 65) return "⚠️ Probably Safe";
  if (s >= 45) return "⚠️ Suspicious";
  if (s >= 25) return "🚨 Likely Phishing";
  return "🔴 Malicious";
}

function showStatus(msg, type = "info") {
  const el = document.getElementById("status-msg");
  if (!el) return;
  el.textContent = msg;
  el.className = `status ${type}`;
  el.style.display = "block";
  setTimeout(() => { el.style.display = "none"; }, 3000);
}

// ── Render score ring ──────────────────────────────────
function renderScore(score, verdict, url) {
  const ring    = document.getElementById("score-ring");
  const numEl   = document.getElementById("score-number");
  const lblEl   = document.getElementById("verdict-label");
  const urlEl   = document.getElementById("scanned-url");
  const color   = scoreColor(score);

  if (ring)  { ring.style.borderColor = color; ring.classList.remove("scanning"); }
  if (numEl) { numEl.textContent = score; numEl.style.color = color; }
  if (lblEl) { lblEl.textContent = verdict; lblEl.style.color = color; }
  if (urlEl) { urlEl.textContent = url; }
}

// ── Render history table ───────────────────────────────
function renderHistory(history) {
  const tbody = document.getElementById("popup-history");
  if (!tbody) return;

  if (!history || history.length === 0) {
    tbody.innerHTML = `<tr><td colspan="3" style="text-align:center;color:#555;padding:14px;font-size:11px">No scans yet</td></tr>`;
    return;
  }

  // Deduplicate — show only latest scan per domain
  const seen = new Set();
  const deduped = [];
  for (const entry of history) {
    const domain = entry.domain || entry.url;
    if (!seen.has(domain)) {
      seen.add(domain);
      deduped.push(entry);
    }
    if (deduped.length >= 5) break;
  }

  tbody.innerHTML = deduped.map(e => {
    const score   = e.score ?? 0;
    const color   = scoreColor(score);
    const verdict = scoreVerdict(score);
    const domain  = e.domain || new URL(e.url).hostname;
    return `<tr>
      <td class="url-cell" title="${e.url}">${domain}</td>
      <td style="color:${color};font-weight:700;font-family:var(--mono)">${score}</td>
      <td style="color:${color};font-size:10px">${verdict}</td>
    </tr>`;
  }).join("");
}

// ── Save to history ────────────────────────────────────
function saveToHistory(data, url) {
  chrome.storage.local.get("scanHistory", (result) => {
    const history = result.scanHistory || [];

    // Dedup — skip if same URL scanned in last 60s
    const now = Date.now();
    const recent = history.find(e =>
      e.url === url && (now - new Date(e.timestamp).getTime()) < 60000
    );
    if (recent) return;

    history.unshift({
      url,
      score:     data.safety_score,
      category:  data.category,
      risk:      data.risk_level,
      site_type: data.domain_info?.site_type ?? "Unknown",
      domain:    data.domain_info?.domain    ?? "",
      protocol:  data.domain_info?.protocol  ?? "",
      timestamp: new Date().toISOString()
    });
    if (history.length > 200) history.pop();
    chrome.storage.local.set({ scanHistory: history });
  });
}

// ── Fetch with retry ───────────────────────────────────
async function fetchWithRetry(url, options, retries = MAX_RETRIES) {
  for (let attempt = 1; attempt <= retries; attempt++) {
    try {
      const res = await fetch(url, options);
      if (!res.ok) throw new Error(`Server error: ${res.status}`);
      return res;
    } catch (err) {
      if (attempt === retries) throw err;
      showStatus(`Server waking up... attempt ${attempt}/${retries}`, "info");
      await new Promise(r => setTimeout(r, RETRY_DELAY_MS));
    }
  }
}

// ── Main scan ──────────────────────────────────────────
async function requestScan() {
  const btn = document.getElementById("btn-scan");
  if (btn) btn.disabled = true;

  // Reset ring to scanning state
  const ring  = document.getElementById("score-ring");
  const numEl = document.getElementById("score-number");
  const lblEl = document.getElementById("verdict-label");
  if (ring)  { ring.style.borderColor = ""; ring.classList.add("scanning"); }
  if (numEl) { numEl.textContent = "…"; numEl.style.color = "var(--text3)"; }
  if (lblEl) { lblEl.textContent = "Scanning…"; lblEl.style.color = "var(--text3)"; }

  try {
    const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
    const url  = tabs[0]?.url || "";

    if (!url || url.startsWith("chrome://") || url.startsWith("chrome-extension://")) {
      showStatus("Navigate to a real website first.", "error");
      if (ring) ring.classList.remove("scanning");
      if (numEl) numEl.textContent = "—";
      if (lblEl) lblEl.textContent = "Not a webpage";
      if (btn) btn.disabled = false;
      return;
    }

    document.getElementById("scanned-url").textContent = url;

    const res  = await fetchWithRetry(`${API_URL}/check`, {
      method:  "POST",
      headers: { "Content-Type": "application/json" },
      body:    JSON.stringify({ url })
    });
    const data = await res.json();
    const score   = data.safety_score ?? 50;
    const verdict = scoreVerdict(score);

    renderScore(score, verdict, url);
    saveToHistory(data, url);

    // Refresh history table
    chrome.storage.local.get("scanHistory", r => renderHistory(r.scanHistory || []));

    // Show status
    if (score >= 85) showStatus("Site appears safe!", "success");
    else if (score >= 65) showStatus("Low-medium risk detected.", "info");
    else showStatus("Risk detected — stay cautious!", "error");

  } catch (err) {
    showStatus("Backend unreachable. Please retry in 30s.", "error");
    if (ring)  ring.classList.remove("scanning");
    if (numEl) numEl.textContent = "!";
    if (lblEl) { lblEl.textContent = "Error"; lblEl.style.color = "#ff4d6d"; }
  }

  if (btn) btn.disabled = false;
}

// ── Export CSV ─────────────────────────────────────────
function exportCSV(history) {
  if (!history || history.length === 0) { alert("No scan history to export."); return; }
  const headers = ["URL","Safety Score","Category","Risk Level","Site Type","Domain","Protocol","Date & Time"];
  const rows = history.map(e => {
    const url = `"${(e.url||"").replace(/"/g,'""')}"`;
    return [url, e.score??"", `"${e.category??""}"`, `"${e.risk??""}"`,
            `"${e.site_type??""}"`, `"${e.domain??""}"`, `"${e.protocol??""}"`,
            `"${new Date(e.timestamp).toLocaleString()}"`].join(",");
  });
  const blob = new Blob([[headers.join(","), ...rows].join("\n")], { type:"text/csv;charset=utf-8;" });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = `fraudshield-${new Date().toISOString().slice(0,10)}.csv`;
  a.click();
}

// ── Export PDF ─────────────────────────────────────────
function exportPDF(history) {
  if (!history || history.length === 0) { alert("No scan history to export."); return; }
  const esc = s => String(s).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;");
  const rows = history.map((e,i) => {
    const score = e.score ?? 0;
    const color = score>=85?"#00aa55":score>=65?"#cc9900":score>=45?"#cc6600":"#cc2222";
    return `<tr><td>${i+1}</td><td class="url-cell">${esc(e.url||"")}</td>
      <td><span style="color:${color};font-weight:700">${score}/100</span></td>
      <td>${esc(e.category||"")}</td><td>${esc(e.risk||"")}</td>
      <td>${new Date(e.timestamp).toLocaleString()}</td></tr>`;
  }).join("");
  const html = `<!DOCTYPE html><html><head><meta charset="utf-8"><title>FraudShield History</title>
  <style>body{font-family:'Segoe UI',sans-serif;padding:32px;color:#1a1a1a}
  .brand{font-size:24px;font-weight:800;color:#00aa55}
  table{width:100%;border-collapse:collapse;font-size:13px}
  th{background:#f5f5f5;padding:10px 12px;text-align:left;border-bottom:2px solid #e0e0e0}
  td{padding:9px 12px;border-bottom:1px solid #f0f0f0;vertical-align:top}
  .url-cell{max-width:280px;word-break:break-all;color:#1a5fa8;font-size:12px}
  tr:nth-child(even) td{background:#fafafa}
  .footer{margin-top:24px;text-align:center;color:#aaa;font-size:12px}</style></head>
  <body><div class="brand">FraudShield <span style="font-size:14px;color:#888">v4.2 AI</span></div>
  <p style="color:#666;margin:4px 0 16px">Generated: ${new Date().toLocaleString()} | Total: ${history.length} scans</p>
  <table><thead><tr><th>#</th><th>URL</th><th>Score</th><th>Category</th><th>Risk</th><th>Date</th></tr></thead>
  <tbody>${rows}</tbody></table>
  <div class="footer">FraudShield v4.2 — AI Fraud Detection</div></body></html>`;
  const win = window.open("","_blank");
  win.document.write(html);
  win.document.close();
  setTimeout(() => win.print(), 500);
}

// ── Init ───────────────────────────────────────────────
document.addEventListener("DOMContentLoaded", async () => {

  // Wire buttons to their IDs in popup.html
  document.getElementById("btn-scan")
    ?.addEventListener("click", requestScan);

  document.getElementById("btn-dashboard")
    ?.addEventListener("click", () => {
      chrome.tabs.create({ url: chrome.runtime.getURL("history.html") });
    });

  document.getElementById("btn-allowlist")
    ?.addEventListener("click", async () => {
      const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
      const url  = tabs[0]?.url || "";
      showStatus(`Allowed: ${new URL(url).hostname}`, "success");
    });

  document.getElementById("btn-blocklist")
    ?.addEventListener("click", async () => {
      const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
      const url  = tabs[0]?.url || "";
      showStatus(`Blocked: ${new URL(url).hostname}`, "error");
    });

  // Load history immediately
  chrome.storage.local.get("scanHistory", r => renderHistory(r.scanHistory || []));

  // Auto-scan current tab
  const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
  const url  = tabs[0]?.url || "";
  if (url && !url.startsWith("chrome://") && !url.startsWith("chrome-extension://")) {
    requestScan();
  } else {
    const ring  = document.getElementById("score-ring");
    const numEl = document.getElementById("score-number");
    const lblEl = document.getElementById("verdict-label");
    const urlEl = document.getElementById("scanned-url");
    if (ring)  ring.classList.remove("scanning");
    if (numEl) numEl.textContent = "—";
    if (lblEl) lblEl.textContent = "Not a webpage";
    if (urlEl) urlEl.textContent = "Open a website to scan";
  }
});