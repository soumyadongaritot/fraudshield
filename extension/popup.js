// popup.js - FraudShield v3.1
const API_URL = "https://fraudshield-2u9l.onrender.com";
const MAX_RETRIES = 3;
const RETRY_DELAY_MS = 5000;

document.addEventListener("DOMContentLoaded", async () => {
  document.getElementById("scanBtn").addEventListener("click", requestScan);
  document.getElementById("historyBtn").addEventListener("click", () => {
    chrome.tabs.create({ url: chrome.runtime.getURL("history.html") });
  });
  document.getElementById("exportCSVBtn").addEventListener("click", () => {
    chrome.storage.local.get("scanHistory", (r) => exportCSV(r.scanHistory || []));
  });
  document.getElementById("exportPDFBtn").addEventListener("click", () => {
    chrome.storage.local.get("scanHistory", (r) => exportPDF(r.scanHistory || []));
  });

  const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
  const url = tabs[0]?.url || "";
  document.getElementById("urlDisplay").textContent = url || "No URL";

  // Show live scan log immediately
  showLiveScanLog();

  if (url && !url.startsWith("chrome://") && !url.startsWith("chrome-extension://")) {
    requestScan();
  } else {
    showError("Navigate to a website first.");
  }
});

// ── Live scan log (shows last 5 scans live in popup) ──
function showLiveScanLog() {
  chrome.storage.local.get("scanHistory", (result) => {
    const history = (result.scanHistory || []).slice(0, 5);
    if (history.length === 0) return;

    const logEl = document.getElementById("liveScanLog");
    if (!logEl) return;

    logEl.innerHTML = history.map(e => {
      const score = e.score ?? 0;
      const color = score >= 85 ? "#00ff88"
                  : score >= 65 ? "#00d4aa"
                  : score >= 45 ? "#ffd600"
                  : score >= 25 ? "#ff8800"
                  : "#ff3d5a";
      const domain = e.domain || new URL(e.url).hostname;
      const time   = new Date(e.timestamp).toLocaleTimeString();
      return `
        <div class="log-row">
          <div class="log-score" style="color:${color}">${score}</div>
          <div class="log-info">
            <div class="log-domain">${domain}</div>
            <div class="log-time">${e.category} · ${time}</div>
          </div>
          <div class="log-dot" style="background:${color}"></div>
        </div>`;
    }).join("");

    logEl.style.display = "block";
  });
}

async function fetchWithRetry(url, options, retries = MAX_RETRIES) {
  for (let attempt = 1; attempt <= retries; attempt++) {
    try {
      showLoading(attempt);
      const res = await fetch(url, options);
      if (!res.ok) throw new Error(`Server error: ${res.status}`);
      return res;
    } catch (err) {
      if (attempt === retries) throw err;
      await new Promise(resolve => setTimeout(resolve, RETRY_DELAY_MS));
    }
  }
}

async function requestScan() {
  const btn = document.getElementById("scanBtn");
  btn.disabled = true;
  try {
    const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
    const url = tabs[0]?.url || "";
    if (!url || url.startsWith("chrome://") || url.startsWith("chrome-extension://")) {
      showError("Navigate to a real website first.");
      btn.disabled = false;
      return;
    }
    const res = await fetchWithRetry(`${API_URL}/check`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url })
    });
    const data = await res.json();
    document.getElementById("scanTime").textContent = new Date().toLocaleTimeString();
    showResult(data);
    saveToHistory(data, url);
    // Refresh live log after scan
    setTimeout(showLiveScanLog, 300);
  } catch (err) {
    showError("⚠️ Backend unreachable after 3 attempts.\nPlease wait 30 seconds and try again.");
  }
  btn.disabled = false;
}

function showLoading(attempt = 1) {
  const msg = attempt === 1 ? "Analyzing with AI..." : `Waking server... (attempt ${attempt}/${MAX_RETRIES})`;
  document.getElementById("content").innerHTML =
    `<div class="loading"><div class="spinner"></div>${msg}</div>`;
}

function showError(msg) {
  document.getElementById("content").innerHTML = `<div class="error-msg">⚠️ ${msg}</div>`;
}

function saveToHistory(data, url) {
  chrome.storage.local.get("scanHistory", (result) => {
    const history = result.scanHistory || [];
    history.unshift({
      url, score: data.safety_score, category: data.category, risk: data.risk_level,
      site_type: data.domain_info?.site_type ?? "Unknown",
      domain: data.domain_info?.domain ?? "",
      protocol: data.domain_info?.protocol ?? "",
      timestamp: new Date().toISOString()
    });
    if (history.length > 200) history.splice(200);
    chrome.storage.local.set({ scanHistory: history });
  });
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
  <body><div class="brand">FraudShield <span style="font-size:14px;color:#888">v3.1 AI</span></div>
  <p style="color:#666;margin:4px 0 16px">Generated: ${new Date().toLocaleString()} | Total: ${history.length} scans</p>
  <table><thead><tr><th>#</th><th>URL</th><th>Score</th><th>Category</th><th>Risk</th><th>Date</th></tr></thead>
  <tbody>${rows}</tbody></table>
  <div class="footer">FraudShield v3.1 — AI Fraud Detection</div></body></html>`;
  const win = window.open("","_blank");
  win.document.write(html);
  win.document.close();
  setTimeout(() => win.print(), 500);
}

function showResult(data) {
  const score = data.safety_score ?? 50;
  const flags = data.flags ?? [];
  const category = data.category ?? "Unknown";
  const riskLevel = data.risk_level ?? "";
  const domainInfo = data.domain_info ?? {};
  const age = domainInfo.age ?? {};

  let color, statusLabel, statusDesc, catStyle, riskStyle;
  if (score >= 85) {
    color="#00ff88"; statusLabel="✅ SAFE"; statusDesc="No threats detected. Site appears legitimate.";
    catStyle="background:#00ff8815;color:#00ff88;border:1px solid #00ff8830"; riskStyle="background:#00ff8815;color:#00ff88;";
  } else if (score >= 65) {
    color="#00d4aa"; statusLabel="✅ PROBABLY SAFE"; statusDesc="Low risk. Appears mostly legitimate.";
    catStyle="background:#00d4aa15;color:#00d4aa;border:1px solid #00d4aa30"; riskStyle="background:#00d4aa15;color:#00d4aa;";
  } else if (score >= 45) {
    color="#ffd600"; statusLabel="⚠️ SUSPICIOUS"; statusDesc="Risk factors found. Proceed with caution.";
    catStyle="background:#ffd60015;color:#ffd600;border:1px solid #ffd60030"; riskStyle="background:#ffd60015;color:#ffd600;";
  } else if (score >= 25) {
    color="#ff8800"; statusLabel="🚨 LIKELY PHISHING"; statusDesc="High risk! This may be a phishing attempt.";
    catStyle="background:#ff880015;color:#ff8800;border:1px solid #ff880030"; riskStyle="background:#ff880015;color:#ff8800;";
  } else {
    color="#ff3d5a"; statusLabel="🔴 MALICIOUS"; statusDesc="DANGER! Do not enter any information here.";
    catStyle="background:#ff3d5a15;color:#ff3d5a;border:1px solid #ff3d5a30"; riskStyle="background:#ff3d5a15;color:#ff3d5a;";
  }

  const circumference = 2 * Math.PI * 36;
  const offset = circumference - (score / 100) * circumference;

  let ageBadge = "";
  if (age.trust==="established") ageBadge=`<span class="trust-badge trust-established">✓ Established</span>`;
  else if (age.trust==="relatively new") ageBadge=`<span class="trust-badge trust-new">⚡ Relatively New</span>`;
  else if (age.trust==="untrustworthy") ageBadge=`<span class="trust-badge trust-bad">⚠ Suspicious TLD</span>`;
  else ageBadge=`<span class="trust-badge trust-unknown">? Age Unverified</span>`;

  const proto = domainInfo.protocol ?? "HTTP";
  const protoClass = proto === "HTTPS" ? "proto-https" : "proto-http";
  const tldTrust = domainInfo.tld_trust ?? "";
  let tldColor = "#6b7d99";
  if (tldTrust==="Trusted TLD") tldColor="#00ff88";
  if (tldTrust==="Suspicious TLD") tldColor="#ff3d5a";

  const flagsHTML = flags.length > 0
    ? flags.map(f => `<div class="flag-item">${f.message}</div>`).join("")
    : `<div class="flag-item">✅ No suspicious patterns detected</div>`;

  document.getElementById("content").innerHTML = `
    <div class="score-row">
      <div class="score-ring">
        <svg width="84" height="84" viewBox="0 0 84 84">
          <circle class="track" cx="42" cy="42" r="36"/>
          <circle class="fill" cx="42" cy="42" r="36" stroke="${color}"
            stroke-dasharray="${circumference}" stroke-dashoffset="${offset}"/>
        </svg>
        <div class="score-center">
          <div class="score-num" style="color:${color}">${score}</div>
          <div class="score-den">/ 100</div>
        </div>
      </div>
      <div class="score-info">
        <div class="status-tag" style="color:${color}">${statusLabel}</div>
        <div class="risk-tag" style="${riskStyle}">${riskLevel}</div>
        <div class="status-desc">${statusDesc}</div>
        <span class="category-pill" style="${catStyle}">${category}</span>
      </div>
    </div>
    <div class="info-grid">
      <div class="info-card">
        <div class="info-label">🌐 Domain</div>
        <div class="info-value">${domainInfo.domain ?? "Unknown"}</div>
        <div class="info-sub" style="color:${tldColor}">${domainInfo.tld ?? ""} · ${tldTrust}</div>
      </div>
      <div class="info-card">
        <div class="info-label">🔒 Protocol</div>
        <div class="info-value ${protoClass}">${proto}</div>
        <div class="info-sub">${proto==="HTTPS"?"Encrypted ✓":"Not Encrypted ✗"}</div>
      </div>
      <div class="info-card">
        <div class="info-label">🏷️ Site Type</div>
        <div class="info-value" style="font-size:10px">${domainInfo.site_type ?? "Unknown"}</div>
        <div class="info-sub">${domainInfo.org_type ?? ""}</div>
      </div>
      <div class="info-card">
        <div class="info-label">📅 Domain Age</div>
        <div class="info-value">${age.age_years != null ? age.age_years+" yrs" : "Unknown"}</div>
        <div class="info-sub">${age.estimated_year ? "Est. "+age.estimated_year : age.age_label ?? ""}</div>
      </div>
    </div>
    <div class="info-card-full">
      <div class="info-label">🛡️ Domain Trust Level</div>
      <div style="margin-top:4px">${ageBadge}</div>
      <div class="info-sub" style="margin-top:5px">${age.age_label ?? "Verify with WHOIS for exact age"}</div>
    </div>
    <div class="flags-section">
      <div class="section-title">⚡ Security Analysis — ${flags.length} signal(s)</div>
      ${flagsHTML}
    </div>`;
}