// popup.js - FraudShield v3.0
const API_URL = "https://fraudshield-2u9l.onrender.com";

document.addEventListener("DOMContentLoaded", async () => {
  document.getElementById("scanBtn")
    .addEventListener("click", requestScan);

  document.getElementById("historyBtn")
    .addEventListener("click", () => {
      chrome.tabs.create({
        url: chrome.runtime.getURL("history.html")
      });
    });

  const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
  const url = tabs[0]?.url || "";
  document.getElementById("urlDisplay").textContent = url || "No URL";

  if (url && !url.startsWith("chrome://") && !url.startsWith("chrome-extension://")) {
    requestScan();
  } else {
    showError("Navigate to a website first.");
  }
});

async function requestScan() {
  const btn = document.getElementById("scanBtn");
  btn.disabled = true;
  showLoading();

  try {
    const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
    const url = tabs[0]?.url || "";

    if (!url || url.startsWith("chrome://") || url.startsWith("chrome-extension://")) {
      showError("Navigate to a real website first.");
      btn.disabled = false;
      return;
    }

    const res = await fetch(`${API_URL}/check`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url })
    });

    if (!res.ok) throw new Error(`Server error: ${res.status}`);

    const data = await res.json();
    document.getElementById("scanTime").textContent = new Date().toLocaleTimeString();
    showResult(data);
    saveToHistory(data, url);

  } catch (err) {
    showError("Backend unreachable!\nThe server may be waking up.\nPlease wait 30 seconds and try again.");
  }
  btn.disabled = false;
}

function showLoading() {
  document.getElementById("content").innerHTML =
    `<div class="loading"><div class="spinner"></div>Analyzing with AI...</div>`;
}

function showError(msg) {
  document.getElementById("content").innerHTML =
    `<div class="error-msg">⚠️ ${msg}</div>`;
}

function saveToHistory(data, url) {
  chrome.storage.local.get("scanHistory", (result) => {
    const history = result.scanHistory || [];
    history.push({
      url,
      score:     data.safety_score,
      category:  data.category,
      risk:      data.risk_level,
      site_type: data.domain_info?.site_type ?? "Unknown",
      domain:    data.domain_info?.domain    ?? "",
      protocol:  data.domain_info?.protocol  ?? "",
      timestamp: new Date().toISOString()
    });
    if (history.length > 200) history.shift();
    chrome.storage.local.set({ scanHistory: history });
  });
}

function showResult(data) {
  const score      = data.safety_score ?? 50;
  const flags      = data.flags        ?? [];
  const category   = data.category     ?? "Unknown";
  const riskLevel  = data.risk_level   ?? "";
  const domainInfo = data.domain_info  ?? {};
  const age        = domainInfo.age    ?? {};

  let color, statusLabel, statusDesc, catStyle, riskStyle;

  if (score >= 85) {
    color = "#00ff88"; statusLabel = "✅ SAFE";
    statusDesc = "No threats detected. Site appears legitimate.";
    catStyle  = "background:#00ff8815;color:#00ff88;border:1px solid #00ff8830";
    riskStyle = "background:#00ff8815;color:#00ff88;";
  } else if (score >= 65) {
    color = "#00d4aa"; statusLabel = "✅ PROBABLY SAFE";
    statusDesc = "Low risk. Appears mostly legitimate.";
    catStyle  = "background:#00d4aa15;color:#00d4aa;border:1px solid #00d4aa30";
    riskStyle = "background:#00d4aa15;color:#00d4aa;";
  } else if (score >= 45) {
    color = "#ffd600"; statusLabel = "⚠️ SUSPICIOUS";
    statusDesc = "Risk factors found. Proceed with caution.";
    catStyle  = "background:#ffd60015;color:#ffd600;border:1px solid #ffd60030";
    riskStyle = "background:#ffd60015;color:#ffd600;";
  } else if (score >= 25) {
    color = "#ff8800"; statusLabel = "🚨 LIKELY PHISHING";
    statusDesc = "High risk! This may be a phishing attempt.";
    catStyle  = "background:#ff880015;color:#ff8800;border:1px solid #ff880030";
    riskStyle = "background:#ff880015;color:#ff8800;";
  } else {
    color = "#ff3d5a"; statusLabel = "🔴 MALICIOUS";
    statusDesc = "DANGER! Do not enter any information here.";
    catStyle  = "background:#ff3d5a15;color:#ff3d5a;border:1px solid #ff3d5a30";
    riskStyle = "background:#ff3d5a15;color:#ff3d5a;";
  }

  const circumference = 2 * Math.PI * 36;
  const offset = circumference - (score / 100) * circumference;

  let ageBadge = "";
  if (age.trust === "established")
    ageBadge = `<span class="trust-badge trust-established">✓ Established</span>`;
  else if (age.trust === "relatively new")
    ageBadge = `<span class="trust-badge trust-new">⚡ Relatively New</span>`;
  else if (age.trust === "untrustworthy")
    ageBadge = `<span class="trust-badge trust-bad">⚠ Suspicious TLD</span>`;
  else
    ageBadge = `<span class="trust-badge trust-unknown">? Age Unverified</span>`;

  const proto      = domainInfo.protocol ?? "HTTP";
  const protoClass = proto === "HTTPS" ? "proto-https" : "proto-http";
  const tldTrust   = domainInfo.tld_trust ?? "";
  let tldColor     = "#6b7d99";
  if (tldTrust === "Trusted TLD")    tldColor = "#00ff88";
  if (tldTrust === "Suspicious TLD") tldColor = "#ff3d5a";

  const flagsHTML = flags.length > 0
    ? flags.map(f => `<div class="flag-item">${f.message}</div>`).join("")
    : `<div class="flag-item">✅ No suspicious patterns detected</div>`;

  document.getElementById("content").innerHTML = `
    <div class="score-row">
      <div class="score-ring">
        <svg width="84" height="84" viewBox="0 0 84 84">
          <circle class="track" cx="42" cy="42" r="36"/>
          <circle class="fill" cx="42" cy="42" r="36"
            stroke="${color}"
            stroke-dasharray="${circumference}"
            stroke-dashoffset="${offset}"/>
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
        <div class="info-sub" style="color:${tldColor}">
          ${domainInfo.tld ?? ""} · ${tldTrust}
        </div>
      </div>
      <div class="info-card">
        <div class="info-label">🔒 Protocol</div>
        <div class="info-value ${protoClass}">${proto}</div>
        <div class="info-sub">
          ${proto === "HTTPS" ? "Encrypted ✓" : "Not Encrypted ✗"}
        </div>
      </div>
      <div class="info-card">
        <div class="info-label">🏷️ Site Type</div>
        <div class="info-value" style="font-size:10px">
          ${domainInfo.site_type ?? "Unknown"}
        </div>
        <div class="info-sub">${domainInfo.org_type ?? ""}</div>
      </div>
      <div class="info-card">
        <div class="info-label">📅 Domain Age</div>
        <div class="info-value">
          ${age.age_years != null ? age.age_years + " yrs" : "Unknown"}
        </div>
        <div class="info-sub">
          ${age.estimated_year ? "Est. " + age.estimated_year : age.age_label ?? ""}
        </div>
      </div>
    </div>

    <div class="info-card-full">
      <div class="info-label">🛡️ Domain Trust Level</div>
      <div style="margin-top:4px">${ageBadge}</div>
      <div class="info-sub" style="margin-top:5px">
        ${age.age_label ?? "Verify with WHOIS for exact age"}
      </div>
    </div>

    <div class="flags-section">
      <div class="section-title">
        ⚡ Security Analysis — ${flags.length} signal(s)
      </div>
      ${flagsHTML}
    </div>
  `;
}