// popup.js - FraudShield v4.0 with Supabase Auth
const API_URL        = "https://fraudshield-2u9l.onrender.com";
const MAX_RETRIES    = 3;
const RETRY_DELAY_MS = 5000;

// ── Init ──────────────────────────────────────────────────────────────
document.addEventListener("DOMContentLoaded", async () => {
  // Check auth state first
  const session = await getSession();
  if (session) {
    showMainApp(session);
  } else {
    showAuthScreen();
  }
});

// ── Auth Screen ───────────────────────────────────────────────────────
function showAuthScreen(mode = "login") {
  document.getElementById("app").innerHTML = `
    <div class="auth-container">
      <div class="auth-logo">
        <span class="fraud">Fraud</span><span class="shield">Shield</span>
        <span class="version">v4.0 AI</span>
      </div>
      <div class="auth-subtitle">AI-Powered Fraud Detection</div>

      <div class="auth-tabs">
        <button class="auth-tab ${mode === "login" ? "active" : ""}"
          id="tabLogin">Login</button>
        <button class="auth-tab ${mode === "signup" ? "active" : ""}"
          id="tabSignup">Sign Up</button>
      </div>

      <div class="auth-form">
        <input type="email" id="authEmail" placeholder="Email address"
          class="auth-input" autocomplete="email"/>
        <input type="password" id="authPassword" placeholder="Password (min 6 chars)"
          class="auth-input" autocomplete="${mode === "login" ? "current-password" : "new-password"}"/>
        ${mode === "signup" ? `
        <input type="password" id="authConfirm" placeholder="Confirm password"
          class="auth-input" autocomplete="new-password"/>
        ` : ""}
        <div id="authError" class="auth-error" style="display:none"></div>
        <button id="authBtn" class="auth-btn">
          ${mode === "login" ? "Login" : "Create Account"}
        </button>
        ${mode === "login" ? `
        <div class="auth-forgot">
          <span style="color:#6b7d99;font-size:11px">
            Don't have an account?
            <a href="#" id="switchMode" style="color:#00d4aa">Sign up</a>
          </span>
        </div>` : `
        <div class="auth-forgot">
          <span style="color:#6b7d99;font-size:11px">
            Already have an account?
            <a href="#" id="switchMode" style="color:#00d4aa">Login</a>
          </span>
        </div>`}
      </div>

      <div class="auth-footer">🛡️ Your scans sync across all devices</div>
    </div>
  `;

  // Attach all event listeners (no inline onclick)
  setTimeout(() => {
    document.getElementById("tabLogin")?.addEventListener("click", () => showAuthScreen("login"));
    document.getElementById("tabSignup")?.addEventListener("click", () => showAuthScreen("signup"));
    document.getElementById("authBtn")?.addEventListener("click", () => handleAuth(mode));
    document.getElementById("switchMode")?.addEventListener("click", (e) => {
      e.preventDefault();
      showAuthScreen(mode === "login" ? "signup" : "login");
    });
    document.querySelectorAll(".auth-input").forEach(input => {
      input.addEventListener("keydown", e => {
        if (e.key === "Enter") handleAuth(mode);
      });
    });
  }, 50);
}

async function handleAuth(mode) {
  const email    = document.getElementById("authEmail")?.value?.trim();
  const password = document.getElementById("authPassword")?.value;
  const errorEl  = document.getElementById("authError");
  const btn      = document.getElementById("authBtn");

  if (!email || !password) {
    showAuthError("Please enter email and password");
    return;
  }
  if (password.length < 6) {
    showAuthError("Password must be at least 6 characters");
    return;
  }
  if (mode === "signup") {
    const confirm = document.getElementById("authConfirm")?.value;
    if (password !== confirm) {
      showAuthError("Passwords do not match");
      return;
    }
  }

  btn.disabled    = true;
  btn.textContent = mode === "login" ? "Logging in..." : "Creating account...";

  try {
    if (mode === "signup") {
      await signUp(email, password);
      showAuthError("✅ Account created! Please login.", "success");
      setTimeout(() => showAuthScreen("login"), 1500);
    } else {
      const session = await signIn(email, password);
      showMainApp(session);
    }
  } catch (err) {
    showAuthError(err.message || "Authentication failed");
    btn.disabled    = false;
    btn.textContent = mode === "login" ? "Login" : "Create Account";
  }
}

function showAuthError(msg, type = "error") {
  const el = document.getElementById("authError");
  if (!el) return;
  el.textContent    = msg;
  el.style.display  = "block";
  el.style.color    = type === "success" ? "#00ff88" : "#ff3d5a";
}

// ── Main App ──────────────────────────────────────────────────────────
async function showMainApp(session) {
  const email = session?.user?.email || "User";

  document.getElementById("app").innerHTML = `
    <div class="header">
      <div class="logo">
        <span class="fraud">Fraud</span><span class="shield">Shield</span>
        <span class="badge">v4.0 AI</span>
      </div>
      <div class="header-actions">
        <button class="icon-btn" id="historyBtn" title="History">📋</button>
        <button class="icon-btn" id="userBtn" title="${email}">👤</button>
      </div>
    </div>

    <div class="user-bar" id="userBar" style="display:none">
      <div class="user-email">${email}</div>
      <button class="signout-btn" id="signoutBtn">Sign Out</button>
    </div>

    <div class="url-bar" id="urlDisplay">Loading...</div>
    <div id="liveScanLog"></div>
    <div id="content"></div>
    <div class="scan-time-bar">
      FraudShield v4.0 — AI Fraud Detection
      <span id="scanTime"></span>
    </div>
    <div class="action-bar">
      <button class="scan-btn" id="scanBtn">🔄 RE-SCAN THIS PAGE</button>
    </div>
    <div class="export-bar">
      <button class="export-btn" id="exportCSVBtn">↓ EXPORT CSV</button>
      <button class="export-btn" id="exportPDFBtn">↓ EXPORT PDF</button>
    </div>
  `;

  // Event listeners
  document.getElementById("scanBtn").addEventListener("click", requestScan);
  document.getElementById("historyBtn").addEventListener("click", () => {
    chrome.tabs.create({ url: chrome.runtime.getURL("history.html") });
  });
  document.getElementById("userBtn").addEventListener("click", () => {
    const bar = document.getElementById("userBar");
    bar.style.display = bar.style.display === "none" ? "flex" : "none";
  });
  document.getElementById("signoutBtn")?.addEventListener("click", handleSignOut);
  document.getElementById("signoutBtn")?.addEventListener("click", handleSignOut);
  document.getElementById("exportCSVBtn").addEventListener("click", async () => {
    const history = await getHistory();
    exportCSV(history);
  });
  document.getElementById("exportPDFBtn").addEventListener("click", async () => {
    const history = await getHistory();
    exportPDF(history);
  });

  const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
  const url  = tabs[0]?.url || "";
  document.getElementById("urlDisplay").textContent = url || "No URL";

  showLiveScanLog();

  if (url && !url.startsWith("chrome://") && !url.startsWith("chrome-extension://")) {
    requestScan();
  } else {
    showError("Navigate to a website first.");
  }
}

async function handleSignOut() {
  await signOut();
  showAuthScreen("login");
}

async function getHistory() {
  const session = await getSession();
  if (session) {
    const cloud = await fetchCloudHistory(session.access_token);
    if (cloud.length > 0) return cloud;
  }
  const local = await new Promise(res =>
    chrome.storage.local.get("scanHistory", r => res(r.scanHistory || []))
  );
  return local;
}

// ── Live scan log ─────────────────────────────────────────────────────
function showLiveScanLog() {
  chrome.storage.local.get("scanHistory", (result) => {
    const history = (result.scanHistory || []).slice(0, 5);
    if (history.length === 0) return;
    const logEl = document.getElementById("liveScanLog");
    if (!logEl) return;
    logEl.innerHTML = history.map(e => {
      const score  = e.score ?? 0;
      const color  = score >= 85 ? "#00ff88" : score >= 65 ? "#00d4aa"
                   : score >= 45 ? "#ffd600" : score >= 25 ? "#ff8800" : "#ff3d5a";
      const domain = e.domain || (() => { try { return new URL(e.url).hostname; } catch { return e.url; } })();
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

// ── Scan ──────────────────────────────────────────────────────────────
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
  if (btn) btn.disabled = true;

  try {
    const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
    const url  = tabs[0]?.url || "";

    if (!url || url.startsWith("chrome://") || url.startsWith("chrome-extension://")) {
      showError("Navigate to a real website first.");
      if (btn) btn.disabled = false;
      return;
    }

    const res  = await fetchWithRetry(`${API_URL}/check`, {
      method:  "POST",
      headers: { "Content-Type": "application/json" },
      body:    JSON.stringify({ url })
    });
    const data = await res.json();

    const scanTimeEl = document.getElementById("scanTime");
    if (scanTimeEl) scanTimeEl.textContent = new Date().toLocaleTimeString();

    showResult(data);
    await saveToHistory(data, url);

  } catch (err) {
    showError("Backend unreachable after 3 attempts.\nPlease wait 30 seconds and try again.");
  }

  if (btn) btn.disabled = false;
}

// ── Save history (local + cloud) ──────────────────────────────────────
async function saveToHistory(data, url) {
  const entry = {
    url,
    score:     data.safety_score,
    category:  data.category,
    risk:      data.risk_level,
    site_type: data.domain_info?.site_type ?? "Unknown",
    domain:    data.domain_info?.domain    ?? "",
    protocol:  data.domain_info?.protocol  ?? "",
    timestamp: new Date().toISOString()
  };

  // Save locally
  chrome.storage.local.get("scanHistory", (result) => {
    const history = result.scanHistory || [];
    history.unshift(entry);
    if (history.length > 200) history.pop();
    chrome.storage.local.set({ scanHistory: history });
  });

  // Save to cloud if logged in
  const session = await getSession();
  if (session) {
    await saveScanToCloud(entry, session.access_token);
  }
}

// ── UI helpers ────────────────────────────────────────────────────────
function showLoading(attempt = 1) {
  const msg = attempt === 1
    ? "Analyzing with AI..."
    : `Server waking up... (attempt ${attempt}/${MAX_RETRIES})`;
  const el = document.getElementById("content");
  if (el) el.innerHTML = `<div class="loading"><div class="spinner"></div>${msg}</div>`;
}

function showError(msg) {
  const el = document.getElementById("content");
  if (el) el.innerHTML = `<div class="error-msg">⚠️ ${msg}</div>`;
}

// ── Export CSV ────────────────────────────────────────────────────────
function exportCSV(history) {
  if (!history || history.length === 0) {
    alert("No scan history to export!");
    return;
  }
  const headers = ["URL","Safety Score","Category","Risk Level","Site Type","Domain","Protocol","Date & Time"];
  const rows = history.map(e => {
    const date = new Date(e.timestamp).toLocaleString();
    return [
      `"${(e.url||"").replace(/"/g,'""')}"`,
      e.score ?? "",
      `"${e.category ?? ""}"`,
      `"${e.risk ?? ""}"`,
      `"${e.site_type ?? ""}"`,
      `"${e.domain ?? ""}"`,
      `"${e.protocol ?? ""}"`,
      `"${date}"`
    ].join(",");
  });
  const csv     = [headers.join(","), ...rows].join("\n");
  const b64     = btoa(unescape(encodeURIComponent(csv)));
  const dataUrl = "data:text/csv;base64," + b64;
  const today   = new Date().toISOString().split("T")[0];
  chrome.runtime.sendMessage({
    type: "DOWNLOAD_CSV",
    url:  dataUrl,
    filename: `fraudshield-${today}.csv`
  });
}

// ── Export PDF ────────────────────────────────────────────────────────
function exportPDF(history) {
  if (!history || history.length === 0) {
    alert("No scan history to export!");
    return;
  }
  chrome.tabs.create({ url: chrome.runtime.getURL("history.html?export=pdf") });
}

// ── Show result ───────────────────────────────────────────────────────
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

  const el = document.getElementById("content");
  if (!el) return;

  el.innerHTML = `
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
        <div class="info-sub">${proto === "HTTPS" ? "Encrypted ✓" : "Not Encrypted ✗"}</div>
      </div>
      <div class="info-card">
        <div class="info-label">🏷️ Site Type</div>
        <div class="info-value" style="font-size:10px">${domainInfo.site_type ?? "Unknown"}</div>
        <div class="info-sub">${domainInfo.org_type ?? ""}</div>
      </div>
      <div class="info-card">
        <div class="info-label">📅 Domain Age</div>
        <div class="info-value">${age.age_years != null ? age.age_years + " yrs" : "Unknown"}</div>
        <div class="info-sub">${age.estimated_year ? "Est. " + age.estimated_year : age.age_label ?? ""}</div>
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
      <div class="section-title">⚡ Security Analysis — ${flags.length} signal(s)</div>
      ${flagsHTML}
    </div>
  `;
}