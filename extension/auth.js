// auth.js - FraudShield Supabase Auth Helper
const SUPABASE_URL = "https://bgfztnukkgcakeogpvdi.supabase.co";
const SUPABASE_KEY = "sb_publishable_w9J9v84ef_Ag0Igc8jJkxw_f0YJYJ5c";

const AUTH_URL = `${SUPABASE_URL}/auth/v1`;
const DB_URL   = `${SUPABASE_URL}/rest/v1`;

// ── Auth functions ────────────────────────────────────────────────────

async function signUp(email, password) {
  const r = await fetch(`${AUTH_URL}/signup`, {
    method: "POST",
    headers: { "Content-Type": "application/json", "apikey": SUPABASE_KEY },
    body: JSON.stringify({ email, password })
  });
  const data = await r.json();
  if (data.error) throw new Error(data.error.message || data.msg || "Signup failed");
  return data;
}

async function signIn(email, password) {
  const r = await fetch(`${AUTH_URL}/token?grant_type=password`, {
    method: "POST",
    headers: { "Content-Type": "application/json", "apikey": SUPABASE_KEY },
    body: JSON.stringify({ email, password })
  });
  const data = await r.json();
  if (data.error || data.error_description) {
    throw new Error(data.error_description || data.error || "Login failed");
  }
  await chrome.storage.local.set({
    sb_access_token:  data.access_token,
    sb_refresh_token: data.refresh_token,
    sb_user:          data.user
  });
  return data;
}

async function signOut() {
  const { sb_access_token } = await chrome.storage.local.get("sb_access_token");
  if (sb_access_token) {
    await fetch(`${AUTH_URL}/logout`, {
      method: "POST",
      headers: { "apikey": SUPABASE_KEY, "Authorization": `Bearer ${sb_access_token}` }
    }).catch(() => {});
  }
  await chrome.storage.local.remove(["sb_access_token", "sb_refresh_token", "sb_user"]);
}

async function getSession() {
  const { sb_access_token, sb_user } = await chrome.storage.local.get([
    "sb_access_token", "sb_user"
  ]);
  if (!sb_access_token || !sb_user) return null;
  return { access_token: sb_access_token, user: sb_user };
}

async function refreshSession() {
  const { sb_refresh_token } = await chrome.storage.local.get("sb_refresh_token");
  if (!sb_refresh_token) return null;
  try {
    const r = await fetch(`${AUTH_URL}/token?grant_type=refresh_token`, {
      method: "POST",
      headers: { "Content-Type": "application/json", "apikey": SUPABASE_KEY },
      body: JSON.stringify({ refresh_token: sb_refresh_token })
    });
    const data = await r.json();
    if (data.access_token) {
      await chrome.storage.local.set({
        sb_access_token:  data.access_token,
        sb_refresh_token: data.refresh_token || sb_refresh_token,
        sb_user:          data.user
      });
      return data;
    }
  } catch (e) {}
  return null;
}

// ── Scan history sync ─────────────────────────────────────────────────

async function saveScanToCloud(entry, accessToken) {
  try {
    const { sb_user } = await chrome.storage.local.get("sb_user");
    if (!sb_user) return;
    await fetch(`${DB_URL}/scan_history`, {
      method: "POST",
      headers: {
        "Content-Type":  "application/json",
        "apikey":        SUPABASE_KEY,
        "Authorization": `Bearer ${accessToken}`,
        "Prefer":        "return=minimal"
      },
      body: JSON.stringify({
        user_id:   sb_user.id,
        url:       entry.url,
        score:     entry.score,
        category:  entry.category,
        risk:      entry.risk,
        site_type: entry.site_type,
        domain:    entry.domain,
        protocol:  entry.protocol,
        timestamp: entry.timestamp
      })
    });
  } catch (e) {
    console.warn("Cloud save failed:", e);
  }
}

async function fetchCloudHistory(accessToken) {
  try {
    const r = await fetch(
      `${DB_URL}/scan_history?order=timestamp.desc&limit=200`,
      {
        headers: {
          "apikey":        SUPABASE_KEY,
          "Authorization": `Bearer ${accessToken}`
        }
      }
    );
    if (!r.ok) return [];
    const data = await r.json();
    return data.map(e => ({
      url:       e.url,
      score:     e.score,
      category:  e.category,
      risk:      e.risk,
      site_type: e.site_type,
      domain:    e.domain,
      protocol:  e.protocol,
      timestamp: e.timestamp
    }));
  } catch (e) {
    return [];
  }
}

// ── UI rendering ──────────────────────────────────────────────────────

function renderAuthScreen() {
  document.getElementById("app").innerHTML = `
    <div class="auth-container">
      <div class="auth-logo">
        <span class="fraud">Fraud</span><span class="shield">Shield</span>
        <span class="version">v4.1</span>
      </div>
      <div class="auth-subtitle">AI-powered fraud &amp; phishing detection</div>

      <div class="auth-tabs">
        <button class="auth-tab active" id="tabLogin">Login</button>
        <button class="auth-tab" id="tabSignup">Sign Up</button>
      </div>

      <div class="auth-form">
        <div id="authError" class="auth-error" style="display:none"></div>
        <input class="auth-input" id="authEmail"    type="email"    placeholder="Email address" autocomplete="email"/>
        <input class="auth-input" id="authPassword" type="password" placeholder="Password" autocomplete="current-password"/>
        <button class="auth-btn" id="authSubmitBtn">Login</button>
      </div>

      <div class="auth-footer">🔒 Your data is encrypted &amp; private</div>
    </div>`;

  let mode = "login";

  document.getElementById("tabLogin").addEventListener("click", () => {
    mode = "login";
    document.getElementById("tabLogin").classList.add("active");
    document.getElementById("tabSignup").classList.remove("active");
    document.getElementById("authSubmitBtn").textContent = "Login";
    document.getElementById("authError").style.display = "none";
  });

  document.getElementById("tabSignup").addEventListener("click", () => {
    mode = "signup";
    document.getElementById("tabSignup").classList.add("active");
    document.getElementById("tabLogin").classList.remove("active");
    document.getElementById("authSubmitBtn").textContent = "Create Account";
    document.getElementById("authError").style.display = "none";
  });

  document.getElementById("authSubmitBtn").addEventListener("click", async () => {
    const email    = document.getElementById("authEmail").value.trim();
    const password = document.getElementById("authPassword").value;
    const errEl    = document.getElementById("authError");
    const btn      = document.getElementById("authSubmitBtn");

    errEl.style.display = "none";
    if (!email || !password) {
      errEl.style.color = "#ff3d5a";
      errEl.textContent = "Please enter your email and password.";
      errEl.style.display = "block";
      return;
    }

    btn.disabled = true;
    btn.textContent = mode === "login" ? "Logging in…" : "Creating account…";

    try {
      if (mode === "signup") {
        await signUp(email, password);
        errEl.style.color = "#00d4aa";
        errEl.textContent = "Account created! Check your email to confirm, then log in.";
        errEl.style.display = "block";
        btn.disabled = false;
        btn.textContent = "Create Account";
      } else {
        const data = await signIn(email, password);
        renderMainApp(data.user);
      }
    } catch (err) {
      errEl.style.color = "#ff3d5a";
      errEl.textContent = err.message || "Authentication failed.";
      errEl.style.display = "block";
      btn.disabled = false;
      btn.textContent = mode === "login" ? "Login" : "Create Account";
    }
  });
}

function renderMainApp(user) {
  const email = user?.email || "";
  document.getElementById("app").innerHTML = `
    <div class="header">
      <div class="logo">
        <span class="fraud">Fraud</span><span class="shield">Shield</span>
        <span class="badge">v4.1 AI</span>
      </div>
    </div>

    <div class="user-bar">
      <span class="user-email">${email}</span>
      <button class="signout-btn" id="signoutBtn">Sign Out</button>
    </div>

    <div class="url-bar" id="urlDisplay">Loading…</div>

    <div id="content">
      <div class="loading"><div class="spinner"></div>Analyzing with AI…</div>
    </div>

    <div class="scan-time-bar">
      <span>Last scan: <span id="scanTime">—</span></span>
      <span>FraudShield AI</span>
    </div>

    <div class="action-bar">
      <button class="scan-btn" id="scanBtn">🔍 SCAN THIS PAGE</button>
    </div>

    <div id="historyTableSection" class="history-table-section"></div>

    <div class="export-bar">
      <button class="export-btn" id="exportCSVBtn">⬇ Export CSV</button>
      <button class="export-btn" id="exportPDFBtn">⬇ Export PDF</button>
    </div>`;

  document.getElementById("signoutBtn").addEventListener("click", async () => {
    await signOut();
    renderAuthScreen();
  });

  // All DOM elements exist — hand off to popup.js
  window.initMainApp();
}

// ── Bootstrap ─────────────────────────────────────────────────────────

document.addEventListener("DOMContentLoaded", async () => {
  let session = await getSession();
  if (!session) {
    const refreshed = await refreshSession();
    if (refreshed) session = await getSession();
  }
  if (session) {
    renderMainApp(session.user);
  } else {
    renderAuthScreen();
  }
});