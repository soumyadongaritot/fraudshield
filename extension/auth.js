// auth.js - FraudShield Supabase Auth Helper
const SUPABASE_URL = "https://bgfztnukkgcakeogpvdi.supabase.co";
const SUPABASE_KEY = "sb_publishable_w9J9v84ef_Ag0Igc8jJkxw_f0YJYJ5c";

const AUTH_URL  = `${SUPABASE_URL}/auth/v1`;
const DB_URL    = `${SUPABASE_URL}/rest/v1`;

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
  // Save session
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