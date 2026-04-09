// ════════════════════════════════════════════
//  FraudShield — background.js  (v4.2)
//  Backend: https://fraudshield-1-pkvb.onrender.com
// ════════════════════════════════════════════

const API_URL = "https://fraudshield-1-pkvb.onrender.com/predict";

// ── Dedup cache: url → timestamp of last scan ──────────────────────────────
const recentScans = {};

// ── Default settings ────────────────────────────────────────────────────────
const DEFAULT_SETTINGS = {
  proactive:     true,
  dedupSec:      60,
  httpsOnly:     false,
  dangerThresh:  45,
  notifications: true,
  badge:         true,
  sound:         false,
};

// ════════════════════════════════════════════
//  VERDICT HELPER
// ════════════════════════════════════════════
function getVerdict(score) {
  if (score >= 85) return { label: "Safe",          color: "#00d4aa" };
  if (score >= 65) return { label: "Probably safe", color: "#00d4aa" };
  if (score >= 45) return { label: "Suspicious",    color: "#f59e0b" };
  return               { label: "Dangerous",      color: "#ff4d6d" };
}

function getVerdictCls(score) {
  if (score >= 65) return "safe";
  if (score >= 45) return "warn";
  return "danger";
}

// ════════════════════════════════════════════
//  BADGE
// ════════════════════════════════════════════
function setBadge(tabId, score, settings) {
  if (!settings.badge) {
    chrome.action.setBadgeText({ text: "", tabId });
    return;
  }
  const text  = String(score);
  const color = score >= 65 ? "#00d4aa" : score >= 45 ? "#f59e0b" : "#ff4d6d";
  chrome.action.setBadgeText({ text, tabId });
  chrome.action.setBadgeBackgroundColor({ color, tabId });
}

// ════════════════════════════════════════════
//  NOTIFICATION
// ════════════════════════════════════════════
function showNotification(url, score, label) {
  chrome.notifications.create("fs-" + Date.now(), {
    type:     "basic",
    iconUrl:  "icons/icon48.png",
    title:    "⚠️ FraudShield — " + label,
    message:  "Score: " + score + "/100\n" + url,
    priority: 2,
  });
}

// ════════════════════════════════════════════
//  CORE SCAN
// ════════════════════════════════════════════
async function scanURL(url, tabId, source) {
  source = source || "manual";

  // Load settings
  const stored   = await chrome.storage.sync.get("fs_settings");
  const settings = Object.assign({}, DEFAULT_SETTINGS, stored.fs_settings || {});

  // HTTPS only filter
  if (settings.httpsOnly && !url.startsWith("https://")) return null;

  // Dedup check
  const now     = Date.now();
  const dedupMs = settings.dedupSec * 1000;
  if (recentScans[url] && now - recentScans[url] < dedupMs) {
    console.log("[FraudShield] Dedup skip:", url);
    return null;
  }
  recentScans[url] = now;

  // Check allow / block lists
  const listsData = await chrome.storage.sync.get(["fs_allowlist", "fs_blocklist"]);
  const allowList = listsData.fs_allowlist || [];
  const blockList = listsData.fs_blocklist || [];

  let domain = "";
  try { domain = new URL(url).hostname; } catch (e) {}

  if (allowList.some(item => url.includes(item.url) || domain.includes(item.url))) {
    setBadge(tabId, 100, settings);
    console.log("[FraudShield] Allowlisted:", url);
    return { url, score: 100, label: "Safe (allowlisted)" };
  }

  if (blockList.some(item => url.includes(item.url) || domain.includes(item.url))) {
    setBadge(tabId, 0, settings);
    if (settings.notifications) showNotification(url, 0, "Blocked");
    console.log("[FraudShield] Blocklisted:", url);
    return { url, score: 0, label: "Dangerous (blocklisted)" };
  }

  // ── Call ML backend ────────────────────────────────────────────────────
  let score = 50;
  try {
    const resp = await fetch(API_URL, {
      method:  "POST",
      headers: { "Content-Type": "application/json" },
      body:    JSON.stringify({ url: url }),
    });

    if (resp.ok) {
      const data = await resp.json();

      // Handle both response formats your Flask app might return:
      // { "score": 87 }  OR  { "phishing_score": 87 }  OR  { "prediction": 0.87 }
      if (typeof data.score === "number") {
        score = Math.round(data.score);
      } else if (typeof data.phishing_score === "number") {
        score = Math.round(data.phishing_score);
      } else if (typeof data.prediction === "number") {
        // If prediction is 0-1 probability, convert to 0-100
        score = data.prediction <= 1
          ? Math.round((1 - data.prediction) * 100)  // 1=phishing → score=0
          : Math.round(data.prediction);
      } else if (typeof data.probability === "number") {
        score = Math.round((1 - data.probability) * 100);
      }
    } else {
      console.warn("[FraudShield] API error status:", resp.status);
    }
  } catch (err) {
    console.warn("[FraudShield] API fetch failed:", err.message);
  }

  // Clamp score to 0-100
  score = Math.max(0, Math.min(100, score));

  const verdict = getVerdict(score);

  // Set badge on extension icon
  setBadge(tabId, score, settings);

  // Proactive notification for dangerous sites
  if (source === "proactive" && score < settings.dangerThresh && settings.notifications) {
    showNotification(url, score, verdict.label);
  }

  // ── Save to history ────────────────────────────────────────────────────
  const histData = await chrome.storage.sync.get("fs_history");
  const history  = histData.fs_history || [];

  // Dedup: don't save same URL within dedup window
  const alreadySaved = history.find(
    h => h.url === url && now - (h.ts || 0) < dedupMs
  );

  if (!alreadySaved) {
    history.unshift({
      url:   url,
      score: score,
      label: verdict.label,
      cls:   getVerdictCls(score),
      time:  new Date().toLocaleString("en-GB", {
        day: "2-digit", month: "short",
        hour: "2-digit", minute: "2-digit",
      }),
      ts: now,
    });

    // Cap at 500 entries
    if (history.length > 500) history.length = 500;
    await chrome.storage.sync.set({ fs_history: history });
  }

  // Notify popup if it's open
  chrome.runtime.sendMessage({
    type:  "SCAN_COMPLETE",
    url:   url,
    score: score,
    label: verdict.label,
    tabId: tabId,
  }).catch(function() {}); // ignore error if popup is closed

  return { url: url, score: score, label: verdict.label };
}

// ════════════════════════════════════════════
//  PROACTIVE SCAN on every page load
// ════════════════════════════════════════════
chrome.tabs.onUpdated.addListener(async function(tabId, changeInfo, tab) {
  if (changeInfo.status !== "complete") return;
  if (!tab.url || !tab.url.startsWith("http")) return;

  const stored   = await chrome.storage.sync.get("fs_settings");
  const settings = Object.assign({}, DEFAULT_SETTINGS, stored.fs_settings || {});
  if (!settings.proactive) return;

  scanURL(tab.url, tabId, "proactive");
});

// ════════════════════════════════════════════
//  MESSAGE HANDLER — from popup.js
// ════════════════════════════════════════════
chrome.runtime.onMessage.addListener(function(msg, sender, sendResponse) {

  if (msg.type === "SCAN_URL") {
    const tabId = msg.tabId || (sender.tab && sender.tab.id) || 0;
    scanURL(msg.url, tabId, "manual")
      .then(function(result) {
        sendResponse({ success: true, result: result });
      })
      .catch(function(err) {
        sendResponse({ success: false, error: String(err) });
      });
    return true; // keep channel open for async
  }

  if (msg.type === "GET_HISTORY") {
    chrome.storage.sync.get("fs_history").then(function(data) {
      sendResponse({ history: data.fs_history || [] });
    });
    return true;
  }

  if (msg.type === "CLEAR_HISTORY") {
    chrome.storage.sync.set({ fs_history: [] }).then(function() {
      sendResponse({ success: true });
    });
    return true;
  }

  if (msg.type === "SAVE_SETTINGS") {
    chrome.storage.sync.set({ fs_settings: msg.settings }).then(function() {
      sendResponse({ success: true });
    });
    return true;
  }

  if (msg.type === "ADD_TO_LIST") {
    const key = msg.listType === "allow" ? "fs_allowlist" : "fs_blocklist";
    chrome.storage.sync.get(key).then(function(data) {
      const list = data[key] || [];
      if (!list.find(function(x) { return x.url === msg.url; })) {
        list.unshift({
          url:   msg.url,
          added: new Date().toLocaleString("en-GB", {
            day: "2-digit", month: "short",
            hour: "2-digit", minute: "2-digit",
          }),
        });
      }
      chrome.storage.sync.set({ [key]: list }).then(function() {
        sendResponse({ success: true });
      });
    });
    return true;
  }

  if (msg.type === "REMOVE_FROM_LIST") {
    const key = msg.listType === "allow" ? "fs_allowlist" : "fs_blocklist";
    chrome.storage.sync.get(key).then(function(data) {
      const list = (data[key] || []).filter(function(x) { return x.url !== msg.url; });
      chrome.storage.sync.set({ [key]: list }).then(function() {
        sendResponse({ success: true });
      });
    });
    return true;
  }

  if (msg.type === "SUBMIT_REPORT") {
    chrome.storage.sync.get("fs_reports").then(function(data) {
      const reports = data.fs_reports || [];
      reports.unshift({
        url:    msg.url,
        notes:  msg.notes,
        time:   new Date().toLocaleString("en-GB", {
          day: "2-digit", month: "short",
          hour: "2-digit", minute: "2-digit",
        }),
        status: "pending",
      });
      chrome.storage.sync.set({ fs_reports: reports }).then(function() {
        sendResponse({ success: true });
      });
    });
    return true;
  }

});