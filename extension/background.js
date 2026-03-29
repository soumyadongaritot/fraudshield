// FraudShield v3.1 — Background Service Worker
// Handles: notifications, auto-CSV, badge updates

const API_URL = "https://fraudshield-1-pkvb.onrender.com";

// ── Badge ──────────────────────────────────────────────
function getBadgeColor(score) {
  if (score >= 85) return "#00ff88";
  if (score >= 65) return "#ffcc00";
  if (score >= 45) return "#ff8800";
  return "#ff4444";
}

// ── Desktop notification ───────────────────────────────
function sendNotification(result, url) {
  const score    = result.safety_score;
  const domain   = result.domain_info?.domain || new URL(url).hostname;
  const category = result.category;

  let title, message, iconColor;

  if (score < 25) {
    title   = "🔴 MALICIOUS PAGE DETECTED";
    message = `${domain} is DANGEROUS! Do not enter any information.`;
  } else if (score < 45) {
    title   = "🚨 Likely Phishing Detected";
    message = `${domain} looks like a phishing site! (Score: ${score}/100)`;
  } else if (score < 65) {
    title   = "⚠️ Suspicious Page";
    message = `${domain} has risk factors. Proceed with caution. (Score: ${score}/100)`;
  } else {
    title   = "⚡ Low-Medium Risk Page";
    message = `${domain} appears mostly safe but has some signals. (Score: ${score}/100)`;
  }

  chrome.notifications.create({
    type:     "basic",
    iconUrl:  "icons/icon128.png",
    title:    title,
    message:  message,
    priority: score < 45 ? 2 : 1
  });
}

// ── Auto-save CSV ──────────────────────────────────────
function autoSaveCSV(entry) {
  chrome.storage.local.get("scanHistory", (result) => {
    const history = result.scanHistory || [];

    // Build full CSV from history
    const headers = ["URL","Safety Score","Category","Risk Level","Site Type","Domain","Protocol","Date & Time"];
    const rows = history.map(e => {
      const date = new Date(e.timestamp).toLocaleString();
      const safeUrl = `"${(e.url||"").replace(/"/g,'""')}"`;
      return [
        safeUrl,
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

    // Save to downloads folder silently
    chrome.downloads.download({
      url:      dataUrl,
      filename: "fraudshield-scans.csv",
      saveAs:   false,
      conflictAction: "overwrite"
    });
  });
}

// ── Listen for messages from content.js ───────────────
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {

  // Scan result from content script
  if (message.type === "SCAN_COMPLETE") {
    const { result, url, tabId } = message;
    const score = result.safety_score;

    // 1. Update badge
    if (tabId) {
      chrome.action.setBadgeText({
        text:  score < 85 ? "!" : "",
        tabId: tabId
      });
      chrome.action.setBadgeBackgroundColor({
        color: getBadgeColor(score),
        tabId: tabId
      });
    }

    // 2. Send desktop notification for all risky pages (score < 85)
    if (score < 85) {
      sendNotification(result, url);
    }

    // 3. Auto-save CSV
    autoSaveCSV({ url, score, result });

    sendResponse({ ok: true });
  }

  // Badge update only
  if (message.type === "UPDATE_BADGE") {
    const tabId = sender.tab?.id;
    if (!tabId) return;
    chrome.action.setBadgeText({
      text:  message.score < 85 ? "!" : "",
      tabId: tabId
    });
    chrome.action.setBadgeBackgroundColor({
      color: getBadgeColor(message.score),
      tabId: tabId
    });
  }
});

// ── Clear badge on navigation ──────────────────────────
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === "loading") {
    chrome.action.setBadgeText({ text: "", tabId });
    chrome.storage.local.remove(String(tabId));
  }
});