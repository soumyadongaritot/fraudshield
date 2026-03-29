// FraudShield v3.2 — Background Service Worker
// Handles: notifications, auto-CSV, badge updates

const API_URL = "https://fraudshield-2u9l.onrender.com";

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

  let title, message;

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
function autoSaveCSV() {
  chrome.storage.local.get("scanHistory", (result) => {
    const history = result.scanHistory || [];
    if (history.length === 0) return;

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

    const today = new Date().toISOString().split("T")[0];

    chrome.downloads.download({
      url:      dataUrl,
      filename: `fraudshield-${today}.csv`,
      saveAs:   false,
      conflictAction: "overwrite"
    }, (downloadId) => {
      if (chrome.runtime.lastError) {
        console.warn("CSV download error:", chrome.runtime.lastError.message);
      }
    });
  });
}

// ── Listen for messages from popup/content ─────────────
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {

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

    // 2. Send desktop notification for risky pages only
    if (score < 65) {
      sendNotification(result, url);
    }

    // 3. Auto-save CSV
    autoSaveCSV();

    sendResponse({ ok: true });
  }

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

  if (message.type === "EXPORT_CSV") {
    autoSaveCSV();
    sendResponse({ ok: true });
  }
});

// ── Clear badge on navigation ──────────────────────────
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === "loading") {
    chrome.action.setBadgeText({ text: "", tabId });
    chrome.storage.local.remove(String(tabId));
  }
});