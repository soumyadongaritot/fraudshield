// FraudShield v4.0 — Background Service Worker

const API_URL = "https://fraudshield-1-pkvb.onrender.com/check";

function getBadgeColor(score) {
  if (score >= 85) return "#00ff88";
  if (score >= 65) return "#ffcc00";
  if (score >= 45) return "#ff8800";
  return "#ff4444";
}

function sendNotification(result, url) {
  const score  = result.safety_score;
  const domain = result.domain_info?.domain || new URL(url).hostname;
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
    return;
  }

  chrome.notifications.create({
    type:     "basic",
    iconUrl:  "icons/icon128.png",
    title:    title,
    message:  message,
    priority: score < 45 ? 2 : 1
  });
}

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {

  if (message.type === "SCAN_COMPLETE") {
    const { result, url, tabId } = message;
    const score = result.safety_score;

    if (tabId) {
      chrome.action.setBadgeText({ text: score < 85 ? "!" : "", tabId });
      chrome.action.setBadgeBackgroundColor({ color: getBadgeColor(score), tabId });
    }

    if (score < 65) sendNotification(result, url);
    sendResponse({ ok: true });
  }

  if (message.type === "UPDATE_BADGE") {
    const tabId = sender.tab?.id;
    if (!tabId) return;
    chrome.action.setBadgeText({ text: message.score < 85 ? "!" : "", tabId });
    chrome.action.setBadgeBackgroundColor({ color: getBadgeColor(message.score), tabId });
  }

  if (message.type === "DOWNLOAD_CSV") {
    chrome.downloads.download({
      url:            message.url,
      filename:       message.filename || "fraudshield-scans.csv",
      saveAs:         false,
      conflictAction: "overwrite"
    }, (downloadId) => {
      if (chrome.runtime.lastError) {
        console.warn("CSV download error:", chrome.runtime.lastError.message);
      }
    });
    sendResponse({ ok: true });
  }

  return true;
});

chrome.tabs.onUpdated.addListener((tabId, changeInfo) => {
  if (changeInfo.status === "loading") {
    chrome.action.setBadgeText({ text: "", tabId });
    chrome.storage.local.remove(String(tabId));
  }
});