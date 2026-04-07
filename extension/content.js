// content.js - FraudShield v4.2
// Proactive scan: fires when user lands on any page
// Only scans http/https pages, skips chrome:// and extensions

(function () {
  const url = window.location.href;
  if (!url.startsWith("http://") && !url.startsWith("https://")) return;

  // Small delay so page starts loading first
  setTimeout(() => {
    chrome.runtime.sendMessage({
      type: "PROACTIVE_SCAN",
      url,
      tabId: null // background fills this in via sender.tab.id
    });
  }, 1500);
})();