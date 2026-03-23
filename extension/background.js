// background.js
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === "complete" && tab.url) {
    const url = tab.url;
    if (url.startsWith("chrome://") ||
        url.startsWith("chrome-extension://")) return;
    chrome.storage.local.remove(String(tabId));
  }
});