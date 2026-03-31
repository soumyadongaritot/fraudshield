// popup.js - FraudShield v3.1
const API_URL = "https://fraudshield-1-pkvb.onrender.com";
const MAX_RETRIES = 3;
const RETRY_DELAY_MS = 5000;

window.initMainApp = async function () {
  document.getElementById("scanBtn").addEventListener("click", requestScan);
  document.getElementById("historyBtn").addEventListener("click", () => {
    chrome.tabs.create({ url: chrome.runtime.getURL("history.html") });
  });
  document.getElementById("exportCSVBtn").addEventListener("click", () => {
    chrome.storage.local.get("scanHistory", (result) => exportCSV(result.scanHistory || []));
  });
  document.getElementById("exportPDFBtn").addEventListener("click", () => {
    chrome.storage.local.get("scanHistory", (result) => exportPDF(result.scanHistory || []));
  });

  const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
  const url = tabs[0]?.url || "";
  document.getElementById("urlDisplay").textContent = url || "No URL";

  if (url && !url.startsWith("chrome://") && !url.startsWith("chrome-extension://")) {
    requestScan();
  } else {
    showError("Navigate to a website first.");
  }
};
