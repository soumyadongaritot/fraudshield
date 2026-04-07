// background.js - FraudShield v4.2
const API_URL = "https://fraudshield-1-pkvb.onrender.com";

// ── FIX 3: Badge update listener ──────────────────────────────────────
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg.type === "UPDATE_BADGE") {
    const score = msg.score ?? 50;
    const color =
      score >= 85 ? "#00ff88" :
      score >= 65 ? "#00d4aa" :
      score >= 45 ? "#ffd600" :
      score >= 25 ? "#ff8800" : "#ff3d5a";

    chrome.action.setBadgeText({ text: String(score) });
    chrome.action.setBadgeBackgroundColor({ color });
  }

  // ── FIX 4: Proactive warning from content script ──────────────────
  if (msg.type === "PROACTIVE_SCAN") {
    const { url } = msg;
    const tabId = sender?.tab?.id;
    fetch(`${API_URL}/check`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url })
    })
    .then(r => r.json())
    .then(data => {
      const score = data.safety_score ?? 50;

      // Update badge
      const color =
        score >= 85 ? "#00ff88" :
        score >= 65 ? "#00d4aa" :
        score >= 45 ? "#ffd600" :
        score >= 25 ? "#ff8800" : "#ff3d5a";
      chrome.action.setBadgeText({ text: String(score), tabId });
      chrome.action.setBadgeBackgroundColor({ color, tabId });

      // Show notification only for dangerous sites (score < 45)
      if (score < 45) {
        const riskLabel =
          score >= 25 ? "⚠️ LIKELY PHISHING" : "🔴 MALICIOUS SITE";

        chrome.notifications.create({
          type: "basic",
          iconUrl: "icons/icon128.png",
          title: `FraudShield Warning — ${riskLabel}`,
          message: `This site scored ${score}/100. Do NOT enter personal information here.\n${url}`,
          priority: 2
        });
      }

      // Save to history
      chrome.storage.local.get("scanHistory", (result) => {
        const history = result.scanHistory || [];
        const now = Date.now();
        const recentDupe = history.find(h =>
          h.url === url && (now - new Date(h.timestamp).getTime()) < 60000
        );
        if (!recentDupe) {
          history.push({
            url,
            score: data.safety_score,
            category: data.category,
            risk: data.risk_level,
            site_type: data.domain_info?.site_type ?? "Unknown",
            domain: data.domain_info?.domain ?? "",
            protocol: data.domain_info?.protocol ?? "",
            timestamp: new Date().toISOString()
          });
          if (history.length > 200) history.shift();
          chrome.storage.local.set({ scanHistory: history });
        }
      });
    })
    .catch(() => {
      // Backend asleep — set grey badge, no warning
      chrome.action.setBadgeText({ text: "...", tabId });
      chrome.action.setBadgeBackgroundColor({ color: "#3a4a5c", tabId });
    });
  }
});

// Clear badge when tab navigates away
chrome.tabs.onUpdated.addListener((tabId, changeInfo) => {
  if (changeInfo.status === "loading") {
    chrome.action.setBadgeText({ text: "", tabId });
  }
});