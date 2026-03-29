// FraudShield v3.0 — Content Script
const BACKEND_URL = "https://fraudshield-1-pkvb.onrender.com";
const BLOCK_THRESHOLD = 45;
let warningInjected = false;

function saveToHistory(url, result) {
  chrome.storage.local.get(["scanHistory"], data => {
    const history = data.scanHistory || [];
    history.unshift({
      url, score: result.safety_score, category: result.category,
      risk: result.risk_level, site_type: result.domain_info?.site_type ?? "Unknown",
      domain: result.domain_info?.domain ?? "", protocol: result.domain_info?.protocol ?? "",
      timestamp: new Date().toISOString()
    });
    if (history.length > 200) history.splice(200);
    chrome.storage.local.set({ scanHistory: history });
  });
}

function injectWarningScreen(result) {
  if (warningInjected) return;
  warningInjected = true;
  const score = result.safety_score;
  const category = result.category;
  const flags = result.flags || [];
  const domain = result.domain_info?.domain || window.location.hostname;
  const flagsHTML = flags.filter(f => f.severity === "high" || f.severity === "medium").slice(0, 4).map(f => `<li>${f.message}</li>`).join("");
  const overlay = document.createElement("div");
  overlay.id = "fraudshield-warning-overlay";
  overlay.innerHTML = `
    <div class="fs-overlay-bg"></div>
    <div class="fs-warning-box">
      <div class="fs-warning-header"><div class="fs-shield-icon">🛡️</div><div><span class="fs-brand">FraudShield</span><span class="fs-version">v3.0 AI</span></div></div>
      <div class="fs-danger-badge">⚠️ DANGEROUS PAGE BLOCKED</div>
      <div class="fs-score-row">
        <div class="fs-score-circle">
          <svg viewBox="0 0 100 100"><circle cx="50" cy="50" r="40" fill="none" stroke="#ff000033" stroke-width="8"/><circle cx="50" cy="50" r="40" fill="none" stroke="#ff4444" stroke-width="8" stroke-dasharray="${score * 2.51} 251" stroke-dashoffset="62.8" stroke-linecap="round"/></svg>
          <div class="fs-score-num">${score}</div><div class="fs-score-label">/100</div>
        </div>
        <div class="fs-score-info"><div class="fs-category">${category}</div><div class="fs-risk">${result.risk_level}</div><div class="fs-domain">${domain}</div></div>
      </div>
      ${flagsHTML ? `<div class="fs-flags"><div class="fs-flags-title">Threats detected:</div><ul>${flagsHTML}</ul></div>` : ""}
      <div class="fs-warning-text">This page has been identified as potentially dangerous. Proceeding may expose you to phishing, scams, or malware.</div>
      <div class="fs-buttons">
        <button class="fs-btn-back" onclick="history.back()">← Go Back (Safe)</button>
        <button class="fs-btn-proceed" onclick="document.getElementById('fraudshield-warning-overlay').remove()">Proceed Anyway (Risk)</button>
      </div>
      <div class="fs-footer">FraudShield v3.0 — AI Fraud Detection</div>
    </div>`;
  const style = document.createElement("style");
  style.textContent = `
    #fraudshield-warning-overlay{position:fixed;inset:0;z-index:2147483647;display:flex;align-items:center;justify-content:center;font-family:'Segoe UI',system-ui,sans-serif;animation:fs-fadein 0.3s ease}
    @keyframes fs-fadein{from{opacity:0}to{opacity:1}}
    .fs-overlay-bg{position:absolute;inset:0;background:rgba(0,0,0,0.92);backdrop-filter:blur(4px)}
    .fs-warning-box{position:relative;background:#0d0d0d;border:1px solid #ff444466;border-radius:16px;padding:32px;max-width:480px;width:90%;box-shadow:0 0 60px #ff000033;animation:fs-slidein 0.3s ease}
    @keyframes fs-slidein{from{transform:translateY(-20px);opacity:0}to{transform:translateY(0);opacity:1}}
    .fs-warning-header{display:flex;align-items:center;gap:12px;margin-bottom:20px}
    .fs-shield-icon{font-size:28px}.fs-brand{color:#00ff88;font-weight:700;font-size:18px}.fs-version{color:#00ff8877;font-size:12px;margin-left:8px}
    .fs-danger-badge{background:#ff000022;border:1px solid #ff4444;color:#ff6666;font-size:13px;font-weight:700;letter-spacing:2px;padding:8px 16px;border-radius:6px;text-align:center;margin-bottom:24px;animation:fs-pulse 2s infinite}
    @keyframes fs-pulse{0%,100%{opacity:1}50%{opacity:0.7}}
    .fs-score-row{display:flex;align-items:center;gap:20px;margin-bottom:20px}
    .fs-score-circle{position:relative;width:80px;height:80px;flex-shrink:0}
    .fs-score-circle svg{width:80px;height:80px;transform:rotate(-90deg)}
    .fs-score-num{position:absolute;inset:0;display:flex;align-items:center;justify-content:center;font-size:22px;font-weight:700;color:#ff4444}
    .fs-score-label{position:absolute;bottom:8px;right:8px;font-size:10px;color:#ff444477}
    .fs-category{color:#ff4444;font-size:18px;font-weight:700}.fs-risk{color:#ff666688;font-size:12px;letter-spacing:1px;margin:4px 0}.fs-domain{color:#ffffff66;font-size:13px;word-break:break-all}
    .fs-flags{background:#ff000011;border:1px solid #ff444433;border-radius:8px;padding:12px 16px;margin-bottom:16px}
    .fs-flags-title{color:#ff6666;font-size:12px;font-weight:600;margin-bottom:8px}
    .fs-flags ul{margin:0;padding-left:4px;list-style:none}.fs-flags li{color:#ffcccc;font-size:13px;padding:3px 0}
    .fs-warning-text{color:#ffffff55;font-size:13px;line-height:1.6;margin-bottom:24px;text-align:center}
    .fs-buttons{display:flex;gap:12px}
    .fs-btn-back{flex:1;padding:12px;background:#00ff8822;border:1px solid #00ff88;color:#00ff88;border-radius:8px;font-size:14px;font-weight:600;cursor:pointer}
    .fs-btn-proceed{flex:1;padding:12px;background:transparent;border:1px solid #ffffff22;color:#ffffff44;border-radius:8px;font-size:13px;cursor:pointer}
    .fs-footer{text-align:center;color:#ffffff22;font-size:11px;margin-top:20px}`;
  document.head.appendChild(style);
  document.body.appendChild(overlay);
}

async function autoScan() {
  try {
    const url = window.location.href;
    if (url.startsWith("chrome://") || url.startsWith("chrome-extension://") || url.startsWith("about:") || url.startsWith("file://")) return;
    const response = await fetch(`${BACKEND_URL}/check`, {
      method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ url })
    });
    if (!response.ok) return;
    const result = await response.json();
    saveToHistory(url, result);
    chrome.runtime.sendMessage({ type: "UPDATE_BADGE", score: result.safety_score });
    if (result.safety_score < BLOCK_THRESHOLD) injectWarningScreen(result);
  } catch (err) {
    console.debug("FraudShield scan skipped:", err.message);
  }
}

if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", autoScan);
} else {
  autoScan();
}
