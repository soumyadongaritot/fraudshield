// content.js
chrome.runtime.onMessage.addListener((message) => {
  if (message.action === "showWarning") {
    showBanner(message.data);
  }
});

function showBanner(data) {
  const existing = document.getElementById("fraudshield-banner");
  if (existing) existing.remove();

  const score = data.safety_score;
  const color = score < 40 ? "#ff2d2d"
              : score < 70 ? "#ff9800"
              : "#4caf50";
  const label = score < 40 ? "DANGEROUS"
              : score < 70 ? "SUSPICIOUS"
              : "SAFE";

  const banner = document.createElement("div");
  banner.id    = "fraudshield-banner";

  const inner  = document.createElement("div");
  inner.style.cssText = `
    position:fixed; top:0; left:0; right:0;
    z-index:2147483647; background:${color};
    color:white; font-family:Segoe UI,sans-serif;
    font-size:14px; font-weight:600;
    padding:12px 20px; display:flex;
    align-items:center; justify-content:space-between;
    box-shadow:0 4px 20px rgba(0,0,0,0.4);
  `;

  const text       = document.createElement("span");
  text.textContent = `FraudShield: ${label} — Score: ${score}/100`;

  const close       = document.createElement("span");
  close.textContent = "✕";
  close.style.cssText = "cursor:pointer;font-size:18px;padding:0 8px;";
  close.addEventListener("click", () => banner.remove());

  inner.appendChild(text);
  inner.appendChild(close);
  banner.appendChild(inner);
  document.documentElement.prepend(banner);
}