// history.js - FraudShield v3.0
let allHistory    = [];
let currentFilter = "all";

document.addEventListener("DOMContentLoaded", () => {
  loadHistory();

  document.getElementById("clearBtn")
    .addEventListener("click", clearHistory);

  document.getElementById("searchInput")
    .addEventListener("input", renderHistory);

  document.querySelectorAll(".filter-btn").forEach(btn => {
    btn.addEventListener("click", () => {
      document.querySelectorAll(".filter-btn")
        .forEach(b => b.classList.remove("active"));
      btn.classList.add("active");
      currentFilter = btn.dataset.filter;
      renderHistory();
    });
  });
});

function loadHistory() {
  chrome.storage.sync.get("fs_history", (result) => {
    allHistory = result.fs_history || [];
    updateStats();
    renderHistory();
  });
}

// Listen for live updates from background scan
chrome.runtime.onMessage.addListener((msg) => {
  if (msg.type === "SCAN_COMPLETE") loadHistory();
});

function updateStats() {
  const total  = allHistory.length;
  const safe   = allHistory.filter(h => h.score >= 85).length;
  const susp   = allHistory.filter(
    h => h.score >= 45 && h.score < 65).length;
  const danger = allHistory.filter(h => h.score < 45).length;

  document.getElementById("totalCount").textContent  = total;
  document.getElementById("safeCount").textContent   = safe;
  document.getElementById("suspCount").textContent   = susp;
  document.getElementById("dangerCount").textContent = danger;
}

function renderHistory() {
  const search = document.getElementById("searchInput")
    .value.toLowerCase();

  let filtered = allHistory.filter(item => {
    const matchSearch = item.url.toLowerCase().includes(search);
    const s = item.score;
    const matchFilter =
      currentFilter === "all"        ? true :
      currentFilter === "safe"       ? s >= 85 :
      currentFilter === "probably"   ? (s >= 65 && s < 85) :
      currentFilter === "suspicious" ? (s >= 45 && s < 65) :
      currentFilter === "phishing"   ? (s >= 25 && s < 45) :
      currentFilter === "malicious"  ? s < 25 : true;
    return matchSearch && matchFilter;
  });

  const list = document.getElementById("historyList");

  if (filtered.length === 0) {
    list.innerHTML = `
      <div class="empty-state">
        <div class="empty-icon">🔍</div>
        <div class="empty-text">No results found.</div>
      </div>`;
    return;
  }

  list.innerHTML = filtered.slice().reverse().map(item => {
    const s = item.score;
    const color =
      s >= 85 ? "#00ff88" :
      s >= 65 ? "#00d4aa" :
      s >= 45 ? "#ffd600" :
      s >= 25 ? "#ff8800" : "#ff3d5a";

    const statusLabel =
      s >= 85 ? "✅ SAFE" :
      s >= 65 ? "✅ PROBABLY SAFE" :
      s >= 45 ? "⚠️ SUSPICIOUS" :
      s >= 25 ? "🚨 PHISHING" : "🔴 MALICIOUS";

    const statusStyle =
      s >= 85 ? "background:#00ff8815;color:#00ff88;border:1px solid #00ff8830" :
      s >= 65 ? "background:#00d4aa15;color:#00d4aa;border:1px solid #00d4aa30" :
      s >= 45 ? "background:#ffd60015;color:#ffd600;border:1px solid #ffd60030" :
      s >= 25 ? "background:#ff880015;color:#ff8800;border:1px solid #ff880030" :
               "background:#ff3d5a15;color:#ff3d5a;border:1px solid #ff3d5a30";

    const time = new Date(item.timestamp).toLocaleString();

    return `
      <div class="history-item">
        <div class="score-badge"
          style="color:${color};border-color:${color};
                 background:${color}15">
          ${item.score}
        </div>
        <div class="item-info">
          <div class="item-url" title="${item.url}">
            ${item.url}
          </div>
          <div class="item-meta">
            <span class="item-status"
                  style="${statusStyle}">
              ${statusLabel}
            </span>
            <span class="item-type">
              ${item.site_type ?? ""}
            </span>
            <span class="item-risk">
              ${item.risk ?? ""}
            </span>
            <span class="item-time">${time}</span>
          </div>
        </div>
      </div>`;
  }).join("");
}

function clearHistory() {
  if (confirm("Clear all scan history?")) {
    chrome.storage.sync.remove("fs_history", () => {
      allHistory = [];
      updateStats();
      renderHistory();
    });
  }
}