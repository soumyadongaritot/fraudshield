// FraudShield background.js v4.5
// Fix 1: 3-layer WHOIS fallback (who-dat → rdap → age estimation)
// Fix 2: OPEN_DASHBOARD handler
// Fix 3: PING handler to wake service worker

const CONFIG = {
  VT_API_KEY:      "90824c5af9f1358e7a0a393809410e281d2151d8751597254dd628885f2e5a4c",
  BACKEND_URL:     "https://fraudshield-1-pkvb.onrender.com/predict",
  BACKEND_TIMEOUT: 15000,
  VT_TIMEOUT:      10000,
  WHOIS_TIMEOUT:   6000,
};

// ── Helpers ───────────────────────────────────────────────────────────────────
function fetchWithTimeout(url, options, ms) {
  return new Promise((resolve, reject) => {
    const t = setTimeout(() => reject(new Error("TIMEOUT")), ms);
    fetch(url, options)
      .then(r  => { clearTimeout(t); resolve(r); })
      .catch(e => { clearTimeout(t); reject(e); });
  });
}

function getBadgeColor(score) {
  if (score >= 85) return "#3fb950";
  if (score >= 65) return "#d29922";
  if (score >= 45) return "#ff8800";
  return "#f85149";
}

function parseAgeFromDate(dateStr) {
  if (!dateStr) return null;
  const raw = Array.isArray(dateStr) ? dateStr[0] : dateStr;
  const created = new Date(raw);
  if (isNaN(created)) return null;

  const diffDays = Math.floor((Date.now() - created) / 86400000);
  const diffMos  = Math.floor(diffDays / 30);
  const diffYrs  = Math.floor(diffDays / 365);

  let ageLabel, ageSub, ageThreat;
  if      (diffDays < 30)  { ageLabel = diffDays + " days"; ageSub = "⚠️ Brand new domain";  ageThreat = "high"; }
  else if (diffMos  < 6)   { ageLabel = diffMos  + " mo";   ageSub = "⚠️ Very new domain";   ageThreat = "medium"; }
  else if (diffMos  < 12)  { ageLabel = diffMos  + " mo";   ageSub = "Est. " + created.getFullYear(); ageThreat = "low"; }
  else                     { ageLabel = diffYrs  + (diffYrs === 1 ? " yr" : " yrs"); ageSub = "Est. " + created.getFullYear(); ageThreat = "low"; }

  return { available: true, ageLabel, ageSub, ageThreat, diffDays, diffMos, diffYrs,
           created: created.toISOString().split("T")[0] };
}

// ── WHOIS — 3 layers of fallback ──────────────────────────────────────────────
async function checkWHOIS(hostname) {
  const apex = hostname.replace(/^www\./, "").split(".").slice(-2).join(".");

  // ── Layer 1: who-dat.as93.net ─────────────────────────────────────────────
  try {
    const r = await fetchWithTimeout(
      `https://who-dat.as93.net/${apex}`,
      { headers: { Accept: "application/json" } },
      CONFIG.WHOIS_TIMEOUT
    );
    if (r.ok) {
      const d = await r.json();
      const raw = d?.domain?.created_date || d?.registrar?.created_date ||
                  d?.created_date || d?.creation_date || (d?.domain?.dates||[])[0] || null;
      const result = parseAgeFromDate(raw);
      if (result) {
        result.registrar = d?.registrar?.name || d?.domain?.registrar || null;
        result.source = "who-dat";
        return result;
      }
    }
  } catch(e) { /* try next */ }

  // ── Layer 2: RDAP (IANA standard, works for most TLDs) ────────────────────
  try {
    const r = await fetchWithTimeout(
      `https://rdap.org/domain/${apex}`,
      { headers: { Accept: "application/json" } },
      CONFIG.WHOIS_TIMEOUT
    );
    if (r.ok) {
      const d = await r.json();
      // RDAP events array contains registration date
      const events = d?.events || [];
      const regEvent = events.find(e =>
        e.eventAction === "registration" || e.eventAction === "last changed"
      );
      const raw = regEvent?.eventDate || null;
      const result = parseAgeFromDate(raw);
      if (result) {
        // Get registrar from entities
        const registrarEntity = (d?.entities || []).find(e =>
          (e.roles || []).includes("registrar")
        );
        result.registrar = registrarEntity?.vcardArray?.[1]?.find(v => v[0]==="fn")?.[3] || null;
        result.source = "rdap";
        return result;
      }
    }
  } catch(e) { /* try next */ }

  // ── Layer 3: Estimate age from known domain registry dates ────────────────
  // For well-known domains we know the approximate age
  const knownAges = {
    "google.com":12927,"youtube.com":10499,"facebook.com":8029,"twitter.com":7043,
    "instagram.com":5113,"linkedin.com":8764,"netflix.com":10134,"amazon.com":10956,
    "microsoft.com":13514,"apple.com":12600,"github.com":5844,"reddit.com":6935,
    "wikipedia.org":8400,"stackoverflow.com":5840,"claude.ai":730,"anthropic.com":1460,
    "openai.com":2920,"cloudflare.com":5475,"stripe.com":4745,"paypal.com":9855,
    "spotify.com":5840,"notion.so":3285,"figma.com":3650,"vercel.com":2920,
    "slack.com":4015,"zoom.us":5110,"dropbox.com":5840,"adobe.com":12410
  };

  if (knownAges[apex]) {
    const diffDays = knownAges[apex];
    const result = parseAgeFromDate(
      new Date(Date.now() - diffDays * 86400000).toISOString()
    );
    if (result) { result.source = "estimated"; result.registrar = null; return result; }
  }

  return { available: false, reason: "All WHOIS lookups failed" };
}

// ── VirusTotal ────────────────────────────────────────────────────────────────
async function checkVirusTotal(url) {
  const key = CONFIG.VT_API_KEY;
  if (!key || key === "YOUR_VIRUSTOTAL_API_KEY") return { available: false, reason: "No API key" };

  try {
    const encoded = btoa(url).replace(/=/g,"").replace(/\+/g,"-").replace(/\//g,"_");
    const getResp = await fetchWithTimeout(
      `https://www.virustotal.com/api/v3/urls/${encoded}`,
      { headers: { "x-apikey": key } },
      CONFIG.VT_TIMEOUT
    );
    if (getResp.ok) {
      const d = await getResp.json();
      const stats = d?.data?.attributes?.last_analysis_stats;
      if (stats) {
        const malicious  = stats.malicious  || 0;
        const suspicious = stats.suspicious || 0;
        const total = Object.values(stats).reduce((a, b) => a + b, 0);
        return { available: true, malicious, suspicious, total,
                 label: malicious > 0 ? `${malicious}/${total} engines` : `0/${total} engines`,
                 status: malicious > 0 ? "threat" : suspicious > 0 ? "warn" : "clean" };
      }
    }
    // Submit for fresh scan
    const sub = await fetchWithTimeout(
      "https://www.virustotal.com/api/v3/urls",
      { method: "POST",
        headers: { "x-apikey": key, "Content-Type": "application/x-www-form-urlencoded" },
        body: "url=" + encodeURIComponent(url) },
      CONFIG.VT_TIMEOUT
    );
    if (!sub.ok) return { available: false, reason: "Submit failed" };
    const sd  = await sub.json();
    const id  = sd?.data?.id;
    if (!id) return { available: false, reason: "No analysis ID" };

    for (let i = 0; i < 3; i++) {
      await new Promise(r => setTimeout(r, 2000));
      const poll = await fetchWithTimeout(
        `https://www.virustotal.com/api/v3/analyses/${id}`,
        { headers: { "x-apikey": key } },
        CONFIG.VT_TIMEOUT
      );
      if (poll.ok) {
        const pd = await poll.json();
        const stats = pd?.data?.attributes?.stats;
        if (stats && pd?.data?.attributes?.status === "completed") {
          const malicious  = stats.malicious  || 0;
          const suspicious = stats.suspicious || 0;
          const total = Object.values(stats).reduce((a, b) => a + b, 0);
          return { available: true, malicious, suspicious, total,
                   label: malicious > 0 ? `${malicious}/${total} engines` : `0/${total} engines`,
                   status: malicious > 0 ? "threat" : suspicious > 0 ? "warn" : "clean" };
        }
      }
    }
    return { available: false, reason: "Scan pending" };
  } catch(e) {
    return { available: false, reason: e.message === "TIMEOUT" ? "Timeout" : "API error" };
  }
}

// ── Heuristic scorer ──────────────────────────────────────────────────────────
function heuristicScore(url) {
  const lo = url.toLowerCase();
  let score = 55, hostname = "", domain = "";
  try { const u = new URL(url); hostname = u.hostname; domain = hostname.replace(/^www\./, ""); } catch(e) { return 20; }

  const trusted = [
    "google.com","google.dev","google.co.in","googleapis.com","gstatic.com",
    "github.com","stackoverflow.com","amazon.com","amazon.in","microsoft.com",
    "apple.com","wikipedia.org","youtube.com","linkedin.com","netflix.com",
    "reddit.com","twitter.com","x.com","claude.ai","anthropic.com","openai.com",
    "mozilla.org","cloudflare.com","stripe.com","paypal.com","spotify.com",
    "notion.so","figma.com","vercel.com","railway.app","render.com",
    "instagram.com","facebook.com","whatsapp.com","zoom.us","slack.com",
    "dropbox.com","adobe.com","shopify.com","npmjs.com","pypi.org","docker.com"
  ];
  if (trusted.some(d => domain === d || domain.endsWith("." + d))) return 92;

  const knownBad = ["testsafebrowsing.appspot.com","malware.testing.google.test","phishing.test","eicar.org","wicar.org"];
  if (knownBad.some(d => hostname.includes(d))) return 4;

  if (!lo.startsWith("https://"))                                        score -= 20;
  if (/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(hostname))            score -= 35;
  if (hostname.split(".").length > 4)                                    score -= 15;
  if (hostname.length > 50)                                              score -= 10;
  if ((hostname.match(/-/g) || []).length > 3)                          score -= 10;
  [".xyz",".tk",".ml",".cf",".ga",".gq",".pw",".zip",".top",".click"].forEach(t => {
    if (hostname.endsWith(t)) score -= 22;
  });
  ["paypal","google","facebook","amazon","apple","microsoft","netflix",
   "instagram","twitter","bank","chase","irs"].forEach(b => {
    if (hostname.includes(b) && !hostname.endsWith(b+".com") &&
        !hostname.endsWith(b+".org") && !hostname.endsWith(b+".gov")) score -= 35;
  });
  const hits = ["login","signin","verify","account","update","secure","banking",
                "credential","password","confirm","suspend","recover"].filter(k => lo.includes(k));
  if (hits.length >= 3) score -= 25; else if (hits.length >= 2) score -= 15; else if (hits.length >= 1) score -= 5;
  if (/[а-яА-Я]/.test(url)) score -= 30;
  if ((url.match(/%/g)||[]).length > 5) score -= 15;
  if (url.length > 200) score -= 10;
  if (lo.startsWith("https://")) score += 10;
  if (hostname.endsWith(".gov"))  score += 20;
  if (hostname.endsWith(".edu"))  score += 15;

  return Math.max(3, Math.min(95, score));
}

function adjustForAge(base, whois) {
  if (!whois?.available) return base;
  let adj = base;
  if      (whois.diffDays < 7)  adj -= 40;
  else if (whois.diffDays < 30) adj -= 30;
  else if (whois.diffMos  < 3)  adj -= 20;
  else if (whois.diffMos  < 6)  adj -= 12;
  else if (whois.diffMos  < 12) adj -= 6;
  else if (whois.diffYrs  > 5)  adj += 5;
  return Math.max(3, Math.min(95, adj));
}

// ── Full scan pipeline ────────────────────────────────────────────────────────
async function fullScan(url) {
  let score = null, source = "api";
  let hostname = ""; try { hostname = new URL(url).hostname; } catch(e) {}

  // Allow / blocklist
  try {
    const data  = await chrome.storage.sync.get(["fs_allowlist","fs_blocklist"]);
    const allow = data.fs_allowlist || [], block = data.fs_blocklist || [];
    if      (allow.some(x => url.includes(x.url) || hostname.includes(x.url))) { score = 100; source = "allowlist"; }
    else if (block.some(x => url.includes(x.url) || hostname.includes(x.url))) { score = 0;   source = "blocklist"; }
  } catch(e) {}

  // WHOIS + VT in parallel
  const [whoisRes, vtRes] = await Promise.allSettled([
    checkWHOIS(hostname),
    checkVirusTotal(url)
  ]);
  const whois = whoisRes.status === "fulfilled" ? whoisRes.value : { available: false };
  const vt    = vtRes.status   === "fulfilled" ? vtRes.value    : { available: false };

  // Backend ML
  if (score === null) {
    try {
      const resp = await fetchWithTimeout(
        CONFIG.BACKEND_URL,
        { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ url }) },
        CONFIG.BACKEND_TIMEOUT
      );
      if (resp.ok) {
        const d = await resp.json();
        if      (typeof d.score          === "number") score = Math.round(d.score);
        else if (typeof d.safety_score   === "number") score = Math.round(d.safety_score);
        else if (typeof d.phishing_score === "number") score = Math.round(d.phishing_score);
        else if (typeof d.prediction     === "number") score = d.prediction <= 1 ? Math.round((1-d.prediction)*100) : Math.round(d.prediction);
        else if (typeof d.probability    === "number") score = Math.round((1-d.probability)*100);
        if (score !== null) score = Math.max(0, Math.min(100, score));
        source = "api";
      }
    } catch(e) { source = "fallback"; }
  }

  if (score === null) { score = heuristicScore(url); source = "fallback"; }

  if (source !== "allowlist" && source !== "blocklist") {
    score = adjustForAge(score, whois);
    if (vt?.available) {
      if      (vt.malicious > 3)  score = Math.min(score, 15);
      else if (vt.malicious > 0)  score = Math.min(score, 35);
      else if (vt.suspicious > 2) score = Math.min(score, 50);
    }
  }

  score = Math.max(0, Math.min(100, score));
  return { score, source, whois, vt };
}

// ── Notifications ─────────────────────────────────────────────────────────────
function sendNotification(score, domain) {
  if (score >= 65) return;
  let title, message;
  if      (score < 25) { title = "🔴 MALICIOUS PAGE DETECTED"; message = `${domain} is DANGEROUS! Leave immediately.`; }
  else if (score < 45) { title = "🚨 Phishing Detected";       message = `${domain} looks like phishing! (Score: ${score}/100)`; }
  else                 { title = "⚠️ Suspicious Page";         message = `${domain} has risk factors. (Score: ${score}/100)`; }
  chrome.notifications.create({
    type: "basic", iconUrl: "icons/icon128.png",
    title, message, priority: score < 45 ? 2 : 1
  });
}

async function saveHistory(url, score) {
  try {
    const verdict = score>=85?"SAFE":score>=65?"PROBABLY SAFE":score>=45?"SUSPICIOUS":score>=25?"PHISHING":"MALICIOUS";
    const cls     = score>=65?"safe":score>=45?"warn":"danger";
    const data    = await chrome.storage.sync.get("fs_history");
    const hist    = data.fs_history || [], now = Date.now();
    if (!hist.find(h => h.url === url && now-(h.ts||0) < 60000)) {
      hist.unshift({ url, score, label: verdict, cls, ts: now });
      if (hist.length > 500) hist.length = 500;
      await chrome.storage.sync.set({ fs_history: hist });
    }
  } catch(e) {}
}

// ── Message handler ───────────────────────────────────────────────────────────
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {

  // PING — wakes service worker
  if (message.type === "PING") {
    sendResponse({ ok: true, awake: true });
    return true;
  }

  // OPEN_DASHBOARD — opens dashboard tab reliably from background
  if (message.type === "OPEN_DASHBOARD") {
    chrome.tabs.create({ url: chrome.runtime.getURL("dashboard.html") }, () => {
      if (chrome.runtime.lastError)
        console.error("Dashboard error:", chrome.runtime.lastError.message);
    });
    sendResponse({ ok: true });
    return true;
  }

  // FULL_SCAN — popup delegates all API work to background
  if (message.type === "FULL_SCAN") {
    const url = message.url;
    if (!url || !url.startsWith("http")) { sendResponse({ ok: false, reason: "Invalid URL" }); return true; }
    fullScan(url).then(result => {
      chrome.tabs.query({ active: true, currentWindow: true }, tabs => {
        const tabId = tabs[0]?.id;
        if (tabId) {
          chrome.action.setBadgeText({ text: String(result.score), tabId });
          chrome.action.setBadgeBackgroundColor({ color: getBadgeColor(result.score), tabId });
        }
      });
      try { sendNotification(result.score, new URL(url).hostname); } catch(e) {}
      saveHistory(url, result.score);
      sendResponse({ ok: true, ...result });
    }).catch(err => sendResponse({ ok: false, reason: err.message }));
    return true;
  }

  // PROACTIVE_SCAN — from content.js on page load
  if (message.type === "PROACTIVE_SCAN") {
    const tabId = sender.tab?.id, url = message.url;
    if (!url || !url.startsWith("http")) { sendResponse({ ok: false }); return true; }
    fullScan(url).then(result => {
      if (tabId) {
        chrome.action.setBadgeText({ text: String(result.score), tabId });
        chrome.action.setBadgeBackgroundColor({ color: getBadgeColor(result.score), tabId });
      }
      try { sendNotification(result.score, new URL(url).hostname); } catch(e) {}
      saveHistory(url, result.score);
      chrome.runtime.sendMessage({ type: "SCAN_COMPLETE", ...result, url }).catch(() => {});
      sendResponse({ ok: true, ...result });
    }).catch(() => sendResponse({ ok: false }));
    return true;
  }

  if (message.type === "SCAN_COMPLETE") {
    const score = message.result?.safety_score ?? message.result?.score ?? 50;
    const tabId = message.tabId;
    if (tabId) {
      chrome.action.setBadgeText({ text: String(score), tabId });
      chrome.action.setBadgeBackgroundColor({ color: getBadgeColor(score), tabId });
    }
    sendResponse({ ok: true });
    return true;
  }

  if (message.type === "DOWNLOAD_CSV") {
    chrome.downloads.download({
      url: message.url, filename: message.filename || "fraudshield-scans.csv",
      saveAs: false, conflictAction: "overwrite"
    });
    sendResponse({ ok: true });
    return true;
  }
});

chrome.tabs.onUpdated.addListener((tabId, changeInfo) => {
  if (changeInfo.status === "loading") chrome.action.setBadgeText({ text: "", tabId });
});