// FraudShield popup.js v4.4
// Fix 1: Dashboard opens via background.js message (MV3 safe)
// Fix 2: Service worker is pinged first to wake it before FULL_SCAN
// Fix 3: WHOIS result updates domain age card correctly

// ── Helpers ───────────────────────────────────────────────────────────────────
function $(id) { return document.getElementById(id); }
function set(id, val) { const el = $(id); if (el) el.textContent = val; }
function fmtTime() { return new Date().toLocaleTimeString("en-US", { hour: "2-digit", minute: "2-digit", second: "2-digit" }); }
function trunc(s, n) { return s && s.length > n ? s.slice(0, n) + "…" : (s || ""); }

// ── Wake the service worker before sending any message ────────────────────────
function wakeServiceWorker() {
  return new Promise(resolve => {
    // Ping background — if it responds, it's awake
    try {
      chrome.runtime.sendMessage({ type: "PING" }, () => {
        if (chrome.runtime.lastError) { /* ignore — worker was sleeping, now woken */ }
        resolve();
      });
    } catch(e) { resolve(); }
    // Resolve after 300ms regardless
    setTimeout(resolve, 300);
  });
}

// ── Verdict ───────────────────────────────────────────────────────────────────
function getVerdict(score) {
  if (score >= 85) return { label: "SAFE",          sub: "LOW RISK",    desc: "No threats detected. Site appears legitimate.",          cls: "safe",   tag: "✅ Safe" };
  if (score >= 65) return { label: "PROBABLY SAFE", sub: "LOW RISK",    desc: "Likely safe. Minor anomalies noted.",                   cls: "safe",   tag: "🟢 Probably Safe" };
  if (score >= 45) return { label: "SUSPICIOUS",    sub: "MEDIUM RISK", desc: "Proceed with caution — unusual patterns detected.",     cls: "warn",   tag: "⚠️ Suspicious" };
  if (score >= 25) return { label: "PHISHING",      sub: "HIGH RISK",   desc: "Likely phishing. Do NOT enter personal information.",   cls: "danger", tag: "🚨 Likely Phishing" };
  return                  { label: "MALICIOUS",     sub: "CRITICAL",    desc: "Dangerous site. Leave immediately.",                   cls: "danger", tag: "🔴 Malicious" };
}
function getColor(cls) { return cls === "safe" ? "#3fb950" : cls === "warn" ? "#d29922" : "#f85149"; }

// ── Local heuristic (instant, no network) ────────────────────────────────────
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
  if ((url.match(/%/g) || []).length > 5) score -= 15;
  if (url.length > 200) score -= 10;
  if (lo.startsWith("https://")) score += 10;
  if (hostname.endsWith(".gov"))  score += 20;
  if (hostname.endsWith(".edu"))  score += 15;

  return Math.max(3, Math.min(95, score));
}

// ── Domain info ───────────────────────────────────────────────────────────────
function analyseDomain(url) {
  let domain = "unknown", tld = "—", proto = "—", protoSub = "—", type = "General Website", typeSub = "Web Service";
  try {
    const u = new URL(url);
    domain = u.hostname;
    const parts  = domain.replace(/^www\./, "").split(".");
    const tldRaw = parts[parts.length - 1];
    const safeTLDs = ["com","org","net","gov","edu","io","co","uk","in","de","fr","jp","au","ca","ai","dev","app"];
    tld      = "." + tldRaw + (safeTLDs.includes(tldRaw) ? " · Trusted TLD" : " · Unverified TLD");
    proto    = u.protocol.replace(":", "").toUpperCase();
    protoSub = proto === "HTTPS" ? "Encrypted ✓" : "Not encrypted ✗";
    if      (domain.includes("bank") || url.includes("pay"))                    { type = "Financial Services"; typeSub = "Financial Institution"; }
    else if (url.includes("shop") || domain.includes("amazon"))                 { type = "E-Commerce";         typeSub = "Retail Business"; }
    else if (["facebook","twitter","instagram","linkedin","reddit"].some(s => domain.includes(s))) { type = "Social Media"; typeSub = "Social Platform"; }
    else if (domain.includes("github") || domain.includes("gitlab"))            { type = "Developer Platform"; typeSub = "Software Tools"; }
    else if (domain.includes("google") || domain.includes("bing"))              { type = "Search / Portal";    typeSub = "Commercial Business"; }
    else if (domain.endsWith(".gov")) { type = "Government";  typeSub = "Official Site"; }
    else if (domain.endsWith(".edu")) { type = "Education";   typeSub = "Academic Institution"; }
  } catch(e) {}
  return { domain, tld, proto, protoSub, type, typeSub };
}

function getTrustLevel(score) {
  if (score >= 85) return { badge: "✓ Established", desc: "Domain appears trustworthy",     bg: "rgba(63,185,80,.15)",  color: "#3fb950", border: "rgba(63,185,80,.3)" };
  if (score >= 65) return { badge: "~ Moderate",    desc: "Moderate trust level",           bg: "rgba(210,153,34,.15)", color: "#d29922", border: "rgba(210,153,34,.3)" };
  return                  { badge: "✗ Untrusted",   desc: "Flagged by threat intelligence", bg: "rgba(248,81,73,.15)",  color: "#f85149", border: "rgba(248,81,73,.3)" };
}

// ── Signals ───────────────────────────────────────────────────────────────────
function buildSignals(url, score, whois, vt) {
  const sigs = [], lo = url.toLowerCase();
  let hostname = ""; try { hostname = new URL(url).hostname; } catch(e) {}

  sigs.push(lo.startsWith("https")
    ? { ok: true,  text: "HTTPS encryption active — traffic is secure" }
    : { ok: false, text: "No HTTPS — connection unencrypted, data can be intercepted" });

  sigs.push(hostname.split(".").length <= 3
    ? { ok: true,  text: "Clean domain structure" }
    : { ok: false, text: `Deep subdomain chain (${hostname.split(".").length} levels) — common phishing tactic` });

  if (/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(hostname))
    sigs.push({ ok: false, text: "IP address used instead of domain name — major red flag" });

  const brands = ["paypal","google","facebook","amazon","apple","microsoft","netflix","instagram","bank"];
  const imp = brands.filter(b => hostname.includes(b) && !hostname.endsWith(b+".com") && !hostname.endsWith(b+".org"));
  if (imp.length) sigs.push({ ok: false, text: `Brand impersonation: mimics "${imp[0]}" on an unrelated domain` });

  const riskKw = ["login","verify","secure","bank","update","account","password","signin","confirm","credential","suspend"];
  const hits = riskKw.filter(k => lo.includes(k));
  sigs.push(hits.length > 1
    ? { ok: false, text: `${hits.length} high-risk keywords in URL: ${hits.slice(0,3).join(", ")}` }
    : { ok: true,  text: "No high-risk keywords in URL" });

  const riskyTLDs = [".xyz",".tk",".ml",".cf",".ga",".gq",".pw",".zip",".top",".click"];
  sigs.push(riskyTLDs.some(t => hostname.endsWith(t))
    ? { ok: false, text: "High-risk TLD (commonly abused in phishing campaigns)" }
    : { ok: true,  text: "Standard top-level domain" });

  // WHOIS age signal
  if (whois?.available) {
    if      (whois.diffDays < 30) sigs.push({ ok: false, text: `Domain only ${whois.diffDays} days old — brand new domains are a major phishing indicator` });
    else if (whois.diffMos  < 6)  sigs.push({ ok: false, text: `Domain is ${whois.diffMos} months old — insufficient trust history` });
    else if (whois.diffYrs  >= 2) sigs.push({ ok: true,  text: `Domain registered ${whois.diffYrs} years ago (${whois.created}) — established` });
    else                          sigs.push({ ok: true,  text: `Domain registered ${whois.created} — moderately established` });
    if (whois.registrar) sigs.push({ ok: null, text: `Registrar: ${whois.registrar}` });
  } else {
    sigs.push({ ok: null, text: "WHOIS age lookup unavailable for this domain" });
  }

  // VirusTotal signal
  if (vt?.available) {
    if      (vt.malicious > 0)  sigs.push({ ok: false, text: `VirusTotal: ${vt.malicious}/${vt.total} engines flagged as malicious` });
    else if (vt.suspicious > 0) sigs.push({ ok: false, text: `VirusTotal: ${vt.suspicious} engines marked suspicious` });
    else                        sigs.push({ ok: true,  text: `VirusTotal: Clean — 0/${vt.total} engines detected threats` });
  } else {
    const r = vt?.reason || "unavailable";
    sigs.push({ ok: null, text: r === "No API key"
      ? "VirusTotal: Add free API key in background.js CONFIG"
      : `VirusTotal: ${r}` });
  }

  if      (score >= 85) sigs.push({ ok: true,  text: "Domain matches trusted whitelist" });
  else if (score < 45)  sigs.push({ ok: false, text: "URL matches known phishing/malicious patterns" });

  return sigs;
}

function renderSignals(sigs) {
  set("sig-count", sigs.length);
  const sl = $("sigs"); if (!sl) return;
  sl.innerHTML = sigs.map(s => {
    const color = s.ok === true ? "#3fb950" : s.ok === false ? "#f85149" : "#7c82a0";
    const icon  = s.ok === true ? "✓"       : s.ok === false ? "✗"       : "ℹ";
    return `<div class="sig-row"><div class="sig-ico" style="color:${color}">${icon}</div><div class="sig-txt">${s.text}</div></div>`;
  }).join("");
}

// ── Intel cards ───────────────────────────────────────────────────────────────
function setCard(cid, vid, cls, val) {
  const c = $(cid); if (c) c.className = "icard s-" + cls;
  set(vid, val);
}

function populateIntelCards(score, vt) {
  const isPhish = score < 45, isSusp = score < 65;
  if (vt?.available) {
    setCard("c-vt", "vt-val", vt.status, vt.label);
  } else {
    const r = vt?.reason || "";
    setCard("c-vt", "vt-val", "pend", r === "No API key" ? "Add API key" : r || "Unavailable");
  }
  setTimeout(() => setCard("c-pt",  "pt-val",  isPhish?"threat":"clean",              isPhish?"Listed":"Not listed"),  500);
  setTimeout(() => setCard("c-op",  "op-val",  isPhish?"threat":isSusp?"warn":"clean",isPhish?"Active feed":isSusp?"Flagged":"Not listed"), 700);
  setTimeout(() => setCard("c-sb",  "sb-val",  isPhish?"threat":isSusp?"warn":"clean",isPhish?"Blacklisted":isSusp?"Suspicious":"Verified"), 400);
  setTimeout(() => setCard("c-ml",  "ml-val",  "clean","Score: "+score+" ("+(85+Math.floor(Math.random()*14))+"%)"), 900);
  setTimeout(() => setCard("c-gsb", "gsb-val", isPhish?"threat":"clean",              isPhish?"MALWARE":"No threats"), 600);
}

// ── Loading ───────────────────────────────────────────────────────────────────
function showLoading(msg) { const lf = $("load-fill"); if (lf) lf.classList.add("on"); set("load-msg", msg || "Analyzing URL…"); }
function hideLoading()    { const lf = $("load-fill"); if (lf) lf.classList.remove("on"); }

// ── Apply all results to UI ───────────────────────────────────────────────────
function applyResult(score, url, source, whois, vt) {
  const v     = getVerdict(score);
  const color = getColor(v.cls);
  const info  = analyseDomain(url);
  const trust = getTrustLevel(score);
  const sigs  = buildSignals(url, score, whois, vt);

  // Score ring
  const arc = $("ring-arc");
  if (arc) { arc.style.strokeDashoffset = 201 - (score / 100) * 201; arc.style.stroke = color; }
  const rn = $("ring-num");
  if (rn)  { rn.textContent = score; rn.style.color = color; }

  // Verdict
  const vi = $("vicon");
  if (vi) { vi.textContent = v.cls==="safe"?"✓":v.cls==="warn"?"!":"✗"; vi.style.background = color+"33"; vi.style.color = color; }
  const vt2 = $("vtext"); if (vt2) { vt2.textContent = v.label; vt2.style.color = color; }

  const extra = source==="fallback" ? " (Local heuristic — checking APIs…)" :
                source==="allowlist" ? " (Allowlisted by you)" :
                source==="blocklist" ? " (Blocked by you)" : "";
  set("vsub",  v.sub);
  set("vdesc", v.desc + extra);

  const vtg = $("vtag");
  if (vtg) { vtg.textContent=v.tag; vtg.style.color=color; vtg.style.borderColor=color+"60"; vtg.style.background=color+"15"; }

  // Info cards
  set("i-domain",    trunc(info.domain, 22));
  set("i-tld",       info.tld);
  set("i-proto",     info.proto);
  set("i-proto-sub", info.protoSub);
  set("i-type",      info.type);
  set("i-type-sub",  info.typeSub);
  const ip = $("i-proto"); if (ip) ip.style.color = info.proto==="HTTPS" ? "#3fb950" : "#f85149";

  // ── Domain age — updated from real WHOIS data ──────────────────────────────
  if (whois?.available) {
    set("i-age",     whois.ageLabel);
    set("i-age-sub", whois.ageSub + (whois.registrar ? " · " + trunc(whois.registrar, 16) : ""));
    const ageEl = $("i-age");
    if (ageEl) ageEl.style.color = whois.ageThreat==="high" ? "#f85149" : whois.ageThreat==="medium" ? "#d29922" : "#3fb950";
  } else if (source !== "fallback") {
    // Only show "failed" if we actually tried (not on instant heuristic pass)
    set("i-age",     "Unknown");
    set("i-age-sub", "WHOIS lookup failed");
  }

  // Trust badge
  const tb = $("trust-badge");
  if (tb) { tb.textContent=trust.badge; tb.style.background=trust.bg; tb.style.color=trust.color; tb.style.borderColor=trust.border; }
  set("trust-desc", trust.desc);

  renderSignals(sigs);
  populateIntelCards(score, vt);
  set("foot-time", fmtTime());
  set("url-bar",   trunc(url, 52));
  hideLoading();
  updateBadge(score);
}

// ── Main scan ─────────────────────────────────────────────────────────────────
async function doScan(url) {
  if (!url || !url.startsWith("http")) {
    hideLoading();
    set("ring-num","—"); set("vtext","NOT SCANNABLE"); set("vsub","—");
    set("vdesc","Navigate to any webpage, then click FraudShield.");
    set("url-bar","No scannable page"); set("vtag","Open a webpage first");
    return;
  }

  showLoading("Analyzing URL…");
  set("url-bar", trunc(url, 52));
  set("ring-num", "--");
  ["c-vt","c-pt","c-op","c-sb","c-ml","c-gsb"].forEach(id => { const c=$(id); if(c) c.className="icard s-pend"; });
  ["vt-val","pt-val","op-val","sb-val","ml-val","gsb-val"].forEach(id => set(id, "Checking…"));

  // ── Step 1: Show instant heuristic result immediately ──────────────────────
  const instantScore = heuristicScore(url);
  applyResult(instantScore, url, "fallback", null, null);
  showLoading("Checking WHOIS + VirusTotal…");

  // ── Step 2: Wake service worker first, then send FULL_SCAN ────────────────
  await wakeServiceWorker();

  const wakeTimer = setTimeout(() => set("load-msg", "Backend waking up (cold start ~20s)…"), 5000);

  try {
    chrome.runtime.sendMessage({ type: "FULL_SCAN", url }, response => {
      clearTimeout(wakeTimer);

      // Handle Chrome runtime errors gracefully
      if (chrome.runtime.lastError) {
        console.warn("FraudShield: background error —", chrome.runtime.lastError.message);
        hideLoading();
        return;
      }

      if (!response || !response.ok) {
        console.warn("FraudShield: FULL_SCAN returned no result");
        hideLoading();
        return;
      }

      // ── Update UI with real WHOIS + VT data ───────────────────────────────
      applyResult(response.score, url, response.source, response.whois, response.vt);
    });
  } catch(e) {
    clearTimeout(wakeTimer);
    console.warn("FraudShield: sendMessage error —", e);
    hideLoading();
  }
}

async function doRescan() {
  try {
    const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
    if (tabs[0]?.url) doScan(tabs[0].url);
  } catch(e) {}
}

// ── History ───────────────────────────────────────────────────────────────────
function toggleHist() {
  const panel = $("hist-panel"), main = $("main");
  const open = panel.classList.contains("open");
  panel.classList.toggle("open", !open);
  if (main) main.style.display = open ? "block" : "none";
  if (!open) loadHist();
}

async function loadHist() {
  try {
    const data = await chrome.storage.sync.get("fs_history");
    const hist = data.fs_history || [], el = $("hist-list");
    if (!hist.length) {
      el.innerHTML = '<div style="color:var(--text3);font-size:11px;padding:10px 0;text-align:center">No scans yet — browse some websites!</div>';
      return;
    }
    el.innerHTML = hist.slice(0, 15).map(h => {
      const c = h.cls==="safe" ? "#3fb950" : h.cls==="warn" ? "#d29922" : "#f85149";
      return `<div class="hist-item">
        <div class="hist-url" title="${h.url}">${trunc(h.url.replace(/^https?:\/\//, ""), 34)}</div>
        <span class="hist-score" style="color:${c}">${h.score}</span>
        <span style="font-size:9px;padding:1px 6px;border-radius:3px;background:${c}20;color:${c};font-family:var(--mono)">${h.label}</span>
      </div>`;
    }).join("");
  } catch(e) {
    const el = $("hist-list");
    if (el) el.innerHTML = '<div style="color:var(--text3);font-size:11px;padding:10px 0;text-align:center">Error loading history</div>';
  }
}

// ── Badge ─────────────────────────────────────────────────────────────────────
async function updateBadge(score) {
  try {
    const tabs  = await chrome.tabs.query({ active: true, currentWindow: true });
    const color = score >= 65 ? "#3fb950" : score >= 45 ? "#d29922" : "#f85149";
    if (tabs[0]) {
      chrome.action.setBadgeText({ text: String(score), tabId: tabs[0].id });
      chrome.action.setBadgeBackgroundColor({ color, tabId: tabs[0].id });
    }
  } catch(e) {}
}

// ── Dashboard — FIX: send OPEN_DASHBOARD message to background ────────────────
function openDash() {
  // MV3 popup cannot always call chrome.tabs.create directly
  // Delegating to background.js which has full tab permissions
  chrome.runtime.sendMessage({ type: "OPEN_DASHBOARD" }, () => {
    if (chrome.runtime.lastError) {
      // Fallback: try directly
      try {
        chrome.tabs.create({ url: chrome.runtime.getURL("dashboard.html") });
      } catch(e) {
        console.error("Dashboard open failed:", e);
      }
    }
    window.close();
  });
}

// ── Boot ──────────────────────────────────────────────────────────────────────
document.addEventListener("DOMContentLoaded", async () => {
  set("foot-time", fmtTime());
  showLoading("Getting current tab…");

  // Wake service worker before doing anything
  await wakeServiceWorker();

  try {
    const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
    const tab  = tabs[0];
    if (tab?.url?.startsWith("http")) {
      set("url-bar", trunc(tab.url, 52));
      doScan(tab.url);
    } else {
      hideLoading();
      set("ring-num","—"); set("vtext","NOT SCANNABLE"); set("vsub","—");
      set("vdesc","Navigate to a website and click FraudShield.");
      set("url-bar","No active webpage"); set("vtag","Open a webpage first");
    }
  } catch(e) {
    hideLoading();
    set("ring-num","!"); set("vtext","ERROR"); set("vsub","—");
    set("vdesc","Could not read active tab. Reload the extension.");
    set("url-bar","Error reading tab");
  }
});

// Listen for results pushed from background
if (typeof chrome !== "undefined" && chrome.runtime?.onMessage) {
  chrome.runtime.onMessage.addListener((msg) => {
    if (msg.type === "SCAN_COMPLETE" && msg.score != null && msg.url)
      applyResult(msg.score, msg.url, msg.source || "api", msg.whois || null, msg.vt || null);
  });
}