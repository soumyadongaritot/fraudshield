// dashboard.js — FraudShield v4.2
// Real Supabase email/password auth

// ── Supabase config ───────────────────────────────────────────────────────────
const SUPABASE_URL = "https://bgfztnukkgcakeogpvdi.supabase.co";
const SUPABASE_ANON_KEY = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImJnZnp0bnVra2djYWtlb2dwdmRpIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NzQ5MTcxMTksImV4cCI6MjA5MDQ5MzExOX0.etzN6ar5hWvmroLhKynt8mcJtCQZyF-uM9W9uGlc2OU";
const API_URL = "https://fraudshield-1-pkvb.onrender.com/check";

var scanHistory = [], allowList = [], blockList = [], fpReports = [];
var WEEK_DAYS = ["Mon","Tue","Wed","Thu","Fri","Sat","Sun"];
var WEEK_DATA = [12,8,19,7,14,21,6];
var currentUser = null;

// ── Supabase REST helper ──────────────────────────────────────────────────────
async function supabaseFetch(path, options) {
  var opts = Object.assign({ headers: {} }, options);
  opts.headers["apikey"]       = SUPABASE_ANON_KEY;
  opts.headers["Content-Type"] = "application/json";
  if (currentUser && currentUser.access_token) {
    opts.headers["Authorization"] = "Bearer " + currentUser.access_token;
  }
  var resp = await fetch(SUPABASE_URL + path, opts);
  var text = await resp.text();
  var data = text ? JSON.parse(text) : {};
  return { ok: resp.ok, status: resp.status, data: data };
}

// ── Auth: Sign Up ─────────────────────────────────────────────────────────────
async function doSignup() {
  var email    = document.getElementById("signup-email").value.trim();
  var pass     = document.getElementById("signup-pass").value;
  var confirm  = document.getElementById("signup-confirm").value;
  var errEl    = document.getElementById("signup-err");
  var okEl     = document.getElementById("signup-ok");
  var spinner  = document.getElementById("signup-spinner");
  var btnText  = document.getElementById("signup-btn-text");
  var btn      = document.getElementById("btn-signup");

  errEl.style.display = "none";
  okEl.style.display  = "none";

  if (!email || !pass) { showAuthErr(errEl, "Please fill in all fields."); return; }
  if (pass.length < 6) { showAuthErr(errEl, "Password must be at least 6 characters."); return; }
  if (pass !== confirm) { showAuthErr(errEl, "Passwords do not match."); return; }

  btn.disabled = true; spinner.style.display = "block"; btnText.textContent = "Creating account…";

  try {
    var res = await supabaseFetch("/auth/v1/signup", {
      method: "POST",
      body: JSON.stringify({ email: email, password: pass })
    });
    if (res.ok && res.data.user) {
      okEl.textContent = "Account created! Please check your email to confirm, then sign in.";
      okEl.style.display = "block";
      document.getElementById("signup-email").value = "";
      document.getElementById("signup-pass").value  = "";
      document.getElementById("signup-confirm").value = "";
      // Switch to login tab after 2s
      setTimeout(function() { switchTab("login"); }, 2000);
    } else {
      var msg = (res.data.msg || res.data.error_description || res.data.message || "Sign up failed.");
      showAuthErr(errEl, msg);
    }
  } catch(e) {
    showAuthErr(errEl, "Network error. Please try again.");
  }
  btn.disabled = false; spinner.style.display = "none"; btnText.textContent = "Create account →";
}

// ── Auth: Sign In ─────────────────────────────────────────────────────────────
async function doLogin() {
  var email   = document.getElementById("login-email").value.trim();
  var pass    = document.getElementById("login-pass").value;
  var errEl   = document.getElementById("login-err");
  var spinner = document.getElementById("login-spinner");
  var btnText = document.getElementById("login-btn-text");
  var btn     = document.getElementById("btn-login");

  errEl.style.display = "none";
  if (!email || !pass) { showAuthErr(errEl, "Please enter your email and password."); return; }

  btn.disabled = true; spinner.style.display = "block"; btnText.textContent = "Signing in…";

  try {
    var res = await supabaseFetch("/auth/v1/token?grant_type=password", {
      method: "POST",
      body: JSON.stringify({ email: email, password: pass })
    });
    if (res.ok && res.data.access_token) {
      currentUser = res.data;
      // Save session to chrome.storage so popup can also use it
      if (typeof chrome !== "undefined" && chrome.storage) {
        chrome.storage.local.set({ fs_session: res.data });
      }
      onLoginSuccess(res.data.user || { email: email });
    } else {
      var msg = res.data.error_description || res.data.msg || res.data.message || "Invalid email or password.";
      showAuthErr(errEl, msg);
    }
  } catch(e) {
    showAuthErr(errEl, "Network error. Please try again.");
  }
  btn.disabled = false; spinner.style.display = "none"; btnText.textContent = "Sign in →";
}

// ── Auth: Sign Out ────────────────────────────────────────────────────────────
async function doLogout() {
  try {
    await supabaseFetch("/auth/v1/logout", { method: "POST" });
  } catch(e) {}
  currentUser = null;
  if (typeof chrome !== "undefined" && chrome.storage) {
    chrome.storage.local.remove("fs_session");
  }
  document.getElementById("app").classList.remove("visible");
  document.getElementById("auth-screen").style.display = "flex";
}

// ── On successful login ───────────────────────────────────────────────────────
function onLoginSuccess(user) {
  document.getElementById("auth-screen").style.display = "none";
  document.getElementById("app").classList.add("visible");
  var email = user.email || "";
  var name  = email.split("@")[0];
  document.getElementById("tb-name").textContent   = email;
  document.getElementById("tb-avatar").textContent = name.slice(0, 2).toUpperCase();
  loadFromStorage();
}

function showAuthErr(el, msg) {
  el.textContent    = msg;
  el.style.display  = "block";
}

function switchTab(tab) {
  document.getElementById("form-login").style.display   = tab === "login"  ? "block" : "none";
  document.getElementById("form-signup").style.display  = tab === "signup" ? "block" : "none";
  document.getElementById("tab-login").classList.toggle("active",  tab === "login");
  document.getElementById("tab-signup").classList.toggle("active", tab === "signup");
}

// ── Helpers ───────────────────────────────────────────────────────────────────
function getVerdict(s) {
  if (s >= 85) return { label:"Safe",          cls:"safe"   };
  if (s >= 65) return { label:"Probably safe", cls:"safe"   };
  if (s >= 45) return { label:"Suspicious",    cls:"warn"   };
  return             { label:"Dangerous",      cls:"danger" };
}
function spill(s) { return '<span class="spill ' + getVerdict(s).cls + '">' + s + '</span>'; }
function tNow() { return new Date().toLocaleString("en-GB", { day:"2-digit", month:"short", hour:"2-digit", minute:"2-digit" }); }
function trunc(s, n) { return s.length > n ? s.slice(0, n) + "…" : s; }

function toast(msg, type) {
  type = type || "success";
  var t = document.getElementById("toast");
  t.textContent = msg; t.className = "show " + type;
  setTimeout(function() { t.className = ""; }, 2600);
}

// ── Storage ───────────────────────────────────────────────────────────────────
function loadFromStorage() {
  if (typeof chrome !== "undefined" && chrome.storage) {
    chrome.storage.sync.get(["fs_history","fs_allowlist","fs_blocklist","fs_reports"], function(data) {
      var raw = data.fs_history || [];
      scanHistory = raw.map(function(e) {
        var v = getVerdict(e.score || 0);
        return Object.assign({}, e, { label:e.label||v.label, cls:e.cls||v.cls, time:e.time||tNow(), ts:e.ts||Date.now() });
      });
      allowList = data.fs_allowlist || [];
      blockList = data.fs_blocklist || [];
      fpReports = data.fs_reports   || [];
      if (!scanHistory.length) loadDemoData();
      refreshAll();
    });
  } else {
    loadDemoData(); refreshAll();
  }
}

function saveToStorage() {
  if (typeof chrome !== "undefined" && chrome.storage) {
    chrome.storage.sync.set({ fs_history:scanHistory, fs_allowlist:allowList, fs_blocklist:blockList, fs_reports:fpReports });
  }
}

function loadDemoData() {
  var urls = [
    {url:"https://google.com",score:96},{url:"https://paypal-login-verify.ru",score:11},
    {url:"https://github.com",score:93},{url:"https://secure-bank-update.xyz",score:18},
    {url:"https://stackoverflow.com",score:91},{url:"https://amazon.com",score:88},
    {url:"https://phishing-alert.net",score:8},{url:"https://netflix.com",score:85},
  ];
  scanHistory = urls.map(function(u, i) {
    return Object.assign({}, u, getVerdict(u.score), {
      time: new Date(Date.now() - i * 3600000).toLocaleString("en-GB", { day:"2-digit", month:"short", hour:"2-digit", minute:"2-digit" }),
      ts: Date.now() - i * 3600000
    });
  });
  allowList = [{ url:"mycompany.intranet", added:tNow() }, { url:"localhost", added:tNow() }];
  blockList = [{ url:"paypal-login-verify.ru", added:tNow() }, { url:"secure-bank-update.xyz", added:tNow() }];
}

// ── API ───────────────────────────────────────────────────────────────────────
async function callAPI(url) {
  var resp = await fetch(API_URL, { method:"POST", headers:{"Content-Type":"application/json"}, body:JSON.stringify({ url:url }) });
  if (!resp.ok) throw new Error("HTTP " + resp.status);
  var data = await resp.json();
  if (typeof data.safety_score === "number") return Math.round(data.safety_score);
  if (typeof data.score        === "number") return Math.round(data.score);
  if (typeof data.prediction   === "number") return data.prediction <= 1 ? Math.round((1 - data.prediction) * 100) : Math.round(data.prediction);
  return 50;
}

// ── Scanner ───────────────────────────────────────────────────────────────────
async function runScan() {
  var inp = document.getElementById("scan-url-input");
  var btn = document.getElementById("scan-btn");
  var url = inp.value.trim();
  if (!url) { toast("Enter a URL first", "error"); return; }
  if (!url.startsWith("http")) url = "https://" + url;
  var dedupMs = parseInt(document.getElementById("set-dedup").value) * 1000;
  var exist = scanHistory.find(function(h) { return h.url === url && Date.now() - (h.ts||0) < dedupMs; });
  if (exist) { toast("Already scanned recently", "error"); showScanResult(exist); return; }
  var domain = ""; try { domain = new URL(url).hostname; } catch(e) {}
  if (allowList.some(function(x) { return url.includes(x.url) || domain.includes(x.url); })) {
    var e2 = { url:url, score:100, label:"Safe (allowlisted)", cls:"safe", time:tNow(), ts:Date.now() };
    scanHistory.unshift(e2); inp.value=""; showScanResult(e2); refreshAll(); saveToStorage(); return;
  }
  if (blockList.some(function(x) { return url.includes(x.url) || domain.includes(x.url); })) {
    var e3 = { url:url, score:0, label:"Dangerous (blocklisted)", cls:"danger", time:tNow(), ts:Date.now() };
    scanHistory.unshift(e3); inp.value=""; showScanResult(e3); refreshAll(); saveToStorage(); return;
  }
  btn.disabled = true; btn.textContent = "Scanning…"; toast("Calling ML backend…", "info");
  var score = 50;
  try { score = await callAPI(url); toast("Scan complete", "success"); }
  catch(err) {
    console.warn(err); toast("Backend error — fallback score", "error");
    var lower = url.toLowerCase();
    if (lower.includes("phishing") || lower.includes("verify")) score = 15;
    else if (lower.includes("google") || lower.includes("github")) score = 93;
    else score = 55;
  }
  btn.disabled = false; btn.textContent = "Scan now";
  var v = getVerdict(score);
  var ent = Object.assign({ url:url, score:score, time:tNow(), ts:Date.now() }, v);
  scanHistory.unshift(ent); inp.value=""; showScanResult(ent); refreshAll(); saveToStorage();
}

function showScanResult(entry) {
  var clrMap = { safe:"#00e5b0", warn:"#f5a623", danger:"#ff3d5a" };
  var bgMap  = { safe:"rgba(0,229,176,0.07)", warn:"rgba(245,166,35,0.07)", danger:"rgba(255,61,90,0.07)" };
  var color  = clrMap[entry.cls] || "#00e5b0", bg = bgMap[entry.cls] || "rgba(0,229,176,0.07)";
  var res = document.getElementById("scan-result");
  res.style.cssText = "display:flex;align-items:center;gap:14px;background:" + bg + ";border:0.5px solid " + color + "40;border-radius:10px";
  res.innerHTML =
    '<div class="result-ring" style="background:' + bg + ';border:2px solid ' + color + ';color:' + color + '">' + entry.score + '</div>' +
    '<div class="result-info">' +
    '<div class="result-url">' + entry.url + '</div>' +
    '<div class="result-verdict" style="color:' + color + '">' + entry.label + '</div>' +
    '<div class="result-detail">via fraudshield-1-pkvb.onrender.com · ' + entry.time + '</div>' +
    '<div class="result-acts">' +
    '<button class="btn-sm btn-al" data-action="allow" data-url="' + encodeURIComponent(entry.url) + '">+ Allowlist</button>' +
    '<button class="btn-sm btn-bl" data-action="block" data-url="' + encodeURIComponent(entry.url) + '">⊘ Blocklist</button>' +
    '</div></div>';
  res.querySelectorAll('[data-action]').forEach(function(b) {
    b.addEventListener('click', function() { quickAdd(b.dataset.action, decodeURIComponent(b.dataset.url)); });
  });
}

function quickAdd(type, url) {
  if (type === "allow") {
    if (!allowList.find(function(x) { return x.url === url; })) { allowList.unshift({ url:url, added:tNow() }); toast("Added to allowlist"); }
    else toast("Already in allowlist", "error");
  } else {
    if (!blockList.find(function(x) { return x.url === url; })) { blockList.unshift({ url:url, added:tNow() }); toast("Added to blocklist", "error"); }
    else toast("Already in blocklist", "error");
  }
  refreshAll(); saveToStorage();
}

function addToList(type) {
  var val = document.getElementById("list-url-input").value.trim();
  if (!val) { toast("Enter a domain or URL", "error"); return; }
  if (type === "allow") {
    if (allowList.find(function(x) { return x.url === val; })) { toast("Already in allowlist", "error"); return; }
    allowList.unshift({ url:val, added:tNow() }); toast("Added to allowlist");
  } else {
    if (blockList.find(function(x) { return x.url === val; })) { toast("Already in blocklist", "error"); return; }
    blockList.unshift({ url:val, added:tNow() }); toast("Added to blocklist", "error");
  }
  document.getElementById("list-url-input").value = ""; refreshAll(); saveToStorage();
}

function removeFromList(type, url) {
  if (type === "allow") allowList = allowList.filter(function(x) { return x.url !== url; });
  else blockList = blockList.filter(function(x) { return x.url !== url; });
  refreshAll(); saveToStorage(); toast("Removed");
}

function removeHistory(url) { scanHistory = scanHistory.filter(function(x) { return x.url !== url; }); refreshAll(); saveToStorage(); toast("Removed"); }
function clearHistory() { if (!confirm("Clear all scan history?")) return; scanHistory = []; refreshAll(); saveToStorage(); toast("History cleared"); }
function exportCSV() { dlCSV([["URL","Score","Verdict","Time"]].concat(scanHistory.map(function(h) { return [h.url, h.score, h.label, h.time]; })), "fraudshield_history.csv"); toast("CSV exported"); }
function exportReports() { dlCSV([["URL","Notes","Time","Status"]].concat(fpReports.map(function(r) { return [r.url, r.notes, r.time, r.status]; })), "fraudshield_reports.csv"); toast("Reports exported"); }
function dlCSV(rows, fn) {
  var csv = rows.map(function(r) { return r.map(function(c) { return '"' + String(c).replace(/"/g,'""') + '"'; }).join(","); }).join("\n");
  var a = document.createElement("a"); a.href = "data:text/csv," + encodeURIComponent(csv); a.download = fn; a.click();
}

function submitReport() {
  var url = document.getElementById("fp-url").value.trim(), notes = document.getElementById("fp-notes").value.trim();
  if (!url) { toast("Enter a URL", "error"); return; }
  fpReports.unshift({ url:url, notes:notes, time:tNow(), status:"pending" });
  document.getElementById("fp-url").value = ""; document.getElementById("fp-notes").value = "";
  toast("Report submitted"); renderReports(); saveToStorage();
}

function saveSettings() {
  var s = { proactive:document.getElementById("set-proactive").checked, dedupSec:parseInt(document.getElementById("set-dedup").value), httpsOnly:document.getElementById("set-https").checked, dangerThresh:parseInt(document.getElementById("thresh-val").textContent), notifications:document.getElementById("set-notif").checked, badge:document.getElementById("set-badge").checked };
  if (typeof chrome !== "undefined" && chrome.storage) { chrome.storage.sync.set({ fs_settings:s }); chrome.runtime.sendMessage({ type:"SAVE_SETTINGS", settings:s }).catch(function(){}); }
  toast("Settings saved");
}

// ── Render ────────────────────────────────────────────────────────────────────
function renderStats() {
  var total=scanHistory.length, threats=scanHistory.filter(function(h){return h.score<45}).length, suspicious=scanHistory.filter(function(h){return h.score>=45&&h.score<85}).length, safe=scanHistory.filter(function(h){return h.score>=85}).length;
  document.getElementById("stat-total").textContent=total; document.getElementById("stat-threats").textContent=threats; document.getElementById("stat-suspicious").textContent=suspicious; document.getElementById("stat-safe").textContent=safe;
  document.getElementById("hist-badge").textContent=total||""; document.getElementById("block-badge").textContent=blockList.length||"";
  var circ=214,tP=threats/Math.max(total,1),wP=suspicious/Math.max(total,1),sP=safe/Math.max(total,1),dL=circ*tP,wL=circ*wP,sL=circ*sP;
  document.getElementById("d-danger").setAttribute("stroke-dasharray",dL+" "+(circ-dL)); document.getElementById("d-danger").setAttribute("stroke-dashoffset","54");
  document.getElementById("d-warn").setAttribute("stroke-dasharray",wL+" "+(circ-wL)); document.getElementById("d-warn").setAttribute("stroke-dashoffset",String(54-dL));
  document.getElementById("d-safe").setAttribute("stroke-dasharray",sL+" "+(circ-sL)); document.getElementById("d-safe").setAttribute("stroke-dashoffset",String(54-dL-wL));
  document.getElementById("leg-d").textContent=threats; document.getElementById("leg-w").textContent=suspicious; document.getElementById("leg-s").textContent=safe;
}

function renderWeekBars() {
  var max=Math.max.apply(null,WEEK_DATA),today=new Date().getDay();
  document.getElementById("week-bars").innerHTML=WEEK_DATA.map(function(v,i){var h=Math.max(6,Math.round(v/max*76));var isToday=(i===(today===0?6:today-1));return'<div class="mini-bar" style="height:'+h+'px;background:'+(isToday?"var(--accent)":"var(--bg5)")+'"></div>';}).join("");
  document.getElementById("week-labels").innerHTML=WEEK_DAYS.map(function(d){return'<div class="bar-label">'+d+'</div>';}).join("");
}

function renderTableBody(id, data) {
  var el=document.getElementById(id); if(!el)return;
  if(!data.length){el.innerHTML='<tr><td colspan="5"><div class="empty">No records yet</div></td></tr>';return;}
  el.innerHTML=data.map(function(h){return"<tr><td class='mono'>"+trunc(h.url,50)+"</td><td>"+spill(h.score)+"</td><td><span class='badge "+h.cls+"'>"+h.label+"</span></td><td class='mono' style='font-size:10px;color:var(--text3)'>"+h.time+"</td><td><button class='del-btn' data-action='remove-history' data-url='"+encodeURIComponent(h.url)+"'>Remove</button></td></tr>";}).join("");
  el.querySelectorAll('[data-action="remove-history"]').forEach(function(b){b.addEventListener('click',function(){removeHistory(decodeURIComponent(b.dataset.url));});});
}

function renderDashRecent() {
  var tbody=document.getElementById("dash-recent"),data=scanHistory.slice(0,6);
  if(!data.length){tbody.innerHTML='<tr><td colspan="4"><div class="empty">No scans yet</div></td></tr>';return;}
  tbody.innerHTML=data.map(function(h){return"<tr><td class='mono'>"+trunc(h.url,48)+"</td><td>"+spill(h.score)+"</td><td><span class='badge "+h.cls+"'>"+h.label+"</span></td><td class='mono' style='font-size:10px;color:var(--text3)'>"+h.time+"</td></tr>";}).join("");
}

function renderLists() {
  var ai=document.getElementById("allow-items"),bi=document.getElementById("block-items");
  ai.innerHTML=allowList.length?allowList.map(function(x){return'<div class="list-item"><div><div class="list-item-url">'+x.url+'</div><div class="list-item-date">'+x.added+'</div></div><button class="del-btn" data-action="remove-list" data-type="allow" data-url="'+encodeURIComponent(x.url)+'">Remove</button></div>';}).join(""):'<div class="empty">No allowed domains</div>';
  bi.innerHTML=blockList.length?blockList.map(function(x){return'<div class="list-item"><div><div class="list-item-url">'+x.url+'</div><div class="list-item-date">'+x.added+'</div></div><button class="del-btn" data-action="remove-list" data-type="block" data-url="'+encodeURIComponent(x.url)+'">Remove</button></div>';}).join(""):'<div class="empty">No blocked domains</div>';
  document.getElementById("allow-count").textContent=allowList.length; document.getElementById("block-count2").textContent=blockList.length;
  document.querySelectorAll('[data-action="remove-list"]').forEach(function(b){b.addEventListener('click',function(){removeFromList(b.dataset.type,decodeURIComponent(b.dataset.url));});});
}

function renderReports() {
  var tbody=document.getElementById("reports-body");
  if(!fpReports.length){tbody.innerHTML='<tr><td colspan="4"><div class="empty">No reports submitted</div></td></tr>';return;}
  tbody.innerHTML=fpReports.map(function(r){return"<tr><td class='mono'>"+trunc(r.url,40)+"</td><td style='font-size:11px;color:var(--text2)'>"+(r.notes||"—")+"</td><td class='mono' style='font-size:10px;color:var(--text3)'>"+r.time+"</td><td><span class='badge warn'>"+r.status+"</span></td></tr>";}).join("");
}

function refreshAll() { renderStats(); renderWeekBars(); renderDashRecent(); renderTableBody("scan-history-body",scanHistory); renderTableBody("history-body",scanHistory); renderLists(); renderReports(); }

function showPage(name) {
  document.querySelectorAll(".page").forEach(function(p){p.classList.remove("active");});
  document.querySelectorAll(".nav-item").forEach(function(n){n.classList.remove("active");});
  var page=document.getElementById("page-"+name); if(page)page.classList.add("active");
  var nav=document.querySelector('[data-page="'+name+'"]'); if(nav)nav.classList.add("active");
}

// ── Init ──────────────────────────────────────────────────────────────────────
document.addEventListener("DOMContentLoaded", function() {

  // Auth tabs
  document.getElementById("tab-login").addEventListener("click",  function() { switchTab("login");  });
  document.getElementById("tab-signup").addEventListener("click", function() { switchTab("signup"); });

  // Auth buttons
  document.getElementById("btn-login").addEventListener("click", doLogin);
  document.getElementById("btn-signup").addEventListener("click", doSignup);
  document.getElementById("btn-logout").addEventListener("click", doLogout);
  document.getElementById("login-pass").addEventListener("keydown",   function(e) { if(e.key==="Enter") doLogin();  });
  document.getElementById("signup-confirm").addEventListener("keydown", function(e) { if(e.key==="Enter") doSignup(); });

  // Nav
  document.querySelectorAll(".nav-item[data-page]").forEach(function(item) {
    item.addEventListener("click", function() { showPage(item.dataset.page); });
  });

  // Scanner
  document.getElementById("scan-btn").addEventListener("click", runScan);
  document.getElementById("scan-url-input").addEventListener("keydown", function(e) { if(e.key==="Enter") runScan(); });

  // History / export
  document.getElementById("btn-export-csv").addEventListener("click", exportCSV);
  document.getElementById("btn-export-csv-2").addEventListener("click", exportCSV);
  document.getElementById("btn-clear-history").addEventListener("click", clearHistory);

  // Lists
  document.getElementById("btn-add-allow").addEventListener("click", function() { addToList("allow"); });
  document.getElementById("btn-add-block").addEventListener("click", function() { addToList("block"); });
  document.getElementById("list-url-input").addEventListener("keydown", function(e) { if(e.key==="Enter") addToList("allow"); });

  // Settings
  ["set-proactive","set-dedup","set-https","set-notif","set-badge"].forEach(function(id) {
    document.getElementById(id).addEventListener("change", saveSettings);
  });
  document.getElementById("thresh-range").addEventListener("input", function() { document.getElementById("thresh-val").textContent = this.value; });
  document.getElementById("thresh-range").addEventListener("change", saveSettings);

  // Reports
  document.getElementById("btn-submit-report").addEventListener("click", submitReport);
  document.getElementById("btn-export-reports").addEventListener("click", exportReports);

  // Check for existing session on load
  if (typeof chrome !== "undefined" && chrome.storage) {
    chrome.storage.local.get("fs_session", function(data) {
      if (data.fs_session && data.fs_session.access_token) {
        currentUser = data.fs_session;
        onLoginSuccess(data.fs_session.user || { email: "" });
      }
    });
  }
});