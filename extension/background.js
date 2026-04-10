// FraudShield background.js v4.3
// ✅ PROACTIVE_SCAN with real WHOIS + VirusTotal
// ✅ Smart notifications
// ✅ Badge management

const CONFIG = {
  VT_API_KEY:      "90824c5af9f1358e7a0a393809410e281d2151d8751597254dd628885f2e5a4c", // same key as popup.js
  BACKEND_URL:     "https://fraudshield-1-pkvb.onrender.com/predict",
  BACKEND_TIMEOUT: 15000,
  VT_TIMEOUT:      10000,
  WHOIS_TIMEOUT:   8000,
};

function getBadgeColor(score){
  if(score>=85) return "#3fb950";
  if(score>=65) return "#d29922";
  if(score>=45) return "#ff8800";
  return "#f85149";
}

function fetchWithTimeout(url,options,ms){
  return new Promise((resolve,reject)=>{
    const t=setTimeout(()=>reject(new Error("TIMEOUT")),ms);
    fetch(url,options).then(r=>{clearTimeout(t);resolve(r);}).catch(e=>{clearTimeout(t);reject(e);});
  });
}

// ── Real WHOIS (RDAP multi-source fallback) ───────────────────────────────────
async function checkWHOIS(hostname){
  const apex=hostname.replace(/^www\./,"").split(".").slice(-2).join(".");

  // Try rdap.org first
  try{
    const resp=await fetchWithTimeout(`https://rdap.org/domain/${apex}`,{headers:{Accept:"application/json"}},CONFIG.WHOIS_TIMEOUT);
    if(resp.ok){
      const d=await resp.json();
      const events=d?.events||[];
      const regEvent=events.find(e=>e.eventAction==="registration");
      const raw=regEvent?.eventDate||null;
      if(raw){
        const created=new Date(raw);
        if(!isNaN(created)){
          const diffDays=Math.floor((Date.now()-created)/86400000);
          const diffMos=Math.floor(diffDays/30);
          const diffYrs=Math.floor(diffDays/365);
          return{available:true,diffDays,diffMos,diffYrs,created:created.toISOString().split("T")[0]};
        }
      }
    }
  }catch(e){}

  // Fallback: whoisjson.com
  try{
    const resp2=await fetchWithTimeout(`https://whoisjson.com/api/v1/whois?domain=${apex}`,{headers:{Accept:"application/json"}},CONFIG.WHOIS_TIMEOUT);
    if(resp2.ok){
      const d2=await resp2.json();
      const raw=d2?.created||d2?.creation_date||d2?.registered||null;
      if(raw){
        const created=new Date(Array.isArray(raw)?raw[0]:raw);
        if(!isNaN(created)){
          const diffDays=Math.floor((Date.now()-created)/86400000);
          const diffMos=Math.floor(diffDays/30);
          const diffYrs=Math.floor(diffDays/365);
          return{available:true,diffDays,diffMos,diffYrs,created:created.toISOString().split("T")[0]};
        }
      }
    }
  }catch(e){}

  return{available:false};
}

// ── Real VirusTotal ───────────────────────────────────────────────────────────
async function checkVirusTotal(url){
  const key=CONFIG.VT_API_KEY;
  if(!key||key==="YOUR_VIRUSTOTAL_API_KEY") return{available:false};
  try{
    const encoded=btoa(url).replace(/=/g,"").replace(/\+/g,"-").replace(/\//g,"_");
    const resp=await fetchWithTimeout(`https://www.virustotal.com/api/v3/urls/${encoded}`,{headers:{"x-apikey":key}},CONFIG.VT_TIMEOUT);
    if(resp.ok){
      const d=await resp.json();
      const stats=d?.data?.attributes?.last_analysis_stats;
      if(stats){
        const malicious=stats.malicious||0,suspicious=stats.suspicious||0;
        const total=Object.values(stats).reduce((a,b)=>a+b,0);
        return{available:true,malicious,suspicious,total,status:malicious>0?"threat":suspicious>0?"warn":"clean"};
      }
    }
    return{available:false};
  }catch(e){return{available:false};}
}

// ── Heuristic (same logic as popup.js) ───────────────────────────────────────
function heuristicScore(url){
  const lo=url.toLowerCase();
  let score=55, hostname="", domain="";
  try{const u=new URL(url);hostname=u.hostname;domain=hostname.replace(/^www\./,"");}catch(e){return 20;}
  const trusted=["google.com","google.dev","github.com","stackoverflow.com","amazon.com",
    "microsoft.com","apple.com","wikipedia.org","youtube.com","linkedin.com","netflix.com",
    "reddit.com","twitter.com","x.com","claude.ai","anthropic.com","openai.com","paypal.com",
    "stripe.com","cloudflare.com","mozilla.org","instagram.com","facebook.com","spotify.com"];
  if(trusted.some(d=>domain===d||domain.endsWith("."+d))) return 92;
  const knownBad=["testsafebrowsing.appspot.com","malware.testing.google.test","phishing.test","eicar.org"];
  if(knownBad.some(d=>hostname.includes(d))) return 4;
  if(!lo.startsWith("https://"))                             score-=20;
  if(/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(hostname)) score-=35;
  if(hostname.split(".").length>4)                           score-=15;
  [".xyz",".tk",".ml",".cf",".ga",".gq",".pw",".zip",".top",".click"].forEach(t=>{if(hostname.endsWith(t))score-=22;});
  ["paypal","google","facebook","amazon","apple","microsoft","netflix","instagram","bank"].forEach(b=>{
    if(hostname.includes(b)&&!hostname.endsWith(b+".com")&&!hostname.endsWith(b+".org")) score-=35;
  });
  const hits=["login","signin","verify","account","update","secure","banking","credential","password"].filter(k=>lo.includes(k));
  if(hits.length>=3)score-=25;else if(hits.length>=2)score-=15;else if(hits.length>=1)score-=5;
  if(lo.startsWith("https://"))score+=10;
  if(hostname.endsWith(".gov"))score+=20;
  if(hostname.endsWith(".edu"))score+=15;
  return Math.max(3,Math.min(95,score));
}

function adjustForAge(base,whois){
  if(!whois?.available) return base;
  let adj=base;
  if(whois.diffDays<7)adj-=40;
  else if(whois.diffDays<30)adj-=30;
  else if(whois.diffMos<3)adj-=20;
  else if(whois.diffMos<6)adj-=12;
  else if(whois.diffMos<12)adj-=6;
  else if(whois.diffYrs>5)adj+=5;
  return Math.max(3,Math.min(95,adj));
}

function sendNotification(score,domain){
  if(score>=65) return;
  let title,message;
  if(score<25){title="🔴 MALICIOUS PAGE DETECTED";message=`${domain} is DANGEROUS! Leave immediately.`;}
  else if(score<45){title="🚨 Phishing Detected";message=`${domain} looks like phishing! (Score: ${score}/100)`;}
  else{title="⚠️ Suspicious Page";message=`${domain} has risk factors. Be careful. (Score: ${score}/100)`;}
  chrome.notifications.create({type:"basic",iconUrl:"icons/icon128.png",title,message,priority:score<45?2:1});
}

// ── Full scan pipeline ────────────────────────────────────────────────────────
async function scanURL(url,tabId){
  let score=null;
  let hostname=""; try{hostname=new URL(url).hostname;}catch(e){}

  // Allow/blocklist
  try{
    const data=await chrome.storage.sync.get(["fs_allowlist","fs_blocklist"]);
    const allow=data.fs_allowlist||[], block=data.fs_blocklist||[];
    if(allow.some(x=>url.includes(x.url)||hostname.includes(x.url))){score=100;}
    else if(block.some(x=>url.includes(x.url)||hostname.includes(x.url))){score=0;}
  }catch(e){}

  // WHOIS + VT in parallel
  const [whoisRes,vtRes]=await Promise.allSettled([checkWHOIS(hostname),checkVirusTotal(url)]);
  const whois=whoisRes.status==="fulfilled"?whoisRes.value:{available:false};
  const vt=vtRes.status==="fulfilled"?vtRes.value:{available:false};

  // Backend ML
  if(score===null){
    try{
      const resp=await fetchWithTimeout(CONFIG.BACKEND_URL,
        {method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({url})},
        CONFIG.BACKEND_TIMEOUT);
      if(resp.ok){
        const d=await resp.json();
        if(typeof d.score==="number")          score=Math.round(d.score);
        else if(typeof d.safety_score==="number") score=Math.round(d.safety_score);
        else if(typeof d.prediction==="number")  score=d.prediction<=1?Math.round((1-d.prediction)*100):Math.round(d.prediction);
        if(score!==null)score=Math.max(0,Math.min(100,score));
      }
    }catch(e){score=null;}
  }

  if(score===null){score=heuristicScore(url);}
  score=adjustForAge(score,whois);
  if(vt?.available){
    if(vt.malicious>3)      score=Math.min(score,15);
    else if(vt.malicious>0) score=Math.min(score,35);
    else if(vt.suspicious>2)score=Math.min(score,50);
  }
  score=Math.max(0,Math.min(100,score));

  // Badge
  if(tabId){
    chrome.action.setBadgeText({text:String(score),tabId});
    chrome.action.setBadgeBackgroundColor({color:getBadgeColor(score),tabId});
  }

  // Notification
  let domain=""; try{domain=new URL(url).hostname;}catch(e){}
  sendNotification(score,domain);

  // Save history
  try{
    const verdict=score>=85?"SAFE":score>=65?"PROBABLY SAFE":score>=45?"SUSPICIOUS":score>=25?"PHISHING":"MALICIOUS";
    const cls=score>=65?"safe":score>=45?"warn":"danger";
    const data=await chrome.storage.sync.get("fs_history");
    const hist=data.fs_history||[], now=Date.now();
    if(!hist.find(h=>h.url===url&&now-(h.ts||0)<60000)){
      hist.unshift({url,score,label:verdict,cls,ts:now});
      if(hist.length>500)hist.length=500;
      await chrome.storage.sync.set({fs_history:hist});
    }
  }catch(e){}

  return score;
}

// ── Message handler ───────────────────────────────────────────────────────────
chrome.runtime.onMessage.addListener((message,sender,sendResponse)=>{

  if(message.type==="PROACTIVE_SCAN"){
    const tabId=sender.tab?.id, url=message.url;
    if(!url||!url.startsWith("http")){sendResponse({ok:false});return true;}
    scanURL(url,tabId).then(score=>{
      chrome.runtime.sendMessage({type:"SCAN_COMPLETE",score,url}).catch(()=>{});
      sendResponse({ok:true,score});
    }).catch(()=>sendResponse({ok:false}));
    return true;
  }

  if(message.type==="SCAN_COMPLETE"){
    const score=message.result?.safety_score??message.result?.score??50;
    const tabId=message.tabId;
    if(tabId){chrome.action.setBadgeText({text:String(score),tabId});chrome.action.setBadgeBackgroundColor({color:getBadgeColor(score),tabId});}
    sendResponse({ok:true}); return true;
  }

  if(message.type==="UPDATE_BADGE"){
    const tabId=sender.tab?.id; if(!tabId) return;
    chrome.action.setBadgeText({text:String(message.score),tabId});
    chrome.action.setBadgeBackgroundColor({color:getBadgeColor(message.score),tabId});
    return true;
  }

  if(message.type==="DOWNLOAD_CSV"){
    chrome.downloads.download({url:message.url,filename:message.filename||"fraudshield-scans.csv",saveAs:false,conflictAction:"overwrite"});
    sendResponse({ok:true}); return true;
  }
});

chrome.tabs.onUpdated.addListener((tabId,changeInfo)=>{
  if(changeInfo.status==="loading") chrome.action.setBadgeText({text:"",tabId});
});