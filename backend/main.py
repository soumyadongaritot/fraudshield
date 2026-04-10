import os
import re
import httpx
import asyncio
import json
import gzip
import whois
from datetime import datetime, timedelta
from pathlib import Path
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from urllib.parse import urlparse
from ml_model import predict_url

app = FastAPI(title="FraudShield API", version="4.2.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)

VIRUSTOTAL_API_KEY   = os.getenv("VIRUSTOTAL_API_KEY", "")
PHISHTANK_CACHE_FILE = Path("phishtank_cache.json")
PHISHTANK_URL        = "http://data.phishtank.com/data/online-valid.json.gz"
_phishtank_urls: set = set()
_phishtank_loaded    = None

SUSPICIOUS_TLDS = {
    ".tk",".ml",".ga",".cf",".gq",".xyz",".click",
    ".win",".loan",".top",".buzz",".icu",".cam",
    ".country",".stream",".download",".racing",
    ".party",".review",".science",".work",".fit",
    ".pw",".cc",".su",".bid",".trade",".date"
}

# ── Known domain ages (instant lookup, no API needed) ────────────────
KNOWN_DOMAIN_AGES = {
    "google.com":1997,"google.co.in":1997,"youtube.com":2005,
    "gmail.com":2004,"yahoo.com":1995,"bing.com":2009,
    "microsoft.com":1991,"office.com":2000,"outlook.com":1997,
    "apple.com":1987,"icloud.com":2012,"amazon.com":1994,
    "amazon.in":2004,"facebook.com":2004,"instagram.com":2010,
    "whatsapp.com":2009,"twitter.com":2006,"x.com":1996,
    "linkedin.com":2002,"reddit.com":2005,"tiktok.com":2016,
    "discord.com":2015,"telegram.org":2013,"netflix.com":1997,
    "spotify.com":2006,"github.com":2007,"gitlab.com":2011,
    "stackoverflow.com":2008,"cloudflare.com":2009,"openai.com":2015,
    "claude.ai":2022,"anthropic.com":2021,"chatgpt.com":2022,
    "paypal.com":1999,"stripe.com":2010,"coinbase.com":2012,
    "binance.com":2017,"sbi.co.in":1955,"hdfcbank.com":1994,
    "icicibank.com":1994,"axisbank.com":1993,"paytm.com":2010,
    "phonepe.com":2015,"flipkart.com":2007,"amazon.in":2004,
    "swiggy.com":2014,"zomato.com":2008,"irctc.co.in":1999,
    "wikipedia.org":2001,"coursera.org":2012,"udemy.com":2010,
    "virustotal.com":2004,"render.com":2019,"vercel.com":2015,
    "netlify.com":2014,"github.io":2007,"uptimerobot.com":2010,
    "bbc.com":1995,"cnn.com":1995,"ndtv.com":1997,
    "timesofindia.com":1838,"thehindu.com":1878,
}


# ══════════════════════════════════════════════════════════════════════
#  HELPERS
# ══════════════════════════════════════════════════════════════════════
def extract_domain(url: str) -> str:
    try:
        parsed = urlparse(url)
        domain = parsed.netloc.lower().replace("www.", "")
        return domain.split(":")[0]
    except Exception:
        return url.lower()


def get_parent_domain(domain: str) -> str:
    parts = domain.split(".")
    if len(parts) >= 3 and parts[-2] in ["co","com","net","org","gov","ac","edu"]:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:]) if len(parts) >= 2 else domain


def get_tld(domain: str) -> str:
    parts = domain.split(".")
    return "." + parts[-1] if len(parts) >= 2 else ""


def get_category(score: int) -> str:
    if score >= 85:   return "Safe"
    elif score >= 65: return "Probably Safe"
    elif score >= 45: return "Suspicious"
    elif score >= 25: return "Likely Phishing"
    else:             return "Malicious"


def get_risk_level(score: int) -> str:
    if score >= 85:   return "LOW RISK"
    elif score >= 65: return "LOW-MEDIUM RISK"
    elif score >= 45: return "MEDIUM RISK"
    elif score >= 25: return "HIGH RISK"
    else:             return "CRITICAL RISK"


# ══════════════════════════════════════════════════════════════════════
#  PHISHTANK
# ══════════════════════════════════════════════════════════════════════
async def load_phishtank():
    global _phishtank_urls, _phishtank_loaded
    now = datetime.now()
    if _phishtank_loaded and (now - _phishtank_loaded) < timedelta(hours=24):
        return
    if PHISHTANK_CACHE_FILE.exists():
        mtime = datetime.fromtimestamp(PHISHTANK_CACHE_FILE.stat().st_mtime)
        if (now - mtime) < timedelta(hours=24):
            try:
                data = json.loads(PHISHTANK_CACHE_FILE.read_text())
                _phishtank_urls   = set(data)
                _phishtank_loaded = now
                print(f"PhishTank: loaded {len(_phishtank_urls)} from cache")
                return
            except Exception:
                pass
    try:
        print("PhishTank: downloading...")
        async with httpx.AsyncClient(timeout=30) as client:
            r = await client.get(PHISHTANK_URL)
            if r.status_code == 200:
                raw  = gzip.decompress(r.content)
                data = json.loads(raw)
                urls = set()
                for entry in data:
                    u = entry.get("url","").lower().strip()
                    if u:
                        urls.add(u)
                        try:
                            d = urlparse(u).netloc.lower().replace("www.","")
                            if d: urls.add(d)
                        except Exception:
                            pass
                _phishtank_urls   = urls
                _phishtank_loaded = now
                PHISHTANK_CACHE_FILE.write_text(json.dumps(list(urls)))
                print(f"PhishTank: {len(urls)} entries loaded")
    except Exception as e:
        print(f"PhishTank error: {e}")


def check_phishtank(url: str, domain: str) -> dict:
    url_lower    = url.lower().strip()
    domain_lower = domain.lower().replace("www.","")
    in_db = url_lower in _phishtank_urls or domain_lower in _phishtank_urls
    return {
        "in_database":  in_db,
        "result":       "phishing" if in_db else "clean",
        "dataset_size": len(_phishtank_urls),
        "last_updated": _phishtank_loaded.strftime("%Y-%m-%d %H:%M") if _phishtank_loaded else "Not loaded"
    }


# ══════════════════════════════════════════════════════════════════════
#  WHOIS / RDAP — with known-domain fast path
# ══════════════════════════════════════════════════════════════════════
async def fetch_whois_data(domain: str) -> dict:
    root   = get_parent_domain(domain)
    result = {
        "registrar":None,"created":None,"expires":None,
        "age_years":None,"age_label":None,
        "org":None,"country":None,"source":None
    }

    # ── Fast path: known domains ──────────────────────────────────────
    check = root.lower()
    if check in KNOWN_DOMAIN_AGES:
        yr  = KNOWN_DOMAIN_AGES[check]
        age = datetime.now().year - yr
        result.update({
            "created":   f"{yr}-01-01",
            "age_years": age,
            "age_label": f"~{age} years old",
            "source":    "Known database"
        })
        return result

    # Also check parent domains (e.g. accounts.google.com → google.com)
    parts = root.split(".")
    for i in range(1, len(parts)):
        parent = ".".join(parts[i:])
        if parent in KNOWN_DOMAIN_AGES:
            yr  = KNOWN_DOMAIN_AGES[parent]
            age = datetime.now().year - yr
            result.update({
                "created":   f"{yr}-01-01",
                "age_years": age,
                "age_label": f"~{age} years old (parent domain)",
                "source":    "Known database"
            })
            return result

    # ── RDAP ──────────────────────────────────────────────────────────
    try:
        tld = root.split(".")[-1]
        rdap_bases = {
            "com":"https://rdap.verisign.com/com/v1/domain/",
            "net":"https://rdap.verisign.com/net/v1/domain/",
            "org":"https://rdap.org/domain/",
            "in": "https://rdap.registry.in/domain/",
            "io": "https://rdap.nic.io/domain/",
            "ai": "https://rdap.nic.ai/domain/",
            "co": "https://rdap.nic.co/domain/",
            "uk": "https://rdap.nominet.uk/uk/domain/",
        }
        base = rdap_bases.get(tld, "https://rdap.org/domain/")
        async with httpx.AsyncClient(timeout=6) as client:
            r = await client.get(f"{base}{root}")
            if r.status_code == 200:
                data   = r.json()
                events = data.get("events", [])
                for e in events:
                    if e.get("eventAction") == "registration":
                        created = e.get("eventDate","")[:10]
                        result["created"] = created
                        if created:
                            yr  = int(created[:4])
                            age = datetime.now().year - yr
                            result["age_years"] = age
                            result["age_label"] = f"~{age} years old"
                    if e.get("eventAction") == "expiration":
                        result["expires"] = e.get("eventDate","")[:10]
                entities = data.get("entities",[])
                for ent in entities:
                    roles = ent.get("roles",[])
                    vcard = ent.get("vcardArray",[])
                    name  = ""
                    if vcard and len(vcard) > 1:
                        for v in vcard[1]:
                            if v[0] == "fn": name = v[3]
                    if "registrar" in roles and name:
                        result["registrar"] = name
                    if "registrant" in roles and name:
                        result["org"] = name
                result["source"] = "RDAP"
    except Exception:
        pass

    # ── Fallback: whois.vu ────────────────────────────────────────────
    if not result["age_years"]:
        try:
            async with httpx.AsyncClient(timeout=6) as client:
                r = await client.get(
                    f"https://api.whois.vu/?q={root}",
                    headers={"Accept":"application/json"}
                )
                if r.status_code == 200:
                    text = r.text
                    for pattern in [
                        r"Creation Date:\s*(\d{4}-\d{2}-\d{2})",
                        r"created:\s*(\d{4}-\d{2}-\d{2})",
                        r"Registered On:\s*(\d{4}-\d{2}-\d{2})",
                    ]:
                        m = re.search(pattern, text, re.IGNORECASE)
                        if m:
                            created = m.group(1)
                            yr  = int(created[:4])
                            age = datetime.now().year - yr
                            result.update({
                                "created":   created,
                                "age_years": age,
                                "age_label": f"~{age} years old",
                                "source":    "WHOIS"
                            })
                            break
                    if not result["registrar"]:
                        m = re.search(r"Registrar:\s*(.+)", text, re.IGNORECASE)
                        if m: result["registrar"] = m.group(1).strip()
        except Exception:
            pass

    # ── Fallback: ip-api for org/country ─────────────────────────────
    if not result["org"] or not result["country"]:
        try:
            async with httpx.AsyncClient(timeout=5) as client:
                r = await client.get(f"http://ip-api.com/json/{root}?fields=org,country,isp")
                if r.status_code == 200:
                    data = r.json()
                    if not result["org"] and data.get("org"):
                        result["org"] = data["org"]
                    if not result["country"]:
                        result["country"] = data.get("country")
        except Exception:
            pass

    return result


# ══════════════════════════════════════════════════════════════════════
#  VIRUSTOTAL
# ══════════════════════════════════════════════════════════════════════
async def fetch_virustotal_data(domain: str) -> dict:
    if not VIRUSTOTAL_API_KEY:
        return {}
    result = {
        "vt_malicious":0,"vt_suspicious":0,
        "vt_harmless":0,"vt_undetected":0,
        "vt_categories":{},"vt_reputation":None,
        "vt_registrar":None,"vt_created":None,
        "vt_org":None,"vt_tags":[],"vt_total_votes":{},
        "vt_total_engines":0,
    }
    root = get_parent_domain(domain)
    try:
        headers = {"x-apikey": VIRUSTOTAL_API_KEY}
        async with httpx.AsyncClient(timeout=10) as client:
            r = await client.get(
                f"https://www.virustotal.com/api/v3/domains/{root}",
                headers=headers
            )
            if r.status_code == 200:
                data  = r.json().get("data",{})
                attrs = data.get("attributes",{})
                stats = attrs.get("last_analysis_stats",{})
                result["vt_malicious"]  = stats.get("malicious",0)
                result["vt_suspicious"] = stats.get("suspicious",0)
                result["vt_harmless"]   = stats.get("harmless",0)
                result["vt_undetected"] = stats.get("undetected",0)
                result["vt_total_engines"] = sum([
                    stats.get("malicious",0), stats.get("suspicious",0),
                    stats.get("harmless",0),  stats.get("undetected",0),
                ])
                result["vt_categories"]  = attrs.get("categories",{})
                result["vt_reputation"]  = attrs.get("reputation",None)
                result["vt_tags"]        = attrs.get("tags",[])
                result["vt_total_votes"] = attrs.get("total_votes",{})
                whois = attrs.get("whois","") or ""
                m = re.search(r"Registrar:\s*(.+)", whois, re.IGNORECASE)
                if m: result["vt_registrar"] = m.group(1).strip()
                m = re.search(r"Creation Date:\s*(\d{4}-\d{2}-\d{2})", whois, re.IGNORECASE)
                if m: result["vt_created"] = m.group(1)
                cd = attrs.get("creation_date")
                if cd and not result["vt_created"]:
                    result["vt_created"] = datetime.fromtimestamp(cd).strftime("%Y-%m-%d")
                reg = attrs.get("registrar")
                if reg: result["vt_registrar"] = reg
    except Exception as e:
        print(f"VT error: {e}")
    return result


def determine_site_type_from_vt(vt_categories: dict) -> str:
    if not vt_categories: return None
    all_cats = " ".join(vt_categories.values()).lower()
    if any(w in all_cats for w in ["search engine","portal","search"]): return "🔍 Search Engine / Portal"
    if any(w in all_cats for w in ["social network","social media"]):   return "📱 Social Media"
    if any(w in all_cats for w in ["shopping","e-commerce"]):           return "🛒 Shopping / E-Commerce"
    if any(w in all_cats for w in ["financial","banking","finance"]):   return "💰 Finance / Banking"
    if any(w in all_cats for w in ["health","medical","healthcare"]):   return "🏥 Healthcare / Medical"
    if any(w in all_cats for w in ["education","school","university"]): return "🎓 Education"
    if any(w in all_cats for w in ["government"]):                      return "🏛️ Government"
    if any(w in all_cats for w in ["news","media","journalism"]):       return "📰 News / Media"
    if any(w in all_cats for w in ["technology","software","computer"]): return "💻 Technology"
    if any(w in all_cats for w in ["streaming","entertainment","music"]): return "🎬 Streaming"
    if any(w in all_cats for w in ["malware","phishing","spam","malicious"]): return "🚨 Malicious"
    first = list(vt_categories.values())[0] if vt_categories else None
    return f"🌐 {first.title()}" if first else None


# ══════════════════════════════════════════════════════════════════════
#  SCORE MERGING
# ══════════════════════════════════════════════════════════════════════
def merge_all_data(base_result, whois, vt, phishtank, domain):
    domain_info = base_result.get("domain_info",{})
    age_info    = domain_info.get("age",{})
    features    = base_result.get("features",{})
    ml_score    = base_result.get("safety_score", 50)

    # ── Domain Age ────────────────────────────────────────────────────
    if whois.get("age_years") is not None:
        age_info["age_years"]      = whois["age_years"]
        age_info["age_label"]      = whois.get("age_label", f"~{whois['age_years']} years old")
        age_info["estimated_year"] = int(whois["created"][:4]) if whois.get("created") else None
        age_info["trust"]          = "established" if whois["age_years"] > 5 else "relatively new"
        age_info["source"]         = whois.get("source","WHOIS/RDAP")
    elif vt.get("vt_created"):
        yr  = int(vt["vt_created"][:4])
        age = datetime.now().year - yr
        age_info["age_years"]      = age
        age_info["age_label"]      = f"~{age} years old"
        age_info["estimated_year"] = yr
        age_info["trust"]          = "established" if age > 5 else "relatively new"
        age_info["source"]         = "VirusTotal"

    # ── Registrar / Org ───────────────────────────────────────────────
    domain_info["registrar"] = whois.get("registrar") or vt.get("vt_registrar") or "Unknown"
    if whois.get("org") or vt.get("vt_org"):
        domain_info["organization"] = whois.get("org") or vt.get("vt_org")
    if whois.get("country"):
        domain_info["country"] = whois["country"]

    # ── Site Type from VT ─────────────────────────────────────────────
    vt_site_type = determine_site_type_from_vt(vt.get("vt_categories",{}))
    if vt_site_type and "General" in domain_info.get("site_type","General"):
        domain_info["site_type"] = vt_site_type

    # ── VT Stats ──────────────────────────────────────────────────────
    vt_malicious  = vt.get("vt_malicious",0)
    vt_suspicious = vt.get("vt_suspicious",0)
    vt_harmless   = vt.get("vt_harmless",0)
    vt_total      = vt.get("vt_total_engines",0)
    vt_reputation = vt.get("vt_reputation",0) or 0

    if vt:
        domain_info["vt_stats"] = {
            "malicious":     vt_malicious,
            "suspicious":    vt_suspicious,
            "harmless":      vt_harmless,
            "undetected":    vt.get("vt_undetected",0),
            "total_engines": vt_total,
            "reputation":    vt_reputation,
            "tags":          vt.get("vt_tags",[]),
            "votes":         vt.get("vt_total_votes",{}),
            "categories":    vt.get("vt_categories",{}),
        }

    # ── Source breakdown for popup ────────────────────────────────────
    base_result["ml_score"] = ml_score
    base_result["phishtank"] = {
        "in_database":  phishtank.get("in_database",False),
        "result":       phishtank.get("result","clean"),
        "dataset_size": phishtank.get("dataset_size",0),
        "last_updated": phishtank.get("last_updated","Unknown"),
    }
    if vt:
        vt_result = f"✅ 0/{vt_total} engines flagged" if vt_malicious == 0 and vt_total > 0 else \
                    f"⚠️ {vt_malicious}/{vt_total} flagged" if vt_malicious > 0 else "⏳ Not checked"
        base_result["virustotal"] = {
            "flagged_engines": vt_malicious,
            "total_engines":   vt_total,
            "result":          vt_result,
            "reputation":      vt_reputation,
        }
    else:
        base_result["virustotal"] = {
            "flagged_engines": 0, "total_engines": 0,
            "result": "⏳ API key not set", "reputation": None,
        }

    # ── Score flags ───────────────────────────────────────────────────
    sus_tld      = features.get("suspicious_tld",0)
    kw_count     = features.get("suspicious_keywords",0)
    no_https     = not features.get("has_https",0)
    has_ip       = features.get("has_ip",0)
    brand_imp    = features.get("brand_impersonation",0)
    strong_flags = bool(sus_tld or has_ip or brand_imp or (kw_count >= 1 and no_https))
    current_score = ml_score

    # PhishTank penalty
    if phishtank.get("in_database"):
        current_score = min(current_score, 15)
        base_result["flags"].insert(0, {"message":"🔴 PhishTank: URL found in phishing database","severity":"high"})
    else:
        base_result["flags"].append({"message":f"✅ PhishTank: Not in database ({phishtank.get('dataset_size',0):,} URLs checked)","severity":"safe"})

    # VT penalty/boost
    if vt_malicious >= 5:
        current_score = min(current_score, 20)
        base_result["flags"].insert(0, {"message":f"🔴 VirusTotal: {vt_malicious} engines flagged malicious","severity":"high"})
    elif vt_malicious >= 1:
        current_score = min(current_score, 40)
        base_result["flags"].insert(0, {"message":f"🔴 VirusTotal: {vt_malicious} engine(s) flagged malicious","severity":"high"})
    elif vt_suspicious >= 3:
        current_score = min(current_score, 55)
        base_result["flags"].insert(0, {"message":f"🟡 VirusTotal: {vt_suspicious} engines suspicious","severity":"medium"})
    elif vt_harmless >= 10 and vt_malicious == 0:
        if not strong_flags:
            current_score = max(current_score, 80)
        base_result["flags"].append({"message":f"✅ VirusTotal: {vt_harmless} vendors confirmed safe","severity":"safe"})

    if vt_reputation > 50 and not strong_flags:
        current_score = max(current_score, 75)
    elif vt_reputation < -50:
        current_score = min(current_score, 35)

    # Hard caps
    if has_ip:                         current_score = min(current_score, 20)
    if brand_imp:                       current_score = min(current_score, 25)
    if sus_tld and kw_count >= 2:      current_score = min(current_score, 15)
    if sus_tld and kw_count >= 1:      current_score = min(current_score, 25)
    if sus_tld and no_https:           current_score = min(current_score, 30)
    if sus_tld:                        current_score = min(current_score, 44)
    if phishtank.get("in_database"):   current_score = min(current_score, 15)

    final_score = max(0, min(100, current_score))
    base_result["safety_score"] = final_score
    base_result["category"]     = get_category(final_score)
    base_result["risk_level"]   = get_risk_level(final_score)
    domain_info["age"]          = age_info
    base_result["domain_info"]  = domain_info
    return base_result


# ══════════════════════════════════════════════════════════════════════
#  STARTUP
# ══════════════════════════════════════════════════════════════════════
@app.on_event("startup")
async def startup_event():
    asyncio.create_task(load_phishtank())


# ══════════════════════════════════════════════════════════════════════
#  ROUTES
# ══════════════════════════════════════════════════════════════════════
class URLRequest(BaseModel):
    url: str


@app.get("/")
def root():
    return {
        "status":           "FraudShield API v4.2 running",
        "phishtank_loaded": len(_phishtank_urls),
        "vt_enabled":       bool(VIRUSTOTAL_API_KEY),
    }


@app.get("/ping")
def ping():
    return {"status": "alive"}


@app.get("/health")
def health():
    return {
        "status":         "ok",
        "phishtank_urls": len(_phishtank_urls),
        "vt_enabled":     bool(VIRUSTOTAL_API_KEY),
    }


@app.get("/whois/{domain}")
async def whois_lookup(domain: str):
    """
    Domain age lookup — uses python-whois library (server-side, no CORS issues).
    Falls back to KNOWN_DOMAIN_AGES for major domains (instant, no network).
    """
    domain = domain.lower().replace("www.", "").strip()
    root   = get_parent_domain(domain)

    # ── Fast path: known domains (instant, no network call) ──────────
    check = root.lower()
    if check in KNOWN_DOMAIN_AGES:
        yr  = KNOWN_DOMAIN_AGES[check]
        age = datetime.now().year - yr
        return {
            "available": True,
            "domain":    root,
            "age_years": age,
            "age_label": f"{age} yrs",
            "created":   f"{yr}-01-01",
            "registrar": None,
            "source":    "known_db"
        }

    # Also check parent domains (e.g. accounts.google.com → google.com)
    parts = root.split(".")
    for i in range(1, len(parts)):
        parent = ".".join(parts[i:])
        if parent in KNOWN_DOMAIN_AGES:
            yr  = KNOWN_DOMAIN_AGES[parent]
            age = datetime.now().year - yr
            return {
                "available": True,
                "domain":    root,
                "age_years": age,
                "age_label": f"{age} yrs",
                "created":   f"{yr}-01-01",
                "registrar": None,
                "source":    "known_db"
            }

    # ── Live lookup via python-whois ──────────────────────────────────
    def do_whois(d):
        try:
            w = whois.whois(d)
            created = w.creation_date
            if isinstance(created, list):
                created = created[0]
            if not created:
                return None
            if isinstance(created, str):
                # try parsing string dates
                for fmt in ["%Y-%m-%d", "%d-%b-%Y", "%Y-%m-%dT%H:%M:%SZ"]:
                    try:
                        created = datetime.strptime(created[:10], fmt[:len(created[:10])])
                        break
                    except Exception:
                        continue
            if not isinstance(created, datetime):
                return None
            age = (datetime.now() - created).days // 365
            registrar = getattr(w, "registrar", None)
            if isinstance(registrar, list):
                registrar = registrar[0] if registrar else None
            return {
                "available": True,
                "domain":    root,
                "age_years": age,
                "age_label": f"{age} yrs",
                "created":   created.strftime("%Y-%m-%d"),
                "registrar": str(registrar) if registrar else None,
                "source":    "whois"
            }
        except Exception:
            return None

    try:
        result = await asyncio.wait_for(
            asyncio.to_thread(do_whois, root),
            timeout=8.0
        )
        if result:
            return result
    except Exception:
        pass

    return {
        "available": False,
        "domain":    root,
        "age_years": None,
        "age_label": "Unknown",
        "created":   None,
        "registrar": None,
        "source":    "failed"
    }


@app.post("/check")
async def check_url(request: URLRequest):
    url    = request.url
    domain = extract_domain(url)

    try:
        base_result, whois_data, vt_data = await asyncio.gather(
            asyncio.to_thread(predict_url, url),
            fetch_whois_data(domain),
            fetch_virustotal_data(domain),
            return_exceptions=True
        )
        if isinstance(base_result, Exception): base_result = predict_url(url)
        if isinstance(whois_data,  Exception): whois_data  = {}
        if isinstance(vt_data,     Exception): vt_data     = {}
    except Exception:
        base_result = predict_url(url)
        whois_data  = {}
        vt_data     = {}

    phishtank_data = check_phishtank(url, domain)
    enriched = merge_all_data(base_result, whois_data, vt_data, phishtank_data, domain)
    return enriched


@app.post("/predict")
async def predict(request: URLRequest):
    return await check_url(request)


@app.options("/check")
def options_check():
    return {"status": "ok"}