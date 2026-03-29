import os
import re
import httpx
import asyncio
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from urllib.parse import urlparse
from ml_model import predict_url

app = FastAPI(title="FraudShield API", version="4.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)

VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")

WHOIS_API      = "https://api.whois.vu/?q="
RDAP_API       = "https://rdap.verisign.com/com/v1/domain/"
WHOIS_JSON_API = "https://whoisjson.com/api/v1/whois?domain="

VT_URL_API    = "https://www.virustotal.com/api/v3/urls"
VT_DOMAIN_API = "https://www.virustotal.com/api/v3/domains/"

SUSPICIOUS_TLDS = {
    ".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".click",
    ".win", ".loan", ".top", ".buzz", ".icu", ".cam",
    ".country", ".stream", ".download", ".racing",
    ".party", ".review", ".science", ".work", ".fit",
    ".pw", ".cc", ".su", ".bid", ".trade", ".date"
}


def extract_domain(url: str) -> str:
    try:
        parsed = urlparse(url)
        domain = parsed.netloc.lower().replace("www.", "")
        return domain.split(":")[0]
    except Exception:
        return url.lower()


def get_parent_domain(domain: str) -> str:
    parts = domain.split(".")
    if len(parts) >= 3 and parts[-2] in ["co", "com", "net", "org", "gov", "ac", "edu"]:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:]) if len(parts) >= 2 else domain


def get_tld(domain: str) -> str:
    parts = domain.split(".")
    return "." + parts[-1] if len(parts) >= 2 else ""


def is_suspicious_domain(features: dict) -> bool:
    """Returns True if the domain has strong red flags that VT should not override."""
    return bool(
        features.get("suspicious_tld") or
        features.get("has_ip") or
        features.get("brand_impersonation") or
        features.get("has_at")
    )


async def fetch_whois_data(domain: str) -> dict:
    root = get_parent_domain(domain)
    result = {
        "registrar": None,
        "created":   None,
        "expires":   None,
        "age_years": None,
        "age_label": None,
        "org":       None,
        "country":   None,
        "source":    None
    }

    # ── Try RDAP ─────────────────────────────────────────────────────
    try:
        tld = root.split(".")[-1]
        rdap_bases = {
            "com": "https://rdap.verisign.com/com/v1/domain/",
            "net": "https://rdap.verisign.com/net/v1/domain/",
            "org": "https://rdap.org/domain/",
            "in":  "https://rdap.registry.in/domain/",
            "io":  "https://rdap.nic.io/domain/",
            "ai":  "https://rdap.nic.ai/domain/",
            "co":  "https://rdap.nic.co/domain/",
            "uk":  "https://rdap.nominet.uk/uk/domain/",
        }
        base = rdap_bases.get(tld, "https://rdap.org/domain/")
        async with httpx.AsyncClient(timeout=6) as client:
            r = await client.get(f"{base}{root}")
            if r.status_code == 200:
                data   = r.json()
                events = data.get("events", [])
                for e in events:
                    if e.get("eventAction") == "registration":
                        created = e.get("eventDate", "")[:10]
                        result["created"] = created
                        if created:
                            from datetime import datetime
                            yr  = int(created[:4])
                            age = datetime.now().year - yr
                            result["age_years"] = age
                            result["age_label"] = f"~{age} years old"
                    if e.get("eventAction") == "expiration":
                        result["expires"] = e.get("eventDate", "")[:10]

                entities = data.get("entities", [])
                for ent in entities:
                    roles = ent.get("roles", [])
                    vcard = ent.get("vcardArray", [])
                    name  = ""
                    if vcard and len(vcard) > 1:
                        for v in vcard[1]:
                            if v[0] == "fn":
                                name = v[3]
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
                    headers={"Accept": "application/json"}
                )
                if r.status_code == 200:
                    text = r.text
                    for pattern in [
                        r"Creation Date:\s*(\d{4}-\d{2}-\d{2})",
                        r"created:\s*(\d{4}-\d{2}-\d{2})",
                        r"Registered On:\s*(\d{4}-\d{2}-\d{2})",
                        r"Registration Time:\s*(\d{4}-\d{2}-\d{2})",
                    ]:
                        m = re.search(pattern, text, re.IGNORECASE)
                        if m:
                            from datetime import datetime
                            created = m.group(1)
                            yr  = int(created[:4])
                            age = datetime.now().year - yr
                            result["created"]   = created
                            result["age_years"] = age
                            result["age_label"] = f"~{age} years old"
                            result["source"]    = "WHOIS"
                            break
                    if not result["registrar"]:
                        m = re.search(r"Registrar:\s*(.+)", text, re.IGNORECASE)
                        if m:
                            result["registrar"] = m.group(1).strip()
                    if not result["org"]:
                        m = re.search(r"Registrant Organization:\s*(.+)", text, re.IGNORECASE)
                        if m:
                            result["org"] = m.group(1).strip()
        except Exception:
            pass

    # ── Fallback: ip-api ──────────────────────────────────────────────
    if not result["org"] or not result["country"]:
        try:
            async with httpx.AsyncClient(timeout=5) as client:
                r = await client.get(
                    f"http://ip-api.com/json/{root}?fields=org,country,isp"
                )
                if r.status_code == 200:
                    data = r.json()
                    if not result["org"] and data.get("org"):
                        result["org"] = data["org"]
                    if not result["country"]:
                        result["country"] = data.get("country")
        except Exception:
            pass

    return result


async def fetch_virustotal_data(domain: str) -> dict:
    if not VIRUSTOTAL_API_KEY:
        return {}
    result = {
        "vt_malicious":   0,
        "vt_suspicious":  0,
        "vt_harmless":    0,
        "vt_undetected":  0,
        "vt_categories":  {},
        "vt_reputation":  None,
        "vt_registrar":   None,
        "vt_created":     None,
        "vt_org":         None,
        "vt_tags":        [],
        "vt_total_votes": {},
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
                data  = r.json().get("data", {})
                attrs = data.get("attributes", {})

                stats = attrs.get("last_analysis_stats", {})
                result["vt_malicious"]  = stats.get("malicious", 0)
                result["vt_suspicious"] = stats.get("suspicious", 0)
                result["vt_harmless"]   = stats.get("harmless", 0)
                result["vt_undetected"] = stats.get("undetected", 0)

                result["vt_categories"]  = attrs.get("categories", {})
                result["vt_reputation"]  = attrs.get("reputation", None)

                whois = attrs.get("whois", "") or ""
                m = re.search(r"Registrar:\s*(.+)", whois, re.IGNORECASE)
                if m:
                    result["vt_registrar"] = m.group(1).strip()

                m = re.search(r"Creation Date:\s*(\d{4}-\d{2}-\d{2})", whois, re.IGNORECASE)
                if m:
                    result["vt_created"] = m.group(1)

                cd = attrs.get("creation_date")
                if cd and not result["vt_created"]:
                    from datetime import datetime
                    result["vt_created"] = datetime.fromtimestamp(cd).strftime("%Y-%m-%d")

                reg = attrs.get("registrar")
                if reg:
                    result["vt_registrar"] = reg

                result["vt_tags"]        = attrs.get("tags", [])
                result["vt_total_votes"] = attrs.get("total_votes", {})

    except Exception as e:
        print(f"VT error: {e}")

    return result


def determine_site_type_from_vt(vt_categories: dict) -> str:
    if not vt_categories:
        return None
    all_cats = " ".join(vt_categories.values()).lower()
    if any(w in all_cats for w in ["search engine", "portal", "search"]):
        return "🔍 Search Engine / Portal"
    if any(w in all_cats for w in ["social network", "social media"]):
        return "📱 Social Media"
    if any(w in all_cats for w in ["shopping", "e-commerce", "online shopping"]):
        return "🛒 Shopping / E-Commerce"
    if any(w in all_cats for w in ["financial", "banking", "finance", "investment"]):
        return "💰 Finance / Banking"
    if any(w in all_cats for w in ["health", "medical", "healthcare", "pharmacy"]):
        return "🏥 Healthcare / Medical"
    if any(w in all_cats for w in ["education", "educational", "school", "university"]):
        return "🎓 Education"
    if any(w in all_cats for w in ["government", "government & politics"]):
        return "🏛️ Government"
    if any(w in all_cats for w in ["news", "media", "journalism"]):
        return "📰 News / Media"
    if any(w in all_cats for w in ["technology", "software", "computer", "web hosting"]):
        return "💻 Technology"
    if any(w in all_cats for w in ["streaming", "entertainment", "music", "video"]):
        return "🎬 Streaming / Entertainment"
    if any(w in all_cats for w in ["travel", "hotel", "airline"]):
        return "✈️ Travel / Hospitality"
    if any(w in all_cats for w in ["malware", "phishing", "spam", "malicious"]):
        return "🚨 Malicious / Phishing"
    if any(w in all_cats for w in ["job", "career", "recruitment"]):
        return "💼 Jobs / Recruitment"
    if any(w in all_cats for w in ["food", "restaurant"]):
        return "🍔 Food / Restaurant"
    first_cat = list(vt_categories.values())[0] if vt_categories else None
    return f"🌐 {first_cat.title()}" if first_cat else None


def merge_enriched_data(base_result: dict, whois: dict, vt: dict, domain: str) -> dict:
    domain_info = base_result.get("domain_info", {})
    age_info    = domain_info.get("age", {})
    features    = base_result.get("features", {})

    # ── Domain Age ────────────────────────────────────────────────────
    if whois.get("age_years") is not None:
        age_info["age_years"]      = whois["age_years"]
        age_info["age_label"]      = whois.get("age_label", f"~{whois['age_years']} years old")
        age_info["estimated_year"] = int(whois["created"][:4]) if whois.get("created") else None
        age_info["trust"]          = "established" if whois["age_years"] > 5 else "relatively new"
        age_info["source"]         = whois.get("source", "WHOIS/RDAP")
    elif vt.get("vt_created"):
        from datetime import datetime
        yr  = int(vt["vt_created"][:4])
        age = datetime.now().year - yr
        age_info["age_years"]      = age
        age_info["age_label"]      = f"~{age} years old"
        age_info["estimated_year"] = yr
        age_info["trust"]          = "established" if age > 5 else "relatively new"
        age_info["source"]         = "VirusTotal"

    # ── Registrar & Org ───────────────────────────────────────────────
    domain_info["registrar"] = (
        whois.get("registrar") or vt.get("vt_registrar") or "Unknown Registrar"
    )
    org = whois.get("org") or vt.get("vt_org") or None
    if org:
        domain_info["organization"] = org
    if whois.get("country"):
        domain_info["country"] = whois["country"]

    # ── Site Type ─────────────────────────────────────────────────────
    vt_site_type = determine_site_type_from_vt(vt.get("vt_categories", {}))
    if vt_site_type and "General" in domain_info.get("site_type", "General"):
        domain_info["site_type"] = vt_site_type

    # ── VirusTotal Score Adjustment ───────────────────────────────────
    if vt:
        domain_info["vt_stats"] = {
            "malicious":  vt.get("vt_malicious", 0),
            "suspicious": vt.get("vt_suspicious", 0),
            "harmless":   vt.get("vt_harmless", 0),
            "undetected": vt.get("vt_undetected", 0),
            "reputation": vt.get("vt_reputation"),
            "tags":       vt.get("vt_tags", []),
            "votes":      vt.get("vt_total_votes", {}),
            "categories": vt.get("vt_categories", {}),
        }

        malicious   = vt.get("vt_malicious", 0)
        suspicious  = vt.get("vt_suspicious", 0)
        harmless    = vt.get("vt_harmless", 0)
        reputation  = vt.get("vt_reputation", 0) or 0
        current_score = base_result.get("safety_score", 50)

        # ── Detect strong red flags — VT cannot override these ────────
        sus_tld      = features.get("suspicious_tld", 0)
        kw_count     = features.get("suspicious_keywords", 0)
        no_https     = not features.get("has_https", 0)
        has_ip       = features.get("has_ip", 0)
        brand_imp    = features.get("brand_impersonation", 0)
        strong_flags = bool(sus_tld or has_ip or brand_imp or (kw_count >= 1 and no_https))

        # VT malicious detections always apply (penalize only, never boost)
        if malicious >= 5:
            current_score = min(current_score, 20)
            base_result["flags"].insert(0, {
                "message":  f"🔴 VirusTotal: {malicious} security vendors flagged as malicious",
                "severity": "high"
            })
        elif malicious >= 1:
            current_score = min(current_score, 40)
            base_result["flags"].insert(0, {
                "message":  f"🔴 VirusTotal: {malicious} vendor(s) flagged as malicious",
                "severity": "high"
            })
        elif suspicious >= 3:
            current_score = min(current_score, 55)
            base_result["flags"].insert(0, {
                "message":  f"🟡 VirusTotal: {suspicious} vendors flagged as suspicious",
                "severity": "medium"
            })
        elif harmless >= 10 and malicious == 0:
            # ── Only boost if NO strong red flags present ─────────────
            if not strong_flags:
                current_score = max(current_score, 80)
            base_result["flags"].append({
                "message":  f"✅ VirusTotal: {harmless} vendors confirmed safe",
                "severity": "safe"
            })

        # Reputation boost/penalty — blocked when strong flags present
        if reputation > 50 and not strong_flags:
            current_score = max(current_score, 75)
        elif reputation < -50:
            current_score = min(current_score, 35)

        # ── Re-apply hard caps after VT adjustment ────────────────────
        # These are absolute maximums that can never be exceeded
        if has_ip:
            current_score = min(current_score, 20)
        if brand_imp:
            current_score = min(current_score, 25)
        if sus_tld and kw_count >= 2:
            current_score = min(current_score, 15)
        if sus_tld and kw_count >= 1:
            current_score = min(current_score, 25)
        if sus_tld and no_https:
            current_score = min(current_score, 30)
        if sus_tld:
            current_score = min(current_score, 44)

        base_result["safety_score"] = max(0, min(100, current_score))
        base_result["category"]     = get_category(base_result["safety_score"])
        base_result["risk_level"]   = get_risk_level(base_result["safety_score"])

    domain_info["age"]      = age_info
    base_result["domain_info"] = domain_info
    return base_result


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


class URLRequest(BaseModel):
    url: str


@app.get("/")
def root():
    return {"status": "FraudShield API v4.1 running"}


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/check")
async def check_url(request: URLRequest):
    url    = request.url
    domain = extract_domain(url)

    # Step 1: ML + heuristic prediction
    base_result = predict_url(url)

    # Step 2: WHOIS + VT in parallel
    try:
        whois_data, vt_data = await asyncio.gather(
            fetch_whois_data(domain),
            fetch_virustotal_data(domain),
            return_exceptions=True
        )
        if isinstance(whois_data, Exception): whois_data = {}
        if isinstance(vt_data,   Exception):  vt_data    = {}
    except Exception:
        whois_data, vt_data = {}, {}

    # Step 3: Merge and return
    enriched = merge_enriched_data(base_result, whois_data, vt_data, domain)
    return enriched


@app.options("/check")
def options_check():
    return {"status": "ok"}