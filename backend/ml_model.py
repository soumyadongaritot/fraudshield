import re
import math
import string
from urllib.parse import urlparse, parse_qs
import joblib
import os
from datetime import datetime


def extract_features(url: str) -> dict:
    try:
        parsed  = urlparse(url)
        domain  = parsed.netloc.lower()
        path    = parsed.path.lower()
        query   = parsed.query.lower()
        full    = url.lower()
        features = {}

        features["url_length"]       = len(url)
        features["domain_length"]    = len(domain)
        features["path_length"]      = len(path)
        features["num_dots"]         = url.count(".")
        features["num_hyphens"]      = url.count("-")
        features["num_underscores"]  = url.count("_")
        features["num_slashes"]      = url.count("/")
        features["num_digits"]       = sum(c.isdigit() for c in url)
        features["num_params"]       = len(parse_qs(query))
        features["num_fragments"]    = 1 if "#" in url else 0

        parts = domain.split(".")
        features["num_subdomains"]   = max(0, len(parts) - 2)
        features["domain_entropy"]   = calculate_entropy(domain)
        features["has_port"]         = 1 if parsed.port else 0
        features["has_ip"]           = 1 if re.match(
            r"^\d+\.\d+\.\d+\.\d+$", domain.split(":")[0]) else 0
        features["tld_length"]       = len(parts[-1]) if parts else 0

        features["has_https"]        = 1 if url.startswith("https") else 0
        features["has_at"]           = 1 if "@" in url else 0
        features["has_double_slash"] = 1 if url.count("//") > 1 else 0
        features["has_redirect"]     = 1 if "//" in path else 0
        features["has_punycode"]     = 1 if "xn--" in domain else 0

        PHISH_KEYWORDS = [
            "login","signin","verify","account","update","secure",
            "banking","paypal","password","confirm","free","prize",
            "winner","click","alert","warning","suspended","urgent",
            "limited","expire","blocked","locked","unusual","activity",
            "validate","authenticate","authorize","credential","billing",
            "invoice","payment","refund","cancel","suspend","restore",
            "recover","helpdesk","support","service","customer","security"
        ]
        features["suspicious_keywords"] = sum(
            1 for kw in PHISH_KEYWORDS if kw in full)

        SHORTENERS = [
            "bit.ly","tinyurl","goo.gl","t.co","ow.ly","short.link",
            "rb.gy","cutt.ly","is.gd","buff.ly","ift.tt","dlvr.it",
            "su.pr","twit.ac","snurl.com","cli.gs","twitthis.com"
        ]
        features["is_shortener"] = 1 if any(
            s in domain for s in SHORTENERS) else 0

        FREE_HOSTS = [
            "godaddysites.com","wixsite.com","weebly.com","webflow.io",
            "sites.google.com","blogspot.com","000webhostapp.com",
            "netlify.app","vercel.app","github.io","glitch.me",
            "replit.dev","carrd.co","strikingly.com","jimdo.com",
            "yolasite.com","angelfire.com","tripod.com","bravenet.com",
            "freehosting.com","infinityfree.net","byethost.com",
            "esy.es","atspace.com","site123.me","sitey.me"
        ]
        features["is_free_host"] = 1 if any(
            h in domain for h in FREE_HOSTS) else 0

        SUSPICIOUS_TLDS = [
            ".tk",".ml",".ga",".cf",".gq",".xyz",".click",
            ".win",".loan",".top",".buzz",".icu",".cam",
            ".country",".stream",".download",".racing",
            ".party",".review",".science",".work"
        ]
        tld = "." + domain.split(".")[-1] if "." in domain else ""
        features["suspicious_tld"] = 1 if tld in SUSPICIOUS_TLDS else 0

        BRANDS = [
            "paypal","google","microsoft","amazon","apple","facebook",
            "netflix","instagram","twitter","whatsapp","linkedin",
            "dropbox","adobe","yahoo","outlook","office","windows",
            "gmail","youtube","spotify","uber","airbnb","ebay",
            "bankofamerica","chase","wellsfargo","citibank",
            "sbi","hdfc","icici","axis","paytm","phonepe"
        ]
        domain_clean = domain.replace("www.","")
        known_domains = [b + ".com" for b in BRANDS] + \
                       [b + ".in" for b in BRANDS]
        brand_in_domain  = any(b in domain_clean for b in BRANDS)
        is_actual_brand  = domain_clean in known_domains
        features["brand_impersonation"] = 1 if (
            brand_in_domain and not is_actual_brand) else 0

        domain_alpha = domain_clean.split(".")[0]
        if domain_alpha:
            features["digit_ratio"] = sum(
                c.isdigit() for c in domain_alpha) / len(domain_alpha)
        else:
            features["digit_ratio"] = 0

        features["special_chars"] = sum(
            1 for c in domain if not c.isalnum() and c not in ".-")

        return features

    except Exception:
        return {k: 0 for k in [
            "url_length","domain_length","path_length","num_dots",
            "num_hyphens","num_underscores","num_slashes","num_digits",
            "num_params","num_fragments","num_subdomains","domain_entropy",
            "has_port","has_ip","tld_length","has_https","has_at",
            "has_double_slash","has_redirect","has_punycode",
            "suspicious_keywords","is_shortener","is_free_host",
            "suspicious_tld","brand_impersonation","digit_ratio",
            "special_chars"
        ]}


def calculate_entropy(text: str) -> float:
    if not text:
        return 0.0
    prob = [text.count(c) / len(text) for c in set(text)]
    return -sum(p * math.log2(p) for p in prob)


def heuristic_score(features: dict) -> int:
    score = 100
    if features.get("has_ip"):               score -= 40
    if features.get("has_at"):               score -= 30
    if features.get("brand_impersonation"):  score -= 35
    if features.get("suspicious_tld"):       score -= 25
    if features.get("has_punycode"):         score -= 20
    if not features.get("has_https"):        score -= 20
    if features.get("has_double_slash"):     score -= 15
    if features.get("has_redirect"):         score -= 10
    if features.get("has_port"):             score -= 10
    if features.get("is_shortener"):         score -= 15
    if features.get("is_free_host"):         score -= 20
    kw = features.get("suspicious_keywords", 0)
    score -= min(kw * 10, 40)
    if features.get("num_subdomains", 0) > 2:
        score -= 10 * (features["num_subdomains"] - 2)
    if features.get("url_length", 0) > 75:       score -= 5
    if features.get("url_length", 0) > 100:      score -= 10
    if features.get("url_length", 0) > 150:      score -= 15
    if features.get("domain_entropy", 0) > 3.5:  score -= 10
    if features.get("domain_entropy", 0) > 4:    score -= 15
    if features.get("digit_ratio", 0) > 0.4:     score -= 10
    if features.get("special_chars", 0) > 0:     score -= 10
    return max(0, min(100, score))


def get_flags(features: dict) -> list:
    flags = []
    if features.get("has_ip"):
        flags.append({"message": "🔴 IP address used instead of domain name", "severity": "high"})
    if features.get("brand_impersonation"):
        flags.append({"message": "🔴 Possible brand impersonation detected", "severity": "high"})
    if features.get("has_at"):
        flags.append({"message": "🔴 @ symbol in URL — phishing trick", "severity": "high"})
    if features.get("suspicious_tld"):
        flags.append({"message": "🔴 Suspicious free/untrusted TLD", "severity": "high"})
    if features.get("has_punycode"):
        flags.append({"message": "🔴 Punycode domain — visual spoofing risk", "severity": "high"})
    if not features.get("has_https"):
        flags.append({"message": "🟡 No HTTPS — connection not encrypted", "severity": "medium"})
    if features.get("is_free_host"):
        flags.append({"message": "🟡 Free website builder — common fraud tactic", "severity": "medium"})
    if features.get("is_shortener"):
        flags.append({"message": "🟡 URL shortener hides real destination", "severity": "medium"})
    if features.get("has_double_slash"):
        flags.append({"message": "🟡 Double slash redirect in URL", "severity": "medium"})
    if features.get("num_subdomains", 0) > 2:
        flags.append({"message": f"🟡 Excessive subdomains ({features['num_subdomains']})", "severity": "medium"})
    kw = features.get("suspicious_keywords", 0)
    if kw > 0:
        flags.append({"message": f"🟡 {kw} phishing keyword(s) found in URL", "severity": "medium"})
    if features.get("domain_entropy", 0) > 3.5:
        flags.append({"message": "🟡 Domain name appears randomly generated", "severity": "medium"})
    if features.get("digit_ratio", 0) > 0.4:
        flags.append({"message": "🟡 High digit ratio in domain name", "severity": "medium"})
    if features.get("url_length", 0) > 100:
        flags.append({"message": f"⚪ Very long URL ({features['url_length']} chars)", "severity": "low"})
    if features.get("has_port"):
        flags.append({"message": "⚪ Non-standard port in URL", "severity": "low"})
    if features.get("special_chars", 0) > 0:
        flags.append({"message": "⚪ Special characters in domain", "severity": "low"})
    if not flags:
        flags.append({"message": "✅ No suspicious patterns detected", "severity": "safe"})
    return flags


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


def get_tld(domain: str) -> str:
    parts = domain.split(".")
    return "." + parts[-1] if len(parts) >= 2 else "unknown"


def estimate_domain_age(domain: str) -> dict:
    d = domain.replace("www.", "").lower()

    KNOWN_DOMAINS = {
        "google.com": 1997, "google.co.in": 2004,
        "youtube.com": 2005, "microsoft.com": 1991,
        "apple.com": 1987, "amazon.com": 1994,
        "amazon.in": 2004, "meta.com": 2021,
        "facebook.com": 2004, "twitter.com": 2006,
        "x.com": 1996, "instagram.com": 2010,
        "linkedin.com": 2002, "reddit.com": 2005,
        "pinterest.com": 2010, "tiktok.com": 2016,
        "snapchat.com": 2011, "whatsapp.com": 2009,
        "telegram.org": 2013, "discord.com": 2015,
        "twitch.tv": 2011, "yahoo.com": 1995,
        "bing.com": 2009, "duckduckgo.com": 2008,
        "ebay.com": 1995, "walmart.com": 1996,
        "etsy.com": 2005, "shopify.com": 2006,
        "flipkart.com": 2007, "myntra.com": 2007,
        "meesho.com": 2015, "snapdeal.com": 2010,
        "ajio.com": 2016, "nykaa.com": 2012,
        "bigbasket.com": 2011, "blinkit.com": 2013,
        "zepto.com": 2021, "swiggy.com": 2014,
        "zomato.com": 2008, "alibaba.com": 1999,
        "aliexpress.com": 2010, "target.com": 1999,
        "paypal.com": 1999, "stripe.com": 2010,
        "razorpay.com": 2014, "paytm.com": 2010,
        "phonepe.com": 2015, "sbi.co.in": 1955,
        "hdfcbank.com": 1994, "icicibank.com": 1994,
        "axisbank.com": 1993, "kotakbank.com": 1985,
        "zerodha.com": 2010, "groww.in": 2016,
        "upstox.com": 2012, "coinbase.com": 2012,
        "binance.com": 2017, "visa.com": 1975,
        "netflix.com": 1997, "spotify.com": 2006,
        "hotstar.com": 2015, "primevideo.com": 2016,
        "disneyplus.com": 2019, "sonyliv.com": 2013,
        "zee5.com": 2018, "jiosaavn.com": 2007,
        "soundcloud.com": 2007, "hulu.com": 2007,
        "github.com": 2007, "gitlab.com": 2011,
        "bitbucket.org": 2008, "stackoverflow.com": 2008,
        "npmjs.com": 2010, "pypi.org": 2003,
        "docker.com": 2013, "cloudflare.com": 2009,
        "digitalocean.com": 2011, "vercel.com": 2015,
        "netlify.com": 2014, "wordpress.com": 2005,
        "wix.com": 2006, "godaddy.com": 1997,
        "virustotal.com": 2004, "kaspersky.com": 1997,
        "norton.com": 1990, "malwarebytes.com": 2004,
        "crowdstrike.com": 2011, "openai.com": 2015,
        "anthropic.com": 2021, "claude.ai": 2022,
        "huggingface.co": 2016, "nvidia.com": 1993,
        "bbc.com": 1995, "cnn.com": 1995,
        "reuters.com": 1995, "bloomberg.com": 1990,
        "ndtv.com": 1997, "thehindu.com": 1878,
        "timesofindia.com": 1838, "hindustantimes.com": 1924,
        "indianexpress.com": 1932, "moneycontrol.com": 1999,
        "techcrunch.com": 2005, "theverge.com": 2011,
        "wikipedia.org": 2001, "coursera.org": 2012,
        "udemy.com": 2010, "edx.org": 2012,
        "khanacademy.org": 2008, "codecademy.com": 2011,
        "freecodecamp.org": 2014, "w3schools.com": 1998,
        "geeksforgeeks.org": 2009, "hackerrank.com": 2009,
        "leetcode.com": 2011, "duolingo.com": 2011,
        "apollohospitals.com": 1983, "practo.com": 2008,
        "1mg.com": 2012, "pharmeasy.in": 2015,
        "webmd.com": 1996, "mayoclinic.org": 1998,
        "who.int": 1948, "cdc.gov": 1946,
        "makemytrip.com": 2000, "goibibo.com": 2009,
        "cleartrip.com": 2006, "irctc.co.in": 1999,
        "airbnb.com": 2008, "booking.com": 1996,
        "expedia.com": 1996, "tripadvisor.com": 2000,
        "notion.so": 2016, "figma.com": 2016,
        "slack.com": 2013, "zoom.us": 2011,
        "dropbox.com": 2007, "adobe.com": 1986,
        "salesforce.com": 1999, "gmail.com": 2004,
        "outlook.com": 1997, "india.gov.in": 2005,
        "mygov.in": 2014, "uidai.gov.in": 2009,
        "incometax.gov.in": 2004, "gst.gov.in": 2017,
        "rbi.org.in": 1935, "sebi.gov.in": 1988,
        "naukri.com": 1997, "indeed.com": 2004,
        "glassdoor.com": 2007, "medium.com": 2012,
        "archive.org": 1996, "neverssl.com": 2016,
        "pnbindia.in": 1895, "bankofbaroda.in": 1908,
        "canarabank.com": 1906, "indusind.com": 1994,
        "yesbank.in": 2004, "rblbank.com": 1943,
        "federalbank.co.in": 1931, "angelone.in": 1996,
        "mastercard.com": 1966, "americanexpress.com": 1850,
        "westernunion.com": 1851, "ebay.com": 1995,
        "bestbuy.com": 1999, "quora.com": 2009,
        "yelp.com": 2004, "flipkart.com": 2007,
        "myntra.com": 2007, "nykaa.com": 2012,
        "bigbasket.com": 2011, "zepto.com": 2021,
        "nptel.ac.in": 2001, "internshala.com": 2010,
        "avg.com": 1991, "bitdefender.com": 2001,
        "sophos.com": 1985, "avast.com": 1988,
        "mcafee.com": 1987, "deepmind.com": 2010,
        "epfindia.gov.in": 2001, "digilocker.gov.in": 2015,
        "wired.com": 1993, "forbes.com": 1917,
        "phonpe.com": 2015, "mobikwik.com": 2009,
        "gaana.com": 2010, "wynk.in": 2014,
    }

    current_year = datetime.now().year

    if d in KNOWN_DOMAINS:
        reg_year  = KNOWN_DOMAINS[d]
        age_years = current_year - reg_year
        return {
            "estimated_year": reg_year,
            "age_years":      age_years,
            "age_label":      f"~{age_years} years old",
            "trust": "established" if age_years > 5 else "relatively new"
        }

    tld = get_tld(d)
    SUSPICIOUS_TLDS = [
        ".tk",".ml",".ga",".cf",".gq",".xyz",".click",
        ".win",".loan",".top",".buzz",".icu",".cam"
    ]
    if tld in SUSPICIOUS_TLDS:
        return {
            "estimated_year": current_year,
            "age_years":      0,
            "age_label":      "Likely very new (<1 year)",
            "trust":          "untrustworthy"
        }

    return {
        "estimated_year": None,
        "age_years":      None,
        "age_label":      "Unknown — WHOIS lookup needed",
        "trust":          "unverified"
    }


def get_site_type(url: str, domain: str) -> str:
    d = domain.replace("www.", "").lower()

    SOCIAL     = ["facebook","twitter","instagram","linkedin","tiktok",
                  "snapchat","pinterest","reddit","youtube","telegram",
                  "whatsapp","discord","twitch","quora","x.com","meta","threads"]
    ECOMMERCE  = ["amazon","ebay","flipkart","shopify","etsy","walmart",
                  "meesho","myntra","ajio","nykaa","snapdeal","bigbasket",
                  "blinkit","zepto","swiggy","zomato","alibaba","aliexpress",
                  "shop","store","cart","buy","mall","market","deals","order"]
    FINANCE    = ["bank","finance","invest","trading","crypto","paypal","stripe",
                  "razorpay","paytm","phonepe","zerodha","groww","upstox",
                  "wallet","money","loan","insurance","mortgage","credit",
                  "sbi","hdfc","icici","axis","kotak","pnb","canara","rbi",
                  "sebi","visa","mastercard","binance","coinbase","stock"]
    HEALTH     = ["health","hospital","clinic","doctor","pharma","medicine",
                  "medical","apollo","fortis","practo","1mg","pharmeasy",
                  "webmd","mayoclinic","who","cdc","dental","therapy",
                  "wellness","fitness","gym","diet","pharmacy","drug"]
    EDU        = ["university","college","school","academy","learn","course",
                  "tutorial","wikipedia","stackoverflow","coursera","udemy",
                  "edx","khanacademy","nptel","codecademy","freecodecamp",
                  "w3schools","geeksforgeeks","hackerrank","leetcode","edu"]
    GOV        = [".gov",".gov.in","government","ministry","official",
                  "india.gov","mygov","uidai","incometax","gst.gov",
                  "epfindia","municipality","parliament","court","police"]
    NEWS       = ["news","times","post","herald","tribune","media","bbc",
                  "cnn","ndtv","hindu","express","reuters","bloomberg",
                  "forbes","techcrunch","theverge","wired","hindustantimes",
                  "indianexpress","livemint","economictimes","moneycontrol"]
    TECH       = ["github","microsoft","google","apple","amazon","cloud",
                  "api","dev","software","tech","app","virustotal","security",
                  "cyber","openai","anthropic","claude","huggingface","nvidia",
                  "docker","kubernetes","aws","azure","cloudflare","heroku",
                  "vercel","netlify","wordpress","wix","godaddy","stackoverflow"]
    STREAM     = ["netflix","hotstar","primevideo","disneyplus","spotify",
                  "jiocinema","sonyliv","zee5","voot","gaana","jiosaavn",
                  "soundcloud","hulu","hbo","music","video","stream",
                  "play","watch","movie","series","podcast","radio"]
    TRAVEL     = ["travel","hotel","flight","booking","airbnb","makemytrip",
                  "goibibo","cleartrip","irctc","expedia","tripadvisor",
                  "agoda","hotels","kayak","skyscanner","vacation","tour"]
    FOOD       = ["food","restaurant","cafe","kitchen","recipe","swiggy",
                  "zomato","ubereats","pizza","burger","menu","dining"]
    REALESTATE = ["realty","property","estate","housing","apartment","rent",
                  "lease","mortgage","magicbricks","99acres","housing.com",
                  "nobroker","zillow","realtor","builder","construction"]
    AUTO       = ["auto","car","bike","vehicle","motor","maruti","hyundai",
                  "tata","mahindra","honda","toyota","bmw","mercedes",
                  "cardekho","carwale","bikewale"]
    JOBS       = ["job","career","recruit","hire","employment","naukri",
                  "indeed","monster","glassdoor","foundit","timesjobs",
                  "internshala","placement","resume","interview"]
    MARKETING  = ["marketing","advertising","ads","seo","digital","campaign",
                  "brand","mailchimp","hubspot","salesforce","analytics",
                  "semrush","agency","consultant","promotion"]
    FREE_BUILD = ["godaddysites","wixsite","weebly","webflow","blogspot",
                  "000webhostapp","netlify.app","vercel.app","github.io",
                  "glitch.me","replit.dev","carrd","strikingly","jimdo"]
    PHISH      = ["verify-account","secure-login","account-update",
                  "confirm-identity","suspended-account","prize-claim",
                  "free-reward","urgent-action","limited-time-offer"]

    if any(s in d for s in FREE_BUILD):  return "⚠️ Free Website Builder"
    if any(s in d for s in PHISH):       return "🚨 Likely Phishing Page"
    if any(s in d for s in SOCIAL):      return "📱 Social Media"
    if any(s in d for s in ECOMMERCE):   return "🛒 Shopping / E-Commerce"
    if any(s in d for s in FINANCE):     return "💰 Finance / Banking"
    if any(s in d for s in HEALTH):      return "🏥 Healthcare / Medical"
    if any(s in d for s in EDU):         return "🎓 Education"
    if any(s in d for s in GOV):         return "🏛️ Government"
    if any(s in d for s in NEWS):        return "📰 News / Media"
    if any(s in d for s in TECH):        return "💻 Technology / Security"
    if any(s in d for s in STREAM):      return "🎬 Streaming / Entertainment"
    if any(s in d for s in TRAVEL):      return "✈️ Travel / Hospitality"
    if any(s in d for s in FOOD):        return "🍔 Food / Restaurant"
    if any(s in d for s in REALESTATE):  return "🏠 Real Estate"
    if any(s in d for s in AUTO):        return "🚗 Automobile"
    if any(s in d for s in JOBS):        return "💼 Jobs / Recruitment"
    if any(s in d for s in MARKETING):   return "📣 Marketing / Advertising"
    return "🌐 General / Unknown"


def get_org_type(domain: str) -> str:
    d   = domain.replace("www.", "").lower()
    tld = get_tld(d)
    if tld in [".gov",".gov.in",".mil",".nic.in"]: return "🏛️ Government"
    if tld in [".edu",".ac.in",".ac.uk",".edu.in"]: return "🎓 Educational"
    if tld in [".org"]:                              return "🤝 Non-Profit / NGO"
    if tld in [".io",".ai",".dev",".tech",".app"]:  return "💻 Tech Startup"
    if tld in [".in",".co.in"]:                     return "🇮🇳 Indian Business"
    if tld in [".uk",".co.uk"]:                     return "🇬🇧 UK Business"
    if tld in [".us"]:                              return "🇺🇸 US Business"
    if tld in [".eu"]:                              return "🇪🇺 European Business"
    if tld in [".com",".co",".net"]:                return "🏢 Commercial Business"
    return "🌍 International"


def get_domain_info(url: str) -> dict:
    parsed    = urlparse(url)
    domain    = parsed.netloc.lower().replace("www.", "")
    tld       = get_tld(domain)
    age_info  = estimate_domain_age(domain)
    site_type = get_site_type(url, domain)
    org_type  = get_org_type(domain)
    protocol  = parsed.scheme.upper()

    TRUSTED_TLDS = [
        ".com",".org",".net",".edu",".gov",".co.uk",
        ".co.in",".in",".ai",".io",".ac.in",".gov.in",
        ".mil",".int",".dev",".app",".tech"
    ]
    SUSPICIOUS_TLDS = [
        ".tk",".ml",".ga",".cf",".gq",".xyz",".click",
        ".win",".loan",".top",".buzz",".icu",".cam"
    ]

    tld_trust = (
        "Trusted TLD"    if tld in TRUSTED_TLDS    else
        "Suspicious TLD" if tld in SUSPICIOUS_TLDS else
        "Neutral TLD"
    )

    return {
        "domain":    domain,
        "tld":       tld,
        "tld_trust": tld_trust,
        "protocol":  protocol,
        "site_type": site_type,
        "org_type":  org_type,
        "age":       age_info,
    }


MODEL_PATH  = "fraud_model.pkl"
SCALER_PATH = "scaler.pkl"


def predict_url(url: str) -> dict:
    features    = extract_features(url)
    domain_info = get_domain_info(url)
    vector      = list(features.values())

    ml_score = None
    if os.path.exists(MODEL_PATH) and os.path.exists(SCALER_PATH):
        try:
            model    = joblib.load(MODEL_PATH)
            scaler   = joblib.load(SCALER_PATH)
            scaled   = scaler.transform([vector])
            prob     = model.predict_proba(scaled)[0]
            ml_score = int(prob[0] * 100)
        except Exception:
            pass

    if ml_score is None and os.path.exists(MODEL_PATH):
        try:
            model    = joblib.load(MODEL_PATH)
            prob     = model.predict_proba([vector])[0]
            ml_score = int(prob[0] * 100)
        except Exception:
            pass

    h_score = heuristic_score(features)

    if ml_score is not None:
        final_score = int(ml_score * 0.6 + h_score * 0.4)
    else:
        final_score = h_score

    if features.get("brand_impersonation"): final_score = min(final_score, 30)
    if features.get("has_ip"):              final_score = min(final_score, 25)
    if features.get("suspicious_tld") and not features.get("has_https"):
        final_score = min(final_score, 35)

    return {
        "url":          url,
        "safety_score": max(0, min(100, final_score)),
        "category":     get_category(final_score),
        "risk_level":   get_risk_level(final_score),
        "flags":        get_flags(features),
        "features":     features,
        "domain_info":  domain_info
    }