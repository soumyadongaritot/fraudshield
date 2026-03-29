import re
import math
import os
from urllib.parse import urlparse, parse_qs
from datetime import datetime
import joblib

# ── MASTER TRUSTED DOMAINS WHITELIST ─────────────────────────────────
TRUSTED_DOMAINS = {
    # Google
    "google.com","google.co.in","google.co.uk","google.com.au",
    "gmail.com","youtube.com","drive.google.com","docs.google.com",
    "maps.google.com","accounts.google.com","mail.google.com",
    "cloud.google.com","scholar.google.com","play.google.com",
    "search.google.com","in.search.yahoo.com",
    # Yahoo
    "yahoo.com","yahoo.co.in","yahoo.co.uk","search.yahoo.com",
    "in.search.yahoo.com","mail.yahoo.com","finance.yahoo.com",
    "news.yahoo.com","sports.yahoo.com",
    # Microsoft
    "microsoft.com","office.com","outlook.com","live.com",
    "hotmail.com","bing.com","msn.com","xbox.com",
    "azure.microsoft.com","teams.microsoft.com",
    "onedrive.live.com","account.microsoft.com",
    "login.microsoftonline.com","portal.azure.com",
    # Apple
    "apple.com","icloud.com","developer.apple.com",
    "support.apple.com","store.apple.com","appleid.apple.com",
    # Amazon
    "amazon.com","amazon.in","amazon.co.uk","amazon.de",
    "aws.amazon.com","prime.amazon.com","payments.amazon.in",
    "sellercentral.amazon.in",
    # Meta / Social
    "facebook.com","instagram.com","whatsapp.com","messenger.com",
    "meta.com","twitter.com","x.com","linkedin.com","reddit.com",
    "pinterest.com","tumblr.com","snapchat.com","tiktok.com",
    "discord.com","twitch.tv","telegram.org","signal.org",
    "threads.net","quora.com",
    # Entertainment
    "netflix.com","spotify.com","hulu.com","disneyplus.com",
    "primevideo.com","hotstar.com","sonyliv.com","zee5.com",
    "jiosaavn.com","gaana.com","wynk.in","soundcloud.com",
    "pandora.com","deezer.com","tidal.com","vimeo.com",
    # Tech / Dev
    "github.com","gitlab.com","bitbucket.org","stackoverflow.com",
    "cloudflare.com","digitalocean.com","heroku.com","vercel.com",
    "netlify.com","render.com","railway.app","supabase.com",
    "notion.so","figma.com","canva.com","slack.com","zoom.us",
    "dropbox.com","box.com","adobe.com","shopify.com","wordpress.com",
    "npmjs.com","pypi.org","docker.com","kubernetes.io",
    # AI
    "claude.ai","anthropic.com","openai.com","chat.openai.com",
    "chatgpt.com","huggingface.co","midjourney.com","perplexity.ai",
    "gemini.google.com","copilot.microsoft.com","stability.ai",
    # Finance Global
    "paypal.com","stripe.com","chase.com","bankofamerica.com",
    "wellsfargo.com","citibank.com","capitalone.com","discover.com",
    "americanexpress.com","goldmansachs.com","fidelity.com",
    "schwab.com","vanguard.com","robinhood.com","coinbase.com",
    "binance.com","kraken.com","venmo.com","cashapp.com","zelle.com",
    "visa.com","mastercard.com","westernunion.com",
    # Indian Finance
    "sbi.co.in","onlinesbi.sbi.co.in","hdfcbank.com",
    "netbanking.hdfcbank.com","icicibank.com","axisbank.com",
    "kotakbank.com","yesbank.in","pnbindia.in","canarabank.com",
    "federalbank.co.in","rblbank.com","indusind.com","idfcfirstbank.com",
    "paytm.com","phonepe.com","razorpay.com","mobikwik.com",
    "zerodha.com","groww.in","upstox.com","angelone.in",
    "policybazaar.com","coverfox.com","acko.com",
    "rbi.org.in","sebi.gov.in","nse.com","bseindia.com",
    # Indian Shopping
    "flipkart.com","myntra.com","snapdeal.com","meesho.com",
    "nykaa.com","bigbasket.com","grofers.com","blinkit.com",
    "swiggy.com","zomato.com","dunzo.com","zepto.com",
    "indiamart.com","tradeindia.com","justdial.com","ajio.com",
    # Indian Travel
    "irctc.co.in","makemytrip.com","goibibo.com","yatra.com",
    "cleartrip.com","redbus.in","rapido.bike","ola.com",
    # Indian News
    "ndtv.com","timesofindia.com","thehindu.com","hindustantimes.com",
    "indianexpress.com","livemint.com","businessstandard.com",
    "economictimes.indiatimes.com","news18.com","moneycontrol.com",
    "indiatimes.com","aajtak.in","abplive.com","zeenews.india.com",
    # Indian Govt
    "india.gov.in","mygov.in","uidai.gov.in","incometax.gov.in",
    "gst.gov.in","epfindia.gov.in","digilocker.gov.in","mca.gov.in",
    "nic.in","nptel.ac.in","irda.gov.in","trai.gov.in",
    # Shopping Global
    "ebay.com","etsy.com","walmart.com","target.com","bestbuy.com",
    "costco.com","ikea.com","wayfair.com","aliexpress.com","alibaba.com",
    # Travel Global
    "booking.com","airbnb.com","expedia.com","tripadvisor.com",
    "hotels.com","kayak.com","skyscanner.com","uber.com","lyft.com",
    "agoda.com","airasia.com","emirates.com","singaporeair.com",
    # News Global
    "nytimes.com","bbc.com","bbc.co.uk","cnn.com","reuters.com",
    "theguardian.com","forbes.com","bloomberg.com","wsj.com",
    "washingtonpost.com","techcrunch.com","wired.com",
    "theverge.com","arstechnica.com","apnews.com",
    # Education
    "wikipedia.org","coursera.org","udemy.com","edx.org",
    "khanacademy.org","duolingo.com","codecademy.com",
    "freecodecamp.org","w3schools.com","geeksforgeeks.org",
    "hackerrank.com","leetcode.com","harvard.edu","mit.edu",
    "stanford.edu","britannica.com","archive.org","medium.com",
    # Health
    "who.int","cdc.gov","nih.gov","mayoclinic.org","webmd.com",
    "healthline.com","apollohospitals.com","practo.com",
    "1mg.com","pharmeasy.in","netmeds.com",
    # Security
    "virustotal.com","kaspersky.com","norton.com","malwarebytes.com",
    "crowdstrike.com","avg.com","bitdefender.com","avast.com",
    "mcafee.com","sophos.com","trendmicro.com",
    # Other
    "duckduckgo.com","ecosia.org","wolframalpha.com","internshala.com",
    "naukri.com","indeed.com","glassdoor.com","monster.com",
    "yelp.com","trustpilot.com","imdb.com","goodreads.com",
    "producthunt.com","trello.com","asana.com","hubspot.com",
    "salesforce.com","mailchimp.com","sendinblue.com",
    "uptimerobot.com","dashboard.uptimerobot.com",
}


def is_trusted_domain(domain: str) -> bool:
    domain = domain.lower().replace("www.", "")
    if domain in TRUSTED_DOMAINS:
        return True
    parts = domain.split(".")
    for i in range(1, len(parts)):
        parent = ".".join(parts[i:])
        if parent in TRUSTED_DOMAINS:
            return True
    return False


def extract_features(url: str) -> dict:
    try:
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        path   = parsed.path.lower()
        query  = parsed.query.lower()
        full   = url.lower()
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
        domain_clean = domain.replace("www.", "")
        trusted = is_trusted_domain(domain_clean)
        if trusted:
            features["suspicious_keywords"] = sum(
                1 for kw in PHISH_KEYWORDS if kw in domain_clean)
        else:
            features["suspicious_keywords"] = sum(
                1 for kw in PHISH_KEYWORDS if kw in full)

        SHORTENERS = [
            "bit.ly","tinyurl","goo.gl","t.co","ow.ly","short.link",
            "rb.gy","cutt.ly","is.gd","buff.ly","ift.tt","dlvr.it",
        ]
        features["is_shortener"] = 1 if any(s in domain for s in SHORTENERS) else 0

        FREE_HOSTS = [
            "godaddysites.com","wixsite.com","weebly.com","webflow.io",
            "blogspot.com","000webhostapp.com","glitch.me",
            "replit.dev","carrd.co","strikingly.com","jimdo.com",
            "yolasite.com","angelfire.com","tripod.com",
        ]
        features["is_free_host"] = 1 if any(h in domain for h in FREE_HOSTS) else 0

        SUSPICIOUS_TLDS = [
            ".tk",".ml",".ga",".cf",".gq",".xyz",".click",
            ".win",".loan",".top",".buzz",".icu",".cam",
            ".country",".stream",".download",".racing",
            ".party",".review",".science",".work",".fit",
            ".pw",".cc",".su",".bid",".trade",".date"
        ]
        tld = "." + domain.split(".")[-1] if "." in domain else ""
        features["suspicious_tld"] = 1 if tld in SUSPICIOUS_TLDS else 0

        BRANDS = [
            "paypal","google","microsoft","amazon","apple","facebook",
            "netflix","instagram","twitter","whatsapp","linkedin",
            "dropbox","adobe","yahoo","outlook","office","windows",
            "gmail","youtube","spotify","uber","airbnb","ebay",
            "bankofamerica","chase","wellsfargo","citibank",
            "sbi","hdfc","icici","axis","paytm","phonepe",
            "flipkart","myntra","swiggy","zomato","zerodha","groww"
        ]
        brand_in_domain = any(b in domain_clean for b in BRANDS)
        features["brand_impersonation"] = 1 if (brand_in_domain and not trusted) else 0

        domain_alpha = domain_clean.split(".")[0]
        if domain_alpha:
            features["digit_ratio"] = sum(
                c.isdigit() for c in domain_alpha) / len(domain_alpha)
        else:
            features["digit_ratio"] = 0

        features["special_chars"] = sum(
            1 for c in domain if not c.isalnum() and c not in ".-")
        features["is_trusted_domain"] = 1 if trusted else 0

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
            "special_chars","is_trusted_domain"
        ]}


def calculate_entropy(text: str) -> float:
    if not text:
        return 0.0
    prob = [text.count(c) / len(text) for c in set(text)]
    return -sum(p * math.log2(p) for p in prob)


def heuristic_score(features: dict, is_trusted: bool) -> int:
    # Trusted domains always get high score
    if is_trusted:
        score = 95
        if features.get("has_ip"):       score -= 40
        if features.get("has_at"):       score -= 30
        if features.get("has_punycode"): score -= 10
        return max(60, min(100, score))

    # Unknown domains — full strict scoring
    score = 100

    # ── Critical signals (very strong deductions) ──────────────────
    if features.get("has_ip"):               score -= 50
    if features.get("has_at"):               score -= 40
    if features.get("brand_impersonation"):  score -= 45
    if features.get("suspicious_tld"):       score -= 40  # was 25 → now 40
    if features.get("has_punycode"):         score -= 30

    # ── High signals ───────────────────────────────────────────────
    if not features.get("has_https"):        score -= 30  # was 20 → now 30
    if features.get("is_free_host"):         score -= 30  # was 20 → now 30
    if features.get("is_shortener"):         score -= 20
    if features.get("has_double_slash"):     score -= 20
    if features.get("has_redirect"):         score -= 15
    if features.get("has_port"):             score -= 15

    # ── Keyword penalty ─────────────────────────────────────────────
    kw = features.get("suspicious_keywords", 0)
    score -= min(kw * 12, 48)  # was 10 per kw → now 12, max 48

    # ── Subdomain penalty ───────────────────────────────────────────
    if features.get("num_subdomains", 0) > 2:
        score -= 15 * (features["num_subdomains"] - 2)

    # ── URL length penalty ──────────────────────────────────────────
    if features.get("url_length", 0) > 75:   score -= 5
    if features.get("url_length", 0) > 100:  score -= 10
    if features.get("url_length", 0) > 150:  score -= 15

    # ── Entropy penalty ─────────────────────────────────────────────
    if features.get("domain_entropy", 0) > 3.5: score -= 10
    if features.get("domain_entropy", 0) > 4.0: score -= 15

    # ── Other signals ───────────────────────────────────────────────
    if features.get("digit_ratio", 0) > 0.4:    score -= 15
    if features.get("special_chars", 0) > 0:    score -= 10

    return max(0, min(100, score))


def get_flags(features: dict, is_trusted: bool) -> list:
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
    if not features.get("has_https") and not is_trusted:
        flags.append({"message": "🟡 No HTTPS — connection not encrypted", "severity": "medium"})
    if features.get("is_free_host"):
        flags.append({"message": "🟡 Free website builder — common fraud tactic", "severity": "medium"})
    if features.get("is_shortener"):
        flags.append({"message": "🟡 URL shortener hides real destination", "severity": "medium"})
    if features.get("has_double_slash"):
        flags.append({"message": "🟡 Double slash redirect in URL", "severity": "medium"})
    if features.get("num_subdomains", 0) > 2 and not is_trusted:
        flags.append({"message": f"🟡 Excessive subdomains ({features['num_subdomains']})", "severity": "medium"})
    kw = features.get("suspicious_keywords", 0)
    if kw > 0 and not is_trusted:
        flags.append({"message": f"🟡 {kw} phishing keyword(s) found in URL", "severity": "medium"})
    if features.get("domain_entropy", 0) > 3.5 and not is_trusted:
        flags.append({"message": "🟡 Domain name appears randomly generated", "severity": "medium"})
    if features.get("digit_ratio", 0) > 0.4 and not is_trusted:
        flags.append({"message": "🟡 High digit ratio in domain name", "severity": "medium"})
    if features.get("url_length", 0) > 100 and not is_trusted:
        flags.append({"message": f"⚪ Very long URL ({features['url_length']} chars)", "severity": "low"})
    if features.get("has_port"):
        flags.append({"message": "⚪ Non-standard port in URL", "severity": "low"})
    if features.get("special_chars", 0) > 0 and not is_trusted:
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
        "google.com": 1997, "google.co.in": 1997, "google.co.uk": 1997,
        "youtube.com": 2005, "gmail.com": 2004, "yahoo.com": 1995,
        "bing.com": 2009, "duckduckgo.com": 2008, "ask.com": 1996,
        "baidu.com": 2000, "yandex.com": 1997,
        "microsoft.com": 1991, "office.com": 2000, "outlook.com": 1997,
        "live.com": 2005, "hotmail.com": 1996, "msn.com": 1995,
        "azure.microsoft.com": 2010, "xbox.com": 2000, "skype.com": 2003,
        "apple.com": 1987, "icloud.com": 2012, "itunes.com": 1999,
        "amazon.com": 1994, "amazon.in": 2004, "amazon.co.uk": 1998,
        "aws.amazon.com": 2006,
        "facebook.com": 2004, "instagram.com": 2010, "whatsapp.com": 2009,
        "twitter.com": 2006, "x.com": 1996, "linkedin.com": 2002,
        "reddit.com": 2005, "pinterest.com": 2010, "snapchat.com": 2011,
        "tiktok.com": 2016, "discord.com": 2015, "telegram.org": 2013,
        "signal.org": 2014, "twitch.tv": 2011, "quora.com": 2009,
        "tumblr.com": 2007, "threads.net": 2023, "meta.com": 2021,
        "netflix.com": 1997, "spotify.com": 2006, "hulu.com": 2007,
        "disneyplus.com": 2019, "primevideo.com": 2016, "hotstar.com": 2015,
        "sonyliv.com": 2013, "zee5.com": 2018, "jiosaavn.com": 2007,
        "gaana.com": 2010, "wynk.in": 2014, "soundcloud.com": 2007,
        "pandora.com": 2000, "deezer.com": 2007, "tidal.com": 2014,
        "vimeo.com": 2004,
        "github.com": 2007, "gitlab.com": 2011, "bitbucket.org": 2008,
        "stackoverflow.com": 2008, "cloudflare.com": 2009,
        "digitalocean.com": 2011, "heroku.com": 2007, "vercel.com": 2015,
        "netlify.com": 2014, "render.com": 2019, "notion.so": 2016,
        "figma.com": 2016, "canva.com": 2013, "slack.com": 2013,
        "zoom.us": 2011, "dropbox.com": 2007, "box.com": 2005,
        "adobe.com": 1986, "shopify.com": 2006, "wordpress.com": 2005,
        "npmjs.com": 2010, "pypi.org": 2003, "docker.com": 2013,
        "huggingface.co": 2016, "medium.com": 2012,
        "openai.com": 2015, "claude.ai": 2022, "anthropic.com": 2021,
        "chatgpt.com": 2022, "gemini.google.com": 2023,
        "perplexity.ai": 2022, "midjourney.com": 2021,
        "paypal.com": 1999, "stripe.com": 2010, "coinbase.com": 2012,
        "binance.com": 2017, "robinhood.com": 2013, "visa.com": 1975,
        "mastercard.com": 1966, "americanexpress.com": 1850,
        "westernunion.com": 1851, "chase.com": 1799, "citibank.com": 1812,
        "bankofamerica.com": 1904, "wellsfargo.com": 1852,
        "sbi.co.in": 1955, "hdfcbank.com": 1994, "icicibank.com": 1994,
        "axisbank.com": 1993, "kotakbank.com": 1985, "yesbank.in": 2004,
        "pnbindia.in": 1895, "canarabank.com": 1906, "rblbank.com": 1943,
        "federalbank.co.in": 1931, "indusind.com": 1994,
        "paytm.com": 2010, "phonepe.com": 2015, "razorpay.com": 2014,
        "mobikwik.com": 2009, "zerodha.com": 2010, "groww.in": 2016,
        "upstox.com": 2012, "angelone.in": 1996,
        "rbi.org.in": 1935, "sebi.gov.in": 1988,
        "flipkart.com": 2007, "myntra.com": 2007, "snapdeal.com": 2010,
        "meesho.com": 2015, "nykaa.com": 2012, "bigbasket.com": 2011,
        "blinkit.com": 2013, "zepto.com": 2021, "swiggy.com": 2014,
        "zomato.com": 2008, "ajio.com": 2016, "indiamart.com": 1999,
        "irctc.co.in": 1999, "makemytrip.com": 2000, "goibibo.com": 2009,
        "cleartrip.com": 2006, "redbus.in": 2006, "ola.com": 2010,
        "ndtv.com": 1997, "timesofindia.com": 1838, "thehindu.com": 1878,
        "hindustantimes.com": 1924, "indianexpress.com": 1932,
        "livemint.com": 2007, "moneycontrol.com": 1999,
        "economictimes.indiatimes.com": 1961, "news18.com": 1999,
        "india.gov.in": 2005, "mygov.in": 2014, "uidai.gov.in": 2009,
        "incometax.gov.in": 2004, "gst.gov.in": 2017,
        "epfindia.gov.in": 2001, "digilocker.gov.in": 2015,
        "ebay.com": 1995, "etsy.com": 2005, "walmart.com": 1996,
        "target.com": 1999, "bestbuy.com": 1999, "aliexpress.com": 2010,
        "alibaba.com": 1999, "ikea.com": 1997, "wayfair.com": 2002,
        "booking.com": 1996, "airbnb.com": 2008, "expedia.com": 1996,
        "tripadvisor.com": 2000, "hotels.com": 1991, "kayak.com": 2004,
        "skyscanner.com": 2003, "uber.com": 2009, "lyft.com": 2012,
        "bbc.com": 1995, "cnn.com": 1995, "reuters.com": 1851,
        "nytimes.com": 1851, "theguardian.com": 1821, "forbes.com": 1917,
        "bloomberg.com": 1990, "wsj.com": 1889, "techcrunch.com": 2005,
        "theverge.com": 2011, "wired.com": 1993, "arstechnica.com": 1998,
        "wikipedia.org": 2001, "coursera.org": 2012, "udemy.com": 2010,
        "edx.org": 2012, "khanacademy.org": 2008, "duolingo.com": 2011,
        "codecademy.com": 2011, "freecodecamp.org": 2014,
        "w3schools.com": 1998, "geeksforgeeks.org": 2009,
        "hackerrank.com": 2009, "leetcode.com": 2011,
        "britannica.com": 1768, "archive.org": 1996, "nptel.ac.in": 2001,
        "who.int": 1948, "cdc.gov": 1946, "nih.gov": 1993,
        "mayoclinic.org": 1998, "webmd.com": 1996, "healthline.com": 2006,
        "apollohospitals.com": 1983, "practo.com": 2008,
        "1mg.com": 2012, "pharmeasy.in": 2015,
        "virustotal.com": 2004, "kaspersky.com": 1997, "norton.com": 1990,
        "malwarebytes.com": 2004, "crowdstrike.com": 2011,
        "avg.com": 1991, "bitdefender.com": 2001, "avast.com": 1988,
        "mcafee.com": 1987, "sophos.com": 1985,
        "naukri.com": 1997, "indeed.com": 2004, "glassdoor.com": 2007,
        "internshala.com": 2010, "monster.com": 1994,
        "producthunt.com": 2013, "trello.com": 2011, "asana.com": 2008,
        "hubspot.com": 2006, "salesforce.com": 1999,
        "mailchimp.com": 2001, "imdb.com": 1990, "goodreads.com": 2007,
        "trustpilot.com": 2007, "yelp.com": 2004,
        "uptimerobot.com": 2010,
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

    # Smart parent domain lookup
    parts = d.split(".")
    for i in range(1, len(parts)):
        parent = ".".join(parts[i:])
        if parent in KNOWN_DOMAINS:
            reg_year  = KNOWN_DOMAINS[parent]
            age_years = current_year - reg_year
            return {
                "estimated_year": reg_year,
                "age_years":      age_years,
                "age_label":      f"~{age_years} years old (parent domain)",
                "trust": "established" if age_years > 5 else "relatively new"
            }

    tld = get_tld(d)
    SUSPICIOUS_TLDS = [".tk",".ml",".ga",".cf",".gq",".xyz",
                       ".click",".win",".loan",".top",".buzz",".icu",
                       ".pw",".cc",".su",".fit",".bid"]
    if tld in SUSPICIOUS_TLDS:
        return {"estimated_year": current_year, "age_years": 0,
                "age_label": "Likely very new (<1 year)", "trust": "untrustworthy"}

    if tld in [".gov", ".gov.in", ".nic.in"]:
        return {"estimated_year": 2000, "age_years": current_year - 2000,
                "age_label": f"~{current_year - 2000} years old (govt estimate)",
                "trust": "established"}
    if tld in [".edu", ".ac.in", ".edu.in"]:
        return {"estimated_year": 2000, "age_years": current_year - 2000,
                "age_label": f"~{current_year - 2000} years old (edu estimate)",
                "trust": "established"}

    return {"estimated_year": None, "age_years": None,
            "age_label": "Unknown — WHOIS lookup needed", "trust": "unverified"}


def get_site_type(url: str, domain: str) -> str:
    full_d = domain.replace("www.", "").lower()
    parts  = full_d.split(".")
    all_domains = [full_d] + [".".join(parts[i:]) for i in range(1, len(parts))]
    d = " ".join(all_domains)

    SEARCH     = ["google","yahoo","bing","duckduckgo","baidu","yandex","ecosia","search"]
    SOCIAL     = ["facebook","twitter","instagram","linkedin","tiktok","snapchat",
                  "pinterest","reddit","youtube","telegram","whatsapp","discord",
                  "twitch","quora","meta","threads","signal","tumblr"]
    ECOMMERCE  = ["amazon","ebay","flipkart","shopify","etsy","walmart","meesho",
                  "myntra","ajio","nykaa","snapdeal","bigbasket","blinkit","zepto",
                  "swiggy","zomato","alibaba","aliexpress","shop","store","cart"]
    FINANCE    = ["bank","finance","invest","trading","crypto","paypal","stripe",
                  "razorpay","paytm","phonepe","zerodha","groww","upstox","wallet",
                  "sbi","hdfc","icici","axis","kotak","rbi","sebi","visa",
                  "mastercard","binance","coinbase","stock","insurance","loan"]
    HEALTH     = ["health","hospital","clinic","doctor","pharma","medicine",
                  "apollo","practo","1mg","pharmeasy","webmd","mayoclinic","who","cdc"]
    EDU        = ["university","college","school","academy","learn","course",
                  "wikipedia","stackoverflow","coursera","udemy","edx",
                  "khanacademy","nptel","codecademy","freecodecamp",
                  "w3schools","geeksforgeeks","hackerrank","leetcode","edu"]
    GOV        = [".gov",".gov.in","government","ministry","official",
                  "india.gov","mygov","uidai","incometax","gst.gov","epfindia"]
    NEWS       = ["news","times","post","herald","tribune","bbc","cnn","ndtv",
                  "hindu","express","reuters","bloomberg","forbes","techcrunch",
                  "theverge","wired","hindustantimes","indianexpress","livemint"]
    TECH       = ["github","microsoft","google","apple","amazon","cloud","api",
                  "dev","software","tech","virustotal","security","cyber",
                  "openai","anthropic","claude","huggingface","nvidia","docker",
                  "vercel","netlify","render","wordpress","cloudflare","stackoverflow",
                  "uptimerobot"]
    STREAM     = ["netflix","hotstar","primevideo","disneyplus","spotify",
                  "sonyliv","zee5","gaana","jiosaavn","soundcloud","hulu","music",
                  "video","stream","movie","series","podcast"]
    TRAVEL     = ["travel","hotel","flight","booking","airbnb","makemytrip",
                  "goibibo","cleartrip","irctc","expedia","tripadvisor","agoda"]
    JOBS       = ["job","career","recruit","hire","naukri","indeed","glassdoor",
                  "foundit","internshala","monster","placement","resume"]
    FREE_BUILD = ["godaddysites","wixsite","weebly","webflow","blogspot",
                  "000webhostapp","glitch.me","replit","carrd","strikingly","jimdo"]
    PHISH      = ["verify-account","secure-login","account-update",
                  "confirm-identity","suspended-account","prize-claim",
                  "free-reward","urgent-action","limited-time-offer"]

    if any(s in d for s in FREE_BUILD):  return "⚠️ Free Website Builder"
    if any(s in d for s in PHISH):       return "🚨 Likely Phishing Page"
    if any(s in d for s in SEARCH):      return "🔍 Search Engine / Portal"
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
    if any(s in d for s in JOBS):        return "💼 Jobs / Recruitment"
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

    TRUSTED_TLDS = [".com",".org",".net",".edu",".gov",".co.uk",
                    ".co.in",".in",".ai",".io",".ac.in",".gov.in",
                    ".mil",".int",".dev",".app",".tech"]
    SUSPICIOUS_TLDS = [".tk",".ml",".ga",".cf",".gq",".xyz",".click",
                       ".win",".loan",".top",".buzz",".icu",".cam"]
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

    parsed  = urlparse(url)
    domain  = parsed.netloc.lower().replace("www.", "")
    trusted = is_trusted_domain(domain)

    # ── TRUSTED DOMAIN FAST PATH ──────────────────────────────────────
    if trusted:
        base_score = 92
        if features.get("has_ip"): base_score -= 40
        if features.get("has_at"): base_score -= 30
        final_score = max(75, min(100, base_score))
        return {
            "url":          url,
            "safety_score": final_score,
            "category":     get_category(final_score),
            "risk_level":   get_risk_level(final_score),
            "flags":        get_flags(features, trusted),
            "features":     features,
            "domain_info":  domain_info
        }

    # ── ML MODEL for unknown domains ──────────────────────────────────
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

    h_score = heuristic_score(features, trusted)

    if ml_score is not None:
        final_score = int(ml_score * 0.5 + h_score * 0.5)
    else:
        final_score = h_score

    # ── Hard caps — these ALWAYS override everything ──────────────────
    if features.get("has_ip"):
        final_score = min(final_score, 20)
    if features.get("brand_impersonation"):
        final_score = min(final_score, 25)
    if features.get("suspicious_tld") and not features.get("has_https"):
        final_score = min(final_score, 30)   # .tk + no HTTPS = max 30
    if features.get("suspicious_tld"):
        final_score = min(final_score, 44)   # any .tk = max 44 (Suspicious)
    if features.get("suspicious_tld") and features.get("suspicious_keywords", 0) > 0:
        final_score = min(final_score, 20)   # .tk + phishing keywords = max 20
    if features.get("has_at") and features.get("suspicious_tld"):
        final_score = min(final_score, 15)

    return {
        "url":          url,
        "safety_score": max(0, min(100, final_score)),
        "category":     get_category(final_score),
        "risk_level":   get_risk_level(final_score),
        "flags":        get_flags(features, trusted),
        "features":     features,
        "domain_info":  domain_info
    }