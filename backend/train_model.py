# train_model.py — FraudShield ML Retraining Script
# Downloads PhishTank + OpenPhish phishing URLs
# Downloads Alexa/Tranco top legitimate URLs
# Trains a Random Forest classifier and saves fraud_model.pkl + scaler.pkl

import os
import re
import math
import json
import time
import random
import requests
import numpy as np
import pandas as pd
from tqdm import tqdm
from urllib.parse import urlparse, parse_qs
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier, VotingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score
import joblib
import warnings
warnings.filterwarnings("ignore")

print("=" * 60)
print("  FraudShield ML Model Retraining")
print("=" * 60)

# ── Feature extraction (must match ml_model.py exactly) ──────────────

SUSPICIOUS_TLDS = {
    ".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".click",
    ".win", ".loan", ".top", ".buzz", ".icu", ".cam",
    ".country", ".stream", ".download", ".racing",
    ".party", ".review", ".science", ".work", ".fit",
    ".pw", ".cc", ".su", ".bid", ".trade", ".date"
}

PHISH_KEYWORDS = [
    "login", "signin", "verify", "account", "update", "secure",
    "banking", "paypal", "password", "confirm", "free", "prize",
    "winner", "click", "alert", "warning", "suspended", "urgent",
    "limited", "expire", "blocked", "locked", "unusual", "activity",
    "validate", "authenticate", "authorize", "credential", "billing",
    "invoice", "payment", "refund", "cancel", "suspend", "restore",
    "recover", "helpdesk", "support", "service", "customer", "security",
    "phishing", "scam", "hack", "malware", "fraud", "fake", "spoof"
]

SHORTENERS = [
    "bit.ly", "tinyurl", "goo.gl", "t.co", "ow.ly", "short.link",
    "rb.gy", "cutt.ly", "is.gd", "buff.ly",
]

FREE_HOSTS = [
    "godaddysites.com", "wixsite.com", "weebly.com", "webflow.io",
    "blogspot.com", "000webhostapp.com", "glitch.me",
    "replit.dev", "carrd.co", "strikingly.com",
]

BRANDS = [
    "paypal", "google", "microsoft", "amazon", "apple", "facebook",
    "netflix", "instagram", "twitter", "whatsapp", "linkedin",
    "dropbox", "adobe", "yahoo", "outlook", "office", "windows",
    "gmail", "youtube", "spotify", "uber", "airbnb", "ebay",
    "bankofamerica", "chase", "wellsfargo", "citibank",
    "sbi", "hdfc", "icici", "axis", "paytm", "phonepe",
]

TRUSTED_DOMAINS = {
    "google.com", "youtube.com", "facebook.com", "twitter.com",
    "instagram.com", "linkedin.com", "amazon.com", "microsoft.com",
    "apple.com", "netflix.com", "reddit.com", "wikipedia.org",
    "github.com", "stackoverflow.com", "paypal.com", "ebay.com",
    "yahoo.com", "bing.com", "live.com", "outlook.com",
}


def calculate_entropy(text: str) -> float:
    if not text:
        return 0.0
    prob = [text.count(c) / len(text) for c in set(text)]
    return -sum(p * math.log2(p) for p in prob)


def extract_features(url: str) -> list:
    try:
        parsed = urlparse(url if url.startswith("http") else "http://" + url)
        domain = parsed.netloc.lower()
        path   = parsed.path.lower()
        query  = parsed.query.lower()
        full   = url.lower()

        parts = domain.split(".")
        tld   = "." + parts[-1] if parts else ""

        domain_clean = domain.replace("www.", "")
        trusted = domain_clean in TRUSTED_DOMAINS or any(
            ".".join(parts[i:]) in TRUSTED_DOMAINS
            for i in range(1, len(parts))
        )

        brand_in_domain = any(b in domain_clean for b in BRANDS)

        domain_alpha = domain_clean.split(".")[0]
        digit_ratio  = (
            sum(c.isdigit() for c in domain_alpha) / len(domain_alpha)
            if domain_alpha else 0
        )

        kw_count = (
            sum(1 for kw in PHISH_KEYWORDS if kw in domain_clean)
            if trusted else
            sum(1 for kw in PHISH_KEYWORDS if kw in full)
        )

        return [
            len(url),                                          # url_length
            len(domain),                                       # domain_length
            len(path),                                         # path_length
            url.count("."),                                    # num_dots
            url.count("-"),                                    # num_hyphens
            url.count("_"),                                    # num_underscores
            url.count("/"),                                    # num_slashes
            sum(c.isdigit() for c in url),                    # num_digits
            len(parse_qs(query)),                              # num_params
            1 if "#" in url else 0,                           # num_fragments
            max(0, len(parts) - 2),                           # num_subdomains
            calculate_entropy(domain),                         # domain_entropy
            1 if parsed.port else 0,                          # has_port
            1 if re.match(r"^\d+\.\d+\.\d+\.\d+$",           # has_ip
                          domain.split(":")[0]) else 0,
            len(parts[-1]) if parts else 0,                   # tld_length
            1 if url.startswith("https") else 0,              # has_https
            1 if "@" in url else 0,                           # has_at
            1 if url.count("//") > 1 else 0,                  # has_double_slash
            1 if "//" in path else 0,                         # has_redirect
            1 if "xn--" in domain else 0,                     # has_punycode
            kw_count,                                          # suspicious_keywords
            1 if any(s in domain for s in SHORTENERS) else 0, # is_shortener
            1 if any(h in domain for h in FREE_HOSTS) else 0, # is_free_host
            1 if tld in SUSPICIOUS_TLDS else 0,               # suspicious_tld
            1 if (brand_in_domain and not trusted) else 0,    # brand_impersonation
            digit_ratio,                                       # digit_ratio
            sum(1 for c in domain                             # special_chars
                if not c.isalnum() and c not in ".-"),
            1 if trusted else 0,                              # is_trusted_domain
        ]
    except Exception:
        return [0] * 28


# ── Download datasets ─────────────────────────────────────────────────

def download_phishtank(max_urls=50000):
    print("\n[1/4] Downloading PhishTank dataset...")
    urls = []
    try:
        # PhishTank verified phishing URLs (no key needed for basic CSV)
        r = requests.get(
            "http://data.phishtank.com/data/online-valid.csv",
            timeout=60,
            headers={"User-Agent": "FraudShield/1.0 research@fraudshield.com"}
        )
        if r.status_code == 200:
            lines = r.text.strip().split("\n")[1:]  # Skip header
            for line in lines[:max_urls]:
                parts = line.split(",")
                if len(parts) >= 2:
                    url = parts[1].strip().strip('"')
                    if url.startswith("http"):
                        urls.append(url)
            print(f"  ✅ PhishTank: {len(urls)} phishing URLs")
        else:
            print(f"  ⚠️ PhishTank returned {r.status_code}, using fallback...")
    except Exception as e:
        print(f"  ⚠️ PhishTank failed: {e}")
    return urls


def download_openphish(max_urls=10000):
    print("[2/4] Downloading OpenPhish dataset...")
    urls = []
    try:
        r = requests.get(
            "https://openphish.com/feed.txt",
            timeout=30,
            headers={"User-Agent": "Mozilla/5.0"}
        )
        if r.status_code == 200:
            for line in r.text.strip().split("\n")[:max_urls]:
                url = line.strip()
                if url.startswith("http"):
                    urls.append(url)
            print(f"  ✅ OpenPhish: {len(urls)} phishing URLs")
        else:
            print(f"  ⚠️ OpenPhish returned {r.status_code}")
    except Exception as e:
        print(f"  ⚠️ OpenPhish failed: {e}")
    return urls


def download_tranco_legit(max_urls=50000):
    print("[3/4] Downloading Tranco top legitimate domains...")
    urls = []
    try:
        r = requests.get(
            "https://tranco-list.eu/top-1m.csv.zip",
            timeout=60,
            stream=True
        )
        if r.status_code == 200:
            import zipfile
            import io
            z = zipfile.ZipFile(io.BytesIO(r.content))
            with z.open(z.namelist()[0]) as f:
                lines = f.read().decode("utf-8").strip().split("\n")
                for line in lines[:max_urls]:
                    parts = line.split(",")
                    if len(parts) >= 2:
                        domain = parts[1].strip()
                        urls.append(f"https://{domain}")
            print(f"  ✅ Tranco: {len(urls)} legitimate URLs")
        else:
            print(f"  ⚠️ Tranco returned {r.status_code}, using fallback...")
    except Exception as e:
        print(f"  ⚠️ Tranco failed: {e}, using built-in list...")

    # Fallback: built-in legitimate URLs if download fails
    if len(urls) < 1000:
        print("  📦 Using built-in legitimate domain list...")
        legit_domains = [
            "google.com", "youtube.com", "facebook.com", "twitter.com",
            "instagram.com", "linkedin.com", "amazon.com", "microsoft.com",
            "apple.com", "netflix.com", "reddit.com", "wikipedia.org",
            "github.com", "stackoverflow.com", "paypal.com", "ebay.com",
            "yahoo.com", "bing.com", "live.com", "outlook.com",
            "dropbox.com", "adobe.com", "shopify.com", "wordpress.com",
            "cloudflare.com", "digitalocean.com", "heroku.com", "vercel.com",
            "notion.so", "figma.com", "canva.com", "slack.com", "zoom.us",
            "spotify.com", "hulu.com", "disneyplus.com", "twitch.tv",
            "discord.com", "telegram.org", "whatsapp.com", "messenger.com",
            "nytimes.com", "bbc.com", "cnn.com", "reuters.com",
            "theguardian.com", "forbes.com", "bloomberg.com", "wsj.com",
            "coursera.org", "udemy.com", "edx.org", "khanacademy.org",
            "booking.com", "airbnb.com", "expedia.com", "tripadvisor.com",
            "walmart.com", "target.com", "bestbuy.com", "etsy.com",
            "chase.com", "bankofamerica.com", "wellsfargo.com", "citibank.com",
            "stripe.com", "coinbase.com", "robinhood.com", "visa.com",
            "sbi.co.in", "hdfcbank.com", "icicibank.com", "axisbank.com",
            "flipkart.com", "myntra.com", "swiggy.com", "zomato.com",
            "paytm.com", "phonepe.com", "zerodha.com", "groww.in",
            "ndtv.com", "timesofindia.com", "thehindu.com", "moneycontrol.com",
            "github.io", "medium.com", "substack.com", "producthunt.com",
        ]
        # Generate varied URLs for each domain
        paths = [
            "", "/about", "/contact", "/login", "/home", "/products",
            "/services", "/blog", "/help", "/support", "/faq",
        ]
        for domain in legit_domains:
            for path in paths:
                urls.append(f"https://{domain}{path}")
        # Pad to 50000 with random combinations
        while len(urls) < max_urls:
            d = random.choice(legit_domains)
            p = random.choice(paths)
            urls.append(f"https://{d}{p}?ref={random.randint(1,999)}")
        print(f"  ✅ Built-in list: {len(urls)} legitimate URLs")

    return urls[:max_urls]


def generate_synthetic_phishing(n=20000):
    """Generate synthetic phishing URLs to supplement real data."""
    print("[4/4] Generating synthetic phishing URLs...")
    urls = []

    sus_tlds    = [".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".click", ".top", ".pw"]
    brands      = ["paypal", "google", "amazon", "microsoft", "apple", "facebook",
                   "netflix", "instagram", "twitter", "bankofamerica", "chase",
                   "wellsfargo", "hdfc", "sbi", "icici"]
    phish_words = ["login", "verify", "secure", "account", "update", "confirm",
                   "suspended", "urgent", "billing", "password", "signin"]
    legit_tlds  = [".com", ".net", ".org"]

    for _ in range(n):
        brand  = random.choice(brands)
        word   = random.choice(phish_words)
        tld    = random.choice(sus_tlds)
        num    = random.randint(1, 999)
        scheme = random.choice(["http://", "https://"])

        pattern = random.randint(1, 6)
        if pattern == 1:
            url = f"{scheme}{brand}-{word}{tld}"
        elif pattern == 2:
            url = f"{scheme}{word}-{brand}{tld}/login.php"
        elif pattern == 3:
            url = f"{scheme}{brand}.{word}{tld}/verify"
        elif pattern == 4:
            url = f"{scheme}{num}.{brand}-secure{tld}/{word}"
        elif pattern == 5:
            url = f"{scheme}{brand}{word}{num}{tld}"
        else:
            url = f"http://{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}/{brand}/{word}"

        urls.append(url)

    print(f"  ✅ Synthetic: {len(urls)} phishing URLs generated")
    return urls


# ── Main training pipeline ────────────────────────────────────────────

def main():
    # 1. Download data
    phish_real1 = download_phishtank(50000)
    phish_real2 = download_openphish(10000)
    legit_urls  = download_tranco_legit(50000)
    phish_synth = generate_synthetic_phishing(20000)

    all_phish = list(set(phish_real1 + phish_real2 + phish_synth))
    all_legit = list(set(legit_urls))

    print(f"\n📊 Dataset Summary:")
    print(f"  Phishing URLs : {len(all_phish):,}")
    print(f"  Legitimate URLs: {len(all_legit):,}")

    # Balance dataset
    min_size = min(len(all_phish), len(all_legit), 60000)
    random.shuffle(all_phish)
    random.shuffle(all_legit)
    all_phish = all_phish[:min_size]
    all_legit = all_legit[:min_size]

    print(f"  Balanced to   : {min_size:,} each = {min_size*2:,} total")

    # 2. Extract features
    print("\n⚙️  Extracting features...")
    X, y = [], []

    print("  Processing phishing URLs...")
    for url in tqdm(all_phish, ncols=70):
        feats = extract_features(url)
        if len(feats) == 28:
            X.append(feats)
            y.append(0)  # 0 = phishing

    print("  Processing legitimate URLs...")
    for url in tqdm(all_legit, ncols=70):
        feats = extract_features(url)
        if len(feats) == 28:
            X.append(feats)
            y.append(1)  # 1 = legitimate

    X = np.array(X)
    y = np.array(y)
    print(f"  ✅ Feature matrix: {X.shape}")

    # 3. Split
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    # 4. Scale
    print("\n📐 Scaling features...")
    scaler  = StandardScaler()
    X_train = scaler.fit_transform(X_train)
    X_test  = scaler.transform(X_test)

    # 5. Train ensemble model
    print("\n🤖 Training ensemble model (this may take 2-5 minutes)...")

    rf = RandomForestClassifier(
        n_estimators=300,
        max_depth=20,
        min_samples_split=5,
        min_samples_leaf=2,
        class_weight="balanced",
        random_state=42,
        n_jobs=-1
    )

    gb = GradientBoostingClassifier(
        n_estimators=200,
        max_depth=6,
        learning_rate=0.1,
        random_state=42
    )

    lr = LogisticRegression(
        C=1.0,
        max_iter=1000,
        class_weight="balanced",
        random_state=42
    )

    ensemble = VotingClassifier(
        estimators=[("rf", rf), ("gb", gb), ("lr", lr)],
        voting="soft",
        weights=[3, 2, 1]
    )

    ensemble.fit(X_train, y_train)
    print("  ✅ Model trained!")

    # 6. Evaluate
    print("\n📈 Evaluation Results:")
    y_pred = ensemble.predict(X_test)
    y_prob = ensemble.predict_proba(X_test)[:, 1]

    print(classification_report(y_test, y_pred,
          target_names=["Phishing", "Legitimate"]))

    cm  = confusion_matrix(y_test, y_pred)
    auc = roc_auc_score(y_test, y_prob)
    print(f"  Confusion Matrix:\n{cm}")
    print(f"  ROC-AUC Score: {auc:.4f}")

    acc = ensemble.score(X_test, y_test)
    print(f"  Accuracy: {acc*100:.2f}%")

    # 7. Save models
    print("\n💾 Saving models...")
    joblib.dump(ensemble, "fraud_model.pkl")
    joblib.dump(scaler,   "scaler.pkl")
    print("  ✅ fraud_model.pkl saved")
    print("  ✅ scaler.pkl saved")

    # 8. Quick test
    print("\n🧪 Quick sanity test:")
    test_cases = [
        ("https://google.com",              "Legitimate"),
        ("https://paypal.com/login",        "Legitimate"),
        ("http://paypal-verify.tk/login",   "Phishing"),
        ("http://secure-login-amazon.ml",   "Phishing"),
        ("http://192.168.1.1/banking",      "Phishing"),
        ("https://github.com",              "Legitimate"),
        ("http://test-phishing-site.tk",    "Phishing"),
        ("https://netflix.com",             "Legitimate"),
    ]

    for url, expected in test_cases:
        feats  = extract_features(url)
        scaled = scaler.transform([feats])
        prob   = ensemble.predict_proba(scaled)[0]
        score  = int(prob[1] * 100)
        result = "✅ Legitimate" if score >= 65 else "🚨 Phishing"
        match  = "✓" if (score >= 65) == (expected == "Legitimate") else "✗"
        print(f"  {match} {url[:50]:<50} Score: {score:3d} → {result}")

    print("\n" + "=" * 60)
    print("  ✅ Training complete! Models saved.")
    print("  Next: push fraud_model.pkl + scaler.pkl to GitHub")
    print("=" * 60)


if __name__ == "__main__":
    main()