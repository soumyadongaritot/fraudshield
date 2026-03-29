import numpy as np
import pandas as pd
from sklearn.ensemble import GradientBoostingClassifier, RandomForestClassifier, ExtraTreesClassifier, VotingClassifier
from sklearn.model_selection import train_test_split, cross_val_score, StratifiedKFold
from sklearn.metrics import classification_report, accuracy_score, confusion_matrix
from sklearn.preprocessing import StandardScaler
from sklearn.calibration import CalibratedClassifierCV
import joblib
from features import get_features

# ── Hardcoded Safe URLs ───────────────────────────────────────────────
SAFE_URLS = [
    ("https://www.google.com", 0), ("https://www.google.co.in", 0),
    ("https://www.bing.com", 0), ("https://duckduckgo.com", 0),
    ("https://www.yahoo.com", 0), ("https://www.facebook.com", 0),
    ("https://www.instagram.com", 0), ("https://www.twitter.com", 0),
    ("https://www.linkedin.com/feed", 0), ("https://www.reddit.com", 0),
    ("https://www.pinterest.com", 0), ("https://www.tiktok.com", 0),
    ("https://www.youtube.com/watch", 0), ("https://discord.com/login", 0),
    ("https://web.telegram.org", 0), ("https://www.whatsapp.com", 0),
    ("https://www.microsoft.com", 0), ("https://www.apple.com", 0),
    ("https://www.amazon.com", 0), ("https://www.amazon.in", 0),
    ("https://www.netflix.com/login", 0), ("https://www.adobe.com", 0),
    ("https://github.com", 0), ("https://stackoverflow.com", 0),
    ("https://www.paypal.com/login", 0), ("https://stripe.com", 0),
    ("https://www.flipkart.com", 0), ("https://www.wikipedia.org", 0),
    ("https://www.coursera.org", 0), ("https://www.udemy.com", 0),
    ("https://openai.com", 0), ("https://claude.ai", 0),
    ("https://mail.google.com", 0), ("https://drive.google.com", 0),
    ("https://www.india.gov.in", 0), ("https://uidai.gov.in", 0),
    ("https://www.incometax.gov.in", 0), ("https://rbi.org.in", 0),
    ("https://onlinesbi.sbi.co.in", 0), ("https://netbanking.hdfcbank.com", 0),
    ("https://www.icicibank.com", 0), ("https://zerodha.com", 0),
    ("https://groww.in", 0), ("https://www.bbc.com/news", 0),
    ("https://www.cnn.com", 0), ("https://www.ndtv.com", 0),
    ("https://www.thehindu.com", 0), ("https://techcrunch.com", 0),
    ("https://www.makemytrip.com", 0), ("https://www.irctc.co.in", 0),
    ("https://www.booking.com", 0), ("https://zoom.us", 0),
    ("https://slack.com", 0), ("https://www.notion.so", 0),
    ("https://www.figma.com", 0), ("https://vercel.com", 0),
    ("https://netlify.com", 0), ("https://aws.amazon.com", 0),
    ("https://azure.microsoft.com", 0), ("https://cloud.google.com", 0),
    ("https://www.shopify.com", 0), ("https://www.wordpress.com", 0),
    ("https://www.medium.com", 0), ("https://archive.org", 0),
    ("https://huggingface.co", 0), ("https://www.anthropic.com", 0),
    ("https://www.who.int", 0), ("https://www.cdc.gov", 0),
    ("https://www.mayoclinic.org", 0), ("https://www.webmd.com", 0),
    ("https://www.khanacademy.org", 0), ("https://leetcode.com", 0),
    ("https://www.hackerrank.com", 0), ("https://www.geeksforgeeks.org", 0),
    ("https://razorpay.com", 0), ("https://www.paytm.com", 0),
    ("https://www.phonepe.com", 0), ("https://www.coinbase.com", 0),
    ("https://www.spotify.com", 0), ("https://www.hotstar.com", 0),
    ("https://www.naukri.com", 0), ("https://www.indeed.com", 0),
    ("https://www.virustotal.com", 0), ("https://www.kaspersky.com", 0),
]

# ── Hardcoded Phishing URLs ───────────────────────────────────────────
PHISHING_URLS = [
    ("http://192.168.1.1/login/verify", 1),
    ("http://10.0.0.1/admin/verify-account", 1),
    ("http://paypal-secure.tk/verify", 1),
    ("http://google-prize.ml/claim", 1),
    ("http://amazon-winner.ga/free-gift", 1),
    ("http://microsoft-alert.cf/security", 1),
    ("http://apple-id-locked.gq/unlock", 1),
    ("http://free-bitcoin.xyz/claim-now", 1),
    ("http://bank-secure.click/login", 1),
    ("http://account-verify.win/update", 1),
    ("http://secure-banking.icu/login", 1),
    ("http://paypa1-secure-login.com/verify-account", 1),
    ("http://paypal-account-verify.com/login", 1),
    ("http://amazon-prize-winner.click/free-gift", 1),
    ("http://amaz0n-account.com/login", 1),
    ("http://apple-id-suspended.com/verify", 1),
    ("http://microsoft-security-warning.com/alert", 1),
    ("http://microsofft-security.com/verify", 1),
    ("http://google-prize-2024.com/claim", 1),
    ("http://facebook-security-alert.com/login", 1),
    ("http://faceb00k-verify.net/account", 1),
    ("http://netflix-account-suspended.com/restore", 1),
    ("http://sbi-bank-verify-account.tk/login", 1),
    ("http://hdfc-secure-login.verify-now.com", 1),
    ("http://paytm-secure-login.com/verify", 1),
    ("http://bit.ly/2xKj9p3", 1),
    ("http://tinyurl.com/fake-prize-claim", 1),
    ("http://update-your-account-now.tk/login", 1),
    ("http://verify-your-bank-account-now.xyz/login", 1),
    ("http://secure-bank-login.verify-update.com", 1),
    ("http://account-suspended-verify.com/restore", 1),
    ("http://urgent-account-verify.com/login", 1),
    ("http://free-gift-winner.ml/claim-now", 1),
    ("http://password-reset-required.net/update", 1),
    ("http://unusual-activity-detected.com/verify", 1),
    ("http://billing-failed-update.net/payment", 1),
    ("http://secure.login.verify.account.paypal.fake.com", 1),
    ("http://your-paypal-account-has-been-limited-please-verify-now.com/login", 1),
    ("http://xn--pypl-0ra.com/login", 1),
    ("http://bitcoin-prize-2024.tk/claim", 1),
    ("http://crypto-giveaway-elon.com/free-bitcoin", 1),
    ("http://ethereum-prize-winner.xyz/claim-now", 1),
    ("http://nft-free-mint.ml/connect-wallet", 1),
    ("http://work-from-home-earn-daily.tk/register", 1),
    ("http://you-won-1000000-rupees.tk/claim", 1),
    ("http://lucky-draw-winner-2024.xyz/prize", 1),
    ("http://government-scheme-free-money.ml/apply", 1),
    ("http://paypal.com@192.168.1.1/login", 1),
    ("http://google.com@phishing-site.com/steal", 1),
    ("http://amazon.com@fake-site.tk/verify", 1),
    ("http://online-job-5000-per-day.xyz/join", 1),
]


def prepare_dataset():
    rows, labels = [], []

    # Load from CSV
    try:
        df = pd.read_csv("/mnt/user-data/uploads/dataset.csv")
        for _, row in df.iterrows():
            try:
                feats = get_features(str(row["url"]))
                if feats:
                    rows.append(feats)
                    labels.append(int(row["label"]))
            except Exception:
                pass
        print(f"   CSV: {len(rows)} samples loaded")
    except Exception as e:
        print(f"   CSV load failed: {e}")

    # Add hardcoded URLs
    extra_count = 0
    for url, label in SAFE_URLS + PHISHING_URLS:
        try:
            feats = get_features(url)
            if feats:
                rows.append(feats)
                labels.append(label)
                extra_count += 1
        except Exception:
            pass
    print(f"   Hardcoded: {extra_count} extra samples added")

    return np.array(rows), np.array(labels)


def train():
    print("\n" + "="*55)
    print("  FraudShield ML Trainer v4.0 — High Accuracy")
    print("="*55)

    print("\n⚙️  Extracting features...")
    X, y = prepare_dataset()
    print(f"   {X.shape[0]} total samples × {X.shape[1]} features")
    print(f"   Safe: {(y==0).sum()} | Phishing: {(y==1).sum()}")

    print("\n🔀 Splitting 80/20 (stratified)...")
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    print("\n📐 Scaling features...")
    scaler = StandardScaler()
    X_train = scaler.fit_transform(X_train)
    X_test = scaler.transform(X_test)

    print("\n🤖 Training Ensemble Model (3 classifiers)...")

    gb = GradientBoostingClassifier(
        n_estimators=500,
        learning_rate=0.05,
        max_depth=6,
        subsample=0.8,
        min_samples_split=2,
        min_samples_leaf=1,
        random_state=42
    )

    rf = RandomForestClassifier(
        n_estimators=500,
        max_depth=None,
        min_samples_split=2,
        min_samples_leaf=1,
        class_weight="balanced",
        random_state=42
    )

    et = ExtraTreesClassifier(
        n_estimators=500,
        max_depth=None,
        min_samples_split=2,
        class_weight="balanced",
        random_state=42
    )

    ensemble = VotingClassifier(
        estimators=[("gb", gb), ("rf", rf), ("et", et)],
        voting="soft",
        weights=[3, 2, 2]
    )

    ensemble.fit(X_train, y_train)

    print("\n📈 Evaluating on test set...")
    y_pred = ensemble.predict(X_test)
    acc = accuracy_score(y_test, y_pred)
    print(f"\n   ✅ Test Accuracy:  {acc:.2%}")

    print("\n📊 Cross-Validation (5-fold)...")
    skf = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)

    # Scale full dataset for CV
    scaler_full = StandardScaler()
    X_scaled = scaler_full.fit_transform(X)

    cv_scores = cross_val_score(ensemble, X_scaled, y, cv=skf, scoring="accuracy")
    print(f"   CV Mean:  {cv_scores.mean():.2%} ± {cv_scores.std():.2%}")
    print(f"   CV Scores: {[f'{s:.2%}' for s in cv_scores]}")

    print("\n" + classification_report(y_test, y_pred, target_names=["Safe", "Phishing"]))

    cm = confusion_matrix(y_test, y_pred)
    print(f"   Confusion Matrix:")
    print(f"   True  Safe:  {cm[0][0]} | False Phish: {cm[0][1]}")
    print(f"   False Safe:  {cm[1][0]} | True  Phish: {cm[1][1]}")

    print("\n💾 Saving model & scaler...")
    joblib.dump(ensemble, "fraud_model.pkl")
    joblib.dump(scaler,   "scaler.pkl")
    print("   ✅ fraud_model.pkl saved")
    print("   ✅ scaler.pkl saved")
    print(f"\n🎉 Done! Final Accuracy: {acc:.2%}\n")


if __name__ == "__main__":
    train()
