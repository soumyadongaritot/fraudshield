import numpy as np
from sklearn.ensemble import GradientBoostingClassifier, RandomForestClassifier, VotingClassifier
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import classification_report, accuracy_score, confusion_matrix
from sklearn.preprocessing import StandardScaler
import joblib
from ml_model import extract_features

SAFE_URLS = [
    ("https://www.google.com", 0),
    ("https://www.google.co.in", 0),
    ("https://www.bing.com", 0),
    ("https://duckduckgo.com", 0),
    ("https://www.yahoo.com", 0),
    ("https://www.facebook.com", 0),
    ("https://www.instagram.com", 0),
    ("https://www.twitter.com", 0),
    ("https://www.linkedin.com/feed", 0),
    ("https://www.reddit.com", 0),
    ("https://www.pinterest.com", 0),
    ("https://www.tiktok.com", 0),
    ("https://www.snapchat.com", 0),
    ("https://www.youtube.com/watch", 0),
    ("https://discord.com/login", 0),
    ("https://web.telegram.org", 0),
    ("https://www.whatsapp.com", 0),
    ("https://www.quora.com", 0),
    ("https://www.microsoft.com", 0),
    ("https://www.apple.com", 0),
    ("https://www.amazon.com", 0),
    ("https://www.amazon.in", 0),
    ("https://www.netflix.com/login", 0),
    ("https://www.adobe.com", 0),
    ("https://www.salesforce.com", 0),
    ("https://www.oracle.com", 0),
    ("https://github.com", 0),
    ("https://gitlab.com", 0),
    ("https://stackoverflow.com", 0),
    ("https://www.npmjs.com", 0),
    ("https://pypi.org", 0),
    ("https://hub.docker.com", 0),
    ("https://vercel.com", 0),
    ("https://netlify.com", 0),
    ("https://www.cloudflare.com", 0),
    ("https://www.digitalocean.com", 0),
    ("https://aws.amazon.com", 0),
    ("https://azure.microsoft.com", 0),
    ("https://cloud.google.com", 0),
    ("https://www.paypal.com/login", 0),
    ("https://stripe.com", 0),
    ("https://razorpay.com", 0),
    ("https://www.paytm.com", 0),
    ("https://www.phonepe.com", 0),
    ("https://onlinesbi.sbi.co.in", 0),
    ("https://netbanking.hdfcbank.com", 0),
    ("https://www.icicibank.com", 0),
    ("https://www.axisbank.com", 0),
    ("https://www.kotakbank.com", 0),
    ("https://zerodha.com", 0),
    ("https://groww.in", 0),
    ("https://upstox.com", 0),
    ("https://www.coinbase.com", 0),
    ("https://www.flipkart.com", 0),
    ("https://www.myntra.com", 0),
    ("https://www.meesho.com", 0),
    ("https://www.nykaa.com", 0),
    ("https://www.ajio.com", 0),
    ("https://www.snapdeal.com", 0),
    ("https://www.bigbasket.com", 0),
    ("https://www.ebay.com", 0),
    ("https://www.etsy.com", 0),
    ("https://www.shopify.com", 0),
    ("https://www.walmart.com", 0),
    ("https://www.alibaba.com", 0),
    ("https://www.spotify.com", 0),
    ("https://www.hotstar.com", 0),
    ("https://www.primevideo.com", 0),
    ("https://www.disneyplus.com", 0),
    ("https://www.sonyliv.com", 0),
    ("https://www.zee5.com", 0),
    ("https://www.jiosaavn.com", 0),
    ("https://soundcloud.com", 0),
    ("https://www.hulu.com", 0),
    ("https://www.wikipedia.org", 0),
    ("https://www.coursera.org", 0),
    ("https://www.udemy.com", 0),
    ("https://www.edx.org", 0),
    ("https://www.khanacademy.org", 0),
    ("https://nptel.ac.in", 0),
    ("https://www.codecademy.com", 0),
    ("https://www.freecodecamp.org", 0),
    ("https://www.w3schools.com", 0),
    ("https://www.geeksforgeeks.org", 0),
    ("https://www.hackerrank.com", 0),
    ("https://leetcode.com", 0),
    ("https://www.duolingo.com", 0),
    ("https://www.apollohospitals.com", 0),
    ("https://www.practo.com", 0),
    ("https://www.1mg.com", 0),
    ("https://www.pharmeasy.in", 0),
    ("https://www.webmd.com", 0),
    ("https://www.mayoclinic.org", 0),
    ("https://www.who.int", 0),
    ("https://www.cdc.gov", 0),
    ("https://www.bbc.com/news", 0),
    ("https://www.cnn.com", 0),
    ("https://www.reuters.com", 0),
    ("https://www.bloomberg.com", 0),
    ("https://www.ndtv.com", 0),
    ("https://www.thehindu.com", 0),
    ("https://www.timesofindia.com", 0),
    ("https://www.hindustantimes.com", 0),
    ("https://www.indianexpress.com", 0),
    ("https://economictimes.indiatimes.com", 0),
    ("https://www.moneycontrol.com", 0),
    ("https://techcrunch.com", 0),
    ("https://www.theverge.com", 0),
    ("https://www.makemytrip.com", 0),
    ("https://www.goibibo.com", 0),
    ("https://www.cleartrip.com", 0),
    ("https://www.irctc.co.in", 0),
    ("https://www.airbnb.com", 0),
    ("https://www.booking.com", 0),
    ("https://www.expedia.com", 0),
    ("https://www.tripadvisor.com", 0),
    ("https://www.virustotal.com", 0),
    ("https://www.kaspersky.com", 0),
    ("https://www.norton.com", 0),
    ("https://www.malwarebytes.com", 0),
    ("https://openai.com", 0),
    ("https://claude.ai", 0),
    ("https://www.anthropic.com", 0),
    ("https://huggingface.co", 0),
    ("https://www.notion.so", 0),
    ("https://www.figma.com", 0),
    ("https://slack.com", 0),
    ("https://zoom.us", 0),
    ("https://www.dropbox.com", 0),
    ("https://www.trello.com", 0),
    ("https://mail.google.com", 0),
    ("https://www.office.com", 0),
    ("https://drive.google.com", 0),
    ("https://www.india.gov.in", 0),
    ("https://www.mygov.in", 0),
    ("https://uidai.gov.in", 0),
    ("https://www.incometax.gov.in", 0),
    ("https://www.gst.gov.in", 0),
    ("https://rbi.org.in", 0),
    ("https://www.sebi.gov.in", 0),
    ("https://www.naukri.com", 0),
    ("https://www.indeed.com", 0),
    ("https://www.glassdoor.com", 0),
    ("https://internshala.com", 0),
    ("https://www.medium.com", 0),
    ("https://archive.org", 0),
    ("https://www.wordpress.com", 0),
    ("https://www.neverssl.com", 0),
]

PHISHING_URLS = [
    ("http://192.168.1.1/login/verify", 1),
    ("http://10.0.0.1/admin/verify-account", 1),
    ("http://172.16.0.1:8080/phishing", 1),
    ("http://192.168.0.105:9090/login", 1),
    ("http://10.10.10.1/secure/verify", 1),
    ("http://paypal-secure.tk/verify", 1),
    ("http://google-prize.ml/claim", 1),
    ("http://amazon-winner.ga/free-gift", 1),
    ("http://microsoft-alert.cf/security", 1),
    ("http://apple-id-locked.gq/unlock", 1),
    ("http://free-bitcoin.xyz/claim-now", 1),
    ("http://bank-secure.click/login", 1),
    ("http://account-verify.win/update", 1),
    ("http://prize-notification.top/winner", 1),
    ("http://your-account.buzz/verify", 1),
    ("http://secure-banking.icu/login", 1),
    ("http://paypa1-secure-login.com/verify-account", 1),
    ("http://paypal-account-verify.com/login", 1),
    ("http://paypal-security-update.net/verify", 1),
    ("http://amazon-prize-winner.click/free-gift", 1),
    ("http://amazon-security-alert.com/verify", 1),
    ("http://amaz0n-account.com/login", 1),
    ("http://apple-id-suspended.com/verify", 1),
    ("http://apple-support-alert.net/security", 1),
    ("http://microsoft-security-warning.com/alert", 1),
    ("http://microsofft-security.com/verify", 1),
    ("http://google-prize-2024.com/claim", 1),
    ("http://facebook-security-alert.com/login", 1),
    ("http://faceb00k-verify.net/account", 1),
    ("http://netflix-account-suspended.com/restore", 1),
    ("http://netflix-billing-update.net/payment", 1),
    ("http://secure-paypal-account.verify-now.com", 1),
    ("http://sbi-bank-verify-account.tk/login", 1),
    ("http://hdfc-secure-login.verify-now.com", 1),
    ("http://icici-bank-alert.net/verify", 1),
    ("http://paytm-secure-login.com/verify", 1),
    ("http://phonepe-account-verify.net/login", 1),
    ("https://aceacademicssolutions.godaddysites.com", 1),
    ("https://fakebank-login.wixsite.com/account", 1),
    ("https://paypal-phishing.weebly.com/verify", 1),
    ("https://scam-service.000webhostapp.com/login", 1),
    ("https://fraud-site.netlify.app/verify", 1),
    ("https://phishing-page.github.io/steal", 1),
    ("https://fake-amazon.glitch.me/login", 1),
    ("https://scam-bank.carrd.co/verify", 1),
    ("https://fake-prize.strikingly.com/claim", 1),
    ("http://bit.ly/2xKj9p3", 1),
    ("http://tinyurl.com/fake-prize-claim", 1),
    ("http://t.co/phishing-link", 1),
    ("http://update-your-account-now.tk/login", 1),
    ("http://verify-your-bank-account-now.xyz/login", 1),
    ("http://confirm-paypal-account.tk/secure", 1),
    ("http://signin-verify-update.suspicious.com/login", 1),
    ("http://secure-bank-login.verify-update.com", 1),
    ("http://account-suspended-verify.com/restore", 1),
    ("http://urgent-account-verify.com/login", 1),
    ("http://limited-time-offer.tk/claim-prize", 1),
    ("http://free-gift-winner.ml/claim-now", 1),
    ("http://password-reset-required.net/update", 1),
    ("http://unusual-activity-detected.com/verify", 1),
    ("http://billing-failed-update.net/payment", 1),
    ("http://secure.login.verify.account.paypal.fake.com", 1),
    ("http://account.update.verify.secure.amazon.phish.net", 1),
    ("http://your-paypal-account-has-been-limited-please-verify-now.com/login", 1),
    ("http://amazon-prize-winner-claim-your-free-gift-now-limited-time.xyz/claim", 1),
    ("http://xn--pypl-0ra.com/login", 1),
    ("http://xn--80ak6aa92e.com/verify", 1),
    ("http://192.168.1.1:8080/admin", 1),
    ("http://10.0.0.1:9090/phishing/login", 1),
    ("http://cheapessaywriting.wixsite.com/order", 1),
    ("http://fakeuniversity.weebly.com/courses", 1),
    ("http://bitcoin-prize-2024.tk/claim", 1),
    ("http://crypto-giveaway-elon.com/free-bitcoin", 1),
    ("http://ethereum-prize-winner.xyz/claim-now", 1),
    ("http://nft-free-mint.ml/connect-wallet", 1),
    ("http://work-from-home-earn-daily.tk/register", 1),
    ("http://online-job-5000-per-day.xyz/join", 1),
    ("http://you-won-1000000-rupees.tk/claim", 1),
    ("http://lucky-draw-winner-2024.xyz/prize", 1),
    ("http://government-scheme-free-money.ml/apply", 1),
    ("http://paypal.com@192.168.1.1/login", 1),
    ("http://google.com@phishing-site.com/steal", 1),
    ("http://amazon.com@fake-site.tk/verify", 1),
    ("http://legitimate-site.com//phishing-site.com/login", 1),
]

SAMPLE_URLS = SAFE_URLS + PHISHING_URLS


def prepare_dataset():
    rows, labels = [], []
    for url, label in SAMPLE_URLS:
        try:
            features = extract_features(url)
            if features:
                rows.append(list(features.values()))
                labels.append(label)
        except Exception:
            pass
    return np.array(rows), np.array(labels)


def train():
    print("\n" + "="*55)
    print("  FraudShield ML Trainer v3.0 — Ensemble Model")
    print("="*55)
    print(f"\n📊 Dataset: {len(SAMPLE_URLS)} URLs")
    print(f"   Safe: {len(SAFE_URLS)} | Phishing: {len(PHISHING_URLS)}")

    print("\n⚙️  Extracting features...")
    X, y = prepare_dataset()
    print(f"   {X.shape[0]} samples × {X.shape[1]} features")

    print("\n🔀 Splitting 80/20...")
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    print("\n📐 Scaling features...")
    scaler  = StandardScaler()
    X_train = scaler.fit_transform(X_train)
    X_test  = scaler.transform(X_test)

    print("\n🤖 Training Ensemble Model...")
    gb = GradientBoostingClassifier(
        n_estimators=300, learning_rate=0.05,
        max_depth=6, subsample=0.8,
        min_samples_split=3, random_state=42
    )
    rf = RandomForestClassifier(
        n_estimators=300, max_depth=10,
        min_samples_split=3, class_weight="balanced",
        random_state=42
    )
    ensemble = VotingClassifier(
        estimators=[("gb", gb), ("rf", rf)],
        voting="soft", weights=[2, 1]
    )
    ensemble.fit(X_train, y_train)

    print("\n📈 Evaluating...")
    y_pred = ensemble.predict(X_test)
    acc    = accuracy_score(y_test, y_pred)
    print(f"\n   ✅ Accuracy: {acc:.2%}")

    cv = cross_val_score(ensemble, X, y, cv=5, scoring="accuracy")
    print(f"   CV Mean:  {cv.mean():.2%} ± {cv.std():.2%}")

    print("\n" + classification_report(
        y_test, y_pred, target_names=["Safe", "Phishing"]))

    cm = confusion_matrix(y_test, y_pred)
    print(f"   True Safe:  {cm[0][0]} | False Phish: {cm[0][1]}")
    print(f"   False Safe: {cm[1][0]} | True Phish:  {cm[1][1]}")

    print("\n💾 Saving model...")
    joblib.dump(ensemble, "fraud_model.pkl")
    joblib.dump(scaler,   "scaler.pkl")
    print("   ✅ fraud_model.pkl")
    print("   ✅ scaler.pkl")
    print(f"\n🎉 Done! Accuracy: {acc:.2%}\n")


if __name__ == "__main__":
    train()