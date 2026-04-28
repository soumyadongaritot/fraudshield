# 🛡️ FraudShield — AI-Powered Real-Time Phishing & Fraud Detector
(image.png)
![FraudShield](https://img.shields.io/badge/FraudShield-v4.2-blue)
![Python](https://img.shields.io/badge/Python-3.11-green)
![FastAPI](https://img.shields.io/badge/FastAPI-Backend-teal)
![Chrome](https://img.shields.io/badge/Chrome-Extension-yellow)
![ML](https://img.shields.io/badge/ML-93.3%25_Accuracy-brightgreen)

> **"Every click deserves protection."**  
> Samsung Innovation Campus 2026 · AI/ML Batch · Internship Project

---

## 📌 Project Overview

FraudShield is a **Chrome Extension** powered by **Machine Learning** and
**real-time threat intelligence** that protects users from:

- 🔴 Phishing websites
- 🔴 Fake banking login pages (SBI, HDFC, ICICI)
- 🔴 Brand impersonation sites (PayPal, Amazon, Google)
- 🔴 Crypto scams and prize fraud
- 🔴 Newly registered suspicious domains

The extension scans every URL you visit **instantly** and shows a
**safety score (0–100)** with detailed security analysis.

---

## 🚀 Live Demo

Click the FraudShield shield icon on any website to see:
- Safety Score Ring (0–100)
- Domain Trust Level
- Protocol Security (HTTPS check)
- Detection Signals
- Scan History Dashboard

---

## 🏗️ System Architecture

```
BROWSER LAYER          BACKEND LAYER           INTEL LAYER
─────────────          ─────────────           ───────────
Chrome Extension   →   FastAPI Server      →   OpenPhish Feed
Popup UI           →   ML Model            →   Google Safe Browsing
Background Worker  →   Feature Extractor   →   PhishTank DB
Content Script     →   Rule Engine         →   VirusTotal API
```

---

## 🤖 ML Model Details

| Property | Value |
|---|---|
| Algorithm | Ensemble (TF-IDF + RandomForest + GradientBoosting) |
| Features | 31 URL features extracted |
| Training Data | 596 URLs (178 safe + 418 phishing) |
| Accuracy | 93.3% |
| Response Time | < 500ms |
| Data Source | OpenPhish (real phishing URLs) |

### Features Extracted

- URL length, dot count, hyphen count
- HTTPS protocol check
- IP address detection
- Suspicious keywords (login, verify, secure, free, win)
- Bad TLD detection (.tk, .ml, .ga, .xyz)
- Brand impersonation detection
- Subdomain depth analysis
- Domain entropy calculation

### Safety Score System

| Score | Category | Risk |
|---|---|---|
| 85–100 | ✅ SAFE | Low Risk |
| 65–84 | 🟡 PROBABLY SAFE | Medium Risk |
| 45–64 | ⚠️ SUSPICIOUS | High Risk |
| 0–44 | 🔴 DANGEROUS | Critical Risk |

---

## 📁 Project Structure

```
fraudshield/
├── 📁 backend/
│   ├── main.py              # FastAPI server
│   ├── ml_model.py          # Prediction logic
│   ├── features.py          # Feature extraction
│   ├── train_model.py       # Model training script
│   ├── dataset.csv          # Training dataset
│   ├── requirements.txt     # Python dependencies
│   └── Procfile             # Render deployment config
│
├── 📁 extension/
│   ├── manifest.json        # Chrome Extension config
│   ├── popup.html           # Extension UI
│   ├── popup.js             # Popup logic
│   ├── background.js        # Service worker
│   ├── content.js           # In-page warning banner
│   └── 📁 icons/            # Extension icons
│
├── .gitignore
├── render.yaml              # Cloud deployment config
└── README.md
```

---

## ⚙️ Installation & Setup

### Prerequisites
- Python 3.11+
- Google Chrome browser
- Git

### Step 1 — Clone the Repository
```bash
git clone https://github.com/soumyadongaritot/fraudshield.git
cd fraudshield
```

### Step 2 — Setup Backend
```bash
cd backend
pip install -r requirements.txt
python train_model.py
```

### Step 3 — Start Backend Server
```bash
python -m uvicorn main:app --port 8000
```
Backend runs at: `http://127.0.0.1:8000`

### Step 4 — Load Chrome Extension
1. Open Chrome → `chrome://extensions`
2. Enable **Developer Mode** (top right)
3. Click **Load Unpacked**
4. Select the `extension/` folder
5. Pin FraudShield to toolbar

### Step 5 — Test It!
Visit any website and click the FraudShield icon 🛡️

---

## 🧪 Testing

### ✅ Safe Sites
```
https://google.com        →  Safe (98/100)
https://sbi.co.in         →  Safe (98/100)
https://paypal.com        →  Safe (98/100)
```

### 🔴 Dangerous Sites
```
http://paypal-login-secure.xyz    →  Dangerous (0/100)
http://amaz0n-verify.com          →  Dangerous (0/100)
http://free-iphone-winner.tk      →  Dangerous (0/100)
```

---

## 🌐 Deployment

Backend deployed on **Render.com** (Free Tier):  
`https://fraudshield-1-pkvb.onrender.com`

To deploy your own:
1. Push code to GitHub
2. Go to [render.com](https://render.com)
3. New Web Service → Connect repo
4. Root Directory: `backend`
5. Start Command: `uvicorn main:app --host 0.0.0.0 --port $PORT`

---

## 📊 Key Features

| Feature | Description |
|---|---|
| 🔍 Real-Time Scanning | Auto-scans every URL on tab load |
| 💯 Safety Score Ring | Animated 0–100 score with color coding |
| 🛡️ Brand Protection | Detects fake PayPal, Amazon, SBI pages |
| 📊 Scan History | Full history with search and filter |
| 🔔 Desktop Alerts | Notifications for dangerous sites |
| 📅 Domain Age | WHOIS lookup for domain registration age |
| 📋 Allow/Block Lists | Custom whitelist and blacklist |
| 📁 CSV Export | Export scan history for analysis |

---

## 👥 Team

 Name& Role 
 Soumya Dongaritot : Frontend, Backend, Deployment, Overall 
 ML Model + Backend Development, Chrome Extension, UI/UX Design 

**Guide:** Dr. Punit N. Totad  
**Institution:** KLE Institute of Technology, Hubballi  
**Batch:** Samsung Innovation Campus 2026 · AI/ML

---

# License

This project is licensed under the [MIT License](LICENSE).

 Acknowledgements

- [OpenPhish](https://openphish.com) — Real-time phishing URL feed
- [Google Safe Browsing](https://safebrowsing.google.com) — Threat intelligence API
- [VirusTotal](https://virustotal.com) — Multi-engine URL scanning
- [Scikit-learn](https://scikit-learn.org) — ML library
- [FastAPI](https://fastapi.tiangolo.com) — Backend framework
- Samsung Innovation Campus — Project guidance and support
