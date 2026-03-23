import requests
import hashlib
import time

VT_API_KEY = "90824c5af9f1358e7a0a393809410e281d2151d8751597254dd628885f2e5a4c"
VT_BASE    = "https://www.virustotal.com/api/v3"
HEADERS    = {
    "x-apikey": VT_API_KEY,
    "Accept":   "application/json"
}

def get_url_report(url: str) -> dict:
    try:
        url_id   = hashlib.sha256(url.encode()).hexdigest()
        response = requests.get(
            f"{VT_BASE}/urls/{url_id}",
            headers=HEADERS, timeout=10)

        if response.status_code == 404:
            return scan_url(url)
        if response.status_code != 200:
            return _error("Failed to get report")

        attrs = response.json()["data"]["attributes"]
        stats = attrs.get("last_analysis_stats", {})
        return _build_result(stats)

    except Exception as e:
        return _error(str(e))


def scan_url(url: str) -> dict:
    try:
        r = requests.post(
            f"{VT_BASE}/urls",
            headers=HEADERS,
            data={"url": url},
            timeout=10
        )
        if r.status_code != 200:
            return _error("Submit failed")

        aid = r.json()["data"]["id"]
        time.sleep(3)

        r2 = requests.get(
            f"{VT_BASE}/analyses/{aid}",
            headers=HEADERS,
            timeout=10
        )
        if r2.status_code != 200:
            return _error("Analysis failed")

        stats = r2.json()["data"]["attributes"].get("stats", {})
        return _build_result(stats)

    except Exception as e:
        return _error(str(e))


def _build_result(stats: dict) -> dict:
    mal  = stats.get("malicious",  0)
    sus  = stats.get("suspicious", 0)
    har  = stats.get("harmless",   0)
    und  = stats.get("undetected", 0)
    tot  = mal + sus + har + und
    score = int(((har + und) / tot) * 100) if tot > 0 else 50

    if mal >= 5:   level, color = "MALICIOUS",  "red"
    elif mal >= 2: level, color = "SUSPICIOUS", "yellow"
    elif mal == 1: level, color = "LOW RISK",   "yellow"
    else:          level, color = "CLEAN",      "green"

    return {
        "success":       True,
        "vt_score":      score,
        "threat_level":  level,
        "threat_color":  color,
        "malicious":     mal,
        "suspicious":    sus,
        "harmless":      har,
        "undetected":    und,
        "total_engines": tot,
        "summary":       f"{mal} engines flagged out of {tot}"
    }


def _error(msg: str) -> dict:
    return {
        "success":       False,
        "error":         msg,
        "vt_score":      None,
        "threat_level":  "UNKNOWN",
        "threat_color":  "grey",
        "malicious":     0,
        "suspicious":    0,
        "harmless":      0,
        "undetected":    0,
        "total_engines": 0,
        "summary":       msg
    }