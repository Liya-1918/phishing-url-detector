# detector/analyze.py

import tldextract

SUSPICIOUS_KEYWORDS = ["login", "secure", "verify", "update", "banking", "paypal"]

def check_suspicious_keywords(url):
    found = [word for word in SUSPICIOUS_KEYWORDS if word in url.lower()]
    return found

def is_subdomain_used_for_trick(url):
    ext = tldextract.extract(url)
    return ext.subdomain not in ("", "www")

def analyze_url(url):
    score = 0
    reasons = []

    keywords = check_suspicious_keywords(url)
    if keywords:
        score += 2
        reasons.append(f"Suspicious keywords found: {keywords}")

    if is_subdomain_used_for_trick(url):
        score += 1
        reasons.append("URL uses subdomain (possible phishing trick)")

    return {
        "url": url,
        "score": score,
        "reasons": reasons
    }
