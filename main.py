import re
import tldextract
import whois
import datetime
import requests

SUSPICIOUS_KEYWORDS = ['login', 'verify', 'secure', 'account', 'banking', 'update', 'free', 'paypal']

SHORTENERS = ['bit.ly', 'tinyurl.com', 'goo.gl', 'ow.ly', 't.co', 'is.gd', 'buff.ly', 'adf.ly']

def extract_domain(url):
    extracted = tldextract.extract(url)
    return f"{extracted.domain}.{extracted.suffix}"

def check_domain_age(domain):
    try:
        info = whois.whois(domain)
        creation_date = info.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        if creation_date:
            age = (datetime.datetime.now() - creation_date).days
            return age
    except:
        return None

def is_shortened(url):
    domain = extract_domain(url)
    return domain in SHORTENERS

def phishing_score(url):
    score = 0
    reasons = []

    # 1. Suspicious keywords
    keywords_found = [kw for kw in SUSPICIOUS_KEYWORDS if kw in url.lower()]
    if keywords_found:
        score += 1
        reasons.append(f"Suspicious keywords found: {keywords_found}")

    # 2. Shortened URL
    if is_shortened(url):
        score += 1
        reasons.append("URL uses a known shortening service")

    # 3. Too many dots in URL
    if url.count('.') > 5:
        score += 1
        reasons.append("URL has too many dots")

    # 4. Domain age
    domain = extract_domain(url)
    age = check_domain_age(domain)
    if age is not None and age < 180:
        score += 1
        reasons.append(f"Domain is very new ({age} days old)")
    elif age is None:
        reasons.append("Could not determine domain age")

    # 5. HTTPS check
    if not url.startswith("https://"):
        score += 1
        reasons.append("URL does not use HTTPS")

    return score, reasons

# Run as CLI tool
if __name__ == "__main__":
    url = input("Enter a URL to check: ").strip()
    score, reasons = phishing_score(url)

    print("\n--- Analysis Result ---")
    print(f"URL: {url}")
    print(f"Phishing Score: {score}/5")
    print("Reasons:")
    for reason in reasons:
        print(" -", reason)
