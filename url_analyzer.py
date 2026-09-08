"""
Safe Heuristic URL Analysis and Threat Detection Module
Smart Spam Email Detection System
"""

import re
from urllib.parse import urlparse

# Known URL shortener domains commonly abused in phishing/spam
KNOWN_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "adf.ly", "bit.do", "cutt.ly", "rebrand.ly", "shorte.st", "rb.gy", "tiny.cc"
}

# Suspicious Top-Level Domains (TLDs) frequently associated with spam/phishing
SUSPICIOUS_TLDS = {
    "xyz", "top", "work", "click", "loan", "cam", "country", "gq", "cf",
    "tk", "ml", "men", "stream", "bid", "racing", "win", "party", "review",
    "trade", "date", "faith", "accountant", "download", "buzz"
}

# Targeted high-risk brands commonly impersonated
TARGETED_BRANDS = [
    "paypal", "apple", "google", "microsoft", "netflix", "amazon", "chase",
    "bankofamerica", "wellsfargo", "facebook", "instagram", "whatsapp", "dropbox"
]

# High-risk path keywords indicative of credential harvesting
SUSPICIOUS_PATH_KEYWORDS = [
    "login", "signin", "verify", "verification", "update", "account",
    "banking", "secure", "authenticate", "confirm", "wallet", "recover",
    "password", "security", "identity"
]


def extract_urls(text: str) -> list[str]:
    """
    Safely extracts all unique URLs from raw text using regex without opening or resolving them.
    Handles http, https, www, and explicit protocol links.
    """
    if not isinstance(text, str):
        return []

    # Regex capturing http/https/ftp and www. URLs
    url_pattern = r"(?:https?://|www\.)[^\s<>\"'()]+|\b[a-zA-Z0-9.-]+\.(?:com|org|net|edu|gov|io|xyz|top|info|biz|co|me|online|site|app|live|tk|ml|ga|cf|gq)(?:/[^\s<>\"'()]*)?"
    raw_matches = re.findall(url_pattern, text, re.IGNORECASE)

    clean_urls = []
    for match in raw_matches:
        # Strip trailing punctuation that often attaches to URLs in text (.,;:!?)
        cleaned = re.sub(r"[.,;:!?\)\'\"]+$", "", match.strip())
        if len(cleaned) > 4 and cleaned not in clean_urls:
            clean_urls.append(cleaned)

    return clean_urls


def is_ip_address(hostname: str) -> bool:
    """Checks if the hostname is a direct IPv4 address."""
    if not hostname:
        return False
    ip_pattern = r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
    return bool(re.match(ip_pattern, hostname))


def analyze_single_url(raw_url: str) -> dict:
    """
    Heuristically analyzes a single URL without making network requests.
    Returns findings, risk level, and suspicious flags.
    """
    url = raw_url
    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    try:
        parsed = urlparse(url)
        hostname = (parsed.hostname or "").lower()
        path = (parsed.path or "").lower()
        query = (parsed.query or "").lower()
    except Exception:
        return {
            "url": raw_url,
            "is_suspicious": True,
            "risk_score": 50,
            "threats": ["Malformed URL syntax"],
            "hostname": "Unknown",
            "security_warning": "Invalid or deliberately obfuscated URL format."
        }

    threats = []
    risk_points = 0

    # 1. IP Address Host Check (Strong indicator of phishing)
    if is_ip_address(hostname):
        threats.append("Raw IPv4 Host: URL points directly to an IP address instead of a registered domain.")
        risk_points += 35

    # 2. URL Shortener Service Check
    domain_parts = hostname.split(".")
    domain_root = ".".join(domain_parts[-2:]) if len(domain_parts) >= 2 else hostname
    if domain_root in KNOWN_SHORTENERS or hostname in KNOWN_SHORTENERS:
        threats.append(f"URL Shortener Detected ({hostname}): Masks true destination domain.")
        risk_points += 25

    # 3. Suspicious or Abused TLD Check
    tld = domain_parts[-1] if domain_parts else ""
    if tld in SUSPICIOUS_TLDS:
        threats.append(f"Suspicious Top-Level Domain (.{tld}): Frequently associated with spam campaigns.")
        risk_points += 20

    # 4. Brand Impersonation / Deceptive Subdomains
    for brand in TARGETED_BRANDS:
        if brand in hostname:
            # Check if brand is legitimately the main registered domain
            is_legit_brand = (domain_root == f"{brand}.com" or domain_root == f"{brand}.org" or domain_root == f"{brand}.net")
            if not is_legit_brand:
                threats.append(f"Brand Spoofing ({brand}): Brand name appears in subdomains or deceptive domain.")
                risk_points += 30
                break

    # 5. Excessive Subdomain Nesting (e.g. secure.login.paypal.com.malicious.com)
    if len(domain_parts) > 3 and not is_ip_address(hostname):
        threats.append(f"Excessive Subdomains ({len(domain_parts)} levels): Often used to camouflage malicious hosts.")
        risk_points += 15

    # 6. High-Risk Path or Query Keywords
    matched_keywords = [kw for kw in SUSPICIOUS_PATH_KEYWORDS if kw in path or kw in query]
    if matched_keywords:
        threats.append(f"Sensitive Path Keywords ({', '.join(matched_keywords[:3])}): Suggests credential/account harvesting.")
        risk_points += 20

    # 7. Character Anomalies: '@' symbol in URL (HTTP auth spoofing trick)
    if "@" in raw_url:
        threats.append("Embedded '@' symbol: Exploits browser auth syntax to disguise target destination.")
        risk_points += 30

    # 8. Excessive Hyphens in Domain
    if hostname.count("-") >= 2:
        threats.append(f"Multiple Hyphens in Hostname ({hostname.count('-')}): Common in phishing lookalike domains.")
        risk_points += 15

    # 9. Abnormal Length
    if len(raw_url) > 75:
        threats.append("Excessive URL Length (>75 chars): URL may conceal obfuscated tokens.")
        risk_points += 10

    # 10. Non-standard port
    if parsed.port and parsed.port not in [80, 443]:
        threats.append(f"Non-Standard Port (:{parsed.port}): Traffic directed to unusual port.")
        risk_points += 15

    is_suspicious = len(threats) > 0
    security_warning = threats[0] if threats else "No immediate heuristics triggered."

    return {
        "url": raw_url,
        "hostname": hostname,
        "is_suspicious": is_suspicious,
        "risk_points": min(risk_points, 100),
        "threats": threats,
        "security_warning": security_warning
    }


def analyze_urls_in_email(text: str) -> dict:
    """
    Main entry point for Feature 3:
    Extracts all URLs and produces overall metrics and detailed findings.
    """
    urls = extract_urls(text)
    total_count = len(urls)

    if total_count == 0:
        return {
            "total_urls": 0,
            "suspicious_urls_count": 0,
            "has_suspicious_urls": False,
            "url_risk_penalty": 0,
            "security_warning": "No URLs detected in the email.",
            "url_details": []
        }

    url_details = [analyze_single_url(u) for u in urls]
    suspicious_count = sum(1 for d in url_details if d["is_suspicious"])

    # Calculate overall URL risk penalty (0 to 30)
    max_single_risk = max((d["risk_points"] for d in url_details), default=0)
    aggregate_penalty = min(int(max_single_risk * 0.25 + (suspicious_count * 5)), 30)

    if suspicious_count > 0:
        security_warning = f"SECURITY WARNING: {suspicious_count} of {total_count} detected URL(s) exhibit high-risk phishing characteristics!"
    else:
        security_warning = f"{total_count} link(s) inspected. No high-risk anomalies detected in URL structures."

    return {
        "total_urls": total_count,
        "suspicious_urls_count": suspicious_count,
        "has_suspicious_urls": suspicious_count > 0,
        "url_risk_penalty": aggregate_penalty,
        "security_warning": security_warning,
        "url_details": url_details
    }
