"""
Text Preprocessing and Suspicious Content Analysis Module
Smart Spam Email Detection System
"""

import re
import html

# Predefined suspicious content keyword and pattern dictionaries categorized by threat type
SUSPICIOUS_CATEGORIES = {
    "urgency": {
        "label": "Urgency & Coercion",
        "description": "Pressure tactics demanding immediate action to provoke impulsive behavior.",
        "severity": "High",
        "weight": 25,
        "patterns": [
            r"\bimmediate(ly)?\b",
            r"\bact now\b",
            r"\burgent(ly)?\b",
            r"\baction required\b",
            r"\bwithin 24 hours?\b",
            r"\bwithin (12|24|48) hours?\b",
            r"\baccount (will be|has been) (suspended|locked|terminated|closed)\b",
            r"\blast chance\b",
            r"\bfinal (notice|warning|reminder)\b",
            r"\bdo not ignore\b",
            r"\binstant access\b",
            r"\bexpires? (today|soon|promptly)\b",
            r"\btime is running out\b",
            r"\bsecurity alert\b",
            r"\bcritical update\b"
        ]
    },
    "credentials_financial": {
        "label": "Credential & Financial Theft",
        "description": "Attempts to solicit passwords, PINs, OTP codes, or confidential banking data.",
        "severity": "Critical",
        "weight": 35,
        "patterns": [
            r"\b(enter|provide|verify|confirm|update) your (password|credentials?|pin|otp)\b",
            r"\bpassword\b",
            r"\botp\b",
            r"\bpin code\b",
            r"\bcvv\b",
            r"\bcredit card\b",
            r"\bdebit card\b",
            r"\bbank account\b",
            r"\bsocial security\b",
            r"\bssn\b",
            r"\bwire transfer\b",
            r"\bbilling (information|details)\b",
            r"\brouting number\b",
            r"\bverify your account\b",
            r"\bconfirm your identity\b",
            r"\bcrypto(currency)?\b",
            r"\bbitcoin wallet\b",
            r"\bsecret recovery phrase\b"
        ]
    },
    "fake_rewards": {
        "label": "Fake Rewards & Lottery",
        "description": "Deceptive offers of unexpected winnings, prizes, or monetary windfalls.",
        "severity": "High",
        "weight": 25,
        "patterns": [
            r"\byou('ve| have)? won\b",
            r"\bwinner\b",
            r"\blottery\b",
            r"\bcash prize\b",
            r"\bclaim your (prize|reward|gift|money)\b",
            r"\bselected (for|as) a (reward|prize|winner)\b",
            r"\bfree gift card\b",
            r"\bmillion dollars?\b",
            r"\b\$[0-9]+(,[0-9]+)*\s*(usd|cash|bonus|reward)?\b",
            r"\bunclaimed (funds|prize|assets)\b",
            r"\binheritance\b",
            r"\b100% free\b",
            r"\bno investment required\b"
        ]
    },
    "promotional": {
        "label": "Excessive Promotional Language",
        "description": "Aggressive sales language, spam marketing clichés, and unsolicited pitches.",
        "severity": "Medium",
        "weight": 15,
        "patterns": [
            r"\bbuy now\b",
            r"\bhuge discount\b",
            r"\blimited time offer\b",
            r"\brisk[- ]free\b",
            r"\bexclusive deal\b",
            r"\blowest price\b",
            r"\bclick here to claim\b",
            r"\bsatisfaction guaranteed\b",
            r"\bdouble your (income|money)\b",
            r"\bearn from home\b",
            r"\bmake money (fast|online)\b",
            r"\bunsubscribe here\b"
        ]
    }
}


def clean_text(text: str) -> str:
    """
    Cleans raw email text for machine learning preprocessing:
    - Decodes HTML entities
    - Strips HTML tags
    - Replaces URLs, emails, numbers with generic tokens or spaces
    - Removes non-alphanumeric noise while retaining meaningful semantic content
    - Normalizes multiple spaces and lowercases
    """
    if not isinstance(text, str):
        return ""

    # Decode HTML entities
    text = html.unescape(text)

    # Remove HTML tags
    text = re.sub(r"<[^>]+>", " ", text)

    # Normalize email headers if present (e.g., 'From:', 'To:', 'Subject:')
    text = re.sub(r"^(From|To|Subject|Date|Cc|Bcc):", "", text, flags=re.MULTILINE | re.IGNORECASE)

    # Remove URL links during text cleaning (URLs are analyzed separately by url_analyzer)
    text = re.sub(r"https?://\S+|www\.\S+", " ", text)

    # Remove email addresses
    text = re.sub(r"\S+@\S+\.\S+", " ", text)

    # Remove non-word characters (keep letters and basic spaces)
    text = re.sub(r"[^a-zA-Z0-9\s]", " ", text)

    # Collapse multiple whitespaces
    text = re.sub(r"\s+", " ", text).strip().lower()

    return text


def analyze_structural_patterns(subject: str, body: str) -> dict:
    """
    Analyzes structural and visual formatting characteristics of the email:
    - High ALL-CAPS ratio
    - Excessive exclamation / question / dollar symbols
    - Empty or suspicious subject lines
    """
    combined = f"{subject} {body}"
    words = combined.split()
    total_words = len(words)

    # 1. Capitalization check
    all_caps_words = [w for w in words if w.isupper() and len(w) > 2]
    caps_ratio = (len(all_caps_words) / total_words) if total_words > 0 else 0.0

    # 2. Excessive punctuation counts
    exclamation_count = combined.count("!")
    dollar_count = combined.count("$")
    question_count = combined.count("?")

    # 3. Subject-specific checks
    subject_all_caps = subject.isupper() if (len(subject.strip()) > 3) else False
    subject_spam_words = bool(re.search(r"\b(urgent|fwd:|re:|winner|alert|notice)\b", subject, re.IGNORECASE))

    # Anomaly flags
    flags = []
    structural_penalty = 0

    if caps_ratio > 0.25 and total_words >= 8:
        flags.append({
            "type": "excessive_caps",
            "title": "Excessive Capitalization",
            "description": f"Over {int(caps_ratio * 100)}% of words are in ALL CAPS, a common evasion and shouting tactic.",
            "severity": "Medium",
            "penalty": 10
        })
        structural_penalty += 10

    if exclamation_count >= 3:
        flags.append({
            "type": "excessive_exclamation",
            "title": "Excessive Exclamation Marks",
            "description": f"Detected {exclamation_count} exclamation marks, typical of sensationalist spam emails.",
            "severity": "Low",
            "penalty": 5
        })
        structural_penalty += 5

    if dollar_count >= 2:
        flags.append({
            "type": "repeated_currency",
            "title": "Frequent Currency Symbols",
            "description": f"Found {dollar_count} '$' symbols in text, frequently observed in financial scams.",
            "severity": "Medium",
            "penalty": 5
        })
        structural_penalty += 5

    if subject_all_caps:
        flags.append({
            "type": "caps_subject",
            "title": "ALL-CAPS Subject Line",
            "description": "The entire email subject is capitalized to deceive the user's attention filter.",
            "severity": "Medium",
            "penalty": 5
        })
        structural_penalty += 5

    return {
        "caps_ratio": round(caps_ratio, 3),
        "exclamation_count": exclamation_count,
        "dollar_count": dollar_count,
        "structural_penalty": min(structural_penalty, 25),
        "flags": flags
    }


def analyze_suspicious_content(subject: str, body: str) -> dict:
    """
    Scans the combined email subject and body for threat indicators:
    - Urgency
    - Credential / Financial theft
    - Fake rewards & lotteries
    - Promotional clichés
    - Structural anomalies

    Returns a comprehensive dictionary with detected items, severity ratings, and matched phrases.
    """
    text_to_scan = f"{subject}\n{body}"
    detected_indicators = []
    total_threat_weight = 0

    # Match each category
    for category_key, category_data in SUSPICIOUS_CATEGORIES.items():
        matched_phrases = []
        for pattern in category_data["patterns"]:
            matches = re.findall(pattern, text_to_scan, flags=re.IGNORECASE)
            if matches:
                # Capture the actual matched string
                for m in re.finditer(pattern, text_to_scan, flags=re.IGNORECASE):
                    snippet = m.group(0).strip()
                    if snippet.lower() not in [p.lower() for p in matched_phrases]:
                        matched_phrases.append(snippet)

        if matched_phrases:
            severity = category_data["severity"]
            weight = category_data["weight"]
            total_threat_weight += weight

            detected_indicators.append({
                "category": category_data["label"],
                "category_key": category_key,
                "description": category_data["description"],
                "severity": severity,
                "matched_phrases": matched_phrases[:6],  # limit to top 6 matched phrases
                "count": len(matched_phrases),
                "weight": weight
            })

    # Structural patterns
    structural = analyze_structural_patterns(subject, body)
    for flag in structural["flags"]:
        total_threat_weight += flag["penalty"]
        detected_indicators.append({
            "category": "Structural Pattern",
            "category_key": flag["type"],
            "description": flag["description"],
            "severity": flag["severity"],
            "matched_phrases": [flag["title"]],
            "count": 1,
            "weight": flag["penalty"]
        })

    return {
        "indicators": detected_indicators,
        "total_indicators_count": len(detected_indicators),
        "total_threat_weight": min(total_threat_weight, 100),
        "structural_analysis": structural
    }
