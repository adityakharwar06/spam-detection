"""
Multi-Signal Email Risk Scoring Engine (0-100)
Smart Spam Email Detection System
"""


def calculate_risk_score(
    spam_probability: float,
    content_analysis: dict,
    url_analysis: dict,
    structural_analysis: dict = None
) -> dict:
    """
    Computes a balanced, multi-signal 0–100 risk score combining:
    1. ML Spam Probability: Max 50 points
    2. Suspicious Content & Threat Indicators: Max 25 points
    3. Suspicious URL Anomalies: Max 15 points
    4. Structural & Formatting Characteristics: Max 10 points

    Risk Classification:
    - 0 – 39  : LOW RISK (Legitimate/Safe Email)
    - 40 – 69 : MEDIUM RISK (Caution / Suspicious Characteristics)
    - 70 – 100: HIGH RISK (Dangerous Phishing / Malicious Spam)
    """
    # 1. Machine Learning Probability Contribution (0 to 50 points)
    # spam_probability is between 0.0 and 1.0
    ml_points = round(spam_probability * 50.0, 1)

    # 2. Suspicious Content Contribution (0 to 25 points)
    content_raw_weight = content_analysis.get("total_threat_weight", 0)
    # Normalize: every 20 threat points gives ~5 risk points, max 25
    content_points = min(round((content_raw_weight / 80.0) * 25.0, 1), 25.0)

    # 3. URL Indicators Contribution (0 to 15 points)
    url_penalty = url_analysis.get("url_risk_penalty", 0)
    suspicious_urls = url_analysis.get("suspicious_urls_count", 0)
    url_points = min(round((url_penalty / 30.0) * 10.0 + (suspicious_urls * 2.5), 1), 15.0)

    # 4. Structural Characteristics Contribution (0 to 10 points)
    structural = structural_analysis or content_analysis.get("structural_analysis", {})
    structural_penalty = structural.get("structural_penalty", 0)
    structural_points = min(round((structural_penalty / 25.0) * 10.0, 1), 10.0)

    # Calculate raw composite score
    composite_score = ml_points + content_points + url_points + structural_points

    # If ML prediction indicates spam (>= 0.75) and active threat indicators or suspicious URLs are detected, classify as High Risk
    if (spam_probability >= 0.75 and (content_points >= 10 or url_points >= 5)) or \
       (url_analysis.get("has_suspicious_urls") and content_points >= 15):
        composite_score = max(composite_score, 75.0)
    elif spam_probability >= 0.90:
        composite_score = max(composite_score, 70.0)

    # If ML prediction is extremely confident ham (< 0.05) and no high threats, ensure low risk
    if spam_probability <= 0.05 and content_points == 0 and url_points == 0:
        composite_score = min(composite_score, 15.0)

    # Clamp between 0 and 100
    final_score = int(round(min(max(composite_score, 0), 100)))

    # Classification
    if final_score < 40:
        risk_level = "LOW"
        risk_label = "Low Risk"
        badge_class = "success"
        summary_text = "Email demonstrates normal patterns with minimal to zero threat indicators."
    elif final_score < 70:
        risk_level = "MEDIUM"
        risk_label = "Medium Risk"
        badge_class = "warning"
        summary_text = "Email exhibits several questionable attributes. Exercise vigilance before interacting."
    else:
        risk_level = "HIGH"
        risk_label = "High Risk"
        badge_class = "danger"
        summary_text = "Critical threat detected! High likelihood of fraudulent phishing or malicious spam."

    return {
        "score": final_score,
        "risk_level": risk_level,
        "risk_label": risk_label,
        "badge_class": badge_class,
        "summary": summary_text,
        "breakdown": {
            "ml_probability_points": ml_points,
            "content_threat_points": content_points,
            "url_threat_points": url_points,
            "structural_points": structural_points,
            "total_computed": round(composite_score, 1)
        }
    }
