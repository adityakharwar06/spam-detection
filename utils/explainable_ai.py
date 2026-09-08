"""
Explainable AI (XAI) and Decision Rationale Generator
Smart Spam Email Detection System
"""

import numpy as np


def extract_top_contributing_words(model, vectorizer, email_text: str, top_k: int = 8) -> list[dict]:
    """
    Extracts the most influential words in the current email that pushed the model's
    decision toward SPAM or HAM.

    Supports:
    - LogisticRegression (using coef_[0])
    - MultinomialNB (using log-likelihood ratio feature_log_prob_[1] - feature_log_prob_[0])
    - CalibratedClassifierCV / LinearSVC (using calibrated base estimators' coef_)
    """
    if not hasattr(vectorizer, "transform") or not hasattr(vectorizer, "get_feature_names_out"):
        return []

    # Transform the single email text
    try:
        x_vec = vectorizer.transform([email_text])
    except Exception:
        return []

    # Get non-zero indices and feature names
    feature_names = vectorizer.get_feature_names_out()
    nonzero_indices = x_vec.nonzero()[1]

    if len(nonzero_indices) == 0:
        return []

    # Determine feature weights based on model architecture
    weights_vector = None

    # Case 1: Logistic Regression or LinearSVC
    if hasattr(model, "coef_"):
        weights_vector = model.coef_[0]
    # Case 2: CalibratedClassifierCV
    elif hasattr(model, "calibrated_classifiers_"):
        try:
            # Average the coefficients of the underlying estimators
            coefs = [clf.estimator.coef_[0] for clf in model.calibrated_classifiers_ if hasattr(clf.estimator, "coef_")]
            if coefs:
                weights_vector = np.mean(coefs, axis=0)
        except Exception:
            weights_vector = None
    # Case 3: Multinomial Naive Bayes
    elif hasattr(model, "feature_log_prob_"):
        # Log-odds ratio: log(P(w|Spam)) - log(P(w|Ham))
        # Positive value means more associated with Spam
        weights_vector = model.feature_log_prob_[1] - model.feature_log_prob_[0]

    contributions = []

    if weights_vector is not None and len(weights_vector) == len(feature_names):
        for idx in nonzero_indices:
            word = feature_names[idx]
            tfidf_val = x_vec[0, idx]
            weight = weights_vector[idx]
            impact = tfidf_val * weight

            contributions.append({
                "word": word,
                "weight": round(float(impact), 4),
                "association": "Spam" if impact > 0 else "Ham",
                "impact_magnitude": abs(round(float(impact), 4))
            })

        # Sort primarily by positive spam impact, then ham impact
        contributions.sort(key=lambda item: item["weight"], reverse=True)
    else:
        # Fallback: Sort by TF-IDF value if model weights are unavailable
        for idx in nonzero_indices:
            word = feature_names[idx]
            tfidf_val = x_vec[0, idx]
            contributions.append({
                "word": word,
                "weight": round(float(tfidf_val), 4),
                "association": "Neutral",
                "impact_magnitude": round(float(tfidf_val), 4)
            })
        contributions.sort(key=lambda item: item["impact_magnitude"], reverse=True)

    return contributions[:top_k]


def generate_explanation_reasons(
    prediction: str,
    confidence: float,
    content_analysis: dict,
    url_analysis: dict,
    top_words: list[dict],
    risk_info: dict
) -> list[str]:
    """
    Builds a list of clear, human-understandable reasons why the AI classified the email
    as SPAM or NOT SPAM.
    """
    reasons = []
    spam_prob_pct = round(confidence * 100, 1)

    # Reason 1: Core AI Model decision
    if prediction == "SPAM":
        top_spam_words = [w["word"] for w in top_words if w.get("association") == "Spam"][:4]
        if top_spam_words:
            reasons.append(
                f"Machine Learning Classifier assigned a high {spam_prob_pct}% probability of SPAM, "
                f"heavily influenced by frequent spam vocabulary: {', '.join(top_spam_words)}."
            )
        else:
            reasons.append(f"Machine Learning model identified linguistic characteristics typical of spam with {spam_prob_pct}% confidence.")
    else:
        top_ham_words = [w["word"] for w in top_words if w.get("association") == "Ham"][:4]
        if top_ham_words:
            reasons.append(
                f"Machine Learning model classified as NOT SPAM ({spam_prob_pct}% confidence), "
                f"matching normal communication patterns ({', '.join(top_ham_words)})."
            )
        else:
            reasons.append(f"Linguistic patterns align closely with legitimate personal or business correspondence ({spam_prob_pct}% confidence).")

    # Reason 2: Suspicious content indicators
    indicators = content_analysis.get("indicators", [])
    if indicators:
        for ind in indicators[:3]:
            snippets = ", ".join(f"'{s}'" for s in ind.get("matched_phrases", [])[:3])
            reasons.append(
                f"{ind['category']} Triggered ({ind['severity']} Severity): {ind['description']} Detected phrases: [{snippets}]."
            )
    else:
        if prediction == "NOT SPAM":
            reasons.append("Zero suspicious keywords or coercion tactics found in email subject and message body.")

    # Reason 3: URL analysis
    total_urls = url_analysis.get("total_urls", 0)
    suspicious_urls = url_analysis.get("suspicious_urls_count", 0)
    if total_urls > 0:
        if suspicious_urls > 0:
            reasons.append(
                f"URL Threat Alert: {suspicious_urls} out of {total_urls} link(s) display phishing hallmarks "
                f"({url_analysis.get('security_warning', '')})."
            )
        else:
            reasons.append(f"Detected {total_urls} standard link(s) without deceptive redirects, brand-spoofing, or suspicious TLDs.")
    else:
        reasons.append("No embedded URLs were found, mitigating link-based credential phishing risks.")

    # Reason 4: Risk score summary
    reasons.append(
        f"Overall calculated Risk Score is {risk_info['score']}/100 ({risk_info['risk_label']}) based on the multi-signal weighted analysis."
    )

    return reasons


def generate_recommendation(prediction: str, risk_level: str, url_analysis: dict) -> dict:
    """
    Generates actionable advice and safety checklists for the end-user.
    """
    has_suspicious_urls = url_analysis.get("has_suspicious_urls", False)

    if risk_level == "HIGH" or prediction == "SPAM":
        headline = "CRITICAL SECURITY WARNING — DO NOT ENGAGE"
        action = "Mark this message as SPAM / Phishing, delete it immediately, and report it to your organization's IT security team."
        checklist = [
            "Do NOT click any links or download any attachments.",
            "Never provide passwords, OTPs, PINs, or banking information.",
            "Verify sender authenticity through an independent official channel (e.g. phone call or verified portal).",
            "Block the sender address immediately."
        ]
        badge = "danger"
    elif risk_level == "MEDIUM":
        headline = "SUSPICIOUS EMAIL — PROCEED WITH CAUTION"
        action = "Treat this email with caution. Validate the sender's identity before taking any requested action."
        checklist = [
            "Check the full sender email domain carefully for subtle misspellings.",
            "If links are present, avoid clicking them directly; visit the official website manually.",
            "Do not respond with confidential personal or financial data.",
            "If an offer seems too good to be true, it is likely fraudulent."
        ]
        badge = "warning"
    else:
        headline = "SAFE & LEGITIMATE COMMUNICATION"
        action = "This email appears normal and contains standard communication characteristics."
        checklist = [
            "Standard security hygiene: still practice caution when sharing sensitive files.",
            "Legitimate correspondence can proceed as normal."
        ]
        badge = "success"

    return {
        "headline": headline,
        "action": action,
        "checklist": checklist,
        "badge": badge
    }
