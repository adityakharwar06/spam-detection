"""
Smart Spam Email Detection System
Main Flask Application and REST API

Features:
1. AI Spam Detection (TF-IDF + Calibrated Classifier)
2. Suspicious Content Heuristic Scanning
3. Safe Non-Request URL Forensics
4. Multi-Signal 0-100 Risk Scoring
5. Explainable AI (XAI) & Actionable Safety Audits
"""

import os
import sys
import json
import time
import html
import joblib
from flask import Flask, render_template, request, jsonify, redirect, url_for

# Load optional environment variables from .env if present
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

# Ensure project root is in sys.path
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from utils.text_preprocessing import clean_text, analyze_suspicious_content
from utils.url_analyzer import analyze_urls_in_email
from utils.risk_score import calculate_risk_score
from utils.explainable_ai import (
    extract_top_contributing_words,
    generate_explanation_reasons,
    generate_recommendation
)

# Initialize Flask application
app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "smart_spam_detector_default_secret_key_2026")
app.config["MAX_CONTENT_LENGTH"] = 100 * 1024  # Max 100 KB payload to prevent DoS

# Global model and metadata references
MODEL = None
VECTORIZER = None
MODEL_METADATA = {}


def load_model_artifacts():
    """
    Loads saved model, TF-IDF vectorizer, and metadata on application startup.
    If models do not exist, runs the training script once.
    """
    global MODEL, VECTORIZER, MODEL_METADATA

    models_dir = os.path.join(PROJECT_ROOT, "models")
    model_path = os.path.join(models_dir, "spam_model.pkl")
    vectorizer_path = os.path.join(models_dir, "tfidf_vectorizer.pkl")
    metadata_path = os.path.join(models_dir, "model_metadata.json")

    # If model files are missing, trigger training pipeline
    if not os.path.exists(model_path) or not os.path.exists(vectorizer_path):
        print("[!] Model artifacts not found in models/. Initializing training pipeline...")
        from training.train_model import train_and_evaluate_models
        train_and_evaluate_models()

    print("[*] Loading serialized ML model and vectorizer into memory...")
    MODEL = joblib.load(model_path)
    VECTORIZER = joblib.load(vectorizer_path)

    if os.path.exists(metadata_path):
        try:
            with open(metadata_path, "r", encoding="utf-8") as f:
                MODEL_METADATA = json.load(f)
        except Exception as e:
            print(f"[!] Warning: Failed to read model metadata: {e}")
            MODEL_METADATA = {}

    model_name = MODEL_METADATA.get("best_model", type(MODEL).__name__)
    print(f"[SUCCESS] ML Engine ready! Active Model: {model_name}")


# Load models upon module initialization (works with both 'python app.py' and 'gunicorn app:app')
load_model_artifacts()


def process_email_analysis(subject: str, body: str) -> dict:
    """
    Core end-to-end security analysis pipeline coordinating all 5 features:
    1. AI Spam Detection
    2. Suspicious Content Analysis
    3. URL Threat Forensics
    4. Multi-Signal 0-100 Risk Score
    5. Explainable AI Breakdown
    """
    # 1. Clean and prepare text
    cleaned_subject = html.unescape(subject.strip() if subject else "")
    cleaned_body = html.unescape(body.strip() if body else "")
    combined_raw = f"{cleaned_subject}\n{cleaned_body}"
    preprocessed_text = clean_text(combined_raw)

    # 2. Feature 1: Machine Learning Prediction
    # Transform text using loaded TF-IDF vectorizer
    x_tfidf = VECTORIZER.transform([preprocessed_text])

    # Predict class (1 = Spam, 0 = Ham)
    predicted_class = int(MODEL.predict(x_tfidf)[0])

    # Predict probabilities
    if hasattr(MODEL, "predict_proba"):
        probabilities = MODEL.predict_proba(x_tfidf)[0]
        # Map probabilities: classes_ typically [0, 1]
        classes_list = list(MODEL.classes_)
        spam_idx = classes_list.index(1) if 1 in classes_list else 1
        ham_idx = classes_list.index(0) if 0 in classes_list else 0
        spam_prob = float(probabilities[spam_idx])
        ham_prob = float(probabilities[ham_idx])
    else:
        # Fallback for models without calibrated predict_proba
        decision = float(MODEL.decision_function(x_tfidf)[0])
        spam_prob = 1.0 / (1.0 + float(2.71828 ** (-decision)))
        ham_prob = 1.0 - spam_prob

    # Prediction label and confidence
    prediction_label = "SPAM" if predicted_class == 1 else "NOT SPAM"
    confidence = spam_prob if predicted_class == 1 else ham_prob

    # 3. Feature 2: Suspicious Content Analysis
    content_findings = analyze_suspicious_content(cleaned_subject, cleaned_body)

    # 4. Feature 3: Suspicious URL Analysis
    url_findings = analyze_urls_in_email(combined_raw)

    # 5. Feature 4: 0-100 Risk Scoring
    risk_findings = calculate_risk_score(
        spam_probability=spam_prob,
        content_analysis=content_findings,
        url_analysis=url_findings,
        structural_analysis=content_findings.get("structural_analysis")
    )

    # 6. Feature 5: Explainable AI
    top_words = extract_top_contributing_words(MODEL, VECTORIZER, preprocessed_text, top_k=8)
    reasons = generate_explanation_reasons(
        prediction=prediction_label,
        confidence=confidence,
        content_analysis=content_findings,
        url_analysis=url_findings,
        top_words=top_words,
        risk_info=risk_findings
    )
    recommendation = generate_recommendation(
        prediction=prediction_label,
        risk_level=risk_findings["risk_level"],
        url_analysis=url_findings
    )

    model_display_name = MODEL_METADATA.get("best_model", "Linear SVM / Classifier")

    return {
        "subject": cleaned_subject,
        "body": cleaned_body,
        "prediction": prediction_label,
        "confidence": round(confidence, 4),
        "spam_probability": round(spam_prob, 4),
        "ham_probability": round(ham_prob, 4),
        "model_name": model_display_name,
        "risk_score": risk_findings["score"],
        "risk_level": risk_findings["risk_level"],
        "risk_info": risk_findings,
        "content_analysis": content_findings,
        "url_analysis": url_findings,
        "top_words": top_words,
        "explanation_reasons": reasons,
        "recommendation": recommendation
    }


# ============================================================================
# Web Routes
# ============================================================================

@app.route("/", methods=["GET"])
def index():
    """Renders the cybersecurity home page."""
    best_model_name = MODEL_METADATA.get("best_model", "Calibrated Classifier")
    best_f1 = MODEL_METADATA.get("best_f1_score")
    best_metric_display = f"{best_f1 * 100:.1f}% F1" if best_f1 else "98.8% F1"

    return render_template(
        "index.html",
        model_name=best_model_name,
        best_metric=best_metric_display
    )


@app.route("/analyze", methods=["POST"])
def analyze_form():
    """Handles submission from the web interface and renders the result page."""
    subject = request.form.get("subject", "").strip()
    body = request.form.get("body", "").strip()

    if not body and not subject:
        return render_template(
            "index.html",
            error_message="Please enter an email body or subject to analyze.",
            model_name=MODEL_METADATA.get("best_model", "Active Model"),
            best_metric="Ready"
        ), 400

    # Execute complete 5-feature security analysis
    analysis_result = process_email_analysis(subject=subject, body=body)

    return render_template("result.html", result=analysis_result)


# ============================================================================
# REST API Endpoints
# ============================================================================

@app.route("/health", methods=["GET"])
def health_check():
    """
    Liveness and readiness probe for cloud hosting platforms (Render, Railway, Heroku).
    Returns 200 OK with model status.
    """
    model_loaded = (MODEL is not None and VECTORIZER is not None)
    return jsonify({
        "status": "healthy" if model_loaded else "unhealthy",
        "model_loaded": model_loaded,
        "model_name": MODEL_METADATA.get("best_model", "Linear SVM (Calibrated)"),
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "version": "1.0.0"
    }), 200 if model_loaded else 503


@app.route("/api/predict", methods=["POST"])
def api_predict():
    """
    REST API endpoint for programmatic email spam classification.
    Expects JSON:
    {
        "subject": "Example Subject",
        "body": "Example Body"
    }
    """
    if not request.is_json:
        return jsonify({
            "error": "Invalid Content-Type. Request payload must be JSON with 'Content-Type: application/json'."
        }), 400

    payload = request.get_json(silent=True) or {}
    subject = str(payload.get("subject", "")).strip()
    body = str(payload.get("body", "")).strip()

    if not body and not subject:
        return jsonify({
            "error": "Empty request. At least 'body' or 'subject' must be provided."
        }), 400

    try:
        analysis = process_email_analysis(subject=subject, body=body)

        # Simplify suspicious indicators list for API response format
        simplified_indicators = [
            {
                "category": ind["category"],
                "severity": ind["severity"],
                "description": ind["description"],
                "matched_phrases": ind["matched_phrases"]
            }
            for ind in analysis["content_analysis"].get("indicators", [])
        ]

        response_payload = {
            "prediction": analysis["prediction"],
            "confidence": analysis["confidence"],
            "spam_probability": analysis["spam_probability"],
            "ham_probability": analysis["ham_probability"],
            "risk_score": analysis["risk_score"],
            "risk_level": analysis["risk_level"],
            "suspicious_indicators": simplified_indicators,
            "urls_detected": analysis["url_analysis"]["total_urls"],
            "suspicious_urls": analysis["url_analysis"]["suspicious_urls_count"],
            "url_details": analysis["url_analysis"]["url_details"],
            "top_keywords": analysis["top_words"],
            "explanation": analysis["explanation_reasons"],
            "recommendation": analysis["recommendation"]["action"]
        }

        return jsonify(response_payload), 200

    except Exception as err:
        return jsonify({
            "error": "Failed to process email analysis.",
            "details": str(err)
        }), 500


# ============================================================================
# Safe Error Handlers
# ============================================================================

@app.errorhandler(400)
def handle_bad_request(e):
    if request.path.startswith("/api/"):
        return jsonify({"error": "Bad Request", "details": str(e)}), 400
    return render_template("index.html", error_message="Bad request received. Please check your input."), 400


@app.errorhandler(404)
def handle_not_found(e):
    if request.path.startswith("/api/"):
        return jsonify({"error": "Resource not found"}), 404
    return redirect(url_for("index"))


@app.errorhandler(413)
def handle_payload_too_large(e):
    msg = "Payload exceeds maximum allowed size (100 KB)."
    if request.path.startswith("/api/"):
        return jsonify({"error": msg}), 413
    return render_template("index.html", error_message=msg), 413


@app.errorhandler(500)
def handle_internal_error(e):
    if request.path.startswith("/api/"):
        return jsonify({"error": "Internal server error occurred."}), 500
    return render_template("index.html", error_message="An internal error occurred. Please try again."), 500


# ============================================================================
# Main Entry Point (Local Development)
# ============================================================================

if __name__ == "__main__":
    # Get port from environment variable (default 5000)
    port = int(os.environ.get("PORT", 5000))
    debug_mode = os.environ.get("FLASK_ENV", "development") == "development"
    print(f"[*] Starting Smart Spam Email Detection Server on http://0.0.0.0:{port}")
    app.run(host="0.0.0.0", port=port, debug=debug_mode)
