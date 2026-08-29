from fastapi import FastAPI
from pydantic import BaseModel
import joblib
import pandas as pd
import shap
import re
from urllib.parse import urlparse
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------- Load model and feature list once, when the server starts ----------
# Load BOTH models
raw_model = joblib.load("model/phishing_xgb_final_model.pkl")            # for SHAP explanations
calibrated_model = joblib.load("model/phishing_xgb_calibrated_model.pkl") # for confidence score
url_only_features = joblib.load("model/url_only_feature_columns.pkl")
explainer = shap.TreeExplainer(raw_model)   # built on the raw model only

# ---------- Human-readable explanations for each feature ----------
feature_descriptions = {
    "IsHTTPS":                     ("Site uses HTTPS (secure)",             "Site does NOT use HTTPS"),
    "LetterRatioInURL":            ("Normal letter density in URL",         "High letter density in URL"),
    "DegitRatioInURL":             ("Normal digit usage in URL",            "High digit usage in URL"),
    "SpacialCharRatioInURL":       ("Normal special character usage",       "High special character usage in URL"),
    "NoOfOtherSpecialCharsInURL":  ("URL structure looks clean",            "Unusual characters in URL"),
    "DomainLength":                ("Domain name length looks typical",     "Unusual domain name length"),
    "URLLength":                   ("URL length looks typical",             "Unusually long or short URL"),
    "NoOfSubDomain":                ("Normal number of subdomains",          "Unusual number of subdomains"),
    "TLDLength":                    ("Domain extension length looks normal", "Unusual domain extension length"),
    "IsDomainIP":                   ("Domain name looks legitimate",         "URL uses a raw IP address instead of a domain"),
    "HasObfuscation":               ("URL is clean and readable",            "URL contains obfuscated/hidden characters"),
    "NoOfEqualsInURL":              ("Normal URL structure",                  "URL contains many parameters"),
}

# ---------- Feature extraction (same code used during training) ----------
def extract_url_features(url: str) -> dict:
    features = {}
    parsed = urlparse(url)
    domain = parsed.netloc

    features["URLLength"] = len(url)
    features["DomainLength"] = len(domain)
    features["IsHTTPS"] = 1 if parsed.scheme == "https" else 0

    ip_pattern = r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$"
    features["IsDomainIP"] = 1 if re.match(ip_pattern, domain) else 0
    features["NoOfSubDomain"] = max(parsed.netloc.count(".") - 1, 0)

    letters = sum(c.isalpha() for c in url)
    digits = sum(c.isdigit() for c in url)
    features["NoOfLettersInURL"] = letters
    features["LetterRatioInURL"] = letters / len(url) if len(url) else 0
    features["NoOfDegitsInURL"] = digits
    features["DegitRatioInURL"] = digits / len(url) if len(url) else 0

    stripped = re.sub(r"^https?://(www\.)?", "", url)
    special_chars = sum(not c.isalnum() for c in stripped)
    features["SpacialCharRatioInURL"] = special_chars / len(url) if len(url) else 0
    features["NoOfOtherSpecialCharsInURL"] = special_chars

    features["NoOfEqualsInURL"] = url.count("=")
    features["NoOfQMarkInURL"] = url.count("?")
    features["NoOfAmpersandInURL"] = url.count("&")

    tld = domain.split(".")[-1] if "." in domain else ""
    features["TLDLength"] = len(tld)

    obf_chars = url.count("%")
    features["HasObfuscation"] = 1 if obf_chars > 0 else 0
    features["NoOfObfuscatedChar"] = obf_chars
    features["ObfuscationRatio"] = obf_chars / len(url) if len(url) else 0

    return features

# ---------- Request body shape ----------
class URLRequest(BaseModel):
    url: str

# ---------- Root endpoint (already working) ----------
@app.get("/")
def read_root():
    return {"message": "Phishing detector API is running"}

# ---------- The real endpoint ----------
@app.post("/predict")
def predict(request: URLRequest):
    feats = extract_url_features(request.url)
    row = pd.DataFrame([feats])[url_only_features]

    # SHAP explanation comes from the raw model
    shap_vals = explainer.shap_values(row)
    prediction = raw_model.predict(row)[0]

    # Confidence comes from the calibrated model
    calibrated_proba = calibrated_model.predict_proba(row)[0]
    confidence = round(float(calibrated_proba[prediction]) * 100, 2)

    label = "Legitimate" if prediction == 1 else "Phishing"

    exp_df = pd.DataFrame({
        "feature": row.columns,
        "shap_value": shap_vals[0]
    }).sort_values(by="shap_value", key=abs, ascending=False).head(5)

    reasons = []
    for _, r in exp_df.iterrows():
        feat = r["feature"]
        if feat not in feature_descriptions:
            continue
        pos_desc, neg_desc = feature_descriptions[feat]
        reasons.append(f"+ {pos_desc}" if r["shap_value"] > 0 else f"- {neg_desc}")

    return {
        "url": request.url,
        "prediction": label,
        "confidence": confidence,
        "reasons": reasons
    }