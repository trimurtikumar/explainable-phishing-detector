# Explainable Phishing URL Detector

A machine learning system that classifies URLs as phishing or legitimate, with human-readable explanations for every prediction using SHAP.

## What it does

Enter a URL → the system extracts structural features from it → an XGBoost model predicts Phishing or Legitimate → SHAP explains which specific features drove that decision, shown as plain-language reasons (e.g. "Site uses HTTPS", "Unusual number of subdomains").

## Tech Stack

- **ML:** Python, scikit-learn, XGBoost, SHAP
- **Backend:** FastAPI
- **Frontend:** React (Vite)
- **Dataset:** PhiUSIIL Phishing URL Dataset (235,795 rows)

## Project Highlights

- Trained and compared three models (Logistic Regression, Random Forest, XGBoost), validated with 5-fold cross-validation
- Investigated a suspiciously high initial accuracy result and ruled out data leakage by inspecting feature coefficients
- Built SHAP-based explainability to convert model output into human-readable reasoning
- Identified and fixed train/serve skew: the original model's live-prediction accuracy dropped when tested on real-world URLs, because live feature extraction didn't match the dataset's original (undocumented) methodology. Solved by re-extracting all training features using the same code used at prediction time, eliminating the mismatch.
- Applied probability calibration (CalibratedClassifierCV) to address XGBoost's tendency toward overconfident predictions

## Architecture
- React frontend → FastAPI backend → feature extraction → XGBoost model → SHAP explainer → JSON response


## Known Limitations

- The live model uses URL-text features only (not page content), trading some accuracy for reliability — scraping live page content is fragile (bot-blocking, JavaScript rendering, timeouts)
- No live domain-existence verification by default
- Confidence scores, while calibrated, can still skew high due to the nature of tree-based ensemble models

## Running Locally

**Backend:**
```bash
cd Backend
pip install -r requirements.txt
uvicorn main:app --reload
```

**Frontend:**
```bash
cd frontend
npm install
npm run dev
```

## Author's Note

This project involved substantial real-world debugging beyond the initial model training — including discovering and resolving a train/serve skew issue through systematic comparison of live-extracted features against dataset ground truth.