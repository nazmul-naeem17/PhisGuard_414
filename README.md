# PhishGuard 414: Predictive ML-Based Phishing Detector

**PhishGuard 414** is a lightweight, in-context phishing detection system. It fuses **URL machine learning**, **dynamic HTML analysis**, and **cryptographic signatures** to deliver fast, tamper-proof verdicts directly to the client.

## 🚀 Key Features

* **Hybrid Defense:** Extracts **86 features** from URL token statistics, WHOIS age, Certificate Transparency, and DOM indicators.
* **Tamper-Evident Verdicts:** Every prediction is timestamped, authenticated (HMAC-SHA256), and signed (RSA PKCS#1 v1.5) for client-side verification.
* **Resilient Architecture:** Uses a **cache-first policy** with neutral fallbacks to prevent bias when network signals are blocked.
* **Production Ready:** Features **Isotonic Calibration** for reliable probabilities and a **Reputation Prior** to reduce false positives on trusted domains.

## 📊 Model Performance

We selected the **ExtraTrees** ensemble model for its stability and high accuracy after extensive cross-validation.

| Model | CV ROC-AUC | Hold-out ROC-AUC |
| :--- | :--- | :--- |
| **ExtraTrees** | **0.9989** | **1.00** |
| Random Forest | 0.9977 | 0.9996 |
| Logistic Regression | 0.9914 | 0.9996 |

## 🛠️ Quick Start

### Prerequisites
* Python 3.x, Flask, Scikit-learn.
* OpenSSL (for key generation).

### Installation

1.  **Clone & Install:**
    ```bash
    git clone [https://github.com/your-username/PhishGuard_414.git](https://github.com/your-username/PhishGuard_414.git)
    pip install -r requirements.txt
    ```

2.  **Generate Keys:**
    Required for the cryptographic signing layer.
    ```bash
    openssl genrsa -out private.pem 2048
    openssl rsa -in private.pem -pubout -out public.pem
    ```

3.  **Run:**
    ```bash
    python app.py
    ```
    Access the Web UI at `http://localhost:5000` to inspect the "Signed Verdict" and cryptographic proofs.
