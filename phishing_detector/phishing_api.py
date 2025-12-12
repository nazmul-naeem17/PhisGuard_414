# phishing_api.py
from __future__ import annotations

import os
import json
import time
import secrets
from typing import Any, Dict, Tuple
from urllib.parse import urlparse, urljoin

import numpy as np
import requests
from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
from bs4 import BeautifulSoup
import joblib
import tldextract  # make sure this is installed

from feature_extractor import (
    extract_features_with_meta,
    DEFAULT_CACHE_PATH,
)
from crypto_utils import (
    load_or_make_hmac_key,
    load_or_make_rsa,
    sign_and_mac,
)

# --------------------------------------------------------------------
# App
# --------------------------------------------------------------------
app = Flask(
    __name__,
    template_folder="templates",
    static_folder="static",
    static_url_path="/static",
)
CORS(app)

# --------------------------------------------------------------------
# Config / environment
# --------------------------------------------------------------------
SHORTENERS = {"bit.ly", "goo.gl", "tinyurl.com", "ow.ly", "is.gd", "t.co"}

def _env_bool(name: str, default: bool) -> bool:
    v = os.getenv(name)
    if v is None:
        return default
    return str(v).strip().lower() in {"1", "true", "yes", "on"}

MIN_THRESHOLD     = float(os.getenv("MIN_THRESHOLD", "0.35"))
VERDICT_TTL_SECS  = int(os.getenv("VERDICT_TTL_SECS", "300"))

# Inference feature toggles (you can flip with env vars at runtime)
PHG_DISABLE_DOM   = _env_bool("PHG_DISABLE_DOM",   True)   # default True = calmer demo
PHG_DISABLE_CT    = _env_bool("PHG_DISABLE_CT",    False)
PHG_DISABLE_WHOIS = _env_bool("PHG_DISABLE_WHOIS", False)
URL_ONLY          = _env_bool("URL_ONLY",          False)

# Reputation layer
USE_REPUTATION    = _env_bool("USE_REPUTATION",    True)
PHG_TRUSTED_FILE  = os.getenv("PHG_TRUSTED_FILE", "").strip()

# A small built-in trust set (eTLD+1); you can extend via PHG_TRUSTED_FILE
TRUSTED_ETLD1 = {
    "wikipedia.org", "google.com", "youtube.com", "facebook.com", "apple.com",
    "microsoft.com", "github.com", "paypal.com", "linkedin.com", "instagram.com",
    "netflix.com", "reddit.com", "bbc.co.uk", "nytimes.com", "cdc.gov", "nih.gov",
    "office.com"
}

def _load_extra_trusted(path: str) -> set[str]:
    s = set()
    if not path:
        return s
    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                s.add(line.lower())
    except Exception:
        pass
    return s

EXTRA_TRUSTED = _load_extra_trusted(PHG_TRUSTED_FILE)
TRUSTED_ALL = TRUSTED_ETLD1 | EXTRA_TRUSTED

# --------------------------------------------------------------------
# Model + metadata
# --------------------------------------------------------------------
def _safe_load_json(path: str, default: Dict[str, Any]) -> Dict[str, Any]:
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return dict(default)

model = joblib.load("best_model.pkl")

feature_meta = _safe_load_json("feature_meta.json", {"n_features": 86})
N_FEATS = int(feature_meta.get("n_features", 86))

model_meta = _safe_load_json("model_meta.json", {"threshold": 0.5, "best_model": "unknown"})
TAU = float(model_meta.get("threshold", 0.5))
MODEL_NAME = str(model_meta.get("best_model", "unknown"))

EFFECTIVE_TAU = max(TAU, MIN_THRESHOLD)

# --------------------------------------------------------------------
# Crypto
# --------------------------------------------------------------------
HMAC_KEY = load_or_make_hmac_key()
RSA_PRIV, RSA_PUB, PUBKEY_PEM = load_or_make_rsa()

# --------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------
def expand_url(url: str) -> str:
    """Expand shorteners by following redirects or meta-refresh."""
    if "://" not in url:
        url = "http://" + url
    host = urlparse(url).netloc.lower()
    if host not in SHORTENERS:
        return url

    try:
        r = requests.get(url, timeout=5, allow_redirects=True,
                         headers={"User-Agent": "Mozilla/5.0"})
        if r.url and r.url != url:
            return r.url

        soup = BeautifulSoup(r.text, "html.parser")
        meta = soup.find("meta", attrs={"http-equiv": lambda v: v and v.lower() == "refresh"})
        if meta and "content" in meta.attrs:
            parts = [s.strip() for s in meta["content"].split(";")]
            for part in parts:
                if part.lower().startswith("url="):
                    return urljoin(url, part[4:].strip(" '\""))
    except Exception:
        pass
    return url

def etld1_from_url(url: str) -> str:
    e = tldextract.extract(url)
    if e.suffix:
        return f"{e.domain}.{e.suffix}".lower()
    # fallback
    return (e.domain or urlparse(url).netloc).lower()

def _apply_feature_toggles(feats: list[float]) -> dict:
    """
    Apply inference-time toggles and return info about what was applied.
    Mapping (1-based → 0-based):
      f80 -> feats[79] = CT
      f81 -> feats[80] = WHOIS age
      f82..f85 -> feats[81..84] = DOM metrics
      f86 -> feats[85] = CT dup
    """
    applied = {"dom": False, "ct": False, "whois": False, "url_only": False}

    if URL_ONLY:
        feats[79] = 0
        feats[80:85] = [365, 0, 0, 0.0, 0]  # neutral WHOIS + zero DOM
        feats[85] = 0
        applied.update({"dom": True, "ct": True, "whois": True, "url_only": True})
        return applied

    if PHG_DISABLE_DOM:
        feats[81:85] = [0, 0, 0.0, 0]
        applied["dom"] = True

    if PHG_DISABLE_CT:
        feats[79] = 0
        feats[85] = 0
        applied["ct"] = True

    if PHG_DISABLE_WHOIS:
        feats[80] = 365
        applied["whois"] = True

    return applied

def _apply_reputation(url: str, proba: float) -> Tuple[float, dict]:
    """
    If reputation is enabled and the domain is in TRUSTED_ALL, cap the phish
    probability at 5%. Returns (new_proba, rep_info).
    """
    if not USE_REPUTATION:
        return proba, {"used": False}

    d = etld1_from_url(url)
    if d in TRUSTED_ALL:
        return min(proba, 0.05), {"used": True, "etld1": d, "label": "trusted", "source": "builtin+file"}
    return proba, {"used": False, "etld1": d}

# --------------------------------------------------------------------
# Routes
# --------------------------------------------------------------------
@app.route("/", methods=["GET"])
def index():
    return render_template("index.html")

@app.route("/pubkey", methods=["GET"])
def pubkey():
    return PUBKEY_PEM, 200, {"Content-Type": "application/x-pem-file"}

@app.route("/health", methods=["GET"])
def health():
    return jsonify({
        "ok": True,
        "features": N_FEATS,
        "model": MODEL_NAME,
        "threshold": TAU,
        "effective_threshold": EFFECTIVE_TAU,
        "ttl_secs": VERDICT_TTL_SECS,
        "toggles": {
            "PHG_DISABLE_DOM": PHG_DISABLE_DOM,
            "PHG_DISABLE_CT": PHG_DISABLE_CT,
            "PHG_DISABLE_WHOIS": PHG_DISABLE_WHOIS,
            "URL_ONLY": URL_ONLY,
            "USE_REPUTATION": USE_REPUTATION,
        },
        "trusted_count": len(TRUSTED_ALL),
    })

@app.route("/predict", methods=["POST"])
def predict():
    # ---- parse ----
    try:
        data = request.get_json(force=True) or {}
    except Exception:
        return jsonify({"error": "invalid JSON"}), 400

    raw_url = (data.get("url") or "").strip()
    if not raw_url:
        return jsonify({"error": "missing url"}), 400

    url = expand_url(raw_url)

    # ---- features (cache-first; neutral fallbacks) ----
    feats, meta_src = extract_features_with_meta(
        url,
        cache_path=str(DEFAULT_CACHE_PATH),
        network_mode="cache-first",
    )
    feats = (feats + [0.0] * (N_FEATS - len(feats)))[:N_FEATS]

    # ---- toggles ----
    toggles_applied = _apply_feature_toggles(feats)

    # ---- inference ----
    X = np.asarray(feats, dtype=float).reshape(1, -1)
    proba = float(model.predict_proba(X)[0, 1])

    # ---- reputation prior (caps proba for top trusted sites) ----
    proba, rep_info = _apply_reputation(url, proba)

    verdict = "phishing" if proba >= EFFECTIVE_TAU else "legit"

    # ---- sign ----
    now = int(time.time())
    payload = {
        "url": url,
        "prediction": verdict,
        "probability": round(proba, 6),
        "threshold": EFFECTIVE_TAU,
        "features_used": N_FEATS,
        "model": MODEL_NAME,

        "iat": now,
        "exp": now + VERDICT_TTL_SECS,
        "nonce": secrets.token_hex(8),

        # introspection
        "cache_hit": bool(meta_src.get("cache_hit", False)),
        "used_fallback": bool(meta_src.get("used_fallback", False)),
        "sources": meta_src.get("sources", {}),
        "toggles_applied": toggles_applied,
        "reputation": rep_info,
        "req_id": secrets.token_hex(8),
    }

    sigs = sign_and_mac(payload, HMAC_KEY, RSA_PRIV)

    return jsonify({
        "payload": payload,
        "hmac": sigs["hmac"],
        "signature": sigs["signature"],
        "pubkey_pem": PUBKEY_PEM
    })

# --------------------------------------------------------------------
# Main
# --------------------------------------------------------------------
if __name__ == "__main__":
    print("🔌 PhishGuard 414 API: http://127.0.0.1:5000")
    print(f"   Model: {MODEL_NAME} | features={N_FEATS} | τ={TAU} | τ*={EFFECTIVE_TAU}")
    print(f"   Toggles: DOM={'OFF' if PHG_DISABLE_DOM else 'ON'}, CT={'OFF' if PHG_DISABLE_CT else 'ON'}, WHOIS={'OFF' if PHG_DISABLE_WHOIS else 'ON'}, URL_ONLY={'ON' if URL_ONLY else 'OFF'}")
    print(f"   Reputation: USE_REPUTATION={'ON' if USE_REPUTATION else 'OFF'} | trusted domains={len(TRUSTED_ALL)} (+ {len(EXTRA_TRUSTED)} from file)")
    app.run(host="127.0.0.1", port=5000, debug=True)
