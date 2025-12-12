# feature_extractor.py
# Robust feature extractor for PhishGuard 414
# - 86 features (80 URL heuristics + WHOIS + DOM + CT set)
# - Cache-first (feature_cache.json)
# - Neutral fallbacks on failure or unknown fields (no "scare" defaults)
# - Meta info about sources (cache/network/fallback) for debugging

from __future__ import annotations

import os
import re
import math
import json
import socket
from pathlib import Path
from typing import Dict, Tuple, Optional, List
from urllib.parse import urlparse, parse_qs, urljoin
from datetime import datetime, timezone

import requests
from bs4 import BeautifulSoup
import whois
import tldextract

# ----------------------------
# Constants
# ----------------------------

VOWELS = set("aeiou")
CONSONANTS = set("bcdfghjklmnpqrstvwxyz")
EXEC_EXTS = {".exe", ".bat", ".cmd", ".scr", ".com", ".pif"}
SENSITIVE = ["login", "secure", "account", "update", "verify", "bank", "signin"]
SYM = set('!"#$%&\'()*+,-./:;<=>?@[\\]^_`{|}~')

DEFAULT_CACHE_PATH = Path("feature_cache.json")

# ----------------------------
# Helpers
# ----------------------------

def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq: Dict[str, int] = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    ln = len(s)
    return -sum((cnt / ln) * math.log2(cnt / ln) for cnt in freq.values())

def _load_cache(p: Path) -> Dict[str, dict]:
    if p.exists():
        try:
            return json.loads(p.read_text(encoding="utf-8"))
        except Exception:
            return {}
    return {}

def _save_cache(cache: Dict[str, dict], p: Path) -> None:
    tmp = p.with_suffix(".tmp")
    tmp.write_text(json.dumps(cache, ensure_ascii=False), encoding="utf-8")
    tmp.replace(p)

def _etld1_from_url(url: str) -> str:
    e = tldextract.extract(url)
    if e.suffix:
        return f"{e.domain}.{e.suffix}".lower()
    return (e.domain or urlparse(url).netloc).lower()

def _is_ip(host: str) -> int:
    try:
        socket.inet_aton(host)
        return 1
    except Exception:
        return 0

def _fetch_whois_age_days(host: str) -> Optional[int]:
    """
    Returns number of days since domain creation, or None if unknown.
    """
    w = whois.whois(host)
    created = getattr(w, "creation_date", None)
    if isinstance(created, list):
        created = created[0]
    if not created:
        return None  # unknown (privacy/GDPR/registry)
    if isinstance(created, datetime):
        dt = created
    else:
        # Some whois libs can return strings; try parsing lightly
        try:
            dt = datetime.fromisoformat(str(created))
        except Exception:
            return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return max(0, (datetime.now(timezone.utc) - dt).days)

def _fetch_ct_flag(host: str) -> int:
    """
    0 if crt.sh returns any entries (has CT log), 1 otherwise.
    """
    r = requests.get(f"https://crt.sh/?q={host}&output=json", timeout=4)
    if r.ok:
        try:
            data = r.json()
            return 0 if data else 1
        except Exception:
            return 1
    return 1

def _fetch_dom_metrics(url: str) -> Tuple[int, int, float, int]:
    """
    Returns (num_forms, has_password, ext_int_ratio, iframes)
    """
    r = requests.get(url, timeout=6, headers={"User-Agent": "Mozilla/5.0"})
    soup = BeautifulSoup(r.text, "html.parser")

    forms = soup.find_all("form")
    num_forms = len(forms)
    has_password = 1 if soup.find("input", {"type": "password"}) else 0

    domain = urlparse(url).netloc.lower()
    links: List[str] = []
    for tag, attr in (("img", "src"), ("script", "src"), ("link", "href")):
        for el in soup.find_all(tag):
            if el.has_attr(attr):
                links.append(urljoin(url, el[attr]))

    ext, inter = 0, 0
    for l in links:
        host = urlparse(l).netloc.lower()
        if host and host != domain:
            ext += 1
        else:
            inter += 1
    ext_int_ratio = ext / max(1, inter)

    iframes = len(soup.find_all("iframe"))
    return num_forms, has_password, float(ext_int_ratio), iframes

def _neutral_values() -> dict:
    """
    Neutral defaults that DO NOT bias toward "phish" when a signal is unknown/failing.
    """
    return {
        "whois_age_days": 365,       # ~1 year
        "ct_flag": 0,                # assume CT entries exist (conservative)
        "dom_forms": 0,
        "dom_has_password": 0,
        "dom_ext_int_ratio": 0.0,
        "dom_iframes": 0,
        "_source": {"whois": "fallback", "ct": "fallback", "dom": "fallback"},
    }

def _merge_meta(sources: Dict[str, str], key: str, value: str) -> Dict[str, str]:
    d = dict(sources)
    d[key] = value
    return d

# ----------------------------
# Feature extractor
# ----------------------------

def extract_features_with_meta(
    url: str,
    cache_path: Optional[str] = None,
    network_mode: str = "cache-first",
) -> Tuple[List[float], dict]:
    """
    Build the 86-dim feature vector and return (features, meta).

    network_mode:
      - 'cache-first' : use cache if present; otherwise try fetch; otherwise neutral fallback.
      - 'fetch'       : always try fetch, then neutral fallback on failure; also write cache.
      - 'cache-only'  : only use cache; if missing, write neutral fallback into cache.

    meta = {
      "sources": {"whois":"cache|network|fallback", "ct": "...", "dom": "..."},
      "cache_hit": bool,
      "used_fallback": bool,
    }
    """
    # Normalize URL (ensure scheme)
    if "://" not in url:
        url = "http://" + url
    p0 = urlparse(url)
    full_url = p0.geturl()
    p = urlparse(full_url)

    host = p.netloc.lower()
    path = p.path or ""
    query = p.query or ""
    fname = path.rsplit("/", 1)[-1] if "/" in path else path
    ext = ("." + fname.rsplit(".", 1)[-1].lower()) if "." in fname else ""

    d_toks = [t for t in host.split(".") if t]
    p_toks = [t for t in path.split("/") if t]
    qdict = parse_qs(query)

    u, dm, pd, ql = len(full_url), len(host), len(path), len(query)
    lower_url = full_url.lower()

    feats: List[float] = []

    # ---- 80 URL heuristics in fixed positions ----
    feats.append(len(qdict))                                      # 1
    feats.append(len(d_toks))                                     # 2
    feats.append(len(p_toks))                                     # 3
    feats.append(sum(len(t) for t in d_toks) / len(d_toks) if d_toks else 0)  # 4
    feats.append(max((len(t) for t in d_toks), default=0))                    # 5
    feats.append(sum(len(t) for t in p_toks) / len(p_toks) if p_toks else 0)  # 6
    feats.append(len(d_toks[-1]) if d_toks else 0)                            # 7
    feats.append(sum(c in VOWELS for c in lower_url))                         # 8
    feats.append(sum(c in CONSONANTS for c in lower_url))                     # 9

    # 10–14 longest digit run per segment
    for seg in (full_url, host, path, fname, query):
        runs = [len(m.group(0)) for m in re.finditer(r"\d+", seg)]
        feats.append(max(runs, default=0))

    # 15–19 digit count per segment
    for seg in (full_url, host, path, fname, query):
        feats.append(sum(c.isdigit() for c in seg))

    # 20–26 lengths
    feats += [
        u, dm, pd,
        len(path.rsplit("/", 1)[0]) if "/" in path else 0,
        len(fname), len(ext), ql,
    ]

    # 27–32 ratios
    feats += [
        (pd / u) if u else 0,
        (ql / u) if u else 0,
        (ql / dm) if dm else 0,
        (dm / u) if u else 0,
        (pd / dm) if dm else 0,
        (ql / pd) if pd else 0,
    ]

    # 33–38 flags/misc
    feats.append(int(ext in EXEC_EXTS))                   # 33
    feats.append(int(":80" in host))                      # 34
    feats.append(full_url.count("."))                     # 35
    feats.append(_is_ip(host))                            # 36
    runs = [len(m.group(0)) for m in re.finditer(r"(.)\1*", full_url)]
    feats.append((max(runs, default=0) / (u or 1)))       # 37
    vals = [v for vs in qdict.values() for v in vs]
    feats.append(max((len(v) for v in vals), default=0))  # 38

    # 39–44 more digit counts
    feats += [sum(c.isdigit() for c in seg) for seg in (full_url, host, path, fname, ext, query)]

    # 45–50 letter counts
    feats += [sum(c.isalpha() for c in seg) for seg in (full_url, host, path, fname, ext, query)]

    # 51–54 longest token lengths
    feats += [
        max((len(t) for t in p_toks), default=0),
        max((len(t) for t in d_toks), default=0),
        max((len(t) for t in p_toks), default=0),
        max((len(t) for t in p_toks), default=0),
    ]

    # 55 longest query key/value
    feats.append(max((len(a) for a in list(qdict.keys()) + vals), default=0))

    # 56 sensitive-word flag
    feats.append(int(any(w in lower_url for w in SENSITIVE)))

    # 57 distinct query key count
    feats.append(len(qdict))

    # 58 special-char count (excluding typical URL delimiters)
    feats.append(sum(1 for c in full_url if not c.isalnum() and c not in "/:.*?=&-"))

    # 59–61 delimiters
    feats.append(host.count("."))
    feats.append(path.count("/"))
    feats.append(host.count(".") + path.count("/"))

    # 62–67 digit-rate per segment
    for seg_len, seg in ((u, full_url), (dm, host), (pd, path), (len(fname), fname), (len(ext), ext), (ql, query)):
        feats.append((sum(c.isdigit() for c in seg) / (seg_len or 1)))

    # 68–73 symbol counts per segment
    feats += [sum(c in SYM for c in seg) for seg in (full_url, host, path, fname, ext, query)]

    # 74–79 entropy per segment
    feats += [shannon_entropy(seg) for seg in (full_url, host, path, fname, ext, query)]

    # 80 placeholder for CT flag (we'll set after network/cache step)
    feats.append(0)

    # ---- WHOIS/DOM/CT with cache-first policy ----
    cache_file = Path(cache_path) if cache_path else DEFAULT_CACHE_PATH
    cache = _load_cache(cache_file)
    hk = _etld1_from_url(full_url)

    meta = {"sources": {"whois": "", "ct": "", "dom": ""}, "cache_hit": False}
    values: dict

    if hk in cache:
        values = dict(cache[hk])
        meta["cache_hit"] = True
        meta["sources"] = values.get("_source", {"whois": "cache", "ct": "cache", "dom": "cache"})
    elif network_mode in ("cache-first", "fetch"):
        # Start from neutral defaults; fill what we can from network
        values = _neutral_values()

        # WHOIS (unknown age -> neutral, not 0)
        try:
            age = _fetch_whois_age_days(hk)
            if age is None or age <= 0:
                values["whois_age_days"] = 365
                values["_source"] = _merge_meta(values["_source"], "whois", "fallback")
            else:
                values["whois_age_days"] = int(age)
                values["_source"] = _merge_meta(values["_source"], "whois", "network")
        except Exception:
            values["_source"] = _merge_meta(values["_source"], "whois", "fallback")

        # CT
        try:
            ctflag = _fetch_ct_flag(hk)
            values["ct_flag"] = int(ctflag)
            values["_source"] = _merge_meta(values["_source"], "ct", "network")
        except Exception:
            values["_source"] = _merge_meta(values["_source"], "ct", "fallback")

        # DOM
        try:
            f, pw, ratio, ifr = _fetch_dom_metrics(full_url)
            values["dom_forms"] = int(f)
            values["dom_has_password"] = int(pw)
            values["dom_ext_int_ratio"] = float(ratio)
            values["dom_iframes"] = int(ifr)
            values["_source"] = _merge_meta(values["_source"], "dom", "network")
        except Exception:
            values["_source"] = _merge_meta(values["_source"], "dom", "fallback")

        cache[hk] = values
        _save_cache(cache, cache_file)
        meta["sources"] = values["_source"]
    else:
        # cache-only and not found: write neutral
        values = _neutral_values()
        cache[hk] = values
        _save_cache(cache, cache_file)
        meta["sources"] = values["_source"]

    # Set CT flag at position 80 (index 79), then append the rest to reach 86
    feats[79] = int(values["ct_flag"])
    feats += [
        int(values["whois_age_days"]),      # 81
        int(values["dom_forms"]),           # 82
        int(values["dom_has_password"]),    # 83
        float(values["dom_ext_int_ratio"]), # 84
        int(values["dom_iframes"]),         # 85
        int(values["ct_flag"]),             # 86 (duplicate CT)
    ]

    # Ensure exact length 86
    if len(feats) != 86:
        feats = (feats + [0])[:86]

    meta["used_fallback"] = any(v == "fallback" for v in meta["sources"].values())
    return feats, meta

def extract_features(
    url: str,
    network: bool = False,
    cache_path: Optional[str] = None,
) -> List[float]:
    """
    Backward-compatible wrapper returning ONLY the feature vector.
    Set network=True to force fetch on cache-miss (training-time).
    """
    mode = "fetch" if network else "cache-first"
    feats, _ = extract_features_with_meta(url, cache_path=cache_path, network_mode=mode)
    return feats
