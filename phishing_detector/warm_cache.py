#!/usr/bin/env python3
"""
warm_cache.py

Pre-populates feature_cache.json by fetching WHOIS / CT / DOM signals
for a set of trusted, well-known legit domains (and anything you pass in).
This makes inference stable even when your machine is offline or the
target sites throttle requests.

Usage:
  python warm_cache.py
  python warm_cache.py --add https://www.wikipedia.org https://www.google.com
  python warm_cache.py --file extra_urls.txt
  python warm_cache.py --cache my_cache.json
"""

from pathlib import Path
import argparse
from typing import List

from feature_extractor import extract_features_with_meta, DEFAULT_CACHE_PATH

TRUSTED_DEFAULT: List[str] = [
    "https://www.google.com",
    "https://www.wikipedia.org",
    "https://www.youtube.com",
    "https://www.facebook.com",
    "https://www.apple.com",
    "https://www.microsoft.com",
    "https://github.com",
    "https://www.paypal.com",
    "https://www.linkedin.com",
    "https://www.instagram.com",
    "https://www.netflix.com",
    "https://www.reddit.com",
    "https://www.bbc.co.uk",
    "https://www.nytimes.com",
    "https://www.cdc.gov",
    "https://www.nih.gov",
    "https://www.office.com",
]

def read_file_urls(file_path: str) -> List[str]:
    p = Path(file_path)
    if not p.exists():
        return []
    return [line.strip() for line in p.read_text(encoding="utf-8").splitlines() if line.strip()]

def main():
    ap = argparse.ArgumentParser(description="Warm feature cache for trusted domains.")
    ap.add_argument("--add", nargs="*", default=[], help="Additional URLs to warm (space-separated).")
    ap.add_argument("--file", help="Path to a text file with one URL per line.")
    ap.add_argument("--cache", help="Cache file path (default: feature_cache.json).")
    args = ap.parse_args()

    urls = list(TRUSTED_DEFAULT)
    if args.file:
        urls += read_file_urls(args.file)
    if args.add:
        urls += args.add

    # De-duplicate while preserving order
    seen = set()
    ordered = []
    for u in urls:
        if u not in seen:
            seen.add(u)
            ordered.append(u)

    cache_path = str(Path(args.cache) if args.cache else DEFAULT_CACHE_PATH)

    ok, fallback = 0, 0
    print(f"→ warming cache at {cache_path}")
    for u in ordered:
        try:
            _, meta = extract_features_with_meta(
                u, cache_path=cache_path, network_mode="fetch"  # force network on miss
            )
            src = meta.get("sources", {})
            fb = bool(meta.get("used_fallback", False))
            print(f"   {u:60s}  sources={src}  fallback={fb}")
            ok += 1
            if fb:
                fallback += 1
        except Exception as e:
            print(f"   {u:60s}  ERROR: {e}")

    print(f"\n✅ Done. Wrote/updated: {cache_path}")
    print(f"   Warmed: {ok}, with fallback: {fallback}")

if __name__ == "__main__":
    main()
