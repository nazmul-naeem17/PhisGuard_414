#!/usr/bin/env python3
"""
fetch_datasets.py

Downloads a phishing URL feed (one URL per line) and the UNB CIC benign URL list,
saving each to a CSV file.

Usage:
    python fetch_datasets.py \
        --feed <phishing_feed_url> \
        --out <phishing_output.csv> \
        [--benign-out <benign_output.csv>]

Example:
    python fetch_datasets.py \
        --feed https://openphish.com/feed.txt \
        --out phishing.csv \
        --benign-out All.csv
"""

import argparse
import requests
import sys

# Default benign URL dataset
UNB_BENIGN_URL = (
    "http://cicresearch.ca/CICDataset/ISCX-URL-2016/Dataset/All.csv"
)


def download_phishing(feed_url: str, out_file: str):
    """
    Fetch the phishing feed from the given URL and save it as a CSV
    with header 'url'.
    """
    print(f"Fetching phishing feed from {feed_url}…", file=sys.stderr)
    r = requests.get(feed_url, timeout=30)
    r.raise_for_status()

    # Write the output CSV
    with open(out_file, "w", encoding="utf-8") as f:
        f.write("url\n")
        f.write(r.text.strip() + "\n")
    print(f"→ Saved {out_file}", file=sys.stderr)


def download_benign(out_file: str):
    """
    Download the UNB CIC benign URL list and save it directly.
    """
    print(f"Fetching UNB CIC benign list from {UNB_BENIGN_URL}…", file=sys.stderr)
    r = requests.get(UNB_BENIGN_URL, timeout=30)
    r.raise_for_status()

    with open(out_file, "wb") as f:
        f.write(r.content)
    print(f"→ Saved {out_file}", file=sys.stderr)


def main():
    parser = argparse.ArgumentParser(
        description="Fetch phishing and benign URL datasets."
    )
    parser.add_argument(
        "--feed", required=True,
        help="URL of the phishing feed (one URL per line)"
    )
    parser.add_argument(
        "--out", required=True,
        help="Output CSV filename for phishing dataset"
    )
    parser.add_argument(
        "--benign-out", default="All.csv",
        help="Output filename for benign URLs (default: All.csv)"
    )

    args = parser.parse_args()

    try:
        download_phishing(args.feed, args.out)
        download_benign(args.benign_out)
        print("Done. You can now run `python model_training.py`.", file=sys.stderr)
    except requests.RequestException as e:
        print(f"ERROR: network request failed: {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
