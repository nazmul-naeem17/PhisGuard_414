# curate_urls.py
import pandas as pd
import numpy as np
import tldextract
from urllib.parse import urlparse

PHISH_CSV = "Phishing.csv"
BENIGN_CSV = "All.csv"
OUT_CSV = "urls_and_labels.csv"

MAX_PER_DOMAIN_LEGIT = 40
MAX_PER_DOMAIN_PHISH = 30
TARGET_PER_BUCKET = 300

# path buckets for diversity
def path_bucket(p: str, q: str) -> str:
    depth = p.count("/")
    L = len(p)
    has_q = 1 if q else 0
    if L <= 1 and not has_q: return "short_plain"
    if L <= 1 and has_q:     return "short_query"
    if L <= 15:              return "med"
    if L <= 50:              return "long"
    return "xl"

def normalize_url(u: str) -> str:
    u = str(u).strip()
    if not u:
        return ""
    if "://" not in u:
        u = "http://" + u
    return u

def etld1(u: str) -> str:
    e = tldextract.extract(u)
    return (f"{e.domain}.{e.suffix}".lower() if e.suffix else e.domain.lower())

def load_and_clean(path: str, label: str) -> pd.DataFrame:
    df = pd.read_csv(path)
    if "url" not in df.columns:
        df = df.rename(columns={df.columns[0]:"url"})
    df["url"] = df["url"].astype(str).map(normalize_url)
    p = df["url"].map(urlparse)
    df["host"] = p.map(lambda x: x.netloc.lower())
    df["path"] = p.map(lambda x: x.path or "/")
    df["query"] = p.map(lambda x: x.query or "")
    df["bucket"] = [path_bucket(pth, qry) for pth, qry in zip(df["path"], df["query"])]
    df["etld1"] = df["url"].map(etld1)
    df = df[df["host"].str.len() > 0]
    df["label"] = label
    df = df.drop_duplicates(subset=["url"])
    return df[["url","label","etld1","path","query","bucket"]]

def cap_per_domain(df: pd.DataFrame, per_domain: int) -> pd.DataFrame:
    return (df.groupby("etld1", group_keys=False)
              .apply(lambda g: g.sample(min(len(g), per_domain), random_state=42))
              .reset_index(drop=True))

def sample_benign_diverse(df_legit: pd.DataFrame, target_per_bucket: int) -> pd.DataFrame:
    out = []
    for b in ["short_plain","short_query","med","long","xl"]:
        gb = df_legit[df_legit["bucket"]==b]
        if len(gb) == 0: 
            continue
        gb = cap_per_domain(gb, MAX_PER_DOMAIN_LEGIT)
        k = min(len(gb), target_per_bucket)
        out.append(gb.sample(k, random_state=42))
    mix = pd.concat(out, ignore_index=True) if out else df_legit
    # cap again across entire set
    mix = cap_per_domain(mix, MAX_PER_DOMAIN_LEGIT)
    return mix

def main():
    ph = load_and_clean(PHISH_CSV, "phishing")
    lg = load_and_clean(BENIGN_CSV, "legit")

    ph = cap_per_domain(ph, MAX_PER_DOMAIN_PHISH)
    lg = sample_benign_diverse(lg, TARGET_PER_BUCKET)

    # balance 1:1
    n = min(len(ph), len(lg))
    ph = ph.sample(n, random_state=42)
    lg = lg.sample(n, random_state=42)

    df = pd.concat([ph, lg], ignore_index=True)
    df = df.sample(frac=1.0, random_state=42).reset_index(drop=True)
    df[["url","label"]].to_csv(OUT_CSV, index=False)

    # tiny report
    print(f"✅ {OUT_CSV}: {len(df)} rows (balanced {n}/{n})")
    print("   uniques (domains): legit =", lg["etld1"].nunique(), ", phish =", ph["etld1"].nunique())
    print("   benign bucket dist:\n", lg["bucket"].value_counts())

if __name__ == "__main__":
    main()
