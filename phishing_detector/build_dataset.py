# build_dataset.py
import pandas as pd
from tqdm import tqdm
from feature_extractor import extract_features, DEFAULT_CACHE_PATH

def build(in_csv: str, out_csv: str):
    df = pd.read_csv(in_csv)  # url,label
    rows, f0 = [], None
    for _, r in tqdm(df.iterrows(), total=len(df), desc=f"Extracting features ({in_csv})"):
        feats = extract_features(r["url"], network=True, cache_path=str(DEFAULT_CACHE_PATH))
        f0 = f0 or feats
        rows.append(feats + [1 if r["label"]=="phishing" else 0])
    cols = [f"f{i+1}" for i in range(len(f0))] + ["label"]
    pd.DataFrame(rows, columns=cols).to_csv(out_csv, index=False)
    print(f"✅ {out_csv} written")

if __name__ == "__main__":
    build("urls_train.csv", "phishing_dataset_train.csv")
    build("urls_test.csv",  "phishing_dataset_test.csv")
    print("💾 Cache at feature_cache.json")
