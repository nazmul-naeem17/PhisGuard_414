# group_split.py
import pandas as pd
import tldextract

from sklearn.model_selection import GroupShuffleSplit

def etld1(u: str) -> str:
    e = tldextract.extract(u if "://" in u else ("http://" + u))
    return (f"{e.domain}.{e.suffix}".lower() if e.suffix else e.domain.lower())

def main():
    df = pd.read_csv("urls_and_labels.csv")  # url,label
    df["group"] = df["url"].map(etld1)

    gss = GroupShuffleSplit(n_splits=1, test_size=0.2, random_state=42)
    tr_idx, te_idx = next(gss.split(df, groups=df["group"]))
    train_df = df.iloc[tr_idx].drop(columns=["group"]).reset_index(drop=True)
    test_df  = df.iloc[te_idx].drop(columns=["group"]).reset_index(drop=True)

    train_df.to_csv("urls_train.csv", index=False)
    test_df.to_csv("urls_test.csv", index=False)
    print(f"✅ urls_train.csv: {len(train_df)}   ✅ urls_test.csv: {len(test_df)}")
    print("   train domains:", train_df["url"].map(etld1).nunique(),
          " test domains:", test_df["url"].map(etld1).nunique())

if __name__ == "__main__":
    main()
