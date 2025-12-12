# check_overlap.py
import pandas as pd, tldextract

def etld1(u: str) -> str:
    if "://" not in u: u = "http://" + u
    e = tldextract.extract(u)
    return (f"{e.domain}.{e.suffix}".lower() if e.suffix else e.domain.lower())

tr = pd.read_csv("urls_train.csv")
te = pd.read_csv("urls_test.csv")

tr_domains = set(tr["url"].map(etld1))
te_domains = set(te["url"].map(etld1))
overlap = tr_domains & te_domains

print("Train domains:", len(tr_domains))
print("Test domains :", len(te_domains))
print("Domain overlap:", len(overlap))
if overlap:
    print("SAMPLE overlaps:", list(sorted(overlap))[:25])
    print("❌ Fix split: re-run group_split.py")
else:
    print("✅ No domain overlap detected.")
