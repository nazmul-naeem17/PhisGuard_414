# eval_report.py
import numpy as np, pandas as pd
from sklearn.model_selection import StratifiedKFold, cross_val_score
from sklearn.metrics import roc_auc_score, classification_report
from sklearn.ensemble import ExtraTreesClassifier, RandomForestClassifier, GradientBoostingClassifier, AdaBoostClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.naive_bayes import GaussianNB
from xgboost import XGBClassifier
from catboost import CatBoostClassifier
from imblearn.pipeline import Pipeline
from imblearn.over_sampling import SMOTE

TRAIN = "phishing_dataset_train.csv"
TEST  = "phishing_dataset_test.csv"

# Toggle ablations here if you want to stress-test:
DISABLE_CT    = False   # drops f80 and f86
DISABLE_WHOIS = False   # drops f81
DISABLE_DOM   = False   # drops f82..f85

def load_data(path):
    df = pd.read_csv(path)
    cols = [c for c in df.columns if c.startswith("f")]
    drop = []
    if DISABLE_CT:    drop += ["f80","f86"]
    if DISABLE_WHOIS: drop += ["f81"]
    if DISABLE_DOM:   drop += ["f82","f83","f84","f85"]
    cols = [c for c in cols if c not in drop]
    X = df[cols].values
    y = df["label"].astype(int).values
    return X, y, cols

def main():
    Xtr, ytr, cols_tr = load_data(TRAIN)
    Xte, yte, cols_te = load_data(TEST)
    assert cols_tr == cols_te

    models = {
        "GradientBoosting": GradientBoostingClassifier(random_state=42),
        "ExtraTrees"      : ExtraTreesClassifier(n_estimators=600, random_state=42, n_jobs=-1),
        "RandomForest"    : RandomForestClassifier(n_estimators=600, random_state=42, n_jobs=-1),
        "AdaBoost"        : AdaBoostClassifier(n_estimators=400, random_state=42),
        "LogReg"          : LogisticRegression(max_iter=5000, solver="lbfgs"),
        "NaiveBayes"      : GaussianNB(),
        "XGBoost"         : XGBClassifier(n_estimators=800, max_depth=6, learning_rate=0.05,
                                          subsample=0.9, colsample_bytree=0.9,
                                          eval_metric="logloss", random_state=42, n_jobs=-1),
        "CatBoost"        : CatBoostClassifier(depth=6, iterations=800, learning_rate=0.05,
                                               random_state=42, verbose=0),
    }

    skf = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)

    for name, clf in models.items():
        pipe = Pipeline([("smote", SMOTE(random_state=42)), ("clf", clf)])
        cv = cross_val_score(pipe, Xtr, ytr, cv=skf, scoring="roc_auc", n_jobs=-1)
        pipe.fit(Xtr, ytr)
        p = pipe.predict_proba(Xte)[:,1]
        yhat = (p >= 0.5).astype(int)

        print(f"\n=== {name} ===")
        print(f"5-fold CV ROC-AUC: {cv.mean():.4f} ± {cv.std():.4f}")
        print(f"Hold-out ROC-AUC: {roc_auc_score(yte, p):.4f}")
        print("Classification Report on Hold-out:")
        print(classification_report(yte, yhat, target_names=['legit','phishing']))

if __name__ == "__main__":
    main()
