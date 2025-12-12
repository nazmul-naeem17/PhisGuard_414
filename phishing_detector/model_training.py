import json
import joblib
import numpy as np
import pandas as pd

from sklearn.model_selection import StratifiedKFold, train_test_split, cross_val_score
from sklearn.metrics import (
    roc_auc_score, classification_report, confusion_matrix,
    brier_score_loss, f1_score
)
from sklearn.ensemble import (
    ExtraTreesClassifier, RandomForestClassifier,
    GradientBoostingClassifier, AdaBoostClassifier
)
from sklearn.linear_model import LogisticRegression
from sklearn.naive_bayes import GaussianNB
from xgboost import XGBClassifier
from catboost import CatBoostClassifier

from imblearn.pipeline import Pipeline
from imblearn.over_sampling import SMOTE
from sklearn.calibration import CalibratedClassifierCV

TRAIN = "phishing_dataset_train.csv"
TEST  = "phishing_dataset_test.csv"

def choose_threshold(y_true, p, metric="f1"):
    taus = np.linspace(0.1, 0.9, 81)
    best_tau, best = 0.5, -1.0
    for t in taus:
        yhat = (p >= t).astype(int)
        s = f1_score(y_true, yhat, zero_division=0)  # optimize F1 by default
        if s > best:
            best, best_tau = s, float(t)
    return best_tau

def make_calibrator(base_pipe):
    """
    scikit-learn API changed:
      - Newer versions: CalibratedClassifierCV(estimator=..., ...)
      - Older versions: CalibratedClassifierCV(base_estimator=..., ...)
    This shim makes it work on both.
    """
    try:
        return CalibratedClassifierCV(estimator=base_pipe, cv=5, method="isotonic")
    except TypeError:
        return CalibratedClassifierCV(base_estimator=base_pipe, cv=5, method="isotonic")

def main():
    tr = pd.read_csv(TRAIN)
    te = pd.read_csv(TEST)

    Xtr = tr.drop(columns=["label"]).values
    ytr = tr["label"].astype(int).values
    Xte = te.drop(columns=["label"]).values
    yte = te["label"].astype(int).values

    candidates = {
        "ExtraTrees": ExtraTreesClassifier(n_estimators=800, random_state=42, n_jobs=-1),
        "XGBoost": XGBClassifier(
            n_estimators=800, max_depth=6, learning_rate=0.05,
            subsample=0.9, colsample_bytree=0.9,
            eval_metric="logloss", random_state=42, n_jobs=-1
        ),
        "RandomForest": RandomForestClassifier(n_estimators=600, random_state=42, n_jobs=-1),
        "AdaBoost": AdaBoostClassifier(n_estimators=400, random_state=42),
        "GradBoost": GradientBoostingClassifier(random_state=42),
        "LogReg": LogisticRegression(max_iter=5000, solver="lbfgs"),
        "NaiveBayes": GaussianNB(),
        "CatBoost": CatBoostClassifier(depth=6, iterations=800, learning_rate=0.05, random_state=42, verbose=0),
    }

    print("Evaluating models (5-fold ROC-AUC with SMOTE inside pipeline):")
    cv_scores = {}
    skf = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    for name, clf in candidates.items():
        pipe = Pipeline([("smote", SMOTE(random_state=42)), ("clf", clf)])
        scores = cross_val_score(pipe, Xtr, ytr, cv=skf, scoring="roc_auc", n_jobs=-1)
        cv_scores[name] = float(scores.mean())
        print(f"  {name:12s}: {scores.mean():.4f} ± {scores.std():.4f}")

    best_name = max(cv_scores, key=cv_scores.get)
    best_base = candidates[best_name]
    print(f"\n✅ Best by CV: {best_name} (ROC-AUC {cv_scores[best_name]:.4f})")

    base_pipe = Pipeline([("smote", SMOTE(random_state=42)), ("clf", best_base)])
    model = make_calibrator(base_pipe)

    Xtr_a, Xval, ytr_a, yval = train_test_split(
        Xtr, ytr, test_size=0.12, stratify=ytr, random_state=42
    )
    model.fit(Xtr_a, ytr_a)

    p_val = model.predict_proba(Xval)[:, 1]
    tau = choose_threshold(yval, p_val, metric="f1")
    p_test = model.predict_proba(Xte)[:, 1]
    yhat   = (p_test >= tau).astype(int)

    print(f"\nSelected model: {best_name}")
    print("Calibrated threshold (val, F1-opt):", tau)
    print("Test ROC-AUC:", roc_auc_score(yte, p_test))
    print("Brier score :", brier_score_loss(yte, p_test))
    print("\nClassification report (Test):\n", classification_report(yte, yhat, target_names=["legit","phishing"]))
    print("Confusion matrix:\n", confusion_matrix(yte, yhat))

    joblib.dump(model, "best_model.pkl")
    json.dump({"n_features": Xtr.shape[1]}, open("feature_meta.json","w"))
    json.dump({"best_model": best_name, "cv_scores": cv_scores, "threshold": tau}, open("model_meta.json","w"))
    print("\n🎉 Saved: best_model.pkl, feature_meta.json, model_meta.json")

if __name__ == "__main__":
    main()
