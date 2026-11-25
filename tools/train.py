"""Train the RansomSentry Random Forest.   Usage: python tools\\train.py"""
import sys
from pathlib import Path
import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import GroupKFold, cross_val_predict
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from ransomsentry.features import FEATURES

lines = []
def out(s=""):
    print(s)
    lines.append(str(s))

def make_rf():
    return RandomForestClassifier(n_estimators=200, min_samples_leaf=2,
                                  class_weight="balanced", random_state=42, n_jobs=-1)

df = pd.read_csv(ROOT / "data" / "dataset.csv")
X, y, groups = df[FEATURES], df["label"], df["run"]
out(f"Dataset: {len(df)} windows from {df['run'].nunique()} recordings")
out(df.groupby(["label", "scenario"]).size().to_string())

# 1) 5-fold cross-validation, grouped by recording
#    (windows from the same recording never appear in both train and test)
proba = cross_val_predict(make_rf(), X, y, groups=groups, cv=GroupKFold(5),
                          method="predict_proba")[:, 1]
pred = (proba >= 0.5).astype(int)
out("\n=== 5-fold grouped cross-validation ===")
out(classification_report(y, pred, target_names=["benign", "ransomware"], digits=3))
tn, fp, fn, tp = confusion_matrix(y, pred).ravel()
out(f"Confusion matrix: TN={tn} FP={fp} FN={fn} TP={tp}")
out(f"False-positive rate on benign windows: {fp / (fp + tn):.1%}")
out(f"ROC AUC: {roc_auc_score(y, proba):.3f}")

out("\nAccuracy per scenario:")
acc = df.assign(correct=(pred == y)).groupby("scenario")["correct"].mean()
out(acc.sort_values().to_string(float_format=lambda v: f"{v:.0%}"))

# 2) Unseen-variant test: train WITHOUT one ransomware mode, test on it
out("\n=== Detecting a ransomware mode the model never saw ===")
for mode in sorted(df.loc[df.label == 1, "scenario"].unique()):
    train, test = df[df.scenario != mode], df[df.scenario == mode]
    m = make_rf().fit(train[FEATURES], train["label"])
    out(f"  unseen {mode:12} -> {m.predict(test[FEATURES]).mean():.0%} of windows flagged")

# 3) Final model on all data
model = make_rf().fit(X, y)
out("\n=== Feature importance ===")
for imp, name in sorted(zip(model.feature_importances_, FEATURES), reverse=True):
    out(f"  {name:20} {imp:.3f}")

(ROOT / "models").mkdir(exist_ok=True)
joblib.dump(model, ROOT / "models" / "rf.joblib")
(ROOT / "data" / "metrics.txt").write_text("\n".join(lines))
out("\nSaved models/rf.joblib and data/metrics.txt")