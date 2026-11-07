"""Train the optional machine-learning classifier.

    python ml/build_dataset.py                 # create ml/data/urls.csv (once)
    python ml/train_model.py                   # train + save ml/model.joblib
    python ml/train_model.py --data my.csv --algorithm logreg

The model uses the same numeric URL features as the rule engine, so it can be
explained in the same terms. Results (accuracy, precision, recall, F1, confusion
matrix, feature importance) are printed and stored with the model.
"""
from __future__ import annotations

import argparse
import json
import os
from datetime import datetime, timezone

from common import DEFAULT_DATA, DEFAULT_MODEL, ML_FEATURE_NAMES, load_dataset, vectorise


def main():
    parser = argparse.ArgumentParser(description="Train the PhishGuard URL classifier")
    parser.add_argument("--data", default=DEFAULT_DATA)
    parser.add_argument("--out", default=DEFAULT_MODEL)
    parser.add_argument("--algorithm", choices=["rf", "logreg"], default="rf")
    parser.add_argument("--test-size", type=float, default=0.25)
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()

    try:
        import joblib
        from sklearn.ensemble import RandomForestClassifier
        from sklearn.linear_model import LogisticRegression
        from sklearn.metrics import (accuracy_score, confusion_matrix, f1_score,
                                     precision_score, recall_score)
        from sklearn.model_selection import cross_val_score, train_test_split
        from sklearn.pipeline import make_pipeline
        from sklearn.preprocessing import StandardScaler
    except ImportError:
        raise SystemExit("scikit-learn is required: pip install scikit-learn joblib")

    if not os.path.exists(args.data):
        raise SystemExit(f"Dataset not found: {args.data}\nRun: python ml/build_dataset.py")

    urls, labels = load_dataset(args.data)
    X, y, _kept, skipped = vectorise(urls, labels)
    print(f"Loaded {len(y)} URLs ({sum(y)} phishing, {len(y) - sum(y)} legitimate); "
          f"skipped {skipped} invalid rows.")

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=args.test_size, random_state=args.seed, stratify=y)

    if args.algorithm == "rf":
        model = RandomForestClassifier(n_estimators=200, max_depth=14, min_samples_leaf=2,
                                       class_weight="balanced", random_state=args.seed,
                                       n_jobs=1)  # single worker: reliable on Windows
        name = "RandomForest"
    else:
        model = make_pipeline(StandardScaler(),
                              LogisticRegression(max_iter=2000, class_weight="balanced"))
        name = "LogisticRegression"

    cv = cross_val_score(model, X_train, y_train, cv=5, scoring="f1")
    model.fit(X_train, y_train)
    pred = model.predict(X_test)
    metrics = {
        "accuracy": accuracy_score(y_test, pred),
        "precision": precision_score(y_test, pred, zero_division=0),
        "recall": recall_score(y_test, pred, zero_division=0),
        "f1": f1_score(y_test, pred, zero_division=0),
        "cv_f1_mean": float(cv.mean()),
        "confusion_matrix": confusion_matrix(y_test, pred).tolist(),
        "train_size": len(y_train),
        "test_size": len(y_test),
    }

    importance = None
    est = model if args.algorithm == "rf" else model[-1]
    if hasattr(est, "feature_importances_"):
        importance = sorted(zip(ML_FEATURE_NAMES, est.feature_importances_),
                            key=lambda kv: kv[1], reverse=True)
    elif hasattr(est, "coef_"):
        importance = sorted(zip(ML_FEATURE_NAMES, abs(est.coef_[0])),
                            key=lambda kv: kv[1], reverse=True)

    bundle = {
        "model": model,
        "features": ML_FEATURE_NAMES,
        "algorithm": name,
        "trained_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        "dataset": os.path.basename(args.data),
        "metrics": metrics,
        "top_features": [(k, round(float(v), 4)) for k, v in (importance or [])[:10]],
    }
    joblib.dump(bundle, args.out)

    print(f"\n{name} results on held-out test set ({len(y_test)} URLs):")
    for key in ("accuracy", "precision", "recall", "f1", "cv_f1_mean"):
        print(f"  {key:<10} {metrics[key]:.4f}")
    tn, fp, fn, tp = [v for row in metrics["confusion_matrix"] for v in row]
    print(f"  confusion  TN={tn} FP={fp} FN={fn} TP={tp}")
    if importance:
        print("  top features:", ", ".join(f"{k} ({v:.3f})" for k, v in importance[:8]))
    print(f"\nSaved model to {args.out}")
    report = os.path.splitext(args.out)[0] + "_metrics.json"
    with open(report, "w", encoding="utf-8") as fh:
        json.dump({k: v for k, v in bundle.items() if k != "model"}, fh, indent=2)
    print(f"Saved metrics to {report}")


if __name__ == "__main__":
    main()
