"""Shared helpers for the ML scripts."""
from __future__ import annotations

import csv
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from app.detection.features import ML_FEATURE_NAMES, extract_features, feature_vector  # noqa: E402
from app.detection.validators import URLValidationError, normalise_url  # noqa: E402

DEFAULT_DATA = os.path.join(HERE, "data", "urls.csv")
DEFAULT_MODEL = os.path.join(HERE, "model.joblib")

PHISH_LABELS = {"1", "phishing", "phish", "bad", "malicious", "true", "yes"}
LEGIT_LABELS = {"0", "legitimate", "legit", "benign", "good", "safe", "false", "no"}


def load_dataset(path: str) -> tuple[list[str], list[int]]:
    """Read a CSV with 'url' and 'label' columns (label: 1/0 or text)."""
    urls, labels = [], []
    with open(path, newline="", encoding="utf-8", errors="replace") as fh:
        reader = csv.DictReader(fh)
        cols = {c.lower(): c for c in (reader.fieldnames or [])}
        url_col = cols.get("url") or cols.get("urls")
        label_col = cols.get("label") or cols.get("type") or cols.get("class")
        if not url_col or not label_col:
            raise SystemExit(f"{path}: needs 'url' and 'label' columns, found {reader.fieldnames}")
        for row in reader:
            raw = (row[label_col] or "").strip().lower()
            if raw in PHISH_LABELS:
                y = 1
            elif raw in LEGIT_LABELS:
                y = 0
            else:
                continue
            urls.append(row[url_col])
            labels.append(y)
    return urls, labels


def vectorise(urls: list[str], labels: list[int]):
    X, y, kept = [], [], []
    skipped = 0
    for url, label in zip(urls, labels):
        try:
            n = normalise_url(url)
        except URLValidationError:
            skipped += 1
            continue
        X.append(feature_vector(extract_features(n)))
        y.append(label)
        kept.append(url)
    return X, y, kept, skipped


__all__ = ["ML_FEATURE_NAMES", "DEFAULT_DATA", "DEFAULT_MODEL", "load_dataset", "vectorise"]
