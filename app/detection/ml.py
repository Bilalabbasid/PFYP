"""Optional machine-learning classifier.

The model is trained offline by ``ml/train_model.py`` on the same numeric
features the rule engine uses, and saved with joblib. If no model file exists
(or scikit-learn is not installed) the system silently falls back to rules only.
"""
from __future__ import annotations

import logging
import os
import threading

from .features import ML_FEATURE_NAMES, URLFeatures, feature_vector

log = logging.getLogger(__name__)

_lock = threading.Lock()
_cache: dict[str, object] = {}


def load_model(path: str):
    """Load (and cache) a trained model bundle. Returns None if unavailable."""
    if not path or not os.path.exists(path):
        return None
    with _lock:
        mtime = os.path.getmtime(path)
        cached = _cache.get(path)
        if cached and cached[0] == mtime:
            return cached[1]
        try:
            import joblib  # imported lazily so the app runs without scikit-learn
            bundle = joblib.load(path)
        except Exception as exc:  # pragma: no cover - depends on environment
            log.warning("Could not load ML model %s: %s", path, exc)
            return None
        if not isinstance(bundle, dict) or bundle.get("features") != ML_FEATURE_NAMES:
            log.warning("ML model %s was trained on a different feature set; "
                        "retrain it with ml/train_model.py", path)
            return None
        model = bundle["model"]
        if hasattr(model, "n_jobs"):
            model.n_jobs = 1  # scoring one URL at a time; avoid process pools
        _cache[path] = (mtime, bundle)
        return bundle


def predict_probability(features: URLFeatures, path: str) -> float | None:
    """Probability (0-1) that the URL is phishing, or None if no model."""
    bundle = load_model(path)
    if bundle is None:
        return None
    model = bundle["model"]
    proba = model.predict_proba([feature_vector(features)])[0]
    classes = list(model.classes_)
    return float(proba[classes.index(1)]) if 1 in classes else None


def model_info(path: str) -> dict | None:
    bundle = load_model(path)
    if bundle is None:
        return None
    return {k: v for k, v in bundle.items() if k not in ("model",)}
