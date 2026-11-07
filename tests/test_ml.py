"""ML layer: training, loading, prediction and the asymmetric blend."""
import os
import subprocess
import sys

import pytest

pytest.importorskip("sklearn")

from app.detection import analyze, ml  # noqa: E402
from app.detection.engine import ML_CONFIDENT_SAFE  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


@pytest.fixture(scope="module")
def model_path(tmp_path_factory):
    d = tmp_path_factory.mktemp("ml")
    data, model = d / "urls.csv", d / "model.joblib"
    py = sys.executable
    subprocess.run([py, os.path.join(ROOT, "ml", "build_dataset.py"), "--n", "150",
                    "--out", str(data)], check=True, capture_output=True)
    subprocess.run([py, os.path.join(ROOT, "ml", "train_model.py"), "--data", str(data),
                    "--out", str(model)], check=True, capture_output=True,
                   cwd=os.path.join(ROOT, "ml"))
    return str(model)


def test_model_bundle_and_prediction(model_path):
    info = ml.model_info(model_path)
    assert info["algorithm"] == "RandomForest" and info["metrics"]["accuracy"] > 0.8
    phish = analyze("https://secure-paypal-account-verify.tk/update", model_path=model_path)
    safe = analyze("https://github.com/pallets/flask", model_path=model_path)
    assert 0 <= phish.ml_probability <= 1 and phish.ml_probability > safe.ml_probability
    assert any("Machine-learning" in n for n in phish.notes)


def test_ml_cannot_lower_score_unless_confident(model_path):
    for url in ["https://example-website.com/login", "http://paypa1.com/signin",
                "https://bit.ly/3abcXYZ", "http://xk2j9qpzl4mw.com/a"]:
        r = analyze(url, model_path=model_path)
        if r.ml_probability >= ML_CONFIDENT_SAFE:
            assert r.score >= r.rule_score, url


def test_missing_model_falls_back_to_rules(tmp_path):
    r = analyze("http://paypa1.com/signin", model_path=str(tmp_path / "none.joblib"))
    assert r.ml_probability is None and r.score == max(r.rule_score, 60)
