"""Glue between the detection engine and the database."""
from __future__ import annotations

from flask import current_app
from flask_login import current_user

from .detection import analyze
from .extensions import db
from .models import Scan
from .utils import log_activity


def run_scan(raw_url: str, source: str = "web") -> Scan:
    """Analyse ``raw_url`` and store the result. Raises URLValidationError."""
    cfg = current_app.config
    result = analyze(raw_url, model_path=cfg.get("ML_MODEL_PATH"),
                     use_ml=cfg.get("ML_ENABLED", False))
    user_id = current_user.id if current_user.is_authenticated else None
    scan = Scan(
        user_id=user_id,
        url=result.url,
        normalised_url=result.normalised_url,
        domain=(result.features.host or "")[:255],
        classification=result.classification,
        score=result.score,
        rule_score=result.rule_score,
        ml_probability=result.ml_probability,
        reasons=[f.to_dict() for f in result.findings],
        good_signs=result.good_signs,
        notes=result.notes,
        features=result.features.to_dict(),
        source=source,
    )
    db.session.add(scan)
    db.session.flush()
    log_activity("scan", f"#{scan.id} {result.classification} ({result.score}) "
                         f"{result.features.host}", user_id=user_id, commit=False)
    db.session.commit()
    return scan
