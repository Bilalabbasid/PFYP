"""Small JSON API (useful for a future browser extension or mobile app)."""
from flask import Blueprint, current_app, jsonify, request

from ..detection import URLValidationError, analyze, ml
from ..services import run_scan

bp = Blueprint("api", __name__)


@bp.route("/health")
def health():
    cfg = current_app.config
    model = ml.model_info(cfg["ML_MODEL_PATH"]) if cfg.get("ML_ENABLED") else None
    return jsonify(status="ok", ml_model_loaded=model is not None)


@bp.route("/analyze", methods=["POST"])
def analyze_only():
    """Analyse a URL without saving it (used by the awareness quiz)."""
    payload = request.get_json(silent=True) or {}
    url = payload.get("url") if isinstance(payload, dict) else None
    if not isinstance(url, str):
        return jsonify(error="JSON body must contain a 'url' string."), 400
    cfg = current_app.config
    try:
        result = analyze(url, model_path=cfg.get("ML_MODEL_PATH"),
                         use_ml=cfg.get("ML_ENABLED", False))
    except URLValidationError as exc:
        return jsonify(error=str(exc)), 422
    f = result.features
    return jsonify(
        classification=result.classification,
        css_class=result.css_class,
        score=result.score,
        reasons=[r.to_dict() for r in result.risk_findings],
        good_signs=result.good_signs,
        anatomy={"scheme": "https" if f.uses_https else "http", "host": f.host,
                 "subdomain": f.subdomain, "registered_domain": f.registered_domain,
                 "is_ip": f.has_ip_host},
    )


@bp.route("/scan", methods=["POST"])
def scan():
    payload = request.get_json(silent=True) or {}
    url = payload.get("url") if isinstance(payload, dict) else None
    if not isinstance(url, str):
        return jsonify(error="JSON body must contain a 'url' string."), 400
    try:
        record = run_scan(url, source="api")
    except URLValidationError as exc:
        return jsonify(error=str(exc)), 422
    return jsonify(
        id=record.id,
        url=record.url,
        domain=record.domain,
        classification=record.classification,
        score=record.score,
        rule_score=record.rule_score,
        ml_probability=record.ml_probability,
        reasons=record.risk_reasons,
        good_signs=record.good_signs,
        advice=record.advice,
    )
