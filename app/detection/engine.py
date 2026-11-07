"""Detection engine: validation -> features -> rules (+ optional ML) -> result."""
from __future__ import annotations

from dataclasses import dataclass, field

from . import ml, rules
from .features import URLFeatures, extract_features
from .validators import NormalisedURL, normalise_url

# How much the ML probability contributes when a model is available.
ML_WEIGHT = 0.4
# Below this phishing probability the model is trusted to lower the rule score.
ML_CONFIDENT_SAFE = 0.10


@dataclass
class AnalysisResult:
    url: str
    normalised_url: str
    score: int
    classification: str
    rule_score: int
    ml_probability: float | None
    findings: list[rules.Finding]
    good_signs: list[str]
    features: URLFeatures
    notes: list[str] = field(default_factory=list)

    @property
    def risk_findings(self) -> list[rules.Finding]:
        return [f for f in self.findings if f.weight > 0]

    @property
    def css_class(self) -> str:
        return rules.CSS_CLASS[self.classification]

    @property
    def advice(self) -> str:
        return rules.ADVICE[self.classification]

    def to_dict(self) -> dict:
        return {
            "url": self.url,
            "normalised_url": self.normalised_url,
            "classification": self.classification,
            "score": self.score,
            "rule_score": self.rule_score,
            "ml_probability": self.ml_probability,
            "reasons": [f.to_dict() for f in self.findings],
            "good_signs": self.good_signs,
            "advice": self.advice,
            "notes": self.notes,
            "features": self.features.to_dict(),
        }


def analyze(raw_url: str, model_path: str | None = None,
            use_ml: bool = True) -> AnalysisResult:
    """Analyse ``raw_url``. Raises ``URLValidationError`` for invalid input."""
    n: NormalisedURL = normalise_url(raw_url)
    features = extract_features(n)
    rule_score, findings, good_signs = rules.evaluate(features)

    notes: list[str] = []
    if n.scheme_was_added:
        notes.append("No http:// or https:// was given, so the link was analysed as "
                     "plain http.")

    probability = None
    score = rule_score
    if use_ml and model_path:
        probability = ml.predict_probability(features, model_path)
        if probability is not None:
            blended = round((1 - ML_WEIGHT) * rule_score + ML_WEIGHT * probability * 100)
            # The model may raise the risk freely, but it may only lower the
            # explainable rule score when it is highly confident the URL is safe.
            score = blended if probability < ML_CONFIDENT_SAFE else max(blended, rule_score)
            notes.append(f"Machine-learning model estimate: {probability * 100:.0f}% "
                         "probability of phishing (combined with rule score).")

    # Strong, unambiguous indicators should never be averaged down to "safe".
    high_hits = [f for f in findings if f.severity == "high"]
    if len(high_hits) >= 2:
        score = max(score, rules.PHISHING_THRESHOLD)
    elif high_hits:
        score = max(score, rules.SUSPICIOUS_THRESHOLD)

    score = max(0, min(100, score))
    return AnalysisResult(
        url=n.original,
        normalised_url=n.url,
        score=score,
        classification=rules.classify(score),
        rule_score=rule_score,
        ml_probability=probability,
        findings=findings,
        good_signs=good_signs,
        features=features,
        notes=notes,
    )
