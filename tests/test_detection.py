"""Unit tests for URL validation, feature extraction and classification."""
import pytest

from app.detection import PHISHING, SAFE, SUSPICIOUS, URLValidationError, analyze, defang
from app.detection.features import (_double_or_swap, extract_features, feature_vector,
                                    levenshtein, split_domain, ML_FEATURE_NAMES)
from app.detection.validators import normalise_url


# ---------------------------------------------------------------- validation

@pytest.mark.parametrize("bad", ["", "   ", "not a url", "javascript:alert(1)",
                                 "data:text/html,<script>", "ftp://files.example.com/x",
                                 "http://", "http://localhost-only", "a" * 3000,
                                 "http://exa mple.com"])
def test_invalid_urls_rejected(bad):
    with pytest.raises(URLValidationError):
        normalise_url(bad)


def test_scheme_added_and_defang_undone():
    n = normalise_url("hxxp://evil[.]example[.]com/login")
    assert n.url == "http://evil.example.com/login"
    n2 = normalise_url("paypa1.com/signin")
    assert n2.scheme == "http" and n2.scheme_was_added and n2.host == "paypa1.com"


def test_defang_makes_url_non_clickable():
    assert defang("https://evil.com/a") == "hxxps://evil[.]com/a"


# ----------------------------------------------------------------- features

def test_split_domain_handles_multi_part_suffix():
    assert split_domain("www.bank.com.pk") == ("www", "bank.com.pk", "com.pk")
    assert split_domain("a.b.example.co.uk") == ("a.b", "example.co.uk", "co.uk")
    assert split_domain("login.paypal.com") == ("login", "paypal.com", "com")


def test_levenshtein_and_typos():
    assert levenshtein("paypal", "paypa1") == 1
    assert levenshtein("kitten", "sitting") == 3
    assert _double_or_swap("yaahoo", "yahoo")
    assert _double_or_swap("chsae", "chase")
    assert not _double_or_swap("ample", "apple")


def test_feature_extraction_values():
    f = extract_features(normalise_url(
        "http://user@192.168.1.10:8080/paypal//login.php?redirect=http://evil.tk"))
    assert f.has_ip_host and f.has_userinfo and f.has_at_symbol
    assert f.has_non_standard_port and f.has_double_slash_redirect
    assert f.has_redirect_param and f.has_embedded_url
    assert not f.uses_https
    assert "login" in f.suspicious_keywords
    vec = feature_vector(f)
    assert len(vec) == len(ML_FEATURE_NAMES) and all(isinstance(v, float) for v in vec)


def test_brand_impersonation_and_typosquatting_features():
    f = extract_features(normalise_url("https://paypal.com.account-verify.xyz/"))
    assert f.brand_impersonation and f.impersonated_brand == "paypal"
    assert f.registered_domain == "account-verify.xyz"
    t = extract_features(normalise_url("https://arnazon-support.com"))
    assert t.typosquatting and t.typosquat_target == "amazon"
    legit = extract_features(normalise_url("https://www.paypal.com/signin"))
    assert not legit.brand_impersonation and not legit.typosquatting and legit.is_trusted_domain


def test_ip_variants_detected():
    for host in ["http://3232235777/", "http://0xC0A80101/", "http://[::1]/x"]:
        assert extract_features(normalise_url(host)).has_ip_host, host


# ----------------------------------------------------------- classification

SAFE_URLS = [
    "https://www.google.com/search?q=python",
    "https://github.com/pallets/flask",
    "https://en.wikipedia.org/wiki/Phishing",
    "https://www.amazon.com/gp/your-account",
    "https://login.microsoftonline.com/common/oauth2",
    "https://docs.python.org/3/library/urllib.parse.html",
    "https://www.bbc.co.uk/news",
    "https://www.daraz.pk/",
    "https://google.de",
    "https://applebees.com/menu",
    "https://www.example.com/",
    "https://www.nasa.gov/missions",
]

SUSPICIOUS_OR_WORSE = [
    "https://example-website.com/login",          # example from the proposal
    "https://bit.ly/3abcXYZ",
    "http://example.com/redirect?url=http://evil.com",
    "https://xn--pple-43d.com/",
    "https://my-site.netlify.app/office365/login.html",
    "http://xk2j9qpzl4mw.com/a",
]

PHISHING_URLS = [
    "http://paypa1.com/signin",
    "http://192.168.10.5/bank/login.php",
    "https://secure-paypal-account-verify.tk/update",
    "http://www.paypal.com@evil.xyz/login",
    "https://appleid.apple.com.verify-account.info/",
    "https://faceb00k-login.com",
    "https://mail.google.com.secure-check.ru/",
    "http://paypal.tk/x",
]


@pytest.mark.parametrize("url", SAFE_URLS)
def test_safe_urls(url):
    r = analyze(url, use_ml=False)
    assert r.classification == SAFE, (url, r.score, [f.rule_id for f in r.findings])


@pytest.mark.parametrize("url", SUSPICIOUS_OR_WORSE)
def test_suspicious_urls(url):
    r = analyze(url, use_ml=False)
    assert r.classification in (SUSPICIOUS, PHISHING), (url, r.score)


@pytest.mark.parametrize("url", PHISHING_URLS)
def test_phishing_urls(url):
    r = analyze(url, use_ml=False)
    assert r.classification == PHISHING, (url, r.score, [f.rule_id for f in r.findings])


def test_proposal_example_is_suspicious_with_reasons():
    r = analyze("https://example-website.com/login", use_ml=False)
    assert r.classification == SUSPICIOUS
    titles = {f.rule_id for f in r.risk_findings}
    assert {"keywords", "credential_unknown", "hyphens"} <= titles


def test_every_risk_finding_has_explanation():
    r = analyze("http://www.paypal.com@evil.xyz/login", use_ml=False)
    assert r.risk_findings
    for f in r.risk_findings:
        assert f.title and f.detail and f.weight > 0 and f.severity in ("high", "medium", "low")


def test_score_bounded_and_result_serialisable():
    r = analyze("http://paypal-login-verify-account-secure.tk@1.2.3.4:8080//x.exe"
                "?redirect=http://evil.tk&" + "a=%41" * 20, use_ml=False)
    assert 0 <= r.score <= 100 and r.classification == PHISHING
    d = r.to_dict()
    assert d["classification"] == PHISHING and isinstance(d["reasons"], list)


def test_two_high_indicators_force_phishing():
    r = analyze("https://192.168.0.1@paypal.com.example.org/", use_ml=False)
    assert r.classification == PHISHING
