"""Rule-based risk scoring.

Every rule looks at the extracted features and, when it fires, adds a weight to
the risk score together with a plain-language explanation. The total score
(0-100) is mapped to a classification:

    0  - 29  -> Likely Safe
    30 - 59  -> Suspicious
    60 - 100 -> Likely Phishing
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from .features import URLFeatures

SAFE = "Likely Safe"
SUSPICIOUS = "Suspicious"
PHISHING = "Likely Phishing"

SUSPICIOUS_THRESHOLD = 30
PHISHING_THRESHOLD = 60

CREDENTIAL_WORDS = {
    "login", "log-in", "signin", "sign-in", "logon", "verify", "verification",
    "password", "passwd", "credential", "account", "banking", "wallet", "otp",
    "kyc", "webscr", "cmd=_login", "authenticate", "auth",
}


@dataclass
class Finding:
    rule_id: str
    title: str
    detail: str
    weight: int
    severity: str  # "high" | "medium" | "low" | "good"

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "detail": self.detail,
            "weight": self.weight,
            "severity": self.severity,
        }


@dataclass
class Rule:
    rule_id: str
    check: Callable[[URLFeatures], int]          # returns weight (0 = not fired)
    title: str
    detail: Callable[[URLFeatures], str]


def _sev(weight: int) -> str:
    if weight < 0:
        return "good"
    if weight >= 30:
        return "high"
    if weight >= 15:
        return "medium"
    return "low"


def _keyword_weight(f: URLFeatures) -> int:
    n = f.num_suspicious_keywords
    if n == 0:
        return 0
    return min(10 + 6 * (n - 1), 25)


def _length_weight(f: URLFeatures) -> int:
    if f.url_length > 120:
        return 15
    if f.url_length > 75:
        return 8
    return 0


def _subdomain_weight(f: URLFeatures) -> int:
    if f.num_subdomains >= 3:
        return 15
    if f.num_subdomains == 2:
        return 6
    return 0


def _credential_on_unknown(f: URLFeatures) -> int:
    if f.is_trusted_domain and not f.is_free_hosting:
        return 0
    return 12 if any(w in CREDENTIAL_WORDS for w in f.suspicious_keywords) else 0


def _random_label(f: URLFeatures) -> int:
    return 15 if f.random_looking_domain else 0


def _trusted(f: URLFeatures) -> int:
    if f.is_trusted_domain and not f.is_free_hosting and not f.has_userinfo \
            and not f.has_ip_host:
        return -40
    return 0


RULES: list[Rule] = [
    Rule("ip_host", lambda f: 35 if f.has_ip_host else 0,
         "IP address used instead of a domain name",
         lambda f: f"The link points to '{f.host}', a raw IP address. Legitimate "
                   "organisations almost always use a registered domain name."),
    Rule("userinfo", lambda f: 35 if (f.has_userinfo or f.has_at_symbol) else 0,
         "'@' symbol in the address",
         lambda f: "Browsers ignore everything before an '@' in the host part, so "
                   "text such as 'paypal.com@evil.site' actually opens 'evil.site'."),
    Rule("typosquatting", lambda f: 40 if f.typosquatting else 0,
         "Look-alike (typosquatted) domain",
         lambda f: f"'{f.registered_domain}' imitates the name '{f.typosquat_target}' "
                   "using a misspelling or look-alike characters."),
    Rule("brand_impersonation", lambda f: 35 if f.brand_impersonation else 0,
         "Brand name used on an unofficial domain",
         lambda f: f"The address mentions '{f.impersonated_brand}' but the real "
                   f"domain is '{f.registered_domain}', which that brand does not own."),
    Rule("brand_in_path",
         lambda f: 0 if (not f.brand_in_path or f.brand_impersonation
                         or (f.is_trusted_domain and not f.is_free_hosting))
         else (15 if f.is_free_hosting else 10),
         "Brand name inside the path",
         lambda f: f"'{f.impersonated_brand}' appears in the page path of an unrelated "
                   "domain, a common way to make a fake page look official."),
    Rule("punycode", lambda f: 30 if (f.has_punycode or f.has_non_ascii) else 0,
         "International (look-alike) characters in domain",
         lambda f: "The domain uses punycode/Unicode characters, which can imitate "
                   "normal letters (an IDN homograph attack)."),
    Rule("risky_extension", lambda f: 25 if f.has_risky_extension else 0,
         "Link downloads a risky file type",
         lambda f: f"The link ends in '{f.risky_extension}', a file type that can run "
                   "code or hide malware."),
    Rule("https_token", lambda f: 20 if f.https_token_in_host else 0,
         "'http/https' written inside the domain name",
         lambda f: "The word 'http' or 'https' is part of the domain itself, which is "
                   "used to fake a sense of security."),
    Rule("shortener", lambda f: 30 if f.is_shortener else 0,
         "Shortened link hides the destination",
         lambda f: f"'{f.host}' is a link-shortening service; the real destination "
                   "cannot be seen until the link is opened."),
    Rule("redirect_target", lambda f: 20 if f.redirect_target_suspicious else 0,
         "Redirects to a suspicious website",
         lambda f: "The link forwards to another address that itself looks like a "
                   "look-alike or uses a frequently abused domain ending."),
    Rule("redirect", lambda f: 20 if f.redirect_to_other_domain else
         (15 if (f.has_redirect_param or f.has_embedded_url
                 or f.has_double_slash_redirect) else 0),
         "Redirection indicators",
         lambda f: "The address contains another URL or a redirect parameter, so it "
                   "may forward you to a different site."),
    Rule("free_hosting", lambda f: 15 if f.is_free_hosting else 0,
         "Hosted on a free / user-content platform",
         lambda f: f"'{f.host}' is on a free hosting or site-builder platform that "
                   "attackers often abuse to host fake pages."),
    Rule("suspicious_tld", lambda f: 15 if f.suspicious_tld else 0,
         "Uncommon / frequently abused domain ending",
         lambda f: f"The '.{f.tld}' ending is cheap or free and frequently seen in "
                   "phishing campaigns."),
    Rule("non_standard_port", lambda f: 15 if f.has_non_standard_port else 0,
         "Unusual network port",
         lambda f: "The link specifies a non-standard port, which normal websites "
                   "rarely use."),
    Rule("subdomains", _subdomain_weight, "Many subdomains",
         lambda f: f"The address has {f.num_subdomains} subdomain levels ('{f.subdomain}'), "
                   "often used to push the real domain out of view."),
    Rule("keywords", _keyword_weight, "Suspicious keywords",
         lambda f: "Contains words often used in phishing: "
                   + ", ".join(f"'{k}'" for k in f.suspicious_keywords) + "."),
    Rule("credential_unknown", _credential_on_unknown,
         "Login/account wording on an unrecognised domain",
         lambda f: "The page appears to ask for sign-in or account details but the "
                   "domain is not a recognised official site."),
    Rule("hyphens", lambda f: (10 if f.num_hyphens_host >= 2 else 8)
         if f.num_hyphens_host else 0,
         "Hyphens in the domain name",
         lambda f: f"The domain contains {f.num_hyphens_host} hyphen(s); fake domains "
                   "often join words like 'secure-login-bank'."),
    Rule("no_https", lambda f: 10 if not f.uses_https else 0,
         "Connection is not encrypted (no HTTPS)",
         lambda f: "The link uses plain HTTP. Never enter personal information on a "
                   "page without HTTPS."),
    Rule("long_url", _length_weight, "Unusually long URL",
         lambda f: f"The URL is {f.url_length} characters long; long addresses can hide "
                   "the real destination."),
    Rule("random_domain", _random_label, "Random-looking domain name",
         lambda f: "The domain name looks randomly generated (high character entropy)."),
    Rule("digits_host",
         lambda f: 8 if (f.num_digits_host >= 3 and not f.has_ip_host) else 0,
         "Many digits in the domain",
         lambda f: f"The domain contains {f.num_digits_host} digits, unusual for "
                   "legitimate brands."),
    Rule("special_chars", lambda f: 8 if f.num_special_chars > 12 else 0,
         "Many special characters",
         lambda f: f"The URL contains {f.num_special_chars} special characters, "
                   "which can be used to obfuscate it."),
    Rule("encoding", lambda f: 8 if f.num_percent_encoded > 5 else 0,
         "Heavy URL encoding",
         lambda f: f"{f.num_percent_encoded} percent-encoded characters may be hiding "
                   "the real content of the link."),
    Rule("fragment", lambda f: 10 if f.has_fragment_tricks else 0,
         "Suspicious text after '#'",
         lambda f: "The fragment (after '#') contains a URL or '@', a known "
                   "obfuscation trick."),
    Rule("restricted_tld",
         lambda f: -15 if (f.restricted_tld and not f.is_trusted_domain
                           and not f.has_userinfo) else 0,
         "Government / education domain",
         lambda f: f"'.{f.tld}' addresses can only be registered by verified government "
                   "or education bodies (such sites can still be hacked, so stay alert)."),
    Rule("trusted", _trusted, "Recognised legitimate domain",
         lambda f: f"'{f.registered_domain}' is on the list of well-known legitimate "
                   "domains."),
]


ADVICE = {
    PHISHING: ("Do not open this link or enter any information. If you received it "
               "in an email or message, report it and delete it."),
    SUSPICIOUS: ("Be careful. Verify the sender and type the official website "
                 "address yourself instead of clicking this link."),
    SAFE: ("No strong phishing indicators were found, but always check that you are "
           "on the official website before entering personal details."),
}

CSS_CLASS = {SAFE: "safe", SUSPICIOUS: "suspicious", PHISHING: "phishing"}


def classify(score: int) -> str:
    if score >= PHISHING_THRESHOLD:
        return PHISHING
    if score >= SUSPICIOUS_THRESHOLD:
        return SUSPICIOUS
    return SAFE


def evaluate(features: URLFeatures) -> tuple[int, list[Finding], list[str]]:
    """Run all rules. Returns (score 0-100, findings, good_signs)."""
    findings: list[Finding] = []
    total = 0
    for rule in RULES:
        weight = rule.check(features)
        if weight:
            total += weight
            findings.append(Finding(rule.rule_id, rule.title, rule.detail(features),
                                    weight, _sev(weight)))

    good_signs: list[str] = []
    if features.uses_https:
        good_signs.append("Uses HTTPS (note: many phishing sites also use HTTPS, so "
                          "this alone does not prove a site is safe).")
    for finding in findings:
        if finding.weight < 0:  # trusted / government-education domain
            good_signs.insert(0, finding.detail)
    if features.url_length <= 75:
        good_signs.append("URL length is normal.")
    if not features.suspicious_keywords:
        good_signs.append("No common phishing keywords found.")

    findings.sort(key=lambda x: x.weight, reverse=True)
    score = max(0, min(100, total))
    return score, findings, good_signs
