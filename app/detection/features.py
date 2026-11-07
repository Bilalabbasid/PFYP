"""Feature extraction: turn a URL string into measurable security features.

Only the URL text is analysed. The system never connects to the target, so a
malicious page cannot harm the server or the user during analysis.
"""
from __future__ import annotations

import ipaddress
import math
import re
from collections import Counter
from dataclasses import asdict, dataclass, field
from urllib.parse import parse_qsl, unquote

from . import knowledge as kb
from .validators import NormalisedURL

SPECIAL_CHARS = set("@-_~%=&?#!$*+,;'()[]|^`{}\\")


@dataclass
class URLFeatures:
    # --- lengths / counts (numeric) -------------------------------------
    url_length: int = 0
    host_length: int = 0
    path_length: int = 0
    query_length: int = 0
    num_dots: int = 0
    num_hyphens: int = 0
    num_hyphens_host: int = 0
    num_underscores: int = 0
    num_slashes: int = 0
    num_digits: int = 0
    num_digits_host: int = 0
    num_special_chars: int = 0
    num_query_params: int = 0
    num_subdomains: int = 0
    num_percent_encoded: int = 0
    domain_entropy: float = 0.0
    digit_ratio: float = 0.0
    # --- boolean indicators ----------------------------------------------
    uses_https: bool = False
    has_ip_host: bool = False
    has_at_symbol: bool = False
    has_userinfo: bool = False
    has_double_slash_redirect: bool = False
    has_non_standard_port: bool = False
    has_punycode: bool = False
    has_non_ascii: bool = False
    is_shortener: bool = False
    is_free_hosting: bool = False
    is_trusted_domain: bool = False
    restricted_tld: bool = False
    suspicious_tld: bool = False
    https_token_in_host: bool = False
    has_redirect_param: bool = False
    redirect_to_other_domain: bool = False
    redirect_target_suspicious: bool = False
    random_looking_domain: bool = False
    has_embedded_url: bool = False
    has_risky_extension: bool = False
    brand_impersonation: bool = False
    brand_in_path: bool = False
    typosquatting: bool = False
    has_fragment_tricks: bool = False
    # --- descriptive (not used directly by the ML model) ------------------
    host: str = ""
    registered_domain: str = ""
    tld: str = ""
    subdomain: str = ""
    suspicious_keywords: list[str] = field(default_factory=list)
    impersonated_brand: str = ""
    typosquat_target: str = ""
    risky_extension: str = ""

    @property
    def num_suspicious_keywords(self) -> int:
        return len(self.suspicious_keywords)

    def to_dict(self) -> dict:
        data = asdict(self)
        data["num_suspicious_keywords"] = self.num_suspicious_keywords
        return data


# Ordered list of numeric features fed to the optional ML model.
ML_FEATURE_NAMES = [
    "url_length", "host_length", "path_length", "query_length", "num_dots",
    "num_hyphens", "num_hyphens_host", "num_underscores", "num_slashes",
    "num_digits", "num_digits_host", "num_special_chars", "num_query_params",
    "num_subdomains", "num_percent_encoded", "domain_entropy", "digit_ratio",
    "uses_https", "has_ip_host", "has_at_symbol", "has_userinfo",
    "has_double_slash_redirect", "has_non_standard_port", "has_punycode",
    "has_non_ascii", "is_shortener", "is_free_hosting", "is_trusted_domain",
    "restricted_tld", "suspicious_tld", "https_token_in_host", "has_redirect_param",
    "has_embedded_url", "redirect_to_other_domain", "redirect_target_suspicious",
    "random_looking_domain",
    "has_risky_extension", "brand_impersonation",
    "brand_in_path", "typosquatting", "has_fragment_tricks", "num_suspicious_keywords",
]


def feature_vector(features: URLFeatures) -> list[float]:
    data = features.to_dict()
    return [float(data[name]) for name in ML_FEATURE_NAMES]


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def split_domain(host: str) -> tuple[str, str, str]:
    """Return (subdomain, registered_domain, tld) for ``host``."""
    labels = [label for label in host.split(".") if label]
    if len(labels) < 2:
        return "", host, labels[-1] if labels else ""
    last_two = ".".join(labels[-2:])
    if last_two in kb.MULTI_PART_SUFFIXES and len(labels) >= 3:
        registered = ".".join(labels[-3:])
        sub = ".".join(labels[:-3])
        tld = last_two
    else:
        registered = last_two
        sub = ".".join(labels[:-2])
        tld = labels[-1]
    return sub, registered, tld


def _is_ip(host: str) -> bool:
    h = host.strip("[]")
    try:
        ipaddress.ip_address(h)
        return True
    except ValueError:
        pass
    # Decimal (http://3232235777/), hex (0xC0A80001) or octal-dotted forms.
    if re.fullmatch(r"\d{8,10}", h):
        return True
    if re.fullmatch(r"0x[0-9a-f]{6,8}", h):
        return True
    if re.fullmatch(r"(0x[0-9a-f]{1,2}|0[0-7]{1,3}|\d{1,3})(\.(0x[0-9a-f]{1,2}|0[0-7]{1,3}|\d{1,3})){3}", h):
        return True
    return False


def shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    counts = Counter(text)
    total = len(text)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


def levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    if len(a) < len(b):
        a, b = b, a
    previous = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        current = [i]
        for j, cb in enumerate(b, 1):
            current.append(min(
                previous[j] + 1,
                current[j - 1] + 1,
                previous[j - 1] + (ca != cb),
            ))
        previous = current
    return previous[-1]


def _looks_random(label: str) -> bool:
    """Heuristic for algorithmically generated names such as 'xk2j9qpzl4m'."""
    text = label.replace("-", "")
    if len(text) < 10:
        return False
    if shannon_entropy(text) <= 3.3:
        return False
    vowels = sum(ch in "aeiou" for ch in text)
    letters = sum(ch.isalpha() for ch in text)
    digits = sum(ch.isdigit() for ch in text)
    longest_consonant_run = max((len(m) for m in re.findall(r"[b-df-hj-np-tv-z]+", text)),
                                default=0)
    mixed = digits >= 3 and letters >= 3
    return (letters and vowels / letters < 0.25) or longest_consonant_run >= 5 or mixed


def _deglyph(label: str) -> str:
    out = label
    for fake, real in kb.HOMOGLYPHS:
        out = out.replace(fake, real)
    return out


def _double_or_swap(token: str, brand: str) -> bool:
    """True if ``token`` is ``brand`` with one letter doubled or two swapped.

    Catches short-brand typos ("yaahoo", "chsae") without flagging ordinary
    words that differ by one substituted letter ("ample" vs "apple").
    """
    if len(token) == len(brand) + 1:
        return any(token[:i] + token[i + 1:] == brand and token[i] == token[i - 1]
                   for i in range(1, len(token)))
    if len(token) == len(brand) and token != brand:
        diff = [i for i in range(len(token)) if token[i] != brand[i]]
        return (len(diff) == 2 and diff[1] == diff[0] + 1
                and token[diff[0]] == brand[diff[1]] and token[diff[1]] == brand[diff[0]])
    return False


def _typo_match(token: str, brand: str) -> bool:
    """Is ``token`` a look-alike spelling of ``brand``?"""
    if token == brand:
        return False
    if _deglyph(token) == brand:
        return True
    if len(brand) >= 5 and _double_or_swap(token, brand):
        return True
    return (len(brand) >= 6 and abs(len(token) - len(brand)) <= 2
            and levenshtein(token, brand) <= (1 if len(brand) < 8 else 2))


def _looks_like_brand(label: str, registered: str) -> bool:
    """Is ``label`` a look-alike of a brand that does not own ``registered``?"""
    for brand, owned in kb.BRANDS.items():
        if registered in owned or len(brand) < 4:
            continue
        if _typo_match(label, brand):
            return True
    return False


def _host_matches(host: str, domains: set[str]) -> str:
    for d in domains:
        if host == d or host.endswith("." + d):
            return d
    return ""


def _brand_owned(registered: str, brand: str) -> bool:
    return registered in kb.BRANDS.get(brand, set())


def _glued_suspiciously(label: str, brand: str) -> bool:
    """True when ``brand`` is glued to extra text that looks like a lure.

    "paypalsecure", "amazon-support", "netflix2024" -> True
    "applebees", "pineapple"                        -> False
    """
    rest = label.replace(brand, " ", 1)
    if "-" in label or any(ch.isdigit() for ch in rest):
        return True
    rest = rest.replace(" ", "")
    return any(word.replace("-", "") in rest for word in kb.SUSPICIOUS_KEYWORDS
               if len(word) >= 4)


# ---------------------------------------------------------------------------
# main entry point
# ---------------------------------------------------------------------------

def extract_features(n: NormalisedURL) -> URLFeatures:
    f = URLFeatures()
    url = n.url
    host = n.host
    decoded = unquote(url).lower()
    path_query = unquote(n.path + ("?" + n.query if n.query else "")).lower()

    f.host = host
    f.url_length = len(n.original)
    f.host_length = len(host)
    f.path_length = len(n.path)
    f.query_length = len(n.query)
    f.num_dots = url.count(".")
    f.num_hyphens = url.count("-")
    f.num_hyphens_host = host.count("-")
    f.num_underscores = url.count("_")
    f.num_slashes = n.path.count("/")
    f.num_digits = sum(ch.isdigit() for ch in url)
    f.num_digits_host = sum(ch.isdigit() for ch in host)
    f.num_special_chars = sum(ch in SPECIAL_CHARS for ch in url.split("://", 1)[-1])
    f.num_percent_encoded = len(re.findall(r"%[0-9a-fA-F]{2}", url))
    query_pairs = parse_qsl(n.query, keep_blank_values=True)
    f.num_query_params = len(query_pairs)
    f.digit_ratio = round(f.num_digits / max(len(url), 1), 4)

    f.uses_https = n.scheme == "https"
    f.has_ip_host = _is_ip(host)
    f.has_userinfo = n.has_userinfo
    f.has_at_symbol = "@" in url.split("://", 1)[-1]
    f.has_non_standard_port = n.port is not None and n.port not in (80, 443)
    f.has_punycode = "xn--" in host
    f.has_non_ascii = any(ord(ch) > 127 for ch in host)
    f.has_double_slash_redirect = "//" in n.path
    f.has_fragment_tricks = bool(n.fragment) and ("http" in n.fragment.lower() or "@" in n.fragment)

    if f.has_ip_host:
        f.registered_domain, f.subdomain, f.tld = host, "", ""
    else:
        f.subdomain, f.registered_domain, f.tld = split_domain(host)
        f.num_subdomains = len([s for s in f.subdomain.split(".") if s and s != "www"])
        f.suspicious_tld = f.tld.split(".")[-1] in kb.SUSPICIOUS_TLDS

    main_label = f.registered_domain.split(".")[0] if f.registered_domain else ""
    f.domain_entropy = round(shannon_entropy(main_label), 4)
    f.random_looking_domain = (not f.has_ip_host) and _looks_random(main_label)

    f.is_trusted_domain = f.registered_domain in kb.TRUSTED_DOMAINS
    f.restricted_tld = (not f.has_ip_host) and f.tld in kb.RESTRICTED_TLDS
    f.is_shortener = bool(_host_matches(host, kb.URL_SHORTENERS))
    f.is_free_hosting = bool(_host_matches(host, kb.FREE_HOSTING_DOMAINS))
    f.https_token_in_host = bool(re.search(r"https?[-.]|[-.]https?|^https?\w", host))

    # Redirect indicators -------------------------------------------------
    for key, value in query_pairs:
        v = unquote(value).lower()
        if key.lower() in kb.REDIRECT_PARAMS and (v.startswith(("http", "//", "www.")) or "." in v):
            f.has_redirect_param = True
        if re.search(r"https?://|www\.", v):
            f.has_embedded_url = True
    if re.search(r"https?://", path_query):
        f.has_embedded_url = True
    for target in re.findall(r"(?:https?://|//|www\.)([a-z0-9.\-]+\.[a-z]{2,})", path_query):
        target = target.lower().removeprefix("www.")
        _, target_reg, _ = split_domain(target)
        if target_reg and target_reg != f.registered_domain:
            f.redirect_to_other_domain = True
            label = target_reg.split(".")[0]
            if target_reg.split(".")[-1] in kb.SUSPICIOUS_TLDS \
                    or _looks_like_brand(label, target_reg):
                f.redirect_target_suspicious = True
            break

    # Risky file extension ------------------------------------------------
    last_segment = n.path.rsplit("/", 1)[-1].lower()
    for ext in kb.RISKY_EXTENSIONS:
        if last_segment.endswith(ext):
            f.has_risky_extension = True
            f.risky_extension = ext
            break

    # Suspicious keywords (in host or path/query) ---------------------------
    haystack = host + " " + path_query
    seen = []
    for word in kb.SUSPICIOUS_KEYWORDS:
        if word in haystack and word not in seen:
            # avoid double-counting overlapping words ("auth"/"authenticate")
            if any(word in other or other in word for other in seen):
                continue
            seen.append(word)
    f.suspicious_keywords = seen

    # Brand impersonation: a brand name appears in the hostname (subdomain or
    # registered label) but the registered domain is not owned by that brand.
    host_part = host if f.has_ip_host else (f.subdomain + "." + main_label)
    host_tokens = set(re.split(r"[^a-z0-9]+", host_part))
    host_compact = re.sub(r"[^a-z0-9]", "", host_part)
    path_tokens = set(re.split(r"[^a-z0-9]+", path_query))
    for brand in kb.BRANDS:
        if _brand_owned(f.registered_domain, brand):
            continue
        if main_label == brand and not f.subdomain.strip("w.") and not f.suspicious_tld:
            # e.g. google.de / amazon.fr: most likely the brand's own country site
            continue
        hit = brand in host_tokens or (len(brand) >= 6 and brand in host_compact
                                       and _glued_suspiciously(host_compact, brand))
        if not hit and len(brand) >= 4 and brand in main_label:
            hit = f.suspicious_tld or _glued_suspiciously(main_label, brand)
        if hit and not f.has_ip_host:
            f.brand_impersonation = True
            f.impersonated_brand = brand
            break
        if brand in path_tokens and not f.brand_in_path:
            f.brand_in_path = True
            f.impersonated_brand = f.impersonated_brand or brand

    # Typosquatting: the main label *looks like* a brand but is not one.
    if main_label and not f.has_ip_host and not f.is_trusted_domain:
        # check the whole label and each hyphen-separated part ("arnazon-support")
        candidates = [main_label] + [t for t in re.split(r"[-_]", main_label) if t]
        candidates += [t for t in re.split(r"[.\-_]", f.subdomain) if len(t) >= 4]
        for brand in kb.BRANDS:
            if _brand_owned(f.registered_domain, brand) or len(brand) < 4:
                continue
            for token in candidates:
                if token == brand:
                    # exact brand name as the whole label on an abused TLD, e.g.
                    # paypal.tk (country domains like google.de are usually fine)
                    if token == main_label and f.suspicious_tld:
                        f.typosquatting = True
                elif _typo_match(token, brand):
                    f.typosquatting = True
                if f.typosquatting:
                    f.typosquat_target = brand
                    break
            if f.typosquatting:
                break

    return f
