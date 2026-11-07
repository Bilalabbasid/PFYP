"""URL validation and normalisation.

The system never fetches the submitted URL. It only parses the string, so
validation here is about making sure we have something URL-shaped to analyse.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import urlsplit

MAX_URL_LENGTH = 2048
ALLOWED_SCHEMES = {"http", "https"}
# Schemes that are dangerous in a phishing context; we refuse to analyse them
# as web links but tell the user why.
DANGEROUS_SCHEMES = {"javascript", "data", "vbscript", "file"}

_HOST_RE = re.compile(r"^[A-Za-z0-9\-._~%\[\]:¡-￿]+$")


class URLValidationError(ValueError):
    """Raised when the submitted text cannot be analysed as a web URL."""


@dataclass(frozen=True)
class NormalisedURL:
    original: str
    url: str          # normalised form used for analysis
    scheme: str
    host: str         # lower-cased hostname without port / credentials
    port: int | None
    path: str
    query: str
    fragment: str
    has_userinfo: bool
    scheme_was_added: bool


def normalise_url(raw: str) -> NormalisedURL:
    """Validate ``raw`` and return a parsed, normalised representation.

    * Strips surrounding whitespace and common "defanging" (hxxp, [.]).
    * Adds ``http://`` when no scheme is supplied (so "paypa1.com/login" works).
    * Rejects empty input, overly long input, non-web schemes and URLs without
      a usable hostname.
    """
    if raw is None:
        raise URLValidationError("Please enter a URL.")
    text = raw.strip()
    if not text:
        raise URLValidationError("Please enter a URL.")
    if len(text) > MAX_URL_LENGTH:
        raise URLValidationError(
            f"URL is too long to analyse (maximum {MAX_URL_LENGTH} characters)."
        )
    if any(ch in text for ch in ("\n", "\r", "\t")) or " " in text:
        raise URLValidationError("A URL cannot contain spaces or line breaks.")

    # Undo common defanging so security people can paste IOCs safely.
    text = re.sub(r"^hxxp", "http", text, flags=re.IGNORECASE)
    text = text.replace("[.]", ".").replace("(.)", ".").replace("[:]", ":")

    scheme_match = re.match(r"^([A-Za-z][A-Za-z0-9+.\-]*):", text)
    scheme_was_added = False
    if scheme_match:
        scheme = scheme_match.group(1).lower()
        if scheme in DANGEROUS_SCHEMES:
            raise URLValidationError(
                f"'{scheme}:' links are not web pages and are commonly abused "
                "in attacks. Do not open this link."
            )
        if scheme not in ALLOWED_SCHEMES:
            # Could be "example.com:8080/path" which looks like a scheme.
            if "//" not in text and re.match(r"^[A-Za-z0-9.\-]+:\d+", text):
                text = "http://" + text
                scheme_was_added = True
            else:
                raise URLValidationError(
                    "Only http:// and https:// links can be analysed."
                )
    else:
        if text.startswith("//"):
            text = "http:" + text
        else:
            text = "http://" + text
        scheme_was_added = True

    try:
        parts = urlsplit(text)
        port = parts.port
    except ValueError as exc:  # invalid port, bad IPv6 literal, ...
        raise URLValidationError(f"The URL is malformed: {exc}.") from exc

    host = (parts.hostname or "").strip(".").lower()
    if not host:
        raise URLValidationError("The URL does not contain a valid domain name.")
    if not _HOST_RE.match(host):
        raise URLValidationError("The domain name contains invalid characters.")
    if "." not in host and not host.startswith("[") and ":" not in host:
        # decimal / hex encoded IPv4 (http://3232235777/) is a known evasion
        # trick, so it must be accepted and analysed rather than rejected
        if host != "localhost" and not re.fullmatch(r"\d{8,10}|0x[0-9a-f]{6,8}", host):
            raise URLValidationError(
                "The domain name is incomplete (for example: example.com)."
            )

    return NormalisedURL(
        original=raw.strip(),
        url=text,
        scheme=parts.scheme.lower(),
        host=host,
        port=port,
        path=parts.path or "",
        query=parts.query or "",
        fragment=parts.fragment or "",
        has_userinfo="@" in (parts.netloc or ""),
        scheme_was_added=scheme_was_added,
    )


def defang(url: str) -> str:
    """Return a non-clickable representation of a URL for safe display."""
    return (
        url.replace("http://", "hxxp://")
        .replace("https://", "hxxps://")
        .replace(".", "[.]")
    )
