"""Helpers for classifying public reference URL checks.

The helpers are intentionally pure. Network access remains opt-in in tests and is not
required for normal readiness checks.
"""

from __future__ import annotations

from typing import Final
from urllib.parse import urlparse

URL_CHECK_PASS: Final[str] = "PASS"
URL_CHECK_WARN: Final[str] = "WARN"
URL_CHECK_FAIL: Final[str] = "FAIL"

REDIRECT_STATUS_CODES: Final[frozenset[int]] = frozenset({301, 302, 303, 307, 308})
OFFICIAL_SOURCE_HOSTS: Final[frozenset[str]] = frozenset(
    {
        "eur-lex.europa.eu",
        "www.enisa.europa.eu",
        "www.bsi.bund.de",
        "www.nist.gov",
        "www.cisa.gov",
        "owasp.org",
    }
)
WARN_ERROR_KINDS: Final[frozenset[str]] = frozenset({"timeout"})
FAIL_ERROR_KINDS: Final[frozenset[str]] = frozenset({"dns", "invalid_domain"})


def classify_public_url_check(
    url: str,
    *,
    status_code: int | None = None,
    location: str | None = None,
    error_kind: str | None = None,
) -> dict[str, str]:
    """Classify an official public-source URL check as PASS, WARN, or FAIL."""
    status = URL_CHECK_FAIL
    reason = "missing status code"
    if not _is_valid_https_url(url):
        reason = "invalid or non-https url"
    elif error_kind is not None:
        normalized_error = error_kind.lower()
        if normalized_error in WARN_ERROR_KINDS:
            status = URL_CHECK_WARN
            reason = normalized_error
        elif normalized_error in FAIL_ERROR_KINDS:
            reason = normalized_error
        else:
            reason = "unexpected network error"
    elif status_code is not None:
        if 200 <= status_code < 300:
            status = URL_CHECK_PASS
            reason = "reachable"
        elif status_code in REDIRECT_STATUS_CODES:
            if location is None or _is_plausible_redirect(url, location):
                status = URL_CHECK_PASS
                reason = "redirect accepted"
            else:
                status = URL_CHECK_WARN
                reason = "redirect target needs manual review"
        elif status_code == 403 and _is_official_source_url(url):
            status = URL_CHECK_WARN
            reason = "official source blocked automation"
        else:
            reason = "unexpected http status %d" % status_code
    return {"status": status, "reason": reason}


def _is_valid_https_url(url: str) -> bool:
    parsed = urlparse(url)
    return parsed.scheme == "https" and bool(parsed.netloc) and "." in parsed.netloc


def _is_official_source_url(url: str) -> bool:
    host = urlparse(url).netloc.lower()
    return host in OFFICIAL_SOURCE_HOSTS


def _is_plausible_redirect(original_url: str, location: str) -> bool:
    if not _is_valid_https_url(location):
        return False
    original_host = urlparse(original_url).netloc.lower()
    redirect_host = urlparse(location).netloc.lower()
    return redirect_host == original_host or redirect_host in OFFICIAL_SOURCE_HOSTS
