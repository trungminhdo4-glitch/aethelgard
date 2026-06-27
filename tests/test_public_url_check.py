"""Tests for public reference URL check classification."""

from __future__ import annotations

from aethelgard.public_sources import (
    URL_CHECK_FAIL,
    URL_CHECK_PASS,
    URL_CHECK_WARN,
    classify_public_url_check,
)


def test_public_url_check_accepts_success_and_plausible_redirect() -> None:
    success = classify_public_url_check(
        "https://www.cisa.gov/cybersecurity-performance-goals-cpgs",
        status_code=200,
    )
    redirect = classify_public_url_check(
        "https://www.nist.gov/cyberframework",
        status_code=302,
        location="https://www.nist.gov/cybersecurity-framework",
    )

    assert success["status"] == URL_CHECK_PASS
    assert redirect["status"] == URL_CHECK_PASS


def test_public_url_check_treats_official_403_and_timeout_as_warn() -> None:
    forbidden = classify_public_url_check(
        "https://www.cisa.gov/cybersecurity-performance-goals-cpgs",
        status_code=403,
    )
    timeout = classify_public_url_check(
        "https://www.enisa.europa.eu/publications/nis2-technical-implementation-guidance",
        error_kind="timeout",
    )

    assert forbidden["status"] == URL_CHECK_WARN
    assert "automation" in forbidden["reason"]
    assert timeout["status"] == URL_CHECK_WARN


def test_public_url_check_fails_invalid_domain_and_wrong_url() -> None:
    invalid_domain = classify_public_url_check(
        "https://nis2.example.invalid/source",
        error_kind="dns",
    )
    wrong_scheme = classify_public_url_check(
        "http://www.cisa.gov/cybersecurity-performance-goals-cpgs",
        status_code=200,
    )
    bad_redirect = classify_public_url_check(
        "https://www.cisa.gov/cybersecurity-performance-goals-cpgs",
        status_code=302,
        location="https://attacker.example.invalid/path",
    )

    assert invalid_domain["status"] == URL_CHECK_FAIL
    assert wrong_scheme["status"] == URL_CHECK_FAIL
    assert bad_redirect["status"] == URL_CHECK_WARN
