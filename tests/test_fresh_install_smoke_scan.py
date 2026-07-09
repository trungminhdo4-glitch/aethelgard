"""Leak-scan tests for the fresh-install smoke (prose vs. credential assignments)."""

from __future__ import annotations

from scripts.fresh_install_smoke import scan_text_for_leaks


def test_prose_mention_of_cookies_is_not_a_leak() -> None:
    # Trust-bundle README hygiene sentence must not trip the scanner.
    text = "No raw document text, database files, logs, cookies, or private paths are included."
    assert scan_text_for_leaks(text) == []


def test_credential_assignment_is_flagged() -> None:
    assert scan_text_for_leaks("Cookie: session=abc123") == ["credential_assignment:cookie"]
    assert scan_text_for_leaks("api_key = sk-verysecret") == ["credential_assignment:api_key"]


def test_local_path_and_env_reference_are_flagged() -> None:
    assert "forbidden_marker:c:\\users" in scan_text_for_leaks(r"seen at C:\Users\someone\file")
    assert "forbidden_marker:.env" in scan_text_for_leaks("loaded from .env file")


def test_email_address_is_flagged() -> None:
    assert scan_text_for_leaks("contact person@example.com now") == ["email_address"]
