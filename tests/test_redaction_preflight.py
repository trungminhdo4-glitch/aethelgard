"""Tests for local redaction preflight scanning."""

from __future__ import annotations

from pathlib import Path

from aethelgard.redaction_preflight import (
    FindingType,
    PreflightFinding,
    PreflightReport,
    run_redaction_preflight,
)


def _write_text(path: Path, content: str) -> None:
    path.write_text(content, encoding="utf-8")


def _findings_of_type(
    report: PreflightReport,
    finding_type: FindingType,
) -> list[PreflightFinding]:
    return [finding for finding in report["findings"] if finding["type"] == finding_type]


def test_redaction_preflight_detects_email_and_masks_value(tmp_path: Path) -> None:
    document = tmp_path / "contact.md"
    _write_text(document, "Control owner contact: security.owner@example.test\n")

    report = run_redaction_preflight(tmp_path)

    findings = _findings_of_type(report, "email")
    assert report["status"] == "warn"
    assert report["files_scanned"] == 1
    assert len(findings) == 1
    assert findings[0]["severity"] == "medium"
    assert "security.owner@example.test" not in findings[0]["snippet"]
    assert "[email:redacted]" in findings[0]["snippet"]


def test_redaction_preflight_detects_phone_number(tmp_path: Path) -> None:
    document = tmp_path / "phone.md"
    _write_text(document, "Incident bridge phone: +00 0000000000\n")

    report = run_redaction_preflight(tmp_path)

    findings = _findings_of_type(report, "phone")
    assert report["status"] == "warn"
    assert len(findings) == 1
    assert findings[0]["line"] == 1
    assert "+49 30 12345678" not in findings[0]["snippet"]


def test_redaction_preflight_detects_api_key_token_pattern(tmp_path: Path) -> None:
    document = tmp_path / "token.txt"
    token_value = "not-a-real-token-for-tests-1234567890"
    _write_text(document, "api_key = %s\n" % token_value)

    report = run_redaction_preflight(tmp_path)

    findings = _findings_of_type(report, "token")
    assert report["status"] == "block"
    assert report["summary"]["high"] == 1
    assert len(findings) == 1
    assert token_value not in findings[0]["snippet"]
    assert "[token:redacted]" in findings[0]["snippet"]


def test_redaction_preflight_blocks_secret_assignments(tmp_path: Path) -> None:
    document = tmp_path / "policy.txt"
    secret_value = "not-a-real-password-for-tests-12345"
    _write_text(document, "password: %s\n" % secret_value)

    report = run_redaction_preflight(tmp_path)

    findings = _findings_of_type(report, "secret")
    assert report["status"] == "block"
    assert len(findings) == 1
    assert findings[0]["severity"] == "high"
    assert secret_value not in findings[0]["snippet"]


def test_redaction_preflight_fail_on_sensitive_escalates_medium_findings(
    tmp_path: Path,
) -> None:
    document = tmp_path / "contact.md"
    _write_text(document, "Reviewer: reviewer@example.test\n")

    report = run_redaction_preflight(tmp_path, fail_on_sensitive=True)

    assert report["status"] == "block"
    assert report["summary"]["medium"] == 1
    assert report["notes"] == ["--fail-on-sensitive escalated medium findings to block."]


def test_redaction_preflight_scans_multiple_text_files(tmp_path: Path) -> None:
    _write_text(tmp_path / "risk.md", "risk assessment process is documented\n")
    _write_text(tmp_path / "incident.txt", "incident response workflow is reviewed\n")

    report = run_redaction_preflight(tmp_path)

    assert report["status"] == "pass"
    assert report["files_scanned"] == 2
    assert report["findings"] == []


def test_redaction_preflight_warns_for_binary_like_files(tmp_path: Path) -> None:
    document = tmp_path / "binary.txt"
    document.write_bytes(b"not text\x00still not text")

    report = run_redaction_preflight(tmp_path)

    findings = _findings_of_type(report, "unsupported")
    assert report["status"] == "warn"
    assert report["files_scanned"] == 0
    assert len(findings) == 1
    assert findings[0]["severity"] == "low"


def test_redaction_preflight_warns_for_private_network_markers(tmp_path: Path) -> None:
    document = tmp_path / "network.md"
    _write_text(document, "Internal endpoint is app01.internal at 10.0.0.8\n")

    report = run_redaction_preflight(tmp_path)

    findings = _findings_of_type(report, "private_network")
    assert report["status"] == "warn"
    assert len(findings) == 2
    assert all("app01.internal" not in finding["snippet"] for finding in findings)
    assert all("10.0.0.8" not in finding["snippet"] for finding in findings)


def test_redaction_preflight_blocks_database_input(tmp_path: Path) -> None:
    (tmp_path / "customer.sqlite").write_bytes(b"SQLite format 3\x00binary payload")

    report = run_redaction_preflight(tmp_path)

    findings = _findings_of_type(report, "forbidden_binary")
    assert report["status"] == "block"
    assert report["files_scanned"] == 0
    assert len(findings) == 1
    assert findings[0]["severity"] == "high"
    assert "binary payload" not in findings[0]["snippet"]


def test_redaction_preflight_blocks_archive_and_key_inputs(tmp_path: Path) -> None:
    (tmp_path / "backup.zip").write_bytes(b"PK\x03\x04archive")
    (tmp_path / "server.pfx").write_bytes(b"\x30\x82key-material")

    report = run_redaction_preflight(tmp_path)

    findings = _findings_of_type(report, "forbidden_binary")
    assert report["status"] == "block"
    assert len(findings) == 2
    assert all(finding["severity"] == "high" for finding in findings)


def test_redaction_preflight_blocks_oversize_non_text_binary(tmp_path: Path) -> None:
    from aethelgard.redaction_preflight import MAX_INPUT_FILE_BYTES

    document = tmp_path / "dump.bin"
    document.write_bytes(b"\x00" * (MAX_INPUT_FILE_BYTES + 1))

    report = run_redaction_preflight(tmp_path)

    findings = _findings_of_type(report, "forbidden_binary")
    assert report["status"] == "block"
    assert len(findings) == 1
    assert findings[0]["severity"] == "high"


def test_redaction_preflight_small_non_text_stays_unsupported_warn(tmp_path: Path) -> None:
    # A small ordinary non-text file (e.g. a logo) must stay a soft "unsupported" hint, not a block.
    (tmp_path / "logo.png").write_bytes(b"\x89PNG\r\n\x1a\n small image bytes")

    report = run_redaction_preflight(tmp_path)

    assert report["status"] == "warn"
    assert not _findings_of_type(report, "forbidden_binary")
    assert len(_findings_of_type(report, "unsupported")) == 1
