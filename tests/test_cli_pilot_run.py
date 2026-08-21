"""CLI tests for pilot-run bundle generation."""

from __future__ import annotations

import csv
import json
import socket
from pathlib import Path
from typing import NoReturn, cast

import pytest

from aethelgard.cli import PREFLIGHT_BLOCK_EXIT_CODE, REVIEW_CSV_COLUMNS, REVIEW_CSV_NAME, main
from aethelgard.redaction_preflight import PREFLIGHT_JSON_NAME, PREFLIGHT_MD_NAME
from aethelgard.triage import REPORT_JSON_NAME, REPORT_MD_NAME, RUN_SUMMARY_NAME

FIXTURE_ROOT = Path(__file__).resolve().parent / "fixtures"
CUSTOMER_LIKE_DIR = FIXTURE_ROOT / "customer_like_nis2"
PUBLIC_NIS2_DIR = FIXTURE_ROOT / "public_nis2"


def _read_json(path: Path) -> dict[str, object]:
    return cast(dict[str, object], json.loads(path.read_text(encoding="utf-8")))


def _read_review_rows(path: Path) -> tuple[list[str] | None, list[dict[str, str]]]:
    with path.open(encoding="utf-8", newline="") as csv_file:
        reader = csv.DictReader(csv_file)
        headers = list(reader.fieldnames) if reader.fieldnames is not None else None
        return headers, list(reader)


def test_pilot_run_writes_bundle_review_csv_and_audit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    out_dir = tmp_path / "pilot-demo"

    exit_code = main(
        ["pilot-run", "--input", str(CUSTOMER_LIKE_DIR), "--out", str(out_dir), "--audit"]
    )

    assert exit_code == 0
    for file_name in (
        PREFLIGHT_JSON_NAME,
        PREFLIGHT_MD_NAME,
        REPORT_JSON_NAME,
        REPORT_MD_NAME,
        RUN_SUMMARY_NAME,
        REVIEW_CSV_NAME,
    ):
        assert (out_dir / file_name).is_file()

    preflight = _read_json(out_dir / PREFLIGHT_JSON_NAME)
    summary = _read_json(out_dir / RUN_SUMMARY_NAME)
    headers, rows = _read_review_rows(out_dir / REVIEW_CSV_NAME)
    ledger = tmp_path / "reports" / "audit" / "aethelgard_runs.jsonl"
    ledger_line = ledger.read_text(encoding="utf-8").strip()
    audit_entry = json.loads(ledger_line)

    assert preflight["preflight_skipped"] is False
    assert summary["exit_code"] == 0
    assert headers == list(REVIEW_CSV_COLUMNS)
    assert rows
    assert rows[0]["finding_id"].startswith("F-")
    assert rows[0]["review_status"] == ""
    assert rows[0]["recommended_manual_check"]
    assert audit_entry["command"] == "triage"
    assert "source_citation" not in ledger_line


def test_pilot_run_fail_on_sensitive_blocks_before_triage(tmp_path: Path) -> None:
    input_dir = tmp_path / "input"
    input_dir.mkdir()
    (input_dir / "sensitive.md").write_text(
        "Reviewer contact: reviewer@example.test\nrisk assessment process is documented\n",
        encoding="utf-8",
    )
    out_dir = tmp_path / "blocked"

    exit_code = main(
        [
            "pilot-run",
            "--input",
            str(input_dir),
            "--out",
            str(out_dir),
            "--fail-on-sensitive",
        ]
    )

    preflight = _read_json(out_dir / PREFLIGHT_JSON_NAME)
    assert exit_code == PREFLIGHT_BLOCK_EXIT_CODE
    assert preflight["status"] == "block"
    assert (out_dir / PREFLIGHT_MD_NAME).is_file()
    assert not (out_dir / REPORT_JSON_NAME).exists()
    assert not (out_dir / REVIEW_CSV_NAME).exists()


def test_pilot_run_no_preflight_writes_explicit_skipped_report(tmp_path: Path) -> None:
    out_dir = tmp_path / "no-preflight"

    exit_code = main(
        ["pilot-run", "--input", str(CUSTOMER_LIKE_DIR), "--out", str(out_dir), "--no-preflight"]
    )

    preflight = _read_json(out_dir / PREFLIGHT_JSON_NAME)
    assert exit_code == 0
    assert preflight["status"] == "pass"
    assert preflight["preflight_skipped"] is True
    assert preflight["notes"] == ["Preflight skipped by --no-preflight."]
    assert (out_dir / REPORT_JSON_NAME).is_file()
    assert (out_dir / REVIEW_CSV_NAME).is_file()


def test_pilot_run_public_demo_fixtures_do_not_need_network(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def blocked_socket(*args: object, **kwargs: object) -> NoReturn:
        raise AssertionError("network access is not expected for pilot-run")

    monkeypatch.setattr(socket, "socket", blocked_socket)
    out_dir = tmp_path / "public-demo"

    exit_code = main(["pilot-run", "--input", str(PUBLIC_NIS2_DIR), "--out", str(out_dir)])

    report = _read_json(out_dir / REPORT_JSON_NAME)
    document_count = report["document_count"]
    evidence_count = report["evidence_count"]
    assert exit_code == 0
    assert isinstance(document_count, int)
    assert isinstance(evidence_count, int)
    assert document_count == 17
    assert evidence_count > 0
