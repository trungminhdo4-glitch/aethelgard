"""Tests for the human-review import workflow."""

from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import cast

import pytest

from aethelgard.cli import REVIEW_APPLY_ERROR_EXIT_CODE, main
from aethelgard.review import (
    REVIEW_SUMMARY_JSON_NAME,
    REVIEWED_REPORT_JSON_NAME,
    REVIEWED_REPORT_MD_NAME,
)
from aethelgard.triage import REPORT_JSON_NAME

FIXTURE_ROOT = Path(__file__).resolve().parent / "fixtures"
CUSTOMER_LIKE_DIR = FIXTURE_ROOT / "customer_like_nis2"
REVIEW_CSV_NAME = "review_items.csv"


def _read_json(path: Path) -> dict[str, object]:
    return cast(dict[str, object], json.loads(path.read_text(encoding="utf-8")))


def _read_review_rows(path: Path) -> tuple[list[str], list[dict[str, str]]]:
    with path.open(encoding="utf-8", newline="") as csv_file:
        reader = csv.DictReader(csv_file)
        assert reader.fieldnames is not None
        return list(reader.fieldnames), list(reader)


def _write_review_rows(path: Path, headers: list[str], rows: list[dict[str, str]]) -> None:
    with path.open("w", encoding="utf-8", newline="") as csv_file:
        writer = csv.DictWriter(csv_file, fieldnames=headers, lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)


def _report_findings(path: Path) -> list[dict[str, object]]:
    report = _read_json(path)
    findings: list[dict[str, object]] = []
    documents = cast(list[dict[str, object]], report["per_document"])
    for document in documents:
        findings.extend(cast(list[dict[str, object]], document["evidence"]))
    return findings


def _findings_by_id(path: Path) -> dict[str, dict[str, object]]:
    return {str(item["finding_id"]): item for item in _report_findings(path)}


def _run_pilot(out_dir: Path) -> Path:
    exit_code = main(
        ["pilot-run", "--input", str(CUSTOMER_LIKE_DIR), "--out", str(out_dir), "--no-preflight"]
    )
    assert exit_code == 0
    return out_dir / REVIEW_CSV_NAME


def test_review_items_csv_contains_stable_finding_id(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    first_csv = _run_pilot(tmp_path / "pilot-a")
    second_csv = _run_pilot(tmp_path / "pilot-b")

    headers, first_rows = _read_review_rows(first_csv)
    _second_headers, second_rows = _read_review_rows(second_csv)
    report_findings = _report_findings(tmp_path / "pilot-a" / REPORT_JSON_NAME)

    assert "finding_id" in headers
    assert first_rows
    assert all(row["finding_id"].startswith("F-") for row in first_rows)
    assert [row["finding_id"] for row in first_rows] == [
        row["finding_id"] for row in second_rows
    ]
    assert first_rows[0]["finding_id"] == report_findings[0]["finding_id"]


def test_review_apply_writes_outputs_and_applies_statuses(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    pilot_dir = tmp_path / "pilot"
    review_csv = _run_pilot(pilot_dir)
    headers, rows = _read_review_rows(review_csv)
    rows[0]["review_status"] = "accepted"
    rows[0]["review_note"] = "Evidence is usable for the pilot handover."
    rows[1]["review_status"] = "false_positive"
    rows[1]["review_note"] = "Marketing wording only."
    rows[2]["review_status"] = ""
    _write_review_rows(review_csv, headers, rows)

    reviewed_dir = tmp_path / "reviewed"
    exit_code = main(
        [
            "review-apply",
            "--report",
            str(pilot_dir / REPORT_JSON_NAME),
            "--review-csv",
            str(review_csv),
            "--out",
            str(reviewed_dir),
        ]
    )

    assert exit_code == 0
    assert (reviewed_dir / REVIEWED_REPORT_JSON_NAME).is_file()
    assert (reviewed_dir / REVIEWED_REPORT_MD_NAME).is_file()
    assert (reviewed_dir / REVIEW_SUMMARY_JSON_NAME).is_file()

    reviewed_by_id = _findings_by_id(reviewed_dir / REVIEWED_REPORT_JSON_NAME)
    summary = _read_json(reviewed_dir / REVIEW_SUMMARY_JSON_NAME)
    status_counts = cast(dict[str, int], summary["status_counts"])
    markdown = (reviewed_dir / REVIEWED_REPORT_MD_NAME).read_text(encoding="utf-8")

    assert reviewed_by_id[rows[0]["finding_id"]]["review_status"] == "accepted"
    assert reviewed_by_id[rows[1]["finding_id"]]["review_status"] == "false_positive"
    assert reviewed_by_id[rows[2]["finding_id"]]["review_status"] == "open"
    assert status_counts["accepted"] == 1
    assert status_counts["false_positive"] == 1
    assert status_counts["open"] >= 1
    assert "# Aethelgard Reviewed Evidence Report" in markdown
    assert "False Positive" in markdown


def test_review_apply_accepts_reviewed_status_in_strict_mode(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    pilot_dir = tmp_path / "pilot"
    review_csv = _run_pilot(pilot_dir)
    headers, rows = _read_review_rows(review_csv)
    rows[0]["review_status"] = "reviewed"
    rows[0]["review_note"] = "Evidence reviewed for metadata-only handover."
    _write_review_rows(review_csv, headers, rows)

    reviewed_dir = tmp_path / "reviewed"
    exit_code = main(
        [
            "review-apply",
            "--report",
            str(pilot_dir / REPORT_JSON_NAME),
            "--review-csv",
            str(review_csv),
            "--out",
            str(reviewed_dir),
            "--strict",
        ]
    )

    reviewed_by_id = _findings_by_id(reviewed_dir / REVIEWED_REPORT_JSON_NAME)
    summary = _read_json(reviewed_dir / REVIEW_SUMMARY_JSON_NAME)
    status_counts = cast(dict[str, int], summary["status_counts"])

    assert exit_code == 0
    assert reviewed_by_id[rows[0]["finding_id"]]["review_status"] == "reviewed"
    assert status_counts["reviewed"] == 1


def test_review_apply_accepts_rejected_status_in_strict_mode(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    pilot_dir = tmp_path / "pilot"
    review_csv = _run_pilot(pilot_dir)
    headers, rows = _read_review_rows(review_csv)
    rows[0]["review_status"] = "rejected"
    rows[0]["review_note"] = "Reviewed and rejected for customer handover."
    _write_review_rows(review_csv, headers, rows)

    reviewed_dir = tmp_path / "reviewed"
    exit_code = main(
        [
            "review-apply",
            "--report",
            str(pilot_dir / REPORT_JSON_NAME),
            "--review-csv",
            str(review_csv),
            "--out",
            str(reviewed_dir),
            "--strict",
        ]
    )

    reviewed_by_id = _findings_by_id(reviewed_dir / REVIEWED_REPORT_JSON_NAME)
    summary = _read_json(reviewed_dir / REVIEW_SUMMARY_JSON_NAME)
    status_counts = cast(dict[str, int], summary["status_counts"])

    assert exit_code == 0
    assert reviewed_by_id[rows[0]["finding_id"]]["review_status"] == "rejected"
    assert status_counts["rejected"] == 1


def test_review_apply_rejects_existing_output_with_unexpected_files(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    pilot_dir = tmp_path / "pilot"
    review_csv = _run_pilot(pilot_dir)
    reviewed_dir = tmp_path / "reviewed"
    reviewed_dir.mkdir()
    stale_file = reviewed_dir / "raw_report.json"
    stale_file.write_text("RAW_STALE_SHOULD_NOT_EXPORT\n", encoding="utf-8")

    exit_code = main(
        [
            "review-apply",
            "--report",
            str(pilot_dir / REPORT_JSON_NAME),
            "--review-csv",
            str(review_csv),
            "--out",
            str(reviewed_dir),
        ]
    )

    assert exit_code == REVIEW_APPLY_ERROR_EXIT_CODE
    assert stale_file.is_file()
    assert not (reviewed_dir / REVIEWED_REPORT_JSON_NAME).exists()


def test_review_apply_unknown_status_strict_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    pilot_dir = tmp_path / "pilot"
    review_csv = _run_pilot(pilot_dir)
    headers, rows = _read_review_rows(review_csv)
    rows[0]["review_status"] = "surprise"
    _write_review_rows(review_csv, headers, rows)

    reviewed_dir = tmp_path / "reviewed"
    exit_code = main(
        [
            "review-apply",
            "--report",
            str(pilot_dir / REPORT_JSON_NAME),
            "--review-csv",
            str(review_csv),
            "--out",
            str(reviewed_dir),
            "--strict",
        ]
    )

    assert exit_code == REVIEW_APPLY_ERROR_EXIT_CODE
    assert not (reviewed_dir / REVIEWED_REPORT_JSON_NAME).exists()


def test_review_apply_duplicate_finding_id_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    pilot_dir = tmp_path / "pilot"
    review_csv = _run_pilot(pilot_dir)
    headers, rows = _read_review_rows(review_csv)
    rows.append(dict(rows[0]))
    _write_review_rows(review_csv, headers, rows)

    exit_code = main(
        [
            "review-apply",
            "--report",
            str(pilot_dir / REPORT_JSON_NAME),
            "--review-csv",
            str(review_csv),
            "--out",
            str(tmp_path / "reviewed"),
        ]
    )

    assert exit_code == REVIEW_APPLY_ERROR_EXIT_CODE


def test_review_apply_unknown_finding_id_summary_and_strict_block(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    pilot_dir = tmp_path / "pilot"
    review_csv = _run_pilot(pilot_dir)
    headers, rows = _read_review_rows(review_csv)
    unknown_row = {header: "" for header in headers}
    unknown_row["finding_id"] = "F-deadbeef"
    unknown_row["review_status"] = "accepted"
    rows.append(unknown_row)
    _write_review_rows(review_csv, headers, rows)

    reviewed_dir = tmp_path / "reviewed"
    exit_code = main(
        [
            "review-apply",
            "--report",
            str(pilot_dir / REPORT_JSON_NAME),
            "--review-csv",
            str(review_csv),
            "--out",
            str(reviewed_dir),
        ]
    )

    summary = _read_json(reviewed_dir / REVIEW_SUMMARY_JSON_NAME)
    assert exit_code == 0
    assert summary["unknown_review_ids"] == ["F-deadbeef"]

    strict_exit_code = main(
        [
            "review-apply",
            "--report",
            str(pilot_dir / REPORT_JSON_NAME),
            "--review-csv",
            str(review_csv),
            "--out",
            str(tmp_path / "strict-reviewed"),
            "--strict",
        ]
    )
    assert strict_exit_code == REVIEW_APPLY_ERROR_EXIT_CODE


def test_review_apply_masks_secret_like_review_note(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    pilot_dir = tmp_path / "pilot"
    review_csv = _run_pilot(pilot_dir)
    headers, rows = _read_review_rows(review_csv)
    rows[0]["review_status"] = "accepted"
    rows[0]["review_note"] = "Do not share api_key=placeholder with anyone."
    _write_review_rows(review_csv, headers, rows)

    reviewed_dir = tmp_path / "reviewed"
    exit_code = main(
        [
            "review-apply",
            "--report",
            str(pilot_dir / REPORT_JSON_NAME),
            "--review-csv",
            str(review_csv),
            "--out",
            str(reviewed_dir),
        ]
    )

    reviewed_by_id = _findings_by_id(reviewed_dir / REVIEWED_REPORT_JSON_NAME)
    summary = _read_json(reviewed_dir / REVIEW_SUMMARY_JSON_NAME)
    note = str(reviewed_by_id[rows[0]["finding_id"]]["review_note"])

    assert exit_code == 0
    assert "placeholder" not in note
    assert "[token:redacted]" in note
    warnings = cast(list[str], summary["warnings"])
    assert any("sensitive marker masked" in warning for warning in warnings)
