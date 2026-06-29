"""Tests for bridging reviewed findings into evidence-store records."""

from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import cast

import pytest

from aethelgard.cli import C_SCRM_ERROR_EXIT_CODE, main
from aethelgard.control_catalog import load_control_catalog_bundle
from aethelgard.evidence_store import load_evidence_store
from aethelgard.questionnaire import QUESTIONNAIRE_JSON_NAME
from aethelgard.review import (
    REVIEW_CSV_COLUMNS,
    REVIEW_CSV_NAME,
    REVIEW_SUMMARY_JSON_NAME,
    REVIEWED_REPORT_JSON_NAME,
)
from aethelgard.supplier_risk import SUPPLIER_RISK_JSON_NAME

FIXTURE_ROOT = Path(__file__).resolve().parent / "fixtures"
SCRM_FIXTURES = FIXTURE_ROOT / "scrm"
QUESTIONNAIRE_CSV = SCRM_FIXTURES / "questionnaire.csv"
QUESTIONNAIRE_E2E_CSV = SCRM_FIXTURES / "questionnaire_e2e.csv"
REVIEWED_REPORT_E2E = SCRM_FIXTURES / "reviewed_report_e2e.json"
SUPPLIER_PROFILE = SCRM_FIXTURES / "supplier_profile.json"


def _finding(
    finding_id: str,
    review_status: str,
    category: str,
) -> dict[str, object]:
    return {
        "finding_id": finding_id,
        "category": category,
        "quality": "strong",
        "quality_signals": ("implemented",),
        "source_reference": "synthetic.md#evidence-1",
        "source_citation": "Synthetic citation that must not be copied into evidence store.",
        "review_status": review_status,
    }


def _write_reviewed_report(path: Path, items: list[dict[str, object]]) -> None:
    path.write_text(
        json.dumps(
            {
                "per_document": [
                    {
                        "file": "synthetic.md",
                        "evidence": items,
                    }
                ]
            },
            indent=2,
        ),
        encoding="utf-8",
    )


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


def test_evidence_bridge_exports_only_accepted_reviewed_findings(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    report_path = tmp_path / "reviewed_report.json"
    first_out = tmp_path / "evidence_store_a.json"
    second_out = tmp_path / "evidence_store_b.json"
    _write_reviewed_report(
        report_path,
        [
            _finding("F-accepted", "accepted", "supplier_security"),
            _finding("F-reviewed", "reviewed", "incident_reporting"),
            _finding("F-rejected", "rejected", "supplier_security"),
            _finding("F-needs", "needs_evidence", "supplier_security"),
            _finding("F-open", "", "supplier_security"),
        ],
    )

    first_exit = main(
        ["evidence", "from-reviewed-report", "--input", str(report_path), "--out", str(first_out)]
    )
    second_exit = main(
        ["evidence", "from-reviewed-report", "--input", str(report_path), "--out", str(second_out)]
    )

    bundle = load_control_catalog_bundle()
    first_store = load_evidence_store(first_out, catalog_bundle=bundle)
    second_store = load_evidence_store(second_out, catalog_bundle=bundle)
    first_records = first_store.evidence
    second_records = second_store.evidence

    assert first_exit == 0
    assert second_exit == 0
    assert len(first_records) == 2
    assert [record.evidence_id for record in first_records] == [
        record.evidence_id for record in second_records
    ]
    assert [record.sha256 for record in first_records] == [
        record.sha256 for record in second_records
    ]
    assert first_records[0].source_type == "reviewed_report"
    assert first_records[0].source_report == "reviewed_report.json"
    assert first_records[0].source_finding_id == "F-accepted"
    assert first_records[0].mapped_controls == ("NIS2-SCRM-01",)
    assert first_records[0].review_status == "accepted"
    assert first_records[0].review_required is False
    assert first_records[0].requires_human_review is False
    assert first_records[1].mapped_controls == ("NIS2-SCRM-02",)


def test_evidence_bridge_missing_finding_id_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    report_path = tmp_path / "reviewed_report.json"
    out_path = tmp_path / "evidence_store.json"
    missing_id = _finding("F-placeholder", "accepted", "supplier_security")
    del missing_id["finding_id"]
    _write_reviewed_report(report_path, [missing_id])

    exit_code = main(
        ["evidence", "from-reviewed-report", "--input", str(report_path), "--out", str(out_path)]
    )

    assert exit_code == C_SCRM_ERROR_EXIT_CODE
    assert not out_path.exists()


def test_evidence_bridge_duplicate_finding_id_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    report_path = tmp_path / "reviewed_report.json"
    out_path = tmp_path / "evidence_store.json"
    _write_reviewed_report(
        report_path,
        [
            _finding("F-duplicate", "accepted", "supplier_security"),
            _finding("F-duplicate", "false_positive", "supplier_security"),
        ],
    )

    exit_code = main(
        ["evidence", "from-reviewed-report", "--input", str(report_path), "--out", str(out_path)]
    )

    assert exit_code == C_SCRM_ERROR_EXIT_CODE
    assert not out_path.exists()


def test_evidence_bridge_does_not_export_private_or_raw_finding_fields(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    report_path = tmp_path / "reviewed_report.json"
    out_path = tmp_path / "evidence_store.json"
    private_marker = "raw private marker from source citation"
    item = _finding("F-accepted", "accepted", "supplier_security")
    item["source_citation"] = "Raw snippet with %s" % private_marker
    item["recommended_manual_check"] = "Manual reviewer note from raw report."
    report_path.write_text(
        json.dumps(
            {
                "per_document": [
                    {
                        "file": "C:/Users/Example/debug.log",
                        "evidence": [item],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    exit_code = main(
        ["evidence", "from-reviewed-report", "--input", str(report_path), "--out", str(out_path)]
    )

    output_text = out_path.read_text(encoding="utf-8")
    assert exit_code == 0
    assert "source_citation" not in output_text
    assert "recommended_manual_check" not in output_text
    assert "C:/Users/Example" not in output_text
    assert "debug.log" not in output_text
    assert private_marker not in output_text


def test_evidence_bridge_output_feeds_questionnaire_workflow(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    report_path = tmp_path / "reviewed_report.json"
    store_path = tmp_path / "evidence_store.json"
    questionnaire_dir = tmp_path / "questionnaire"
    _write_reviewed_report(
        report_path,
        [_finding("F-accepted", "accepted", "supplier_security")],
    )

    bridge_exit = main(
        ["evidence", "from-reviewed-report", "--input", str(report_path), "--out", str(store_path)]
    )
    questionnaire_exit = main(
        [
            "questionnaire",
            "--questions",
            str(QUESTIONNAIRE_CSV),
            "--evidence-store",
            str(store_path),
            "--out",
            str(questionnaire_dir),
        ]
    )

    questionnaire_report = _read_json(questionnaire_dir / QUESTIONNAIRE_JSON_NAME)
    items = cast(list[dict[str, object]], questionnaire_report["items"])
    ready_items = [item for item in items if item["answer_status"] == "draft_ready"]

    assert bridge_exit == 0
    assert questionnaire_exit == 0
    assert ready_items
    assert str(ready_items[0]["draft_answer"]).startswith("Evidence refs E-RF-")


def test_reviewed_report_to_supplier_risk_e2e_workflow(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    first_store_path = tmp_path / "evidence_store_a.json"
    second_store_path = tmp_path / "evidence_store_b.json"
    questionnaire_dir = tmp_path / "questionnaire"
    reviewed_questionnaire_dir = tmp_path / "reviewed-questionnaire"
    first_risk_dir = tmp_path / "risk-a"
    second_risk_dir = tmp_path / "risk-b"

    first_bridge_exit = main(
        [
            "evidence",
            "from-reviewed-report",
            "--input",
            str(REVIEWED_REPORT_E2E),
            "--out",
            str(first_store_path),
        ]
    )
    second_bridge_exit = main(
        [
            "evidence",
            "from-reviewed-report",
            "--input",
            str(REVIEWED_REPORT_E2E),
            "--out",
            str(second_store_path),
        ]
    )
    questionnaire_exit = main(
        [
            "questionnaire",
            "--questions",
            str(QUESTIONNAIRE_E2E_CSV),
            "--evidence-store",
            str(first_store_path),
            "--out",
            str(questionnaire_dir),
        ]
    )

    bundle = load_control_catalog_bundle()
    first_store = load_evidence_store(first_store_path, catalog_bundle=bundle)
    second_store = load_evidence_store(second_store_path, catalog_bundle=bundle)
    first_records = first_store.evidence
    questionnaire_report = _read_json(questionnaire_dir / QUESTIONNAIRE_JSON_NAME)
    questionnaire_items = cast(list[dict[str, object]], questionnaire_report["items"])
    headers, review_rows = _read_review_rows(questionnaire_dir / REVIEW_CSV_NAME)
    for index, row in enumerate(review_rows):
        row["review_status"] = (
            "accepted"
            if row["status"] == "draft_ready" and index == 0
            else "reviewed"
            if row["status"] == "draft_ready"
            else "needs_evidence"
        )
    _write_review_rows(questionnaire_dir / REVIEW_CSV_NAME, headers, review_rows)

    review_exit = main(
        [
            "review-apply",
            "--report",
            str(questionnaire_dir / QUESTIONNAIRE_JSON_NAME),
            "--review-csv",
            str(questionnaire_dir / REVIEW_CSV_NAME),
            "--out",
            str(reviewed_questionnaire_dir),
            "--strict",
        ]
    )
    first_risk_exit = main(
        [
            "supplier-risk",
            "--profile",
            str(SUPPLIER_PROFILE),
            "--questionnaire-report",
            str(reviewed_questionnaire_dir / REVIEWED_REPORT_JSON_NAME),
            "--findings-report",
            str(REVIEWED_REPORT_E2E),
            "--out",
            str(first_risk_dir),
        ]
    )
    second_risk_exit = main(
        [
            "supplier-risk",
            "--profile",
            str(SUPPLIER_PROFILE),
            "--questionnaire-report",
            str(reviewed_questionnaire_dir / REVIEWED_REPORT_JSON_NAME),
            "--findings-report",
            str(REVIEWED_REPORT_E2E),
            "--out",
            str(second_risk_dir),
        ]
    )

    first_risk = _read_json(first_risk_dir / SUPPLIER_RISK_JSON_NAME)
    second_risk = _read_json(second_risk_dir / SUPPLIER_RISK_JSON_NAME)
    reviewed_questionnaire = _read_json(reviewed_questionnaire_dir / REVIEWED_REPORT_JSON_NAME)
    review_summary = _read_json(reviewed_questionnaire_dir / REVIEW_SUMMARY_JSON_NAME)
    reviewed_documents = cast(list[dict[str, object]], reviewed_questionnaire["per_document"])
    reviewed_items = cast(list[dict[str, object]], reviewed_documents[0]["evidence"])
    reviewed_status_by_id = {
        str(item["finding_id"]): str(item["review_status"]) for item in reviewed_items
    }
    review_status_counts = cast(dict[str, int], review_summary["status_counts"])
    output_text = "\n".join(
        (
            first_store_path.read_text(encoding="utf-8"),
            (questionnaire_dir / QUESTIONNAIRE_JSON_NAME).read_text(encoding="utf-8"),
            (reviewed_questionnaire_dir / REVIEWED_REPORT_JSON_NAME).read_text(encoding="utf-8"),
            (first_risk_dir / SUPPLIER_RISK_JSON_NAME).read_text(encoding="utf-8"),
        )
    )

    assert first_bridge_exit == 0
    assert second_bridge_exit == 0
    assert questionnaire_exit == 0
    assert review_exit == 0
    assert first_risk_exit == 0
    assert second_risk_exit == 0
    assert len(first_records) == 2
    assert {record.source_finding_id for record in first_records} == {
        "F-E2E-SUPPLIER",
        "F-E2E-INCIDENT",
    }
    assert [record.evidence_id for record in first_records] == [
        record.evidence_id for record in second_store.evidence
    ]
    assert [record.sha256 for record in first_records] == [
        record.sha256 for record in second_store.evidence
    ]
    assert headers == list(REVIEW_CSV_COLUMNS)
    ready_items = [item for item in questionnaire_items if item["answer_status"] == "draft_ready"]
    blocked_items = [
        item for item in questionnaire_items if item["answer_status"] == "needs_evidence"
    ]
    assert len(ready_items) == 2
    assert len(blocked_items) == 1
    for item in ready_items:
        assert item["evidence_refs"]
        assert str(cast(str, item["draft_answer"])).startswith("Evidence refs E-RF-")
    for item in blocked_items:
        assert item["evidence_refs"] == []
        assert item["draft_answer"] == ""
    assert review_status_counts["accepted"] == 1
    assert review_status_counts["reviewed"] == 1
    assert review_status_counts["needs_evidence"] == 1
    for row in review_rows:
        assert reviewed_status_by_id[row["finding_id"]] == row["review_status"]
    assert first_risk["risk_score"] == second_risk["risk_score"]
    assert first_risk["score_components"] == second_risk["score_components"]
    assert "RAW_SNIPPET_SHOULD_NOT_EXPORT" not in output_text
    assert "RAW_NOTE_SHOULD_NOT_EXPORT" not in output_text
    assert "C:/Users/Example" not in output_text
    assert "debug.log" not in output_text
