"""Tests for bridging reviewed findings into evidence-store records."""

from __future__ import annotations

import json
from pathlib import Path
from typing import cast

import pytest

from aethelgard.cli import C_SCRM_ERROR_EXIT_CODE, main
from aethelgard.control_catalog import load_control_catalog_bundle
from aethelgard.evidence_store import load_evidence_store
from aethelgard.questionnaire import QUESTIONNAIRE_JSON_NAME

FIXTURE_ROOT = Path(__file__).resolve().parent / "fixtures"
SCRM_FIXTURES = FIXTURE_ROOT / "scrm"
QUESTIONNAIRE_CSV = SCRM_FIXTURES / "questionnaire.csv"


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
