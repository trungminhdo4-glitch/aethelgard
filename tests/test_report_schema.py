"""Schema-level tests for triage and evaluation reports."""

from __future__ import annotations

from pathlib import Path

from aethelgard.triage import run_eval, run_triage

FIXTURE_DIR = Path(__file__).resolve().parent / "fixtures" / "public_nis2"
LABELS_PATH = FIXTURE_DIR / "golden_labels.json"


def test_triage_report_required_fields() -> None:
    result = run_triage(FIXTURE_DIR)
    report = result["report"]
    required = {
        "run_id",
        "timestamp",
        "input_path",
        "document_count",
        "parsed_count",
        "failed_count",
        "evidence_count",
        "categories",
        "per_document",
        "warnings",
        "errors",
        "tool_version",
    }

    assert required.issubset(report)
    assert isinstance(report["per_document"], list)
    assert report["per_document"]


def test_triage_per_document_required_fields() -> None:
    result = run_triage(FIXTURE_DIR)
    document = result["report"]["per_document"][0]
    required = {
        "file",
        "evidence_count",
        "strong_evidence_count",
        "categories",
        "strong_categories",
        "gap_warnings",
        "warnings",
        "evidence",
    }

    assert required.issubset(document)


def test_eval_report_required_fields() -> None:
    report = run_eval(FIXTURE_DIR, LABELS_PATH)
    required = {
        "run_id",
        "timestamp",
        "fixtures_path",
        "labels_path",
        "status",
        "documents_total",
        "documents_passed",
        "documents_failed",
        "category_hits",
        "missing_expected_categories",
        "unexpected_categories",
        "evidence_min_pass_rate",
        "false_positive_cases",
        "false_negative_cases",
        "parser_failures",
        "thresholds",
        "threshold_status",
        "per_document",
    }

    assert required.issubset(report)
    assert report["status"] == "PILOT_READY"
