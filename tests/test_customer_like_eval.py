"""Tests for the customer-like synthetic pilot fixture pack."""

from __future__ import annotations

import json
from pathlib import Path

from aethelgard.triage import run_eval, run_triage

FIXTURE_DIR = Path(__file__).resolve().parent / "fixtures" / "customer_like_nis2"
LABELS_PATH = FIXTURE_DIR / "golden_labels.json"


def test_customer_like_fixture_count_and_labels_match() -> None:
    fixture_files = sorted(path.name for path in FIXTURE_DIR.glob("*.md"))
    labels = json.loads(LABELS_PATH.read_text(encoding="utf-8"))
    labeled_files = sorted(document["file"] for document in labels["documents"])

    assert len(fixture_files) == 8
    assert fixture_files == labeled_files


def test_customer_like_eval_passes_with_expected_warnings() -> None:
    report = run_eval(FIXTURE_DIR, LABELS_PATH)

    assert report["status"] == "PILOT_READY"
    assert report["documents_total"] == 8
    assert report["documents_passed"] == 8
    assert report["calibration"]["warning_count"] > 0
    assert report["calibration"]["strong_evidence_count"] > 0
    assert report["calibration"]["missed_gaps"] == []


def test_customer_like_pack_keeps_marketing_and_partial_incident_weak() -> None:
    result = run_triage(FIXTURE_DIR)
    by_file = {document["file"]: document for document in result["report"]["per_document"]}

    assert by_file["08_management_summary_marketing_noise.md"]["strong_evidence_count"] == 0
    assert by_file["02_incident_response_partial.md"]["strong_evidence_count"] == 0
    assert by_file["02_incident_response_partial.md"]["gap_warnings"]
    assert "supplier_security" not in by_file["07_business_continuity_tabletop.md"][
        "strong_categories"
    ]
