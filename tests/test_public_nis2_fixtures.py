"""Tests for the public synthetic NIS2 fixture corpus."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from aethelgard.triage import run_triage

FIXTURE_DIR = Path(__file__).resolve().parent / "fixtures" / "public_nis2"
LABELS_PATH = FIXTURE_DIR / "golden_labels.json"


def test_public_fixture_count_and_labels_match() -> None:
    fixture_files = sorted(path.name for path in FIXTURE_DIR.glob("*.md"))
    labels = json.loads(LABELS_PATH.read_text(encoding="utf-8"))
    labeled_files = sorted(document["file"] for document in labels["documents"])

    assert len(fixture_files) == 17
    assert fixture_files == labeled_files


def test_golden_labels_have_required_fields() -> None:
    labels = json.loads(LABELS_PATH.read_text(encoding="utf-8"))
    required_fields = {
        "file",
        "expected_categories",
        "expected_evidence_min",
        "expected_gaps",
        "must_include_terms",
        "must_not_include_categories",
    }

    for document in labels["documents"]:
        assert required_fields.issubset(document)
        assert (FIXTURE_DIR / document["file"]).is_file()


def test_all_public_fixtures_parse_without_errors() -> None:
    result = run_triage(FIXTURE_DIR)
    report = result["report"]

    assert report["document_count"] == 17
    assert report["parsed_count"] == 17
    assert report["failed_count"] == 0


def test_positive_and_gap_baseline_behavior() -> None:
    result = run_triage(FIXTURE_DIR)
    by_file = {document["file"]: document for document in result["report"]["per_document"]}

    assert "risk_management" in by_file["risk_management_policy_positive.md"]["strong_categories"]
    assert (
        "incident_reporting"
        in by_file["incident_response_policy_positive.md"]["strong_categories"]
    )
    assert by_file["misleading_security_marketing.md"]["strong_evidence_count"] == 0
    assert by_file["risk_management_policy_gap.md"]["strong_evidence_count"] == 0
    assert by_file["risk_management_policy_gap.md"]["gap_warnings"]


def test_public_fixture_safety_script_passes() -> None:
    command = [sys.executable, "scripts/check_public_fixtures.py", str(FIXTURE_DIR)]
    completed = subprocess.run(command, cwd=FIXTURE_DIR.parents[2], check=False, text=True)

    assert completed.returncode == 0
