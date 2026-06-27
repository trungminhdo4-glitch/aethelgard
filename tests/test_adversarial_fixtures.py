"""Adversarial fixture tests for false-positive control."""

from __future__ import annotations

from pathlib import Path

from aethelgard.triage import run_triage

FIXTURE_DIR = Path(__file__).resolve().parent / "fixtures" / "public_nis2"

ADVERSARIAL_FIXTURES = (
    "security_marketing_false_positive.md",
    "empty_policy_template.md",
    "outdated_policy_no_owner.md",
    "incident_policy_without_reporting_time.md",
    "supplier_policy_without_controls.md",
)


def test_adversarial_fixtures_parse_without_crashes() -> None:
    result = run_triage(FIXTURE_DIR)
    by_file = {document["file"]: document for document in result["report"]["per_document"]}

    for file_name in ADVERSARIAL_FIXTURES:
        assert file_name in by_file
        assert by_file[file_name]["evidence_count"] >= 1


def test_adversarial_fixtures_do_not_emit_strong_evidence() -> None:
    result = run_triage(FIXTURE_DIR)
    by_file = {document["file"]: document for document in result["report"]["per_document"]}

    for file_name in ADVERSARIAL_FIXTURES:
        assert by_file[file_name]["strong_evidence_count"] == 0
        assert by_file[file_name]["gap_warnings"]
