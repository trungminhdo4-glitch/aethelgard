"""Tests for metadata-only trust bundle preview export."""

from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import cast

import pytest

from aethelgard.cli import C_SCRM_ERROR_EXIT_CODE, main
from aethelgard.questionnaire import QUESTIONNAIRE_JSON_NAME
from aethelgard.review import REVIEW_CSV_NAME, REVIEWED_REPORT_JSON_NAME
from aethelgard.supplier_risk import SUPPLIER_RISK_JSON_NAME
from aethelgard.trust_bundle import (
    TRUST_BUNDLE_EVIDENCE_INDEX_NAME,
    TRUST_BUNDLE_FILES,
    TRUST_BUNDLE_MANIFEST_NAME,
    TRUST_BUNDLE_QUESTIONNAIRE_SUMMARY_NAME,
    TRUST_BUNDLE_README_NAME,
    TRUST_BUNDLE_STATUSES,
    TRUST_BUNDLE_SUPPLIER_RISK_SUMMARY_NAME,
)

FIXTURE_ROOT = Path(__file__).resolve().parent / "fixtures"
SCRM_FIXTURES = FIXTURE_ROOT / "scrm"
QUESTIONNAIRE_E2E_CSV = SCRM_FIXTURES / "questionnaire_e2e.csv"
REVIEWED_REPORT_E2E = SCRM_FIXTURES / "reviewed_report_e2e.json"
SUPPLIER_PROFILE = SCRM_FIXTURES / "supplier_profile.json"


def _read_json(path: Path) -> dict[str, object]:
    return cast(dict[str, object], json.loads(path.read_text(encoding="utf-8")))


def _write_json(path: Path, payload: dict[str, object]) -> None:
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


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


def _write_bundle_inputs(tmp_path: Path) -> tuple[Path, Path, Path]:
    evidence_store = tmp_path / "evidence_store.json"
    supplier_risk = tmp_path / "supplier_risk.json"
    questionnaire = tmp_path / "reviewed_answers.json"
    _write_json(
        evidence_store,
        {
            "schema_version": "1.0",
            "evidence": [
                {
                    "claims": ["RAW_CLAIM_SHOULD_NOT_EXPORT"],
                    "evidence_id": "E-approved",
                    "mapped_controls": ["NIS2-SCRM-01"],
                    "review_required": False,
                    "review_status": "accepted",
                    "sha256": "d" * 64,
                    "source_finding_id": "F-approved",
                    "source_path": "reviewed_report.json",
                    "source_report": "reviewed_report.json",
                    "source_type": "reviewed_report",
                    "type": "finding",
                    "validity": "current",
                },
                {
                    "claims": ["RAW_REVIEW_CLAIM_SHOULD_NOT_EXPORT"],
                    "evidence_id": "E-review",
                    "mapped_controls": ["NIS2-SCRM-02"],
                    "review_required": True,
                    "sha256": "e" * 64,
                    "source_path": "synthetic_policy.md",
                    "type": "document",
                    "validity": "current",
                },
                {
                    "claims": ["RAW_REVIEWED_CLAIM_SHOULD_NOT_EXPORT"],
                    "evidence_id": "E-reviewed",
                    "mapped_controls": ["NIS2-SCRM-03"],
                    "review_required": False,
                    "review_status": "reviewed",
                    "sha256": "f" * 64,
                    "source_path": "reviewed_report.json",
                    "source_report": "reviewed_report.json",
                    "source_type": "reviewed_report",
                    "type": "finding",
                    "validity": "current",
                },
                {
                    "claims": ["RAW_NOT_ASSESSED_CLAIM_SHOULD_NOT_EXPORT"],
                    "evidence_id": "E-not-assessed",
                    "mapped_controls": ["NIS2-SCRM-04"],
                    "review_required": False,
                    "review_status": "false_positive",
                    "sha256": "1" * 64,
                    "source_path": "reviewed_report.json",
                    "source_report": "reviewed_report.json",
                    "source_type": "reviewed_report",
                    "type": "finding",
                    "validity": "current",
                },
                {
                    "claims": ["RAW_REJECTED_CLAIM_SHOULD_NOT_EXPORT"],
                    "evidence_id": "E-rejected",
                    "mapped_controls": ["NIS2-SCRM-04"],
                    "review_required": False,
                    "review_status": "rejected",
                    "sha256": "3" * 64,
                    "source_path": "reviewed_report.json",
                    "source_report": "reviewed_report.json",
                    "source_type": "reviewed_report",
                    "type": "finding",
                    "validity": "current",
                },
                {
                    "claims": ["RAW_MISSING_REVIEW_CLAIM_SHOULD_NOT_EXPORT"],
                    "evidence_id": "E-missing-review",
                    "mapped_controls": ["NIS2-SCRM-05"],
                    "review_required": False,
                    "sha256": "2" * 64,
                    "source_path": "synthetic_no_review_policy.md",
                    "type": "document",
                    "validity": "current",
                },
            ],
        },
    )
    _write_json(
        supplier_risk,
        {
            "disclaimer": "Deterministic local prioritization only. Not legal advice.",
            "evidence_gap_count": 1,
            "open_findings": 1,
            "questionnaire_status_counts": {
                "draft_ready": 1,
                "draft_review_required": 1,
                "needs_evidence": 1,
            },
            "risk_level": "medium",
            "risk_score": 68,
            "score_components": {
                "criticality": 60,
                "evidence_gaps": 8,
                "open_findings": 0,
                "questionnaire_review": 0,
            },
            "supplier": {
                "criticality": "high",
                "name": "Synthetic Supplier Name Should Not Export",
                "services": ["managed hosting"],
                "supplier_id": "SUP-SYNTH-001",
            },
        },
    )
    _write_json(
        questionnaire,
        {
            "items": [
                {
                    "answer_status": "draft_ready",
                    "draft_answer": "compliant wording must not export",
                    "evidence_refs": ["E-approved"],
                    "finding_id": "Q-approved",
                    "mapped_controls": ["NIS2-SCRM-01"],
                    "question": "RAW_QUESTION_SHOULD_NOT_EXPORT",
                },
                {
                    "answer_status": "draft_ready",
                    "draft_answer": "RAW_DRAFT_SHOULD_NOT_EXPORT",
                    "evidence_refs": ["E-review"],
                    "finding_id": "Q-open",
                    "mapped_controls": ["NIS2-SCRM-02"],
                    "question": "RAW_OPEN_QUESTION_SHOULD_NOT_EXPORT",
                },
                {
                    "answer_status": "needs_evidence",
                    "draft_answer": "",
                    "evidence_refs": [],
                    "finding_id": "Q-gap",
                    "mapped_controls": ["NIS2-SCRM-05"],
                    "question": "RAW_GAP_QUESTION_SHOULD_NOT_EXPORT",
                },
                {
                    "answer_status": "draft_ready",
                    "draft_answer": "RAW_REVIEWED_DRAFT_SHOULD_NOT_EXPORT",
                    "evidence_refs": ["E-reviewed"],
                    "finding_id": "Q-reviewed",
                    "mapped_controls": ["NIS2-SCRM-03"],
                    "question": "RAW_REVIEWED_QUESTION_SHOULD_NOT_EXPORT",
                },
                {
                    "answer_status": "draft_ready",
                    "draft_answer": "RAW_NOT_ASSESSED_DRAFT_SHOULD_NOT_EXPORT",
                    "evidence_refs": ["E-not-assessed"],
                    "finding_id": "Q-not-assessed",
                    "mapped_controls": ["NIS2-SCRM-04"],
                    "question": "RAW_NOT_ASSESSED_QUESTION_SHOULD_NOT_EXPORT",
                },
                {
                    "answer_status": "draft_ready",
                    "draft_answer": "RAW_REJECTED_DRAFT_SHOULD_NOT_EXPORT",
                    "evidence_refs": ["E-rejected"],
                    "finding_id": "Q-rejected",
                    "mapped_controls": ["NIS2-SCRM-04"],
                    "question": "RAW_REJECTED_QUESTION_SHOULD_NOT_EXPORT",
                },
            ],
            "per_document": [
                {
                    "evidence": [
                        {"finding_id": "Q-approved", "review_status": "accepted"},
                        {"finding_id": "Q-open", "review_status": "open"},
                        {"finding_id": "Q-gap", "review_status": "needs_evidence"},
                        {"finding_id": "Q-reviewed", "review_status": "reviewed"},
                        {"finding_id": "Q-not-assessed", "review_status": "false_positive"},
                        {"finding_id": "Q-rejected", "review_status": "rejected"},
                    ],
                    "file": "questions.csv",
                }
            ],
        },
    )
    return evidence_store, supplier_risk, questionnaire


def test_trust_bundle_builds_expected_metadata_only_files(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    evidence_store, supplier_risk, questionnaire = _write_bundle_inputs(tmp_path)
    first_out = tmp_path / "bundle-a"
    second_out = tmp_path / "bundle-b"

    first_exit = main(
        [
            "trust-bundle",
            "build",
            "--evidence",
            str(evidence_store),
            "--supplier-risk",
            str(supplier_risk),
            "--questionnaire",
            str(questionnaire),
            "--out",
            str(first_out),
        ]
    )
    second_exit = main(
        [
            "trust-bundle",
            "build",
            "--evidence",
            str(evidence_store),
            "--supplier-risk",
            str(supplier_risk),
            "--questionnaire",
            str(questionnaire),
            "--out",
            str(second_out),
        ]
    )

    manifest = _read_json(first_out / TRUST_BUNDLE_MANIFEST_NAME)
    second_manifest = _read_json(second_out / TRUST_BUNDLE_MANIFEST_NAME)
    evidence_index = _read_json(first_out / TRUST_BUNDLE_EVIDENCE_INDEX_NAME)
    questionnaire_summary = _read_json(first_out / TRUST_BUNDLE_QUESTIONNAIRE_SUMMARY_NAME)
    supplier_summary = _read_json(first_out / TRUST_BUNDLE_SUPPLIER_RISK_SUMMARY_NAME)
    bundle_text = "\n".join(
        path.read_text(encoding="utf-8") for path in first_out.iterdir() if path.is_file()
    )

    assert first_exit == 0
    assert second_exit == 0
    assert sorted(path.name for path in first_out.iterdir()) == sorted(TRUST_BUNDLE_FILES)
    assert manifest == second_manifest
    assert manifest["bundle_schema_version"] == "1.0"
    assert manifest["bundle_type"] == "trust_bundle_preview"
    assert manifest["included_sections"] == [
        "evidence_index",
        "questionnaire_summary",
        "supplier_risk_summary",
        "readme",
    ]
    source_hashes = cast(dict[str, str], manifest["source_hashes"])
    assert sorted(source_hashes) == ["evidence_store", "questionnaire", "supplier_risk"]
    assert all(len(value) == 64 for value in source_hashes.values())
    assert evidence_index["evidence_count"] == 6
    assert supplier_summary["risk_score"] == 68
    assert "name" not in cast(dict[str, object], supplier_summary["supplier"])
    evidence_items = cast(list[dict[str, object]], evidence_index["items"])
    evidence_status_by_id = {
        str(item["evidence_id"]): str(item["status"]) for item in evidence_items
    }
    items = cast(list[dict[str, object]], questionnaire_summary["items"])
    statuses = {str(item["status"]) for item in items}
    assert statuses == {
        "accepted",
        "reviewed",
        "rejected",
        "needs_review",
        "needs_evidence",
        "not_assessed",
    }
    assert statuses.issubset(TRUST_BUNDLE_STATUSES)
    assert evidence_status_by_id["E-reviewed"] == "reviewed"
    assert evidence_status_by_id["E-not-assessed"] == "not_assessed"
    assert evidence_status_by_id["E-rejected"] == "rejected"
    assert evidence_status_by_id["E-missing-review"] == "needs_review"
    for unsafe in (
        "RAW_CLAIM_SHOULD_NOT_EXPORT",
        "RAW_REVIEW_CLAIM_SHOULD_NOT_EXPORT",
        "RAW_REVIEWED_CLAIM_SHOULD_NOT_EXPORT",
        "RAW_NOT_ASSESSED_CLAIM_SHOULD_NOT_EXPORT",
        "RAW_REJECTED_CLAIM_SHOULD_NOT_EXPORT",
        "RAW_MISSING_REVIEW_CLAIM_SHOULD_NOT_EXPORT",
        "RAW_QUESTION_SHOULD_NOT_EXPORT",
        "RAW_OPEN_QUESTION_SHOULD_NOT_EXPORT",
        "RAW_GAP_QUESTION_SHOULD_NOT_EXPORT",
        "RAW_REVIEWED_QUESTION_SHOULD_NOT_EXPORT",
        "RAW_NOT_ASSESSED_QUESTION_SHOULD_NOT_EXPORT",
        "RAW_REJECTED_QUESTION_SHOULD_NOT_EXPORT",
        "RAW_DRAFT_SHOULD_NOT_EXPORT",
        "RAW_REVIEWED_DRAFT_SHOULD_NOT_EXPORT",
        "RAW_NOT_ASSESSED_DRAFT_SHOULD_NOT_EXPORT",
        "RAW_REJECTED_DRAFT_SHOULD_NOT_EXPORT",
        "compliant",
        "certified",
        "audit_passed",
        "NIS2 compliant",
        "Synthetic Supplier Name Should Not Export",
        "source_path",
        "claims",
    ):
        assert unsafe not in bundle_text
    assert (first_out / TRUST_BUNDLE_README_NAME).is_file()


def test_trust_bundle_cli_e2e_flow_is_deterministic_and_metadata_only(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    evidence_store = tmp_path / "evidence_store.json"
    questionnaire_dir = tmp_path / "questionnaire"
    reviewed_questionnaire_dir = tmp_path / "reviewed-questionnaire"
    risk_dir = tmp_path / "risk"
    first_bundle = tmp_path / "bundle-a"
    second_bundle = tmp_path / "bundle-b"

    bridge_exit = main(
        [
            "evidence",
            "from-reviewed-report",
            "--input",
            str(REVIEWED_REPORT_E2E),
            "--out",
            str(evidence_store),
        ]
    )
    questionnaire_exit = main(
        [
            "questionnaire",
            "--questions",
            str(QUESTIONNAIRE_E2E_CSV),
            "--evidence-store",
            str(evidence_store),
            "--out",
            str(questionnaire_dir),
        ]
    )

    headers, review_rows = _read_review_rows(questionnaire_dir / REVIEW_CSV_NAME)
    ready_seen = 0
    for row in review_rows:
        if row["status"] == "needs_evidence":
            row["review_status"] = "needs_evidence"
        elif ready_seen == 0:
            row["review_status"] = "accepted"
            ready_seen += 1
        else:
            row["review_status"] = ""
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
    risk_exit = main(
        [
            "supplier-risk",
            "--profile",
            str(SUPPLIER_PROFILE),
            "--questionnaire-report",
            str(reviewed_questionnaire_dir / REVIEWED_REPORT_JSON_NAME),
            "--findings-report",
            str(REVIEWED_REPORT_E2E),
            "--out",
            str(risk_dir),
        ]
    )

    first_bundle.mkdir()
    for bundle_file in TRUST_BUNDLE_FILES:
        (first_bundle / bundle_file).write_text("STALE_SHOULD_BE_OVERWRITTEN\n", encoding="utf-8")

    first_bundle_exit = main(
        [
            "trust-bundle",
            "build",
            "--evidence",
            str(evidence_store),
            "--supplier-risk",
            str(risk_dir / SUPPLIER_RISK_JSON_NAME),
            "--questionnaire",
            str(reviewed_questionnaire_dir / REVIEWED_REPORT_JSON_NAME),
            "--out",
            str(first_bundle),
        ]
    )
    second_bundle_exit = main(
        [
            "trust-bundle",
            "build",
            "--evidence",
            str(evidence_store),
            "--supplier-risk",
            str(risk_dir / SUPPLIER_RISK_JSON_NAME),
            "--questionnaire",
            str(reviewed_questionnaire_dir / REVIEWED_REPORT_JSON_NAME),
            "--out",
            str(second_bundle),
        ]
    )

    first_files = {
        path.name: path.read_text(encoding="utf-8")
        for path in sorted(first_bundle.iterdir(), key=lambda item: item.name)
    }
    second_files = {
        path.name: path.read_text(encoding="utf-8")
        for path in sorted(second_bundle.iterdir(), key=lambda item: item.name)
    }
    manifest = _read_json(first_bundle / TRUST_BUNDLE_MANIFEST_NAME)
    questionnaire_summary = _read_json(first_bundle / TRUST_BUNDLE_QUESTIONNAIRE_SUMMARY_NAME)
    summary_items = cast(list[dict[str, object]], questionnaire_summary["items"])
    gap_items = [item for item in summary_items if item["evidence_refs"] == []]
    draft_review_items = [
        item for item in summary_items if item["evidence_refs"] and item["status"] == "needs_review"
    ]
    bundle_text = "\n".join(first_files.values())

    assert bridge_exit == 0
    assert questionnaire_exit == 0
    assert review_exit == 0
    assert risk_exit == 0
    assert first_bundle_exit == 0
    assert second_bundle_exit == 0
    assert first_files == second_files
    assert sorted(first_files) == sorted(TRUST_BUNDLE_FILES)
    assert manifest["bundle_schema_version"] == "1.0"
    assert "source_hashes" in manifest
    assert "included_sections" in manifest
    assert gap_items
    assert all(item["status"] == "needs_evidence" for item in gap_items)
    assert draft_review_items
    assert all(item["status"] not in {"accepted", "reviewed"} for item in draft_review_items)
    for unsafe in (
        "STALE_SHOULD_BE_OVERWRITTEN",
        "RAW_SNIPPET_SHOULD_NOT_EXPORT",
        "RAW_NOTE_SHOULD_NOT_EXPORT",
        "draft_answer",
        "source_citation",
        "C:/Users/Example",
        "debug.log",
        "compliant",
        "certified",
        "audit_passed",
        "NIS2 compliant",
    ):
        assert unsafe not in bundle_text


def test_trust_bundle_rejects_existing_output_with_unexpected_files(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    evidence_store, supplier_risk, questionnaire = _write_bundle_inputs(tmp_path)
    out_dir = tmp_path / "bundle"
    out_dir.mkdir()
    stale_file = out_dir / "raw_report.json"
    stale_file.write_text("RAW_STALE_SHOULD_NOT_EXPORT\n", encoding="utf-8")

    exit_code = main(
        [
            "trust-bundle",
            "build",
            "--evidence",
            str(evidence_store),
            "--supplier-risk",
            str(supplier_risk),
            "--questionnaire",
            str(questionnaire),
            "--out",
            str(out_dir),
        ]
    )

    assert exit_code == C_SCRM_ERROR_EXIT_CODE
    assert stale_file.is_file()
    assert not (out_dir / TRUST_BUNDLE_MANIFEST_NAME).exists()


def test_trust_bundle_rejects_source_file_inside_output_directory(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    evidence_store, supplier_risk, questionnaire = _write_bundle_inputs(tmp_path)
    out_dir = tmp_path / "bundle"
    out_dir.mkdir()
    questionnaire_alias = out_dir / TRUST_BUNDLE_QUESTIONNAIRE_SUMMARY_NAME
    questionnaire_alias.write_text(questionnaire.read_text(encoding="utf-8"), encoding="utf-8")

    exit_code = main(
        [
            "trust-bundle",
            "build",
            "--evidence",
            str(evidence_store),
            "--supplier-risk",
            str(supplier_risk),
            "--questionnaire",
            str(questionnaire_alias),
            "--out",
            str(out_dir),
        ]
    )

    assert exit_code == C_SCRM_ERROR_EXIT_CODE
    assert questionnaire_alias.read_text(encoding="utf-8") == questionnaire.read_text(
        encoding="utf-8"
    )
    assert not (out_dir / TRUST_BUNDLE_MANIFEST_NAME).exists()


@pytest.mark.parametrize(
    "missing_input",
    ["evidence", "supplier-risk", "questionnaire"],
)
def test_trust_bundle_missing_input_fails_without_output(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    missing_input: str,
) -> None:
    monkeypatch.chdir(tmp_path)
    evidence_store, supplier_risk, questionnaire = _write_bundle_inputs(tmp_path)
    out_dir = tmp_path / "bundle"
    input_paths = {
        "evidence": evidence_store,
        "supplier-risk": supplier_risk,
        "questionnaire": questionnaire,
    }
    input_paths[missing_input] = tmp_path / ("missing_%s.json" % missing_input)

    exit_code = main(
        [
            "trust-bundle",
            "build",
            "--evidence",
            str(input_paths["evidence"]),
            "--supplier-risk",
            str(input_paths["supplier-risk"]),
            "--questionnaire",
            str(input_paths["questionnaire"]),
            "--out",
            str(out_dir),
        ]
    )

    assert exit_code == C_SCRM_ERROR_EXIT_CODE
    assert not out_dir.exists()
