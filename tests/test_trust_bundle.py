"""Tests for metadata-only trust bundle preview export."""

from __future__ import annotations

import json
from pathlib import Path
from typing import cast

import pytest

from aethelgard.cli import C_SCRM_ERROR_EXIT_CODE, main
from aethelgard.trust_bundle import (
    TRUST_BUNDLE_EVIDENCE_INDEX_NAME,
    TRUST_BUNDLE_FILES,
    TRUST_BUNDLE_MANIFEST_NAME,
    TRUST_BUNDLE_QUESTIONNAIRE_SUMMARY_NAME,
    TRUST_BUNDLE_README_NAME,
    TRUST_BUNDLE_STATUSES,
    TRUST_BUNDLE_SUPPLIER_RISK_SUMMARY_NAME,
)


def _read_json(path: Path) -> dict[str, object]:
    return cast(dict[str, object], json.loads(path.read_text(encoding="utf-8")))


def _write_json(path: Path, payload: dict[str, object]) -> None:
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


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
            ],
            "per_document": [
                {
                    "evidence": [
                        {"finding_id": "Q-approved", "review_status": "accepted"},
                        {"finding_id": "Q-open", "review_status": "open"},
                        {"finding_id": "Q-gap", "review_status": "needs_evidence"},
                        {"finding_id": "Q-reviewed", "review_status": "reviewed"},
                        {"finding_id": "Q-not-assessed", "review_status": "false_positive"},
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
    assert manifest["bundle_type"] == "trust_bundle_preview"
    assert evidence_index["evidence_count"] == 5
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
        "needs_review",
        "needs_evidence",
        "not_assessed",
    }
    assert statuses.issubset(TRUST_BUNDLE_STATUSES)
    assert evidence_status_by_id["E-reviewed"] == "reviewed"
    assert evidence_status_by_id["E-not-assessed"] == "not_assessed"
    assert evidence_status_by_id["E-missing-review"] == "needs_review"
    for unsafe in (
        "RAW_CLAIM_SHOULD_NOT_EXPORT",
        "RAW_REVIEW_CLAIM_SHOULD_NOT_EXPORT",
        "RAW_REVIEWED_CLAIM_SHOULD_NOT_EXPORT",
        "RAW_NOT_ASSESSED_CLAIM_SHOULD_NOT_EXPORT",
        "RAW_MISSING_REVIEW_CLAIM_SHOULD_NOT_EXPORT",
        "RAW_QUESTION_SHOULD_NOT_EXPORT",
        "RAW_OPEN_QUESTION_SHOULD_NOT_EXPORT",
        "RAW_GAP_QUESTION_SHOULD_NOT_EXPORT",
        "RAW_REVIEWED_QUESTION_SHOULD_NOT_EXPORT",
        "RAW_NOT_ASSESSED_QUESTION_SHOULD_NOT_EXPORT",
        "RAW_DRAFT_SHOULD_NOT_EXPORT",
        "RAW_REVIEWED_DRAFT_SHOULD_NOT_EXPORT",
        "RAW_NOT_ASSESSED_DRAFT_SHOULD_NOT_EXPORT",
        "compliant",
        "Synthetic Supplier Name Should Not Export",
        "source_path",
        "claims",
    ):
        assert unsafe not in bundle_text
    assert (first_out / TRUST_BUNDLE_README_NAME).is_file()


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
