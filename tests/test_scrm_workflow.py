"""Tests for the technical C-SCRM MVP workflow."""

from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import cast

import pytest

from aethelgard.cli import C_SCRM_ERROR_EXIT_CODE, REVIEW_CSV_COLUMNS, REVIEW_CSV_NAME, main
from aethelgard.control_catalog import (
    ControlCatalog,
    ControlCatalogBundle,
    ControlCatalogError,
    ControlDefinition,
    CrossFrameworkMap,
    load_control_catalog_bundle,
    validate_control_catalog_bundle,
)
from aethelgard.evidence_store import (
    EvidenceStoreError,
    build_file_evidence_record,
    load_evidence_store,
)
from aethelgard.questionnaire import QUESTIONNAIRE_JSON_NAME, QUESTIONNAIRE_MD_NAME
from aethelgard.supplier_risk import SUPPLIER_RISK_JSON_NAME, SUPPLIER_RISK_MD_NAME

FIXTURE_ROOT = Path(__file__).resolve().parent / "fixtures"
SCRM_FIXTURES = FIXTURE_ROOT / "scrm"
QUESTIONNAIRE_CSV = SCRM_FIXTURES / "questionnaire.csv"
EVIDENCE_STORE = SCRM_FIXTURES / "evidence_store.json"
EMPTY_EVIDENCE_STORE = SCRM_FIXTURES / "empty_evidence_store.json"
SUPPLIER_PROFILE = SCRM_FIXTURES / "supplier_profile.json"


def _read_json(path: Path) -> dict[str, object]:
    return cast(dict[str, object], json.loads(path.read_text(encoding="utf-8")))


def _read_review_rows(path: Path) -> tuple[list[str] | None, list[dict[str, str]]]:
    with path.open(encoding="utf-8", newline="") as csv_file:
        reader = csv.DictReader(csv_file)
        headers = list(reader.fieldnames) if reader.fieldnames is not None else None
        return headers, list(reader)


def _control_definition(
    control_id: str,
    *,
    maps_to: tuple[str, ...] = (),
) -> ControlDefinition:
    return ControlDefinition(
        control_id=control_id,
        framework="TEST",
        title="Supplier control",
        summary="Synthetic control used for validation tests.",
        required_evidence=("policy",),
        keywords=("supplier",),
        maps_to=maps_to,
    )


def _catalog_bundle(*controls: ControlDefinition) -> ControlCatalogBundle:
    return ControlCatalogBundle(
        catalogs=(
            ControlCatalog(
                catalog_id="test_catalog",
                title="Test catalog",
                version="2026-06-29",
                controls=controls,
            ),
        ),
        cross_framework_map=CrossFrameworkMap(
            map_id="test_map",
            version="2026-06-29",
            mappings=(),
        ),
    )


def test_control_catalog_ids_unique_and_cli_validates() -> None:
    bundle = load_control_catalog_bundle()
    control_ids = list(bundle.controls_by_id)

    exit_code = main(["validate-controls"])

    assert exit_code == 0
    assert len(control_ids) == len(set(control_ids))


def test_cross_framework_mappings_reference_existing_controls() -> None:
    bundle = load_control_catalog_bundle()
    known_controls = set(bundle.controls_by_id)

    for catalog in bundle.catalogs:
        for control in catalog.controls:
            assert set(control.maps_to).issubset(known_controls)
    for mapping in bundle.cross_framework_map.mappings:
        assert mapping.source_control_id in known_controls
        assert set(mapping.maps_to).issubset(known_controls)


def test_control_catalog_duplicate_control_ids_fail() -> None:
    duplicate = _control_definition("NIS2-SCRM-99")
    bundle = _catalog_bundle(duplicate, duplicate)

    with pytest.raises(ControlCatalogError, match="duplicate control_id"):
        validate_control_catalog_bundle(bundle)


def test_control_catalog_broken_control_refs_fail() -> None:
    bundle = _catalog_bundle(_control_definition("NIS2-SCRM-99", maps_to=("MISSING-01",)))

    with pytest.raises(ControlCatalogError, match="unknown control IDs"):
        validate_control_catalog_bundle(bundle)


def test_questionnaire_without_evidence_stays_needs_evidence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    out_dir = tmp_path / "questionnaire"

    exit_code = main(
        [
            "questionnaire",
            "--questions",
            str(QUESTIONNAIRE_CSV),
            "--evidence-store",
            str(EMPTY_EVIDENCE_STORE),
            "--out",
            str(out_dir),
        ]
    )

    report = _read_json(out_dir / QUESTIONNAIRE_JSON_NAME)
    items = cast(list[dict[str, object]], report["items"])
    headers, rows = _read_review_rows(out_dir / REVIEW_CSV_NAME)

    assert exit_code == 0
    assert headers == list(REVIEW_CSV_COLUMNS)
    assert rows
    assert all(item["answer_status"] == "needs_evidence" for item in items)
    assert all(item["draft_answer"] == "" for item in items)
    assert all(row["status"] == "needs_evidence" for row in rows)


def test_questionnaire_draft_answers_have_evidence_refs_or_are_blocked(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    out_dir = tmp_path / "questionnaire"

    exit_code = main(
        [
            "questionnaire",
            "--questions",
            str(QUESTIONNAIRE_CSV),
            "--evidence-store",
            str(EVIDENCE_STORE),
            "--out",
            str(out_dir),
        ]
    )

    report = _read_json(out_dir / QUESTIONNAIRE_JSON_NAME)
    items = cast(list[dict[str, object]], report["items"])

    assert exit_code == 0
    assert any(item["answer_status"] == "draft_ready" for item in items)
    for item in items:
        evidence_refs = cast(list[str], item["evidence_refs"])
        draft_answer = str(item["draft_answer"])
        if draft_answer:
            assert evidence_refs
            assert evidence_refs[0] in draft_answer
        else:
            assert item["answer_status"] == "needs_evidence"


def test_questionnaire_duplicate_question_ids_fail(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    questions = tmp_path / "questions.csv"
    questions.write_text(
        "question_id,question\n"
        "Q1,How do you review supplier security?\n"
        "Q1,How do you review incident escalation?\n",
        encoding="utf-8",
    )
    out_dir = tmp_path / "questionnaire"

    exit_code = main(
        [
            "questionnaire",
            "--questions",
            str(questions),
            "--evidence-store",
            str(EVIDENCE_STORE),
            "--out",
            str(out_dir),
        ]
    )

    assert exit_code == C_SCRM_ERROR_EXIT_CODE
    assert not out_dir.exists()


def test_questionnaire_reports_mask_secret_and_pii_patterns(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    sensitive_email = "reviewer" + "@" + "example.test"
    sensitive_phone = "030" + " 12345678"
    questions = tmp_path / "questions.csv"
    questions.write_text(
        "question_id,question\n"
        "Q1,Does supplier %s publish contact number %s?\n"
        % (sensitive_email, sensitive_phone),
        encoding="utf-8",
    )
    evidence_store = tmp_path / "evidence_store.json"
    synthetic_hash = "b" * 64
    evidence_store.write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "evidence": [
                        {
                            "evidence_id": "E-redacted",
                            "type": "document",
                            "source_path": "synthetic.md",
                        "sha256": synthetic_hash,
                        "mapped_controls": ["NIS2-SCRM-01"],
                        "claims": [
                            "Contact %s by phone %s." % (sensitive_email, sensitive_phone)
                        ],
                        "validity": "current",
                        "review_required": False,
                    }
                ],
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    out_dir = tmp_path / "questionnaire"

    exit_code = main(
        [
            "questionnaire",
            "--questions",
            str(questions),
            "--evidence-store",
            str(evidence_store),
            "--out",
            str(out_dir),
        ]
    )

    report_text = (out_dir / QUESTIONNAIRE_JSON_NAME).read_text(encoding="utf-8")
    markdown = (out_dir / QUESTIONNAIRE_MD_NAME).read_text(encoding="utf-8")
    review_csv = (out_dir / REVIEW_CSV_NAME).read_text(encoding="utf-8")

    assert exit_code == 0
    for output in (report_text, markdown, review_csv):
        normalized_output = output.replace("\\", "")
        assert sensitive_email not in output
        assert sensitive_phone not in output
        assert "[email:redacted]" in normalized_output or "[phone:redacted]" in normalized_output


def test_supplier_risk_score_is_deterministic(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    questionnaire_dir = tmp_path / "questionnaire"
    first_risk_dir = tmp_path / "risk-a"
    second_risk_dir = tmp_path / "risk-b"

    questionnaire_exit = main(
        [
            "questionnaire",
            "--questions",
            str(QUESTIONNAIRE_CSV),
            "--evidence-store",
            str(EVIDENCE_STORE),
            "--out",
            str(questionnaire_dir),
        ]
    )
    first_exit = main(
        [
            "supplier-risk",
            "--profile",
            str(SUPPLIER_PROFILE),
            "--questionnaire-report",
            str(questionnaire_dir / QUESTIONNAIRE_JSON_NAME),
            "--out",
            str(first_risk_dir),
        ]
    )
    second_exit = main(
        [
            "supplier-risk",
            "--profile",
            str(SUPPLIER_PROFILE),
            "--questionnaire-report",
            str(questionnaire_dir / QUESTIONNAIRE_JSON_NAME),
            "--out",
            str(second_risk_dir),
        ]
    )

    first = _read_json(first_risk_dir / SUPPLIER_RISK_JSON_NAME)
    second = _read_json(second_risk_dir / SUPPLIER_RISK_JSON_NAME)

    assert questionnaire_exit == 0
    assert first_exit == 0
    assert second_exit == 0
    assert (first_risk_dir / SUPPLIER_RISK_MD_NAME).is_file()
    assert first["risk_score"] == second["risk_score"]
    assert first["risk_level"] == second["risk_level"]
    assert first["score_components"] == second["score_components"]


def test_evidence_builder_refuses_secret_like_sources(tmp_path: Path) -> None:
    forbidden = tmp_path / ".env"
    forbidden.write_text("placeholder=value\n", encoding="utf-8")

    with pytest.raises(EvidenceStoreError):
        build_file_evidence_record(forbidden, mapped_controls=("NIS2-SCRM-01",))


@pytest.mark.parametrize(
    "source_path",
    [
        ".env",
        ".env.example",
        "secrets/policy.md",
        "cookies/session.txt",
        "customer.sqlite",
        "debug.log",
        "debug.log.1",
        "C:/Users/Example/private-policy.md",
        "../outside.md",
    ],
)
def test_evidence_store_rejects_unsafe_source_labels(
    tmp_path: Path,
    source_path: str,
) -> None:
    store_path = tmp_path / "evidence_store.json"
    store_path.write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "evidence": [
                    {
                        "evidence_id": "E-unsafe",
                        "type": "document",
                        "source_path": source_path,
                        "sha256": "c" * 64,
                        "mapped_controls": ["NIS2-SCRM-01"],
                        "claims": [],
                        "validity": "current",
                        "review_required": False,
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(EvidenceStoreError):
        load_evidence_store(store_path)


@pytest.mark.parametrize(
    "relative_path",
    [
        "credential-note.txt",
        "sample.sqlite",
        "debug.log",
        "cookies/evidence.txt",
    ],
)
def test_evidence_builder_refuses_unsafe_source_paths(
    tmp_path: Path,
    relative_path: str,
) -> None:
    source_path = tmp_path / relative_path
    source_path.parent.mkdir(parents=True, exist_ok=True)
    source_path.write_text("synthetic placeholder\n", encoding="utf-8")

    with pytest.raises(EvidenceStoreError):
        build_file_evidence_record(source_path, mapped_controls=("NIS2-SCRM-01",))


def test_questionnaire_cli_rejects_output_outside_current_project(tmp_path: Path) -> None:
    out_dir = tmp_path / "outside"

    exit_code = main(
        [
            "questionnaire",
            "--questions",
            str(QUESTIONNAIRE_CSV),
            "--evidence-store",
            str(EVIDENCE_STORE),
            "--out",
            str(out_dir),
        ]
    )

    assert exit_code == C_SCRM_ERROR_EXIT_CODE
    assert not out_dir.exists()
