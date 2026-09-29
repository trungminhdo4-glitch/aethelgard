"""Tests for the SQLite answer vault and questionnaire draft flow."""

from __future__ import annotations

import csv
import json
import contextlib
import sqlite3
from pathlib import Path
from typing import cast

from aethelgard.answer_vault import (
    ANSWER_LIBRARY_EXPORT_NAME,
    CASE_REVIEW_QUEUE_CSV_NAME,
    MISSING_EVIDENCE_CSV_NAME,
    QUESTIONNAIRE_DRAFT_CSV_NAME,
    build_questionnaire_draft,
    export_answer_library,
    import_answer_library_json,
    init_answer_vault,
    list_answer_library,
)
from aethelgard.cli import PILOT_PRODUCT_ERROR_EXIT_CODE, main


def _write_answers(path: Path, *, valid_until: str = "2027-06-30") -> None:
    path.write_text(
        json.dumps(
            {
                "answers": [
                    {
                        "question_cluster": "backup",
                        "canonical_question": "How are backups created and protected?",
                        "answer_de": "Backups are reviewed and restore evidence is retained.",
                        "answer_en": "",
                        "evidence_refs": ["EV-BACKUP-1"],
                        "review_status": "reviewed",
                        "reviewer": "Synthetic Reviewer",
                        "reviewed_at": "2026-06-30",
                        "valid_until": valid_until,
                        "confidence": 0.91,
                        "source_case_id": "baseline",
                    }
                ]
            },
            indent=2,
        ),
        encoding="utf-8",
    )


def _write_questions(path: Path) -> None:
    path.write_text(
        "question_id,question\n"
        "Q1,How are backups created and protected?\n"
        "Q2,Do you document incident response escalation timelines?\n"
        "Q3,Do you have a supplier security review?\n",
        encoding="utf-8",
    )


def _evidence_map() -> dict[str, object]:
    return {
        "schema_version": "1.0",
        "evidence_count": 1,
        "evidence": [
            {
                "evidence_id": "EV-INCIDENT-1",
                "document_id": "DOC-1",
                "source_path": "incident.md",
                "source_type": "markdown",
                "chunk_id": "CH-1",
                "snippet_hash": "a" * 64,
                "mapped_controls": ["incident_response"],
                "confidence": 0.78,
                "reason": "matched_terms=incident response",
            }
        ],
    }


def _read_csv(path: Path) -> list[dict[str, str]]:
    with path.open(encoding="utf-8", newline="") as csv_file:
        return list(csv.DictReader(csv_file))


def test_answer_vault_init_is_idempotent_and_seeds_schema(tmp_path: Path) -> None:
    db_path = tmp_path / "vault.sqlite"

    first = init_answer_vault(db_path, client_id="demo-client")
    second = init_answer_vault(db_path, client_id="demo-client")

    with contextlib.closing(sqlite3.connect(db_path)) as connection:
        table_count = connection.execute(
            "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table'"
        ).fetchone()[0]
        version = connection.execute("SELECT version FROM schema_version").fetchone()[0]

    assert first["status"] == "ready"
    assert second["status"] == "ready"
    assert version == "1"
    assert table_count >= 13


def test_answer_vault_import_export_and_versions_answers(tmp_path: Path) -> None:
    db_path = tmp_path / "vault.sqlite"
    answers_path = tmp_path / "answers.json"
    export_path = tmp_path / ANSWER_LIBRARY_EXPORT_NAME
    _write_answers(answers_path)

    init_answer_vault(db_path, client_id="demo-client")
    first = import_answer_library_json(db_path, answers_path, client_id="demo-client")
    second = import_answer_library_json(db_path, answers_path, client_id="demo-client")
    exported = export_answer_library(db_path, export_path, client_id="demo-client")
    answers = list_answer_library(db_path, client_id="demo-client")

    with contextlib.closing(sqlite3.connect(db_path)) as connection:
        version_count = connection.execute("SELECT COUNT(*) FROM answer_versions").fetchone()[0]

    assert first["imported"] == 1
    assert second["imported"] == 1
    assert len(answers) == 1
    assert version_count >= 1
    assert exported["answer_count"] == 1
    assert export_path.is_file()


def test_questionnaire_draft_reuses_reviewed_answer_and_queues_missing(
    tmp_path: Path,
) -> None:
    db_path = tmp_path / "vault.sqlite"
    answers_path = tmp_path / "answers.json"
    questions_path = tmp_path / "questions.csv"
    out_dir = tmp_path / "draft"
    _write_answers(answers_path)
    _write_questions(questions_path)
    init_answer_vault(db_path, client_id="demo-client")
    import_answer_library_json(db_path, answers_path, client_id="demo-client")

    report = build_questionnaire_draft(
        db_path,
        questions_path,
        _evidence_map(),
        out_dir,
        client_id="demo-client",
        case_id="case001",
    )

    rows = _read_csv(out_dir / QUESTIONNAIRE_DRAFT_CSV_NAME)
    queue = _read_csv(out_dir / CASE_REVIEW_QUEUE_CSV_NAME)
    missing = _read_csv(out_dir / MISSING_EVIDENCE_CSV_NAME)
    draft_answers = cast(list[dict[str, object]], report["draft_answers"])
    by_question = {str(item["question_id"]): item for item in draft_answers}

    assert by_question["Q1"]["review_status"] == "reviewed"
    assert by_question["Q1"]["source_answer_id"]
    assert by_question["Q2"]["review_status"] == "needs_review"
    assert by_question["Q2"]["evidence_refs"] == ("EV-INCIDENT-1",)
    assert by_question["Q3"]["review_status"] == "missing_evidence"
    assert len(rows) == 3
    assert any(row["reason_for_review"] == "no_evidence" for row in queue)
    assert any(row["cluster"] == "supplier_management" for row in missing)


def test_questionnaire_draft_marks_stale_reusable_answer(tmp_path: Path) -> None:
    db_path = tmp_path / "vault.sqlite"
    answers_path = tmp_path / "answers.json"
    questions_path = tmp_path / "questions.csv"
    _write_answers(answers_path, valid_until="2024-01-01")
    questions_path.write_text(
        "question_id,question\nQ1,How are backups created and protected?\n",
        encoding="utf-8",
    )
    init_answer_vault(db_path, client_id="demo-client")
    import_answer_library_json(db_path, answers_path, client_id="demo-client")

    report = build_questionnaire_draft(
        db_path,
        questions_path,
        {"evidence": []},
        client_id="demo-client",
        case_id="case001",
    )
    draft_answers = cast(list[dict[str, object]], report["draft_answers"])

    assert draft_answers[0]["review_status"] == "stale"
    assert draft_answers[0]["reason"] == "reusable_answer_stale"


def test_answer_vault_cli_rejects_db_outside_current_project(
    tmp_path: Path,
    monkeypatch: object,
) -> None:
    from pytest import MonkeyPatch

    typed_monkeypatch = cast(MonkeyPatch, monkeypatch)
    project_dir = tmp_path / "project"
    project_dir.mkdir()
    outside_db = tmp_path / "outside.sqlite"
    typed_monkeypatch.chdir(project_dir)

    exit_code = main(
        [
            "answer-vault",
            "init",
            "--db",
            str(outside_db),
            "--client-id",
            "demo-client",
        ]
    )

    assert exit_code == PILOT_PRODUCT_ERROR_EXIT_CODE
    assert not outside_db.exists()
