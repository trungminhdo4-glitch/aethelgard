"""Tests for local diagnostics and structured debug logging."""

from __future__ import annotations

import json
from pathlib import Path

from aethelgard.cli import build_parser, main
from aethelgard.diagnostics import (
    DOCTOR_JSON_NAME,
    DOCTOR_MD_NAME,
    RUN_DEBUG_JSONL_NAME,
    RUN_SUMMARY_JSONL_NAME,
    run_doctor,
)
from aethelgard.errors import ALL_ERROR_CODES, ERROR_EXIT_CODES, ErrorCode

PROJECT_ROOT = Path(__file__).resolve().parents[1]
EXAMPLES_PILOT = PROJECT_ROOT / "examples" / "pilot"


def test_doctor_creates_json_and_markdown_without_raw_content(tmp_path: Path) -> None:
    out_dir = tmp_path / "doctor"
    unique_raw_phrase = "CUSTOMER RAW INCIDENT RUNBOOK SHOULD NOT LEAK"
    workspace = tmp_path / "workspace"
    documents = workspace / "documents"
    documents.mkdir(parents=True)
    (documents / "policy.md").write_text(unique_raw_phrase, encoding="utf-8")
    (workspace / "questionnaire_demo.csv").write_text(
        "question_id,question\nQ1,How is access reviewed?\n",
        encoding="utf-8",
    )

    report = run_doctor(workspace, out_dir)

    json_text = (out_dir / DOCTOR_JSON_NAME).read_text(encoding="utf-8")
    markdown = (out_dir / DOCTOR_MD_NAME).read_text(encoding="utf-8")
    assert report["status"] in {"OK", "WARN"}
    assert (out_dir / DOCTOR_JSON_NAME).is_file()
    assert (out_dir / DOCTOR_MD_NAME).is_file()
    assert unique_raw_phrase not in json_text
    assert unique_raw_phrase not in markdown
    assert "policy.md" in json_text


def test_pilot_product_debug_writes_private_and_redacted_jsonl(
    tmp_path: Path,
    monkeypatch: object,
) -> None:
    from pytest import MonkeyPatch

    typed_monkeypatch = monkeypatch
    assert isinstance(typed_monkeypatch, MonkeyPatch)
    typed_monkeypatch.chdir(tmp_path)
    out_dir = tmp_path / "pilot-product"

    exit_code = main(
        [
            "pilot-product",
            "--workspace",
            str(EXAMPLES_PILOT),
            "--out",
            str(out_dir),
            "--client-id",
            "demo-client",
            "--case-id",
            "case001",
            "--debug",
        ]
    )

    debug_path = out_dir / "local_private" / RUN_DEBUG_JSONL_NAME
    summary_path = out_dir / "shareable_redacted" / RUN_SUMMARY_JSONL_NAME
    debug_lines = [
        json.loads(line) for line in debug_path.read_text(encoding="utf-8").splitlines()
    ]
    summary_lines = [
        json.loads(line) for line in summary_path.read_text(encoding="utf-8").splitlines()
    ]
    assert exit_code == 0
    assert RUN_DEBUG_JSONL_NAME == "run_debug.jsonl"
    assert RUN_SUMMARY_JSONL_NAME == "run_summary.jsonl"
    assert debug_path.is_file()
    assert summary_path.is_file()
    assert {line["event"] for line in debug_lines} >= {"started", "completed"}
    assert {line["event"] for line in summary_lines} >= {"started", "completed"}
    assert all(line["safe_to_share"] is True for line in summary_lines)


def test_error_taxonomy_has_stable_codes_and_exit_mapping() -> None:
    expected = {
        "DOC_PARSE_FAILED",
        "UNSUPPORTED_FILE_TYPE",
        "OCR_REQUIRED",
        "DB_INIT_FAILED",
        "DB_SCHEMA_MISMATCH",
        "QUESTIONNAIRE_PARSE_FAILED",
        "OUTPUT_WRITE_FAILED",
        "READINESS_FAILED",
        "PRIVACY_GUARD_BLOCKED",
        "CONFIG_ERROR",
        "DEPENDENCY_MISSING",
        "INTERNAL_ERROR",
    }

    assert {code.value for code in ALL_ERROR_CODES} == expected
    assert set(ERROR_EXIT_CODES) == set(ALL_ERROR_CODES)
    assert ERROR_EXIT_CODES[ErrorCode.PRIVACY_GUARD_BLOCKED] > 0


def test_cli_help_includes_doctor_and_support_bundle() -> None:
    help_text = build_parser().format_help()

    assert "doctor" in help_text
    assert "support-bundle" in help_text
