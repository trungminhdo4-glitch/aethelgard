"""CLI-level tests for the document-ingest subcommand."""

from __future__ import annotations

import json
from pathlib import Path
from typing import cast

import pytest

from aethelgard.cli import PILOT_PRODUCT_ERROR_EXIT_CODE, main
from aethelgard.diagnostics import (
    LOCAL_PRIVATE_DIR_NAME,
    RUN_DEBUG_JSONL_NAME,
    RUN_SUMMARY_JSONL_NAME,
    SHAREABLE_REDACTED_DIR_NAME,
)
from aethelgard.document_ingest import (
    DOCUMENT_INVENTORY_NAME,
    DOCUMENT_SUMMARIES_NAME,
    EVIDENCE_MAP_NAME,
)

EXPECTED_DOCUMENT_COUNT = 2


def _read_json(path: Path) -> dict[str, object]:
    return cast(dict[str, object], json.loads(path.read_text(encoding="utf-8")))


def _write_sample_documents(input_dir: Path) -> None:
    input_dir.mkdir()
    (input_dir / "access.md").write_text(
        "Access control is documented. MFA is reviewed quarterly by the owner.",
        encoding="utf-8",
    )
    (input_dir / "backup.txt").write_text(
        "Backup restore test records are reviewed monthly by the continuity owner.",
        encoding="utf-8",
    )


def test_document_ingest_cli_happy_path_writes_artifacts(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    input_dir = tmp_path / "docs"
    out_dir = tmp_path / "ingest-out"
    _write_sample_documents(input_dir)

    exit_code = main(["document-ingest", "--input", str(input_dir), "--out", str(out_dir)])

    inventory = _read_json(out_dir / DOCUMENT_INVENTORY_NAME)
    evidence_map = _read_json(out_dir / EVIDENCE_MAP_NAME)
    assert exit_code == 0
    assert (out_dir / DOCUMENT_SUMMARIES_NAME).is_file()
    assert inventory["document_count"] == EXPECTED_DOCUMENT_COUNT
    assert cast(int, evidence_map["evidence_count"]) >= 1


def test_document_ingest_cli_missing_input_exits_with_pilot_product_code(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.chdir(tmp_path)

    exit_code = main(
        [
            "document-ingest",
            "--input",
            str(tmp_path / "does-not-exist"),
            "--out",
            str(tmp_path / "ingest-out"),
        ]
    )

    captured = capsys.readouterr()
    assert exit_code == PILOT_PRODUCT_ERROR_EXIT_CODE
    assert "document-ingest failed" in captured.err


def test_document_ingest_cli_rejects_out_path_outside_project_folder(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    project_dir = tmp_path / "project"
    project_dir.mkdir()
    monkeypatch.chdir(project_dir)
    input_dir = project_dir / "docs"
    _write_sample_documents(input_dir)
    escape_dir = tmp_path / "outside"

    exit_code = main(["document-ingest", "--input", str(input_dir), "--out", str(escape_dir)])

    captured = capsys.readouterr()
    assert exit_code == PILOT_PRODUCT_ERROR_EXIT_CODE
    assert "document-ingest failed" in captured.err
    assert not escape_dir.exists()


def test_document_ingest_cli_no_local_excerpts_omits_redacted_excerpts(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    input_dir = tmp_path / "docs"
    out_dir = tmp_path / "ingest-out"
    _write_sample_documents(input_dir)

    exit_code = main(
        [
            "document-ingest",
            "--input",
            str(input_dir),
            "--out",
            str(out_dir),
            "--no-local-excerpts",
        ]
    )

    evidence_map = _read_json(out_dir / EVIDENCE_MAP_NAME)
    evidence_items = cast(list[dict[str, object]], evidence_map["evidence"])
    assert exit_code == 0
    assert evidence_items
    assert all("redacted_excerpt" not in item for item in evidence_items)


def test_document_ingest_cli_debug_writes_diagnostic_jsonl_logs(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    input_dir = tmp_path / "docs"
    out_dir = tmp_path / "ingest-out"
    _write_sample_documents(input_dir)

    exit_code = main(
        ["document-ingest", "--input", str(input_dir), "--out", str(out_dir), "--debug"]
    )

    debug_path = out_dir / LOCAL_PRIVATE_DIR_NAME / RUN_DEBUG_JSONL_NAME
    summary_path = out_dir / SHAREABLE_REDACTED_DIR_NAME / RUN_SUMMARY_JSONL_NAME
    assert exit_code == 0
    assert debug_path.is_file()
    assert summary_path.is_file()
    debug_events = [
        cast(dict[str, object], json.loads(line))
        for line in debug_path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    event_names = {str(event["event"]) for event in debug_events}
    assert {"started", "completed"} <= event_names
