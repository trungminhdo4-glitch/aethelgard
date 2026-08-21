"""Tests for metadata-only audit ledger support."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from aethelgard.audit import build_audit_entry
from aethelgard.cli import main

FIXTURE_DIR = Path(__file__).resolve().parent / "fixtures" / "public_nis2"
LABELS_PATH = FIXTURE_DIR / "golden_labels.json"


def test_build_audit_entry_has_required_fields_without_content() -> None:
    entry = build_audit_entry(
        command="triage",
        input_path=FIXTURE_DIR,
        output_path="reports/demo",
        document_count=1,
        parsed_count=1,
        failed_count=0,
        evidence_count=2,
        run_id="triage-test",
        tool_version="0.1.0",
        warnings=[],
        errors=[],
    )

    required = {
        "run_id",
        "timestamp",
        "command",
        "input_path",
        "output_path",
        "document_count",
        "parsed_count",
        "failed_count",
        "evidence_count",
        "evaluation_status",
        "tool_version",
        "content_hashes",
        "warnings",
        "errors",
    }
    assert required.issubset(entry)
    assert "source_citation" not in json.dumps(entry)


def test_triage_audit_writes_jsonl_without_document_content(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    out_dir = tmp_path / "demo"

    exit_code = main(["triage", "--input", str(FIXTURE_DIR), "--out", str(out_dir), "--audit"])

    ledger = tmp_path / "reports" / "audit" / "aethelgard_runs.jsonl"
    assert exit_code == 0
    assert ledger.is_file()
    line = ledger.read_text(encoding="utf-8").strip()
    entry = json.loads(line)
    assert entry["command"] == "triage"
    assert entry["document_count"] == 17
    assert "source_citation" not in line
    assert "risk assessment process is documented" not in line


def test_audit_ledger_appends_multiple_runs(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)

    for index in range(2):
        exit_code = main(
            [
                "eval",
                "--fixtures",
                str(FIXTURE_DIR),
                "--labels",
                str(LABELS_PATH),
                "--out",
                str(tmp_path / ("eval-%d" % index)),
                "--audit",
            ]
        )
        assert exit_code == 0

    ledger = tmp_path / "reports" / "audit" / "aethelgard_runs.jsonl"
    lines = ledger.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 2
    assert all(json.loads(line)["command"] == "eval" for line in lines)
