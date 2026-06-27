"""CLI tests for local triage report generation."""

from __future__ import annotations

import json
from pathlib import Path

from aethelgard.cli import main
from aethelgard.triage import REPORT_JSON_NAME, REPORT_MD_NAME, RUN_SUMMARY_NAME

FIXTURE_DIR = Path(__file__).resolve().parent / "fixtures" / "public_nis2"


def test_triage_cli_writes_reports(tmp_path: Path) -> None:
    out_dir = tmp_path / "demo"
    exit_code = main(["triage", "--input", str(FIXTURE_DIR), "--out", str(out_dir)])

    assert exit_code == 0
    assert (out_dir / REPORT_JSON_NAME).is_file()
    assert (out_dir / REPORT_MD_NAME).is_file()
    assert (out_dir / RUN_SUMMARY_NAME).is_file()

    report = json.loads((out_dir / REPORT_JSON_NAME).read_text(encoding="utf-8"))
    summary = json.loads((out_dir / RUN_SUMMARY_NAME).read_text(encoding="utf-8"))
    markdown = (out_dir / REPORT_MD_NAME).read_text(encoding="utf-8")

    assert report["document_count"] == 17
    assert report["parsed_count"] == 17
    assert report["failed_count"] == 0
    assert report["evidence_count"] > 0
    assert summary["exit_code"] == 0
    assert "Human review required" in markdown
    assert "does not provide legal advice" in markdown
