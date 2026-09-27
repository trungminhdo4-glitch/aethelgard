"""Triage must isolate malformed PDFs per file instead of aborting the batch."""

from __future__ import annotations

from pathlib import Path

from aethelgard.triage import run_triage

TRUNCATED_PDF = (
    b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\ntrailer\n<< /Root 1 0 R >>\n"
)


def test_corrupt_pdf_becomes_error_entry_not_batch_abort(tmp_path: Path) -> None:
    (tmp_path / "notes.txt").write_text(
        "The security owner reviewed and approved the documented control.",
        encoding="utf-8",
    )
    (tmp_path / "broken.pdf").write_bytes(TRUNCATED_PDF)

    result = run_triage(tmp_path, tmp_path / "out")

    summary = result["summary"]
    assert summary["parsed_count"] == 1
    assert summary["failed_count"] == 1
    assert summary["exit_code"] == 1
    errors = result["report"]["errors"]
    assert len(errors) == 1
    assert errors[0]["file"].endswith("broken.pdf")
    assert (tmp_path / "out" / "evidence_report.json").is_file()
