"""Tests for pilot-friendly Markdown report handover."""

from __future__ import annotations

from pathlib import Path

from aethelgard.triage import MAX_REPORT_CITATION_CHARS, render_triage_markdown, run_triage

FIXTURE_DIR = Path(__file__).resolve().parent / "fixtures" / "public_nis2"

REQUIRED_SECTIONS = (
    "## Scope",
    "## Important Disclaimer",
    "## Executive Summary",
    "## Documents Processed",
    "## Evidence by Category",
    "## Potential Gaps",
    "## Items Requiring Human Review",
    "## False Positive Watchlist",
    "## Recommended Next Manual Checks",
    "## Technical Run Metadata",
)


def test_triage_markdown_contains_required_handover_sections() -> None:
    markdown = render_triage_markdown(run_triage(FIXTURE_DIR)["report"])

    for section in REQUIRED_SECTIONS:
        assert section in markdown
    assert "not legal advice" in markdown
    assert "kein Auditurteil" in markdown
    assert "Run ID" in markdown


def test_report_citations_are_bounded_snippets() -> None:
    report = run_triage(FIXTURE_DIR)["report"]

    for document in report["per_document"]:
        for item in document["evidence"]:
            assert len(item["source_citation"]) <= MAX_REPORT_CITATION_CHARS
