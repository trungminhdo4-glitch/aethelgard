"""Tests for BM25 evidence search baselines."""

from __future__ import annotations

import json
from pathlib import Path
from typing import cast

from aethelgard.ml_baselines.bm25 import search_bm25


def test_bm25_search_returns_reason_codes_without_snippets(tmp_path: Path) -> None:
    docs = tmp_path / "docs"
    docs.mkdir()
    (docs / "backup.md").write_text(
        "The backup restore procedure is tested quarterly.",
        encoding="utf-8",
    )
    (docs / "incident.md").write_text(
        "Incident escalation is reviewed by the response team.",
        encoding="utf-8",
    )

    report = search_bm25(
        docs,
        "backup restore",
        project_root=tmp_path,
        generated_at="2026-06-30T00:00:00+00:00",
    )
    results = cast(list[dict[str, object]], report["results"])
    report_text = json.dumps(report, sort_keys=True)

    assert results
    assert results[0]["source_ref"] == "docs/backup.md"
    assert "term_match:backup" in results[0]["reason_codes"]
    assert "term_match:restore" in results[0]["reason_codes"]
    assert "tested quarterly" not in report_text
    assert report["model_metadata"]
