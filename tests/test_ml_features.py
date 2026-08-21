"""Tests for metadata-only ML feature extraction."""

from __future__ import annotations

import json
from pathlib import Path
from typing import cast

import pytest

from aethelgard.ml_baselines.features import build_feature_records, write_features_jsonl


def test_ml_features_are_metadata_only_and_deterministic(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    docs = tmp_path / "docs"
    docs.mkdir()
    doc = docs / "backup_policy.md"
    doc.write_text(
        "Backup restore tests were reviewed on 2026-06-30 by the policy owner.",
        encoding="utf-8",
    )
    out_path = tmp_path / "reports" / "ml" / "features.jsonl"

    records = write_features_jsonl(docs, out_path)
    second_records = build_feature_records(docs)
    lines = out_path.read_text(encoding="utf-8").splitlines()
    payload = cast(dict[str, object], json.loads(lines[0]))
    features = cast(dict[str, object], payload["features"])
    output_text = out_path.read_text(encoding="utf-8")

    assert records == second_records
    assert payload["item_type"] == "document"
    assert payload["source_ref"] == "docs/backup_policy.md"
    assert len(str(payload["text_hash"])) == 64
    assert features["has_backup_terms"] is True
    assert features["has_policy_owner"] is True
    assert features["has_date"] is True
    assert "Backup restore tests were reviewed" not in output_text
    assert "C:/Users" not in output_text
    assert r"C:\Users" not in output_text


def test_ml_features_report_secret_like_input_without_reading(tmp_path: Path) -> None:
    secret_like = tmp_path / ".env.example"
    secret_like.write_text("API_KEY=SHOULD_NOT_BE_READ\n", encoding="utf-8")

    records = build_feature_records(secret_like, project_root=tmp_path)

    assert len(records) == 1
    assert records[0]["features"]["read_error"] is True
    assert records[0]["warnings"] == ["input path is secret-like or private"]
