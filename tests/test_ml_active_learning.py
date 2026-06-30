"""Tests for active-learning review queue assembly."""

from __future__ import annotations

import json
from pathlib import Path
from typing import cast

from aethelgard.ml_baselines.active_learning import build_active_review_queue


def _write_json(path: Path, payload: dict[str, object]) -> None:
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def test_active_learning_combines_uncertainty_reasons(tmp_path: Path) -> None:
    predictions = tmp_path / "predictions.json"
    weak_labels = tmp_path / "weak_labels.jsonl"
    duplicates = tmp_path / "duplicates.json"
    severity = tmp_path / "severity.json"
    review_csv = tmp_path / "review.csv"
    _write_json(
        predictions,
        {"predictions": [{"item_id": "EV-1", "confidence": 0.4}]},
    )
    weak_labels.write_text(
        json.dumps(
            {
                "item_id": "EV-1",
                "weak_labels": ["backup_evidence"],
                "conflict": True,
            },
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    _write_json(
        duplicates,
        {"duplicates": [{"item_a": "EV-1", "item_b": "EV-2", "needs_review": True}]},
    )
    _write_json(
        severity,
        {
            "ranked_findings": [
                {"finding_id": "EV-1", "suggested_priority": "P1", "confidence": 0.6}
            ]
        },
    )
    review_csv.write_text(
        "finding_id,review_status\nEV-2,accepted\n",
        encoding="utf-8",
    )

    report = build_active_review_queue(
        predictions_path=predictions,
        weak_labels_path=weak_labels,
        duplicates_path=duplicates,
        severity_path=severity,
        review_csv_path=review_csv,
        generated_at="2026-06-30T00:00:00+00:00",
    )
    queue = cast(list[dict[str, object]], report["review_queue"])

    assert [item["item_id"] for item in queue] == ["EV-1"]
    assert queue[0]["priority"] == "review_first"
    assert "label_conflict" in str(queue[0]["reason"])
    assert "duplicate_conflict" in str(queue[0]["reason"])
    assert "high_severity_low_confidence" in str(queue[0]["reason"])
    assert "low_confidence_doc_classification" in str(queue[0]["reason"])
