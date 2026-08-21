"""CLI smoke tests for experimental low-compute ML baselines."""

from __future__ import annotations

import json
from pathlib import Path
from typing import cast

import pytest

from aethelgard.cli import ML_ERROR_EXIT_CODE, main


def _write_training(path: Path) -> None:
    path.write_text(
        json.dumps(
            {
                "items": [
                    {
                        "item_id": "T1",
                        "label": "policy_document",
                        "text": "Policy owner review cadence.",
                    },
                    {
                        "item_id": "T2",
                        "label": "audit_or_certificate",
                        "text": "Audit certificate attestation.",
                    },
                ]
            }
        ),
        encoding="utf-8",
    )


def _read_json(path: Path) -> dict[str, object]:
    return cast(dict[str, object], json.loads(path.read_text(encoding="utf-8")))


def test_ml_cli_commands_write_metadata_only_outputs(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    docs = tmp_path / "docs"
    docs.mkdir()
    raw_sentence = "Backup restore evidence has no evidence of a reviewed restore test."
    (docs / "backup.md").write_text(raw_sentence, encoding="utf-8")
    training = tmp_path / "training.json"
    _write_training(training)

    features = tmp_path / "reports" / "ml" / "features.jsonl"
    search = tmp_path / "reports" / "ml" / "search_results.json"
    weak_labels = tmp_path / "reports" / "ml" / "weak_labels.jsonl"
    duplicates = tmp_path / "reports" / "ml" / "duplicates.json"
    model = tmp_path / "reports" / "ml" / "models" / "doc_type_model.json"
    predictions = tmp_path / "reports" / "ml" / "doc_predictions.json"
    controls = tmp_path / "reports" / "ml" / "control_suggestions.json"
    severity = tmp_path / "reports" / "ml" / "ranked_findings.json"
    active = tmp_path / "reports" / "ml" / "active_review_queue.json"

    assert main(["ml", "features", "--input", str(docs), "--out", str(features)]) == 0
    assert main(
        ["ml", "search", "--index", str(docs), "--query", "backup restore", "--out", str(search)]
    ) == 0
    assert main(["ml", "weak-labels", "--input", str(docs), "--out", str(weak_labels)]) == 0
    assert main(["ml", "dedupe", "--input", str(docs), "--out", str(duplicates)]) == 0
    assert main(
        [
            "ml",
            "train-baselines",
            "--task",
            "doc-type",
            "--input",
            str(training),
            "--out",
            str(model),
        ]
    ) == 0
    assert main(
        [
            "ml",
            "classify-docs",
            "--model",
            str(model),
            "--input",
            str(docs),
            "--out",
            str(predictions),
        ]
    ) == 0
    assert main(["ml", "suggest-controls", "--input", str(docs), "--out", str(controls)]) == 0
    assert main(["ml", "rank-findings", "--input", str(features), "--out", str(severity)]) == 0
    assert main(
        [
            "ml",
            "active-review",
            "--predictions",
            str(predictions),
            "--weak-labels",
            str(weak_labels),
            "--duplicates",
            str(duplicates),
            "--severity",
            str(severity),
            "--out",
            str(active),
        ]
    ) == 0

    feature_text = features.read_text(encoding="utf-8")
    weak_text = weak_labels.read_text(encoding="utf-8")
    search_report = _read_json(search)
    active_report = _read_json(active)

    assert raw_sentence not in feature_text
    assert raw_sentence not in weak_text
    assert search_report["results"]
    assert active_report["review_queue"]
    assert "C:/Users" not in feature_text + weak_text
    assert r"C:\Users" not in feature_text + weak_text


def test_ml_active_review_missing_input_returns_ml_error(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    out_path = tmp_path / "reports" / "ml" / "active_review_queue.json"

    exit_code = main(
        [
            "ml",
            "active-review",
            "--severity",
            str(tmp_path / "missing.json"),
            "--out",
            str(out_path),
        ]
    )

    assert exit_code == ML_ERROR_EXIT_CODE
    assert not out_path.exists()
