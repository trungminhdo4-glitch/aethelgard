"""Tests for dependency-free document classifier baselines."""

from __future__ import annotations

import json
from pathlib import Path
from typing import cast

from aethelgard.ml_baselines.doc_classifier import (
    classify_documents,
    is_sklearn_available,
    train_doc_type_baseline,
)


def test_doc_classifier_trains_and_predicts_without_sklearn(tmp_path: Path) -> None:
    training_path = tmp_path / "training.json"
    training_path.write_text(
        json.dumps(
            {
                "items": [
                    {
                        "item_id": "T1",
                        "label": "policy_document",
                        "text": "Security policy owner review cadence.",
                    },
                    {
                        "item_id": "T2",
                        "label": "audit_or_certificate",
                        "text": "Audit certificate attestation report.",
                    },
                ]
            }
        ),
        encoding="utf-8",
    )
    docs = tmp_path / "docs"
    docs.mkdir()
    (docs / "policy.md").write_text("Policy owner review cadence is documented.", encoding="utf-8")
    model_path = tmp_path / "reports" / "ml" / "models" / "doc_type_model.json"

    model = train_doc_type_baseline(
        training_path,
        model_path,
        generated_at="2026-06-30T00:00:00+00:00",
    )
    report = classify_documents(model_path, docs, project_root=tmp_path)
    predictions = cast(list[dict[str, object]], report["predictions"])
    report_text = json.dumps(report, sort_keys=True)

    assert model_path.is_file()
    assert model["model_metadata"]["sklearn_available"] is is_sklearn_available()
    assert predictions[0]["predicted_label"] == "policy_document"
    assert predictions[0]["needs_review"] is True
    assert "Policy owner review cadence is documented" not in report_text
