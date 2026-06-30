"""Tests for severity and evidence-quality ranking."""

from __future__ import annotations

from typing import cast

from aethelgard.ml_baselines.features import FeatureRecord, FeatureValues
from aethelgard.ml_baselines.severity import rank_feature_records


def _record(item_id: str, **features: bool | int) -> FeatureRecord:
    default_features = {
        "word_count": 12,
        "has_date": False,
        "has_policy_owner": False,
        "has_backup_terms": False,
        "has_incident_terms": False,
        "has_supplier_terms": False,
        "has_review_terms": False,
        "contains_future_tense": False,
        "contains_negative_phrase": False,
    }
    default_features.update(features)
    return {
        "record_type": "ml_feature_record",
        "feature_schema_version": "ml-features-v1",
        "item_id": item_id,
        "item_type": "finding",
        "source_ref": "report.json#%s" % item_id,
        "text_hash": "a" * 64,
        "features": cast(FeatureValues, default_features),
    }


def test_severity_ranks_p1_without_raw_text() -> None:
    ranked = rank_feature_records(
        (
            _record(
                "F-1",
                has_backup_terms=True,
                contains_negative_phrase=True,
                contains_future_tense=True,
            ),
            _record("F-2", has_review_terms=True),
        )
    )

    assert ranked[0]["finding_id"] == "F-1"
    assert ranked[0]["suggested_priority"] == "P1"
    assert "missing_restore_test" in ranked[0]["reason_codes"]
    assert "negative_evidence_phrase" in ranked[0]["reason_codes"]
    assert ranked[0]["needs_review"] is True
