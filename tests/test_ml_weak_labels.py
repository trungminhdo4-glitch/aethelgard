"""Tests for weak supervision label rules."""

from __future__ import annotations

from aethelgard.ml_baselines.features import IndexItem, text_hash
from aethelgard.ml_baselines.weak_labels import label_item, label_text


def _item(text: str) -> IndexItem:
    return {
        "item_id": "EV-1",
        "item_type": "evidence",
        "source_ref": "reviewed/report.json#EV-1",
        "text_hash": text_hash(text),
        "text": text,
        "warnings": [],
    }


def test_weak_labels_find_positive_backup_evidence() -> None:
    labels, sources, hit_count = label_text("Quarterly backup restore evidence is reviewed.")

    assert "backup_evidence" in labels
    assert "keyword_rule:backup_restore" in sources
    assert hit_count > 0


def test_weak_labels_negative_case_has_no_labels() -> None:
    labels, sources, hit_count = label_text("General company overview and greeting.")

    assert labels == []
    assert sources == []
    assert hit_count == 0


def test_weak_labels_mark_conflicting_positive_and_negative_text() -> None:
    record = label_item(_item("Backup restore policy has no evidence of testing."))

    assert "backup_evidence" in record["weak_labels"]
    assert record["conflict"] is True
    assert record["needs_review"] is True
