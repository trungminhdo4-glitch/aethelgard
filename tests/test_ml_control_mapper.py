"""Tests for experimental control mapping suggestions."""

from __future__ import annotations

from aethelgard.ml_baselines.control_mapper import suggest_controls_for_item
from aethelgard.ml_baselines.features import IndexItem, text_hash


def _item(text: str) -> IndexItem:
    return {
        "item_id": "EV-1",
        "item_type": "evidence",
        "source_ref": "evidence.json#EV-1",
        "text_hash": text_hash(text),
        "text": text,
        "warnings": [],
    }


def test_control_mapper_suggests_multilabel_controls() -> None:
    record = suggest_controls_for_item(
        _item("Supplier security review includes backup restore and disaster recovery testing.")
    )
    control_ids = {
        suggestion["control_id"]
        for suggestion in record["suggested_controls"]
    }

    assert {"NIS2-SCRM-01", "NIS2-SCRM-04"}.issubset(control_ids)
    assert all(
        suggestion["status"] in {"suggested", "experimental"}
        for suggestion in record["suggested_controls"]
    )
    assert record["needs_review"] is True


def test_control_mapper_empty_label_case_has_no_suggestions() -> None:
    record = suggest_controls_for_item(_item("General welcome text."), min_confidence=0.55)

    assert record["suggested_controls"] == []


def test_control_mapper_low_confidence_can_be_filtered() -> None:
    record = suggest_controls_for_item(_item("backup"), min_confidence=0.95)

    assert record["suggested_controls"] == []
