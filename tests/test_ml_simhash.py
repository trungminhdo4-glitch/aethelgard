"""Tests for SimHash near-duplicate detection."""

from __future__ import annotations

from aethelgard.ml_baselines.features import IndexItem, text_hash
from aethelgard.ml_baselines.simhash import (
    detect_near_duplicates_from_items,
    simhash_similarity,
    simhash_text,
)


def _item(item_id: str, text: str) -> IndexItem:
    return {
        "item_id": item_id,
        "item_type": "document",
        "source_ref": "%s.md" % item_id,
        "text_hash": text_hash(text),
        "text": text,
        "warnings": [],
    }


def test_simhash_identical_text_is_duplicate() -> None:
    text = "backup restore procedure tested quarterly"

    similarity = simhash_similarity(simhash_text(text), simhash_text(text))
    pairs = detect_near_duplicates_from_items((_item("DOC-a", text), _item("DOC-b", text)))

    assert similarity == 1.0
    assert pairs[0]["decision"] == "possible_duplicate"
    assert pairs[0]["needs_review"] is True


def test_simhash_near_duplicate_passes_threshold() -> None:
    first = _item("DOC-a", "backup restore procedure tested quarterly by owner")
    second = _item("DOC-b", "backup restore procedure reviewed quarterly by owner")

    pairs = detect_near_duplicates_from_items((first, second), threshold=0.75)

    assert pairs
    assert pairs[0]["similarity"] >= 0.75


def test_simhash_different_text_stays_outside_threshold() -> None:
    first = _item("DOC-a", "backup restore procedure tested quarterly")
    second = _item("DOC-b", "supplier contract onboarding due diligence")

    pairs = detect_near_duplicates_from_items((first, second), threshold=0.9)

    assert pairs == []
