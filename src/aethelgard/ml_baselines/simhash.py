"""Deterministic SimHash near-duplicate detection."""

from __future__ import annotations

import hashlib
from collections import Counter
from collections.abc import Sequence
from pathlib import Path
from typing import Final, TypedDict

from aethelgard.ml_baselines.features import IndexItem, collect_index_items, tokenize
from aethelgard.ml_baselines.model_registry import (
    attach_metadata,
    build_model_metadata,
    safe_training_ref,
)

SIMHASH_BITS: Final[int] = 64
DEFAULT_DUPLICATE_THRESHOLD: Final[float] = 0.9
SIMILARITY_PRECISION: Final[int] = 6
SIMHASH_MODEL_NAME: Final[str] = "SimHashNearDuplicate"
SIMHASH_MODEL_TYPE: Final[str] = "pure_python_simhash"


class DuplicatePair(TypedDict):
    """One possible duplicate pair."""

    item_a: str
    item_b: str
    similarity: float
    decision: str
    needs_review: bool


class SimHashError(ValueError):
    """Raised when SimHash input is invalid."""


def detect_near_duplicates(
    input_path: Path | str,
    *,
    threshold: float = DEFAULT_DUPLICATE_THRESHOLD,
    project_root: Path | str | None = None,
    generated_at: str | None = None,
) -> dict[str, object]:
    """Detect possible duplicate or versioned local items without exporting raw text."""
    if threshold < 0.0 or threshold > 1.0:
        raise SimHashError("threshold must be between 0.0 and 1.0")
    items = collect_index_items(input_path, project_root=project_root)
    duplicates = detect_near_duplicates_from_items(items, threshold=threshold)
    metadata = build_model_metadata(
        model_name=SIMHASH_MODEL_NAME,
        model_type=SIMHASH_MODEL_TYPE,
        training_data_ref=safe_training_ref(input_path),
        generated_at=generated_at,
        experimental=True,
    )
    return attach_metadata({"duplicates": duplicates}, metadata)


def detect_near_duplicates_from_items(
    items: Sequence[IndexItem],
    *,
    threshold: float = DEFAULT_DUPLICATE_THRESHOLD,
) -> list[DuplicatePair]:
    """Detect duplicates from already-collected in-memory items."""
    fingerprints = [(item, simhash_text(item["text"])) for item in items]
    pairs: list[DuplicatePair] = []
    for left_index, (left_item, left_hash) in enumerate(fingerprints):
        for right_item, right_hash in fingerprints[left_index + 1 :]:
            similarity = simhash_similarity(left_hash, right_hash)
            if similarity < threshold:
                continue
            item_a, item_b = sorted((left_item["item_id"], right_item["item_id"]))
            pairs.append(
                {
                    "item_a": item_a,
                    "item_b": item_b,
                    "similarity": round(similarity, SIMILARITY_PRECISION),
                    "decision": "possible_duplicate",
                    "needs_review": True,
                }
            )
    return sorted(pairs, key=lambda pair: (pair["item_a"], pair["item_b"]))


def simhash_text(text: str) -> int:
    """Return a 64-bit SimHash fingerprint for text."""
    token_counts = Counter(tokenize(text))
    if not token_counts:
        return 0
    weights = [0] * SIMHASH_BITS
    for token, count in token_counts.items():
        token_hash = _hash_token(token)
        for bit_index in range(SIMHASH_BITS):
            bit_is_set = (token_hash >> bit_index) & 1
            weights[bit_index] += count if bit_is_set else -count
    fingerprint = 0
    for bit_index, weight in enumerate(weights):
        if weight >= 0:
            fingerprint |= 1 << bit_index
    return fingerprint


def simhash_similarity(left: int, right: int) -> float:
    """Return normalized Hamming similarity for two SimHash fingerprints."""
    distance = (left ^ right).bit_count()
    return 1.0 - (distance / SIMHASH_BITS)


def _hash_token(token: str) -> int:
    digest = hashlib.sha256(token.encode("utf-8")).digest()
    return int.from_bytes(digest[:8], byteorder="big", signed=False)
