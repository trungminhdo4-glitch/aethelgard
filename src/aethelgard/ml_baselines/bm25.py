"""Small deterministic BM25 search over local documents or metadata-only features."""

from __future__ import annotations

import math
from collections import Counter
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Final, TypedDict

from aethelgard.ml_baselines.features import (
    FeatureRecord,
    IndexItem,
    collect_index_items,
    load_feature_records,
    stable_id,
    text_hash,
    tokenize,
)
from aethelgard.ml_baselines.model_registry import (
    attach_metadata,
    build_model_metadata,
    safe_training_ref,
)

BM25_MODEL_NAME: Final[str] = "BM25EvidenceSearch"
BM25_MODEL_TYPE: Final[str] = "pure_python_bm25"
BM25_K1: Final[float] = 1.5
BM25_B: Final[float] = 0.75
DEFAULT_TOP_K: Final[int] = 10
MAX_TOP_K: Final[int] = 100
MAX_QUERY_CHARS: Final[int] = 300
SCORE_PRECISION: Final[int] = 6


class SearchResult(TypedDict):
    """One metadata-only search result."""

    item_id: str
    score: float
    source_ref: str
    reason_codes: list[str]


class BM25SearchReport(TypedDict):
    """Search output contract."""

    query: str
    results: list[SearchResult]
    model_metadata: Mapping[str, object]


class BM25Error(ValueError):
    """Raised when BM25 search input is invalid."""


def search_bm25(
    index_path: Path | str,
    query: str,
    *,
    top_k: int = DEFAULT_TOP_K,
    project_root: Path | str | None = None,
    generated_at: str | None = None,
) -> dict[str, object]:
    """Search local records with BM25 and return metadata-only results."""
    normalized_query = " ".join(query.split())
    if not normalized_query:
        raise BM25Error("query must not be empty")
    if len(normalized_query) > MAX_QUERY_CHARS:
        raise BM25Error("query exceeds maximum length")
    bounded_top_k = max(1, min(top_k, MAX_TOP_K))
    items = _load_search_items(index_path, project_root=project_root)
    query_terms = tuple(dict.fromkeys(tokenize(normalized_query)))
    results = _score_items(items, query_terms, bounded_top_k)
    metadata = build_model_metadata(
        model_name=BM25_MODEL_NAME,
        model_type=BM25_MODEL_TYPE,
        training_data_ref=safe_training_ref(index_path),
        generated_at=generated_at,
        experimental=True,
    )
    return attach_metadata({"query": normalized_query, "results": results}, metadata)


def _score_items(
    items: Sequence[IndexItem],
    query_terms: Sequence[str],
    top_k: int,
) -> list[SearchResult]:
    if not items or not query_terms:
        return []
    tokenized = [tokenize(item["text"]) for item in items]
    lengths = [len(tokens) for tokens in tokenized]
    average_length = sum(lengths) / len(lengths) if lengths else 0.0
    document_frequency = _document_frequency(tokenized)

    scored: list[SearchResult] = []
    for item, tokens, length in zip(items, tokenized, lengths, strict=True):
        term_counts = Counter(tokens)
        score = 0.0
        reason_codes: list[str] = []
        for term in query_terms:
            frequency = term_counts.get(term, 0)
            if frequency == 0:
                continue
            reason_codes.append("term_match:%s" % term)
            score += _bm25_term_score(
                term,
                frequency,
                length,
                average_length,
                len(items),
                document_frequency,
            )
        if score > 0.0:
            scored.append(
                {
                    "item_id": item["item_id"],
                    "score": round(score, SCORE_PRECISION),
                    "source_ref": item["source_ref"],
                    "reason_codes": sorted(reason_codes),
                }
            )
    return sorted(scored, key=lambda result: (-result["score"], result["item_id"]))[:top_k]


def _document_frequency(tokenized: Sequence[Sequence[str]]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for tokens in tokenized:
        for term in set(tokens):
            counts[term] = counts.get(term, 0) + 1
    return counts


def _bm25_term_score(
    term: str,
    frequency: int,
    document_length: int,
    average_length: float,
    document_count: int,
    document_frequency: Mapping[str, int],
) -> float:
    frequency_for_term = document_frequency.get(term, 0)
    idf = math.log(1.0 + ((document_count - frequency_for_term + 0.5) / (frequency_for_term + 0.5)))
    length_norm = 1.0 - BM25_B
    if average_length > 0.0:
        length_norm += BM25_B * (document_length / average_length)
    numerator = frequency * (BM25_K1 + 1.0)
    denominator = frequency + (BM25_K1 * length_norm)
    return idf * (numerator / denominator)


def _load_search_items(
    index_path: Path | str,
    *,
    project_root: Path | str | None,
) -> tuple[IndexItem, ...]:
    path = Path(index_path)
    if path.suffix.casefold() == ".jsonl":
        try:
            return _feature_records_to_items(load_feature_records(path))
        except (OSError, ValueError):
            return collect_index_items(path, project_root=project_root)
    return collect_index_items(path, project_root=project_root)


def _feature_records_to_items(records: Sequence[FeatureRecord]) -> tuple[IndexItem, ...]:
    items: list[IndexItem] = []
    for record in records:
        feature_terms = [
            name
            for name, value in record["features"].items()
            if name != "word_count" and bool(value)
        ]
        pseudo_text = " ".join((record["item_type"], record["source_ref"], *feature_terms))
        items.append(
            {
                "item_id": record["item_id"] or stable_id("ITEM-", record["source_ref"]),
                "item_type": record["item_type"],
                "source_ref": record["source_ref"],
                "text_hash": record["text_hash"] or text_hash(pseudo_text),
                "text": pseudo_text,
                "warnings": list(record.get("warnings", [])),
            }
        )
    return tuple(items)
