"""Low-compute, local-only ML baseline helpers for AethelGard."""

from __future__ import annotations

from aethelgard.ml_baselines.active_learning import build_active_review_queue
from aethelgard.ml_baselines.bm25 import search_bm25
from aethelgard.ml_baselines.control_mapper import suggest_controls
from aethelgard.ml_baselines.doc_classifier import classify_documents, train_doc_type_baseline
from aethelgard.ml_baselines.features import build_feature_records, write_features_jsonl
from aethelgard.ml_baselines.severity import rank_findings
from aethelgard.ml_baselines.simhash import detect_near_duplicates
from aethelgard.ml_baselines.weak_labels import build_weak_label_records, write_weak_labels_jsonl

__all__ = [
    "build_active_review_queue",
    "build_feature_records",
    "build_weak_label_records",
    "classify_documents",
    "detect_near_duplicates",
    "rank_findings",
    "search_bm25",
    "suggest_controls",
    "train_doc_type_baseline",
    "write_features_jsonl",
    "write_weak_labels_jsonl",
]
