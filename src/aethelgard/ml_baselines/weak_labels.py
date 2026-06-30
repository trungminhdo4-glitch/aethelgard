"""Rule-based weak supervision labels for local review queues."""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Final, NotRequired, TypedDict

from aethelgard.ml_baselines.features import (
    IndexItem,
    collect_index_items,
)
from aethelgard.ml_baselines.model_registry import (
    ModelMetadata,
    build_model_metadata,
    safe_training_ref,
)

WEAK_LABEL_MODEL_NAME: Final[str] = "WeakLabelRules"
WEAK_LABEL_MODEL_TYPE: Final[str] = "deterministic_keyword_rules"
CONFIDENCE_BASE: Final[float] = 0.55
CONFIDENCE_STEP: Final[float] = 0.05
CONFIDENCE_MAX: Final[float] = 0.95
CONFIDENCE_PRECISION: Final[int] = 2
DOCUMENT_TYPE_LABELS: Final[frozenset[str]] = frozenset(
    {"audit_or_certificate", "policy_document", "questionnaire"}
)
LABEL_RULES: Final[Mapping[str, tuple[tuple[str, ...], str]]] = {
    "backup_evidence": (
        ("backup", "restore", "restoration", "recovery time", "disaster recovery"),
        "keyword_rule:backup_restore",
    ),
    "incident_response_evidence": (
        ("incident response", "incident reporting", "escalation", "72 hours", "vorfall"),
        "keyword_rule:incident_response",
    ),
    "supplier_security_evidence": (
        ("supplier security", "supplier review", "vendor security", "third party", "lieferant"),
        "keyword_rule:supplier_security",
    ),
    "access_control_evidence": (
        ("access control", "least privilege", "mfa", "multi-factor", "privileged access"),
        "keyword_rule:access_control",
    ),
    "sbom_evidence": (
        ("sbom", "cyclonedx", "component", "package url", "checksum"),
        "keyword_rule:sbom_metadata",
    ),
    "policy_document": (
        ("policy", "procedure", "richtlinie", "prozess", "standard"),
        "keyword_rule:policy_document",
    ),
    "audit_or_certificate": (
        ("audit", "certificate", "certification", "iso 27001", "soc 2", "attestation"),
        "keyword_rule:audit_certificate",
    ),
    "questionnaire": (
        ("questionnaire", "question_id", "answer_status", "review_items", "fragebogen"),
        "keyword_rule:questionnaire",
    ),
}
NEGATIVE_CONFLICT_TERMS: Final[tuple[str, ...]] = (
    "no evidence",
    "not documented",
    "not reviewed",
    "missing",
    "kein nachweis",
)


class WeakLabelRecord(TypedDict):
    """One weak-label proposal. Labels are suggestions, never ground truth."""

    item_id: str
    weak_labels: list[str]
    label_sources: list[str]
    confidence_hint: float
    needs_review: bool
    conflict: bool
    model_metadata: NotRequired[ModelMetadata]


def build_weak_label_records(
    input_path: Path | str,
    *,
    project_root: Path | str | None = None,
    generated_at: str | None = None,
    include_metadata: bool = True,
) -> tuple[WeakLabelRecord, ...]:
    """Build weak labels for local items using transparent keyword rules."""
    items = collect_index_items(input_path, project_root=project_root)
    metadata = build_model_metadata(
        model_name=WEAK_LABEL_MODEL_NAME,
        model_type=WEAK_LABEL_MODEL_TYPE,
        training_data_ref=safe_training_ref(input_path),
        generated_at=generated_at,
        experimental=True,
    )
    records = [label_item(item, metadata if include_metadata else None) for item in items]
    return tuple(sorted(records, key=lambda record: record["item_id"]))


def write_weak_labels_jsonl(
    input_path: Path | str,
    out_path: Path | str,
    *,
    project_root: Path | str | None = None,
    generated_at: str | None = None,
) -> tuple[WeakLabelRecord, ...]:
    """Write weak-label suggestions as JSONL."""
    records = build_weak_label_records(
        input_path,
        project_root=project_root,
        generated_at=generated_at,
        include_metadata=True,
    )
    target = Path(out_path)
    target.parent.mkdir(parents=True, exist_ok=True)
    with target.open("w", encoding="utf-8", newline="\n") as output_file:
        for record in records:
            output_file.write(json.dumps(record, sort_keys=True) + "\n")
    return records


def label_item(item: IndexItem, metadata: ModelMetadata | None = None) -> WeakLabelRecord:
    """Label one in-memory item without mutating it."""
    labels, sources, rule_hits = label_text(item["text"])
    conflict = _has_conflict(labels, item["text"])
    confidence = _confidence(rule_hits, conflict)
    record: WeakLabelRecord = {
        "item_id": item["item_id"],
        "weak_labels": labels,
        "label_sources": sources,
        "confidence_hint": confidence,
        "needs_review": True,
        "conflict": conflict,
    }
    if metadata is not None:
        record["model_metadata"] = metadata
    return record


def label_text(text: str) -> tuple[list[str], list[str], int]:
    """Return weak labels, sources, and matched-rule count for text."""
    lowered = text.casefold()
    labels: list[str] = []
    sources: list[str] = []
    hit_count = 0
    for label, (terms, source) in LABEL_RULES.items():
        if any(term.casefold() in lowered for term in terms):
            labels.append(label)
            sources.append(source)
            hit_count += 1
    return sorted(labels), sorted(sources), hit_count


def _has_conflict(labels: Sequence[str], text: str) -> bool:
    document_label_count = sum(1 for label in labels if label in DOCUMENT_TYPE_LABELS)
    positive_evidence_labels = [label for label in labels if label.endswith("_evidence")]
    lowered = text.casefold()
    has_negative_marker = any(term in lowered for term in NEGATIVE_CONFLICT_TERMS)
    return document_label_count > 1 or (bool(positive_evidence_labels) and has_negative_marker)


def _confidence(rule_hits: int, conflict: bool) -> float:
    if rule_hits == 0:
        return 0.0
    confidence = min(CONFIDENCE_MAX, CONFIDENCE_BASE + (rule_hits * CONFIDENCE_STEP))
    if conflict:
        confidence -= CONFIDENCE_STEP
    return round(confidence, CONFIDENCE_PRECISION)
