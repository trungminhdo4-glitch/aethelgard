"""Experimental evidence/finding priority scoring from structured features."""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path
from typing import Final, Literal, TypedDict

from aethelgard.ml_baselines.features import (
    FeatureRecord,
    build_feature_records,
    load_feature_records,
)
from aethelgard.ml_baselines.model_registry import (
    attach_metadata,
    build_model_metadata,
    safe_training_ref,
)

Priority = Literal["P1", "P2", "P3"]

SEVERITY_MODEL_NAME: Final[str] = "RuleBasedSeverityRanker"
SEVERITY_MODEL_TYPE: Final[str] = "deterministic_structured_feature_rules"
CONFIDENCE_BASE: Final[float] = 0.5
CONFIDENCE_STEP: Final[float] = 0.08
CONFIDENCE_MAX: Final[float] = 0.9
CONFIDENCE_PRECISION: Final[int] = 2
P1_SCORE: Final[int] = 4
P2_SCORE: Final[int] = 2


class RankedFinding(TypedDict):
    """One priority suggestion requiring review."""

    finding_id: str
    suggested_priority: Priority
    confidence: float
    reason_codes: list[str]
    needs_review: bool
    model: str


class SeverityError(ValueError):
    """Raised when severity ranking input is invalid."""


def rank_findings(
    input_path: Path | str,
    *,
    project_root: Path | str | None = None,
    generated_at: str | None = None,
) -> dict[str, object]:
    """Rank findings/evidence items for human review without changing statuses."""
    records = _load_records(input_path, project_root=project_root)
    ranked = rank_feature_records(records)
    metadata = build_model_metadata(
        model_name=SEVERITY_MODEL_NAME,
        model_type=SEVERITY_MODEL_TYPE,
        training_data_ref=safe_training_ref(input_path),
        generated_at=generated_at,
        experimental=True,
    )
    return attach_metadata({"ranked_findings": ranked}, metadata)


def rank_feature_records(records: Sequence[FeatureRecord]) -> list[RankedFinding]:
    """Rank already-built feature records."""
    ranked = [_rank_record(record) for record in records]
    return sorted(
        ranked,
        key=lambda finding: (
            _priority_rank(finding["suggested_priority"]),
            -finding["confidence"],
            finding["finding_id"],
        ),
    )


def _rank_record(record: FeatureRecord) -> RankedFinding:
    reason_codes, score = _reason_codes(record)
    priority = _priority(score)
    confidence = min(CONFIDENCE_MAX, CONFIDENCE_BASE + (score * CONFIDENCE_STEP))
    return {
        "finding_id": record["item_id"],
        "suggested_priority": priority,
        "confidence": round(confidence, CONFIDENCE_PRECISION),
        "reason_codes": reason_codes,
        "needs_review": True,
        "model": SEVERITY_MODEL_NAME,
    }


def _reason_codes(record: FeatureRecord) -> tuple[list[str], int]:
    features = record["features"]
    reason_codes: list[str] = []
    score = 0
    if features.get("has_backup_terms", False) and not features.get("has_review_terms", False):
        reason_codes.append("missing_restore_test")
        score += 2
    if features.get("contains_negative_phrase", False):
        reason_codes.append("negative_evidence_phrase")
        score += 2
    if features.get("contains_future_tense", False):
        reason_codes.append("future_tense_commitment")
        score += 1
    if features.get("has_incident_terms", False) and not features.get("has_date", False):
        reason_codes.append("incident_without_date")
        score += 1
    if features.get("has_supplier_terms", False) and not features.get("has_policy_owner", False):
        reason_codes.append("supplier_without_owner")
        score += 1
    if features.get("read_error", False):
        reason_codes.append("input_read_error")
        score += 1
    if not reason_codes:
        reason_codes.append("baseline_review")
    return sorted(reason_codes), score


def _priority(score: int) -> Priority:
    if score >= P1_SCORE:
        return "P1"
    if score >= P2_SCORE:
        return "P2"
    return "P3"


def _priority_rank(priority: Priority) -> int:
    return {"P1": 0, "P2": 1, "P3": 2}[priority]


def _load_records(
    input_path: Path | str,
    *,
    project_root: Path | str | None,
) -> tuple[FeatureRecord, ...]:
    path = Path(input_path)
    if path.suffix.casefold() == ".jsonl":
        try:
            return load_feature_records(path)
        except (OSError, ValueError) as exc:
            raise SeverityError("could not load feature records") from exc
    return build_feature_records(path, project_root=project_root)
