"""Experimental multi-label control suggestions for evidence review."""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import Final, Literal, TypedDict

from aethelgard.ml_baselines.features import IndexItem, collect_index_items
from aethelgard.ml_baselines.model_registry import (
    attach_metadata,
    build_model_metadata,
    safe_training_ref,
)

ControlSuggestionStatus = Literal["suggested", "experimental"]

CONTROL_MAPPER_MODEL_NAME: Final[str] = "RuleBasedControlMapper"
CONTROL_MAPPER_MODEL_TYPE: Final[str] = "deterministic_multilabel_rules"
DEFAULT_CONTROL_CONFIDENCE_THRESHOLD: Final[float] = 0.55
SUGGESTED_STATUS_THRESHOLD: Final[float] = 0.7
CONFIDENCE_BASE: Final[float] = 0.45
CONFIDENCE_STEP: Final[float] = 0.1
CONFIDENCE_MAX: Final[float] = 0.9
CONFIDENCE_PRECISION: Final[int] = 2
CONTROL_RULES: Final[Mapping[str, tuple[str, ...]]] = {
    "NIS2-SCRM-01": (
        "supplier security",
        "supplier review",
        "vendor security",
        "third party",
        "due diligence",
        "contractual security",
        "lieferant",
    ),
    "NIS2-SCRM-02": (
        "incident response",
        "incident reporting",
        "incident timeline",
        "supplier incident",
        "escalation",
        "72 hours",
        "vorfall",
    ),
    "NIS2-SCRM-03": (
        "vulnerability management",
        "patch management",
        "security patch",
        "remediation timeline",
        "change control",
        "secure development",
        "sbom",
    ),
    "NIS2-SCRM-04": (
        "business continuity",
        "backup restore",
        "backup",
        "restore",
        "disaster recovery",
        "continuity exercise",
        "recovery time",
    ),
    "NIS2-SCRM-05": (
        "access control",
        "least privilege",
        "multi-factor authentication",
        "mfa",
        "access review",
        "privileged access",
        "secure communications",
    ),
}


class SuggestedControl(TypedDict):
    """One control suggestion that still requires human review."""

    control_id: str
    confidence: float
    status: ControlSuggestionStatus
    needs_review: bool
    reason_codes: list[str]


class ControlSuggestionRecord(TypedDict):
    """Suggestions for one local item."""

    item_id: str
    suggested_controls: list[SuggestedControl]
    needs_review: bool


class ControlMapperError(ValueError):
    """Raised when control mapping input is invalid."""


def suggest_controls(
    input_path: Path | str,
    *,
    min_confidence: float = DEFAULT_CONTROL_CONFIDENCE_THRESHOLD,
    project_root: Path | str | None = None,
    generated_at: str | None = None,
) -> dict[str, object]:
    """Suggest mapped controls without changing any review decision."""
    if min_confidence < 0.0 or min_confidence > 1.0:
        raise ControlMapperError("min_confidence must be between 0.0 and 1.0")
    items = collect_index_items(input_path, project_root=project_root)
    suggestions = [
        suggest_controls_for_item(item, min_confidence=min_confidence)
        for item in sorted(items, key=lambda value: (value["source_ref"], value["item_id"]))
    ]
    metadata = build_model_metadata(
        model_name=CONTROL_MAPPER_MODEL_NAME,
        model_type=CONTROL_MAPPER_MODEL_TYPE,
        training_data_ref=safe_training_ref(input_path),
        generated_at=generated_at,
        experimental=True,
    )
    return attach_metadata({"suggestions": suggestions}, metadata)


def suggest_controls_for_item(
    item: IndexItem,
    *,
    min_confidence: float = DEFAULT_CONTROL_CONFIDENCE_THRESHOLD,
) -> ControlSuggestionRecord:
    """Suggest controls for a single in-memory item."""
    lowered = item["text"].casefold()
    controls: list[SuggestedControl] = []
    for control_id, terms in CONTROL_RULES.items():
        matched_terms = sorted(term for term in terms if term.casefold() in lowered)
        if not matched_terms:
            continue
        confidence = min(CONFIDENCE_MAX, CONFIDENCE_BASE + (len(matched_terms) * CONFIDENCE_STEP))
        if confidence < min_confidence:
            continue
        controls.append(
            {
                "control_id": control_id,
                "confidence": round(confidence, CONFIDENCE_PRECISION),
                "status": _status_for_confidence(confidence),
                "needs_review": True,
                "reason_codes": ["term_match:%s" % term for term in matched_terms],
            }
        )
    return {
        "item_id": item["item_id"],
        "suggested_controls": sorted(controls, key=lambda control: control["control_id"]),
        "needs_review": True,
    }


def _status_for_confidence(confidence: float) -> ControlSuggestionStatus:
    if confidence >= SUGGESTED_STATUS_THRESHOLD:
        return "suggested"
    return "experimental"
