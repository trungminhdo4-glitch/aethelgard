"""Active-learning review queue builder for uncertain ML baseline outputs."""

from __future__ import annotations

import csv
import json
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Final, Literal, TypedDict, cast

from aethelgard.ml_baselines.model_registry import (
    attach_metadata,
    build_model_metadata,
    safe_training_ref,
)

ReviewPriority = Literal["review_first", "review_next"]

ACTIVE_LEARNING_MODEL_NAME: Final[str] = "ActiveReviewQueueRules"
ACTIVE_LEARNING_MODEL_TYPE: Final[str] = "deterministic_uncertainty_rules"
LOW_CONFIDENCE_THRESHOLD: Final[float] = 0.7
RESOLVED_REVIEW_STATUSES: Final[frozenset[str]] = frozenset(
    {"accepted", "reviewed", "rejected", "false_positive", "not_applicable", "resolved"}
)


class ReviewQueueItem(TypedDict):
    """One item that should be reviewed by a human."""

    item_id: str
    reason: str
    priority: ReviewPriority
    needs_review: bool


class ActiveLearningError(ValueError):
    """Raised when active-learning queue inputs cannot be parsed."""


def build_active_review_queue(
    *,
    predictions_path: Path | str | None = None,
    weak_labels_path: Path | str | None = None,
    duplicates_path: Path | str | None = None,
    severity_path: Path | str | None = None,
    review_csv_path: Path | str | None = None,
    generated_at: str | None = None,
) -> dict[str, object]:
    """Build a deterministic review queue from baseline outputs."""
    reasons: dict[str, set[str]] = {}
    priorities: dict[str, ReviewPriority] = {}
    if predictions_path is not None:
        _collect_prediction_reasons(Path(predictions_path), reasons, priorities)
    if weak_labels_path is not None:
        _collect_weak_label_reasons(Path(weak_labels_path), reasons, priorities)
    if duplicates_path is not None:
        _collect_duplicate_reasons(Path(duplicates_path), reasons, priorities)
    if severity_path is not None:
        _collect_severity_reasons(Path(severity_path), reasons, priorities)
    if review_csv_path is not None:
        _apply_review_csv(Path(review_csv_path), reasons, priorities)
    queue = _queue_items(reasons, priorities)
    metadata = build_model_metadata(
        model_name=ACTIVE_LEARNING_MODEL_NAME,
        model_type=ACTIVE_LEARNING_MODEL_TYPE,
        training_data_ref=_training_refs(
            predictions_path,
            weak_labels_path,
            duplicates_path,
            severity_path,
            review_csv_path,
        ),
        generated_at=generated_at,
        experimental=True,
    )
    return attach_metadata({"review_queue": queue}, metadata)


def _collect_prediction_reasons(
    path: Path,
    reasons: dict[str, set[str]],
    priorities: dict[str, ReviewPriority],
) -> None:
    payload = _read_json(path)
    for prediction in _mapping_sequence(payload.get("predictions", ())):
        item_id = str(prediction.get("item_id", "")).strip()
        confidence = _float_value(prediction.get("confidence", 0.0))
        if item_id and confidence < LOW_CONFIDENCE_THRESHOLD:
            _add_reason(
                reasons,
                priorities,
                item_id,
                "low_confidence_doc_classification",
                "review_next",
            )
    for record in _mapping_sequence(payload.get("suggestions", ())):
        item_id = str(record.get("item_id", "")).strip()
        controls = _mapping_sequence(record.get("suggested_controls", ()))
        for control in controls:
            confidence = _float_value(control.get("confidence", 0.0))
            if item_id and confidence < LOW_CONFIDENCE_THRESHOLD:
                _add_reason(
                    reasons,
                    priorities,
                    item_id,
                    "low_confidence_control_mapping",
                    "review_next",
                )


def _collect_weak_label_reasons(
    path: Path,
    reasons: dict[str, set[str]],
    priorities: dict[str, ReviewPriority],
) -> None:
    for record in _read_json_or_jsonl(path):
        item_id = str(record.get("item_id", "")).strip()
        labels = [str(label) for label in _sequence(record.get("weak_labels", ()))]
        if not item_id:
            continue
        if bool(record.get("conflict", False)):
            _add_reason(reasons, priorities, item_id, "label_conflict", "review_first")
        if not labels:
            _add_reason(reasons, priorities, item_id, "new_unknown_document_pattern", "review_next")


def _collect_duplicate_reasons(
    path: Path,
    reasons: dict[str, set[str]],
    priorities: dict[str, ReviewPriority],
) -> None:
    payload = _read_json(path)
    for duplicate in _mapping_sequence(payload.get("duplicates", ())):
        if not bool(duplicate.get("needs_review", False)):
            continue
        for key in ("item_a", "item_b"):
            item_id = str(duplicate.get(key, "")).strip()
            if item_id:
                _add_reason(reasons, priorities, item_id, "duplicate_conflict", "review_first")


def _collect_severity_reasons(
    path: Path,
    reasons: dict[str, set[str]],
    priorities: dict[str, ReviewPriority],
) -> None:
    payload = _read_json(path)
    for finding in _mapping_sequence(payload.get("ranked_findings", ())):
        item_id = str(finding.get("finding_id", "")).strip()
        priority = str(finding.get("suggested_priority", ""))
        confidence = _float_value(finding.get("confidence", 0.0))
        if not item_id:
            continue
        if priority == "P1" and confidence < LOW_CONFIDENCE_THRESHOLD:
            _add_reason(
                reasons,
                priorities,
                item_id,
                "high_severity_low_confidence",
                "review_first",
            )
        elif priority == "P1":
            _add_reason(reasons, priorities, item_id, "high_priority_review", "review_first")


def _apply_review_csv(
    path: Path,
    reasons: dict[str, set[str]],
    priorities: dict[str, ReviewPriority],
) -> None:
    with path.open(encoding="utf-8", newline="") as csv_file:
        rows = list(csv.DictReader(csv_file))
    for row in rows:
        item_id = str(row.get("finding_id", "")).strip()
        status = str(row.get("review_status", "")).strip().casefold()
        if not item_id:
            continue
        if status in RESOLVED_REVIEW_STATUSES:
            reasons.pop(item_id, None)
            priorities.pop(item_id, None)
        elif status == "needs_evidence":
            _add_reason(reasons, priorities, item_id, "review_needs_evidence", "review_first")


def _queue_items(
    reasons: Mapping[str, set[str]],
    priorities: Mapping[str, ReviewPriority],
) -> list[ReviewQueueItem]:
    queue: list[ReviewQueueItem] = [
        {
            "item_id": item_id,
            "reason": "|".join(sorted(item_reasons)),
            "priority": priorities.get(item_id, "review_next"),
            "needs_review": True,
        }
        for item_id, item_reasons in reasons.items()
        if item_reasons
    ]
    return sorted(queue, key=lambda item: (_priority_rank(item["priority"]), item["item_id"]))


def _add_reason(
    reasons: dict[str, set[str]],
    priorities: dict[str, ReviewPriority],
    item_id: str,
    reason: str,
    priority: ReviewPriority,
) -> None:
    reasons.setdefault(item_id, set()).add(reason)
    if priority == "review_first" or item_id not in priorities:
        priorities[item_id] = priority


def _priority_rank(priority: ReviewPriority) -> int:
    return {"review_first": 0, "review_next": 1}[priority]


def _read_json(path: Path) -> Mapping[str, object]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ActiveLearningError("could not read JSON input: %s" % path.name) from exc
    except json.JSONDecodeError as exc:
        raise ActiveLearningError("invalid JSON input: %s" % path.name) from exc
    if not isinstance(payload, Mapping):
        raise ActiveLearningError("JSON input must contain an object: %s" % path.name)
    return cast(Mapping[str, object], payload)


def _read_json_or_jsonl(path: Path) -> tuple[Mapping[str, object], ...]:
    if path.suffix.casefold() != ".jsonl":
        payload = _read_json(path)
        raw_records = payload.get("records", ())
        return _mapping_sequence(raw_records)
    jsonl_records: list[Mapping[str, object]] = []
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise ActiveLearningError("could not read JSONL input: %s" % path.name) from exc
    for line in lines:
        if not line.strip():
            continue
        try:
            payload = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ActiveLearningError("invalid JSONL input: %s" % path.name) from exc
        if not isinstance(payload, Mapping):
            raise ActiveLearningError("JSONL rows must contain objects: %s" % path.name)
        jsonl_records.append(payload)
    return tuple(jsonl_records)


def _float_value(value: object) -> float:
    if isinstance(value, (str, bytes, bytearray, int, float)):
        return float(value)
    return 0.0


def _mapping_sequence(value: object) -> tuple[Mapping[str, object], ...]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        return ()
    return tuple(cast(Mapping[str, object], item) for item in value if isinstance(item, Mapping))


def _sequence(value: object) -> tuple[object, ...]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        return ()
    return tuple(value)


def _training_refs(*paths: Path | str | None) -> str:
    refs = [safe_training_ref(path) for path in paths if path is not None]
    return ",".join(refs) if refs else "none"
