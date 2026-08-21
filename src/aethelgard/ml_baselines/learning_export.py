"""Privacy-safe local learning-feedback export contracts."""

from __future__ import annotations

import csv
import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Final, Literal, TypedDict, cast

LEARNING_EXPORT_SCHEMA_VERSION: Final[str] = "1.0"
LEARNING_EXPORT_MODE: Final[str] = "redacted_review_feedback"
ITEM_HASH_PREFIX: Final[str] = "learning-feedback-v1"
UNMAPPED_CONTROL_ID: Final[str] = "UNMAPPED"
ALLOWED_CONTROL_IDS: Final[frozenset[str]] = frozenset(
    {
        UNMAPPED_CONTROL_ID,
        "NIS2-SCRM-01",
        "NIS2-SCRM-02",
        "NIS2-SCRM-03",
        "NIS2-SCRM-04",
        "NIS2-SCRM-05",
    }
)
ALLOWED_REVIEW_DECISIONS: Final[frozenset[str]] = frozenset(
    {
        "accepted",
        "candidate_evidence",
        "false_positive",
        "manual_review",
        "needs_evidence",
        "not_applicable",
        "open",
        "rejected",
        "resolved",
        "reviewed",
        "warning_review",
    }
)
ALLOWED_REASON_CODES: Final[frozenset[str]] = frozenset(
    {
        "baseline_review",
        "control_term_match",
        "doc_classification_signal",
        "duplicate_conflict",
        "future_tense_commitment",
        "high_priority_review",
        "high_severity_low_confidence",
        "incident_without_date",
        "input_read_error",
        "label_conflict",
        "low_confidence_control_mapping",
        "low_confidence_doc_classification",
        "missing_restore_test",
        "negative_evidence_phrase",
        "new_unknown_document_pattern",
        "review_needs_evidence",
        "review_signal_only",
        "supplier_without_owner",
    }
)
FORBIDDEN_PAYLOAD_KEYS: Final[frozenset[str]] = frozenset(
    {
        "file",
        "filename",
        "notes",
        "path",
        "raw_snippet",
        "raw_text",
        "review_note",
        "snippet",
        "source_citation",
        "source_path",
        "source_ref",
        "text",
    }
)
SAFE_METADATA_KEYS: Final[frozenset[str]] = frozenset(
    {
        "experimental",
        "feature_schema_version",
        "generated_at",
        "git_commit",
        "model_metadata",
        "model_name",
        "model_type",
        "model_version",
        "registry_schema_version",
        "sklearn_available",
        "tool_version",
        "training_data_ref",
    }
)
ITEM_ID_PATTERN: Final[re.Pattern[str]] = re.compile(r"^[A-Za-z0-9:_-]{1,96}$")
EMAIL_PATTERN: Final[re.Pattern[str]] = re.compile(
    r"[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}",
    re.IGNORECASE,
)
IP_PATTERN: Final[re.Pattern[str]] = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
PRIVATE_PATH_PATTERN: Final[re.Pattern[str]] = re.compile(
    r"(?:[A-Za-z]:[\\/]|\\\\|/home/|/Users/)",
    re.IGNORECASE,
)
SECRET_MARKER_PATTERN: Final[re.Pattern[str]] = re.compile(
    r"(?:\.env|\b(?:api[_ -]?key|authorization|bearer|cookie|credential|password|"
    r"secret|token)s?\b)",
    re.IGNORECASE,
)
TOKEN_LIKE_PATTERN: Final[re.Pattern[str]] = re.compile(
    r"\b(?:(?:sk|pk|ghp)_[A-Za-z0-9_]{16,}|[A-Za-z0-9_-]{48,})\b"
)
UNSAFE_PATH_PARTS: Final[tuple[str, ...]] = (
    ".env",
    "credential",
    "cookie",
    "database",
    "log",
    "secret",
    "token",
)

ConfidenceBucket = Literal["high", "low", "medium", "unknown"]


class LearningExportItem(TypedDict):
    """One redacted learning signal without file names or free text."""

    item_type: str
    item_hash: str
    suggested_control: str
    review_decision: str
    reason_codes: list[str]
    confidence_bucket: ConfidenceBucket


class LearningExportPayload(TypedDict):
    """Redacted learning-feedback export envelope."""

    schema_version: str
    export_mode: str
    contains_raw_text: bool
    contains_file_paths: bool
    contains_customer_identifiers: bool
    requires_owner_approval: bool
    safe_for_vendor_upload: bool
    manual_review_required: bool
    item_count: int
    items: list[LearningExportItem]


class PredictionSignal(TypedDict):
    """Internal allowlisted signal derived from local ML outputs."""

    suggested_control: str
    reason_codes: list[str]
    confidence: float


class LearningExportError(ValueError):
    """Raised when a learning export input is not privacy-safe."""


def export_learning_feedback(
    *,
    review_csv_path: Path | str,
    predictions_path: Path | str,
    out_path: Path | str,
) -> LearningExportPayload:
    """Write a redacted, owner-gated learning-feedback file."""
    review_rows = _read_review_rows(_safe_input_path(review_csv_path))
    prediction_payload = _read_json(_safe_input_path(predictions_path))
    _validate_payload_privacy(prediction_payload)
    signals = _prediction_signals(prediction_payload)
    items = [
        _export_item(row, signals.get(row["item_id"], _empty_signal()))
        for row in sorted(review_rows, key=lambda value: value["item_id"])
    ]
    payload: LearningExportPayload = {
        "schema_version": LEARNING_EXPORT_SCHEMA_VERSION,
        "export_mode": LEARNING_EXPORT_MODE,
        "contains_raw_text": False,
        "contains_file_paths": False,
        "contains_customer_identifiers": False,
        "requires_owner_approval": True,
        "safe_for_vendor_upload": False,
        "manual_review_required": True,
        "item_count": len(items),
        "items": items,
    }
    _validate_output_privacy(payload)
    target = Path(out_path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return payload


def _read_review_rows(path: Path) -> list[dict[str, str]]:
    try:
        with path.open(encoding="utf-8", newline="") as csv_file:
            reader = csv.DictReader(csv_file)
            rows = list(reader)
    except OSError as exc:
        raise LearningExportError("could not read review CSV") from exc
    clean_rows: list[dict[str, str]] = []
    for row in rows:
        clean_row = {str(key): str(value or "") for key, value in row.items() if key is not None}
        _validate_review_row(clean_row)
        item_id = (clean_row.get("finding_id") or clean_row.get("item_id") or "").strip()
        if not item_id:
            continue
        review_decision = (clean_row.get("review_status") or "open").strip().casefold() or "open"
        if review_decision not in ALLOWED_REVIEW_DECISIONS:
            raise LearningExportError("unsupported review_status in learning export")
        clean_rows.append({"item_id": item_id, "review_decision": review_decision})
    return clean_rows


def _validate_review_row(row: Mapping[str, str]) -> None:
    for key, value in row.items():
        normalized_key = key.strip().casefold()
        if normalized_key in FORBIDDEN_PAYLOAD_KEYS and value.strip():
            raise LearningExportError("review CSV contains unsupported free-text/private fields")
        _ensure_safe_value(value)
    item_id = (row.get("finding_id") or row.get("item_id") or "").strip()
    if item_id:
        _validate_item_id(item_id)


def _read_json(path: Path) -> Mapping[str, object]:
    try:
        payload = cast(object, json.loads(path.read_text(encoding="utf-8")))
    except OSError as exc:
        raise LearningExportError("could not read predictions JSON") from exc
    except json.JSONDecodeError as exc:
        raise LearningExportError("invalid predictions JSON") from exc
    if not isinstance(payload, Mapping):
        raise LearningExportError("predictions must be a JSON object")
    return cast(Mapping[str, object], payload)


def _prediction_signals(payload: Mapping[str, object]) -> dict[str, PredictionSignal]:
    signals: dict[str, PredictionSignal] = {}
    _collect_doc_prediction_signals(payload.get("predictions", ()), signals)
    _collect_control_suggestion_signals(payload.get("suggestions", ()), signals)
    _collect_severity_signals(payload.get("ranked_findings", ()), signals)
    _collect_review_queue_signals(payload.get("review_queue", ()), signals)
    return signals


def _collect_doc_prediction_signals(
    value: object,
    signals: dict[str, PredictionSignal],
) -> None:
    for prediction in _mapping_sequence(value):
        item_id = str(prediction.get("item_id", "")).strip()
        if not item_id:
            continue
        _validate_item_id(item_id)
        confidence = _float_value(prediction.get("confidence", -1.0))
        reason = (
            "low_confidence_doc_classification"
            if 0.0 <= confidence < 0.7
            else "doc_classification_signal"
        )
        _merge_signal(signals, item_id, UNMAPPED_CONTROL_ID, [reason], confidence)


def _collect_control_suggestion_signals(
    value: object,
    signals: dict[str, PredictionSignal],
) -> None:
    for suggestion in _mapping_sequence(value):
        item_id = str(suggestion.get("item_id", "")).strip()
        if not item_id:
            continue
        _validate_item_id(item_id)
        best_control = UNMAPPED_CONTROL_ID
        best_confidence = -1.0
        reason_codes: list[str] = []
        for control in _mapping_sequence(suggestion.get("suggested_controls", ())):
            control_id = str(control.get("control_id", "")).strip()
            if control_id not in ALLOWED_CONTROL_IDS:
                raise LearningExportError("unsupported control_id in learning export")
            confidence = _float_value(control.get("confidence", -1.0))
            if confidence > best_confidence or (
                confidence == best_confidence and control_id < best_control
            ):
                best_control = control_id
                best_confidence = confidence
            reason_codes.extend(_coerce_reason_codes(control.get("reason_codes", ())))
        _merge_signal(signals, item_id, best_control, reason_codes, best_confidence)


def _collect_severity_signals(value: object, signals: dict[str, PredictionSignal]) -> None:
    for finding in _mapping_sequence(value):
        item_id = str(finding.get("finding_id", "")).strip()
        if not item_id:
            continue
        _validate_item_id(item_id)
        reason_codes = _coerce_reason_codes(finding.get("reason_codes", ()))
        if str(finding.get("suggested_priority", "")) == "P1":
            reason_codes.append("high_priority_review")
        _merge_signal(
            signals,
            item_id,
            UNMAPPED_CONTROL_ID,
            reason_codes,
            _float_value(finding.get("confidence", -1.0)),
        )


def _collect_review_queue_signals(value: object, signals: dict[str, PredictionSignal]) -> None:
    for item in _mapping_sequence(value):
        item_id = str(item.get("item_id", "")).strip()
        if not item_id:
            continue
        _validate_item_id(item_id)
        reason_codes = _coerce_reason_codes(str(item.get("reason", "")).split("|"))
        _merge_signal(signals, item_id, UNMAPPED_CONTROL_ID, reason_codes, -1.0)


def _merge_signal(
    signals: dict[str, PredictionSignal],
    item_id: str,
    suggested_control: str,
    reason_codes: Sequence[str],
    confidence: float,
) -> None:
    existing = signals.get(item_id, _empty_signal())
    control = existing["suggested_control"]
    if control == UNMAPPED_CONTROL_ID and suggested_control != UNMAPPED_CONTROL_ID:
        control = suggested_control
    merged_reasons = sorted(set(existing["reason_codes"]) | set(reason_codes))
    signals[item_id] = {
        "suggested_control": control,
        "reason_codes": merged_reasons,
        "confidence": max(existing["confidence"], confidence),
    }


def _export_item(row: Mapping[str, str], signal: PredictionSignal) -> LearningExportItem:
    reason_codes = signal["reason_codes"] or ["review_signal_only"]
    return {
        "item_type": "finding",
        "item_hash": _item_hash(row["item_id"]),
        "suggested_control": signal["suggested_control"],
        "review_decision": row["review_decision"],
        "reason_codes": sorted(reason_codes),
        "confidence_bucket": _confidence_bucket(signal["confidence"]),
    }


def _coerce_reason_codes(value: object) -> list[str]:
    reason_codes: list[str] = []
    for raw_reason in _string_sequence(value):
        reason = raw_reason.strip().casefold()
        if not reason:
            continue
        if reason.startswith("term_match:"):
            reason = "control_term_match"
        if reason not in ALLOWED_REASON_CODES:
            raise LearningExportError("unsupported reason_code in learning export")
        reason_codes.append(reason)
    return sorted(set(reason_codes))


def _confidence_bucket(confidence: float) -> ConfidenceBucket:
    if confidence < 0.0:
        return "unknown"
    if confidence >= 0.75:
        return "high"
    if confidence >= 0.5:
        return "medium"
    return "low"


def _item_hash(item_id: str) -> str:
    digest = hashlib.sha256(("%s:%s" % (ITEM_HASH_PREFIX, item_id)).encode("utf-8")).hexdigest()
    return "sha256:%s" % digest


def _empty_signal() -> PredictionSignal:
    return {"suggested_control": UNMAPPED_CONTROL_ID, "reason_codes": [], "confidence": -1.0}


def _mapping_sequence(value: object) -> tuple[Mapping[str, object], ...]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        return ()
    return tuple(cast(Mapping[str, object], item) for item in value if isinstance(item, Mapping))


def _string_sequence(value: object) -> tuple[str, ...]:
    if isinstance(value, str):
        return (value,)
    if not isinstance(value, Sequence) or isinstance(value, (bytes, bytearray)):
        return ()
    return tuple(str(item) for item in value)


def _float_value(value: object) -> float:
    if isinstance(value, (int, float, str, bytes, bytearray)):
        try:
            return float(value)
        except ValueError:
            return -1.0
    return -1.0


def _safe_input_path(path: Path | str) -> Path:
    value = Path(path)
    parts = tuple(part.casefold() for part in value.parts)
    for part in parts:
        if part == ".env" or any(marker in part for marker in UNSAFE_PATH_PARTS):
            raise LearningExportError("learning export input path is unsafe")
    suffix = value.suffix.casefold()
    if suffix in {".db", ".sqlite", ".sqlite3", ".log"}:
        raise LearningExportError("learning export input path is unsafe")
    return value


def _validate_payload_privacy(value: object, *, key_name: str = "") -> None:
    if isinstance(value, Mapping):
        for key, item in value.items():
            normalized_key = str(key).strip().casefold()
            if normalized_key in FORBIDDEN_PAYLOAD_KEYS and str(item).strip():
                raise LearningExportError("learning export input contains raw/private fields")
            if normalized_key in SAFE_METADATA_KEYS and normalized_key not in {
                "model_metadata",
                "training_data_ref",
            }:
                continue
            _validate_payload_privacy(item, key_name=normalized_key)
        return
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        for item in value:
            _validate_payload_privacy(item, key_name=key_name)
        return
    if isinstance(value, (str, bytes, bytearray)):
        _ensure_safe_value(str(value), allow_git_commit=key_name == "git_commit")


def _validate_output_privacy(payload: LearningExportPayload) -> None:
    rendered = json.dumps(payload, sort_keys=True)
    _ensure_safe_value(rendered, allow_git_commit=True)
    forbidden_literals = (".env", "C:\\Users", "C:/Users", "D:\\", "/home/", "token", "cookie")
    if any(literal.casefold() in rendered.casefold() for literal in forbidden_literals):
        raise LearningExportError("learning export output contains forbidden markers")


def _ensure_safe_value(value: str, *, allow_git_commit: bool = False) -> None:
    if not value:
        return
    patterns = (EMAIL_PATTERN, IP_PATTERN, PRIVATE_PATH_PATTERN, SECRET_MARKER_PATTERN)
    if any(pattern.search(value) is not None for pattern in patterns):
        raise LearningExportError("learning export contains private or secret-like data")
    if not allow_git_commit and TOKEN_LIKE_PATTERN.search(value) is not None:
        raise LearningExportError("learning export contains private or secret-like data")


def _validate_item_id(item_id: str) -> None:
    _ensure_safe_value(item_id)
    if ITEM_ID_PATTERN.fullmatch(item_id) is None:
        raise LearningExportError("learning export item_id is not safe")
