"""Metadata-only delivery profile validation for local consultant handoff."""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from pathlib import Path
from typing import Final, Literal, TypedDict

DELIVERY_PROFILE_SCHEMA_VERSION: Final[str] = "1.0"
DELIVERY_PROFILE_TYPE: Final[str] = "delivery_profile"
ALLOWED_DISCLAIMER_MODES: Final[frozenset[str]] = frozenset({"pilot", "standard", "strict"})
REQUIRED_FIELDS: Final[tuple[str, ...]] = (
    "display_name",
    "consultant_name",
    "contact_label",
    "report_footer",
    "disclaimer_mode",
)
OPTIONAL_INPUT_FIELDS: Final[frozenset[str]] = frozenset({"schema_version"})
MAX_FIELD_LENGTHS: Final[Mapping[str, int]] = {
    "display_name": 80,
    "consultant_name": 80,
    "contact_label": 120,
    "report_footer": 180,
    "disclaimer_mode": 20,
}
EMAIL_PATTERN: Final[re.Pattern[str]] = re.compile(
    r"[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}",
    re.IGNORECASE,
)
PHONE_PATTERN: Final[re.Pattern[str]] = re.compile(
    r"(?:\+\d{2,}[\d\s().-]{5,}\d|\b\d{3}[\s().-]\d{3}[\s().-]\d{3,}\b)"
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

DisclaimerMode = Literal["pilot", "standard", "strict"]


class DeliveryProfile(TypedDict):
    """Normalized white-label/delivery metadata with no private operator data."""

    schema_version: str
    profile_type: str
    display_name: str
    consultant_name: str
    contact_label: str
    report_footer: str
    disclaimer_mode: DisclaimerMode
    white_label_core_override: bool
    trust_bundle_safety_overrides: bool
    manual_review_required: bool


class DeliveryProfileError(ValueError):
    """Raised when a delivery profile is unsafe or invalid."""


def validate_delivery_profile(
    input_path: Path | str,
    out_path: Path | str,
) -> DeliveryProfile:
    """Validate and write a deterministic normalized delivery profile."""
    payload = _read_mapping(Path(input_path))
    profile = normalize_delivery_profile(payload)
    target = Path(out_path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(profile, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return profile


def normalize_delivery_profile(payload: Mapping[str, object]) -> DeliveryProfile:
    """Normalize profile fields and reject private paths, PII, and secret markers."""
    allowed_input_fields = set(REQUIRED_FIELDS) | set(OPTIONAL_INPUT_FIELDS)
    unknown_fields = sorted(
        str(field) for field in payload if str(field) not in allowed_input_fields
    )
    if unknown_fields:
        raise DeliveryProfileError("delivery profile contains unsupported fields")
    schema_version = str(payload.get("schema_version", DELIVERY_PROFILE_SCHEMA_VERSION)).strip()
    if schema_version != DELIVERY_PROFILE_SCHEMA_VERSION:
        raise DeliveryProfileError("unsupported delivery profile schema_version")
    values = {field: _safe_string(field, payload.get(field)) for field in REQUIRED_FIELDS}
    disclaimer_mode = values["disclaimer_mode"].casefold()
    if disclaimer_mode not in ALLOWED_DISCLAIMER_MODES:
        raise DeliveryProfileError("delivery profile has invalid disclaimer_mode")
    return {
        "schema_version": DELIVERY_PROFILE_SCHEMA_VERSION,
        "profile_type": DELIVERY_PROFILE_TYPE,
        "display_name": values["display_name"],
        "consultant_name": values["consultant_name"],
        "contact_label": values["contact_label"],
        "report_footer": values["report_footer"],
        "disclaimer_mode": _as_disclaimer_mode(disclaimer_mode),
        "white_label_core_override": False,
        "trust_bundle_safety_overrides": False,
        "manual_review_required": True,
    }


def _read_mapping(path: Path) -> Mapping[str, object]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise DeliveryProfileError("could not read delivery profile") from exc
    except json.JSONDecodeError as exc:
        raise DeliveryProfileError("invalid delivery profile JSON") from exc
    if not isinstance(payload, Mapping):
        raise DeliveryProfileError("delivery profile must be a JSON object")
    return payload


def _safe_string(field: str, value: object) -> str:
    if not isinstance(value, str):
        raise DeliveryProfileError("delivery profile field is required: %s" % field)
    normalized = " ".join(value.split())
    if not normalized:
        raise DeliveryProfileError("delivery profile field is empty: %s" % field)
    max_length = MAX_FIELD_LENGTHS[field]
    if len(normalized) > max_length:
        raise DeliveryProfileError("delivery profile field is too long: %s" % field)
    if _has_private_marker(normalized):
        raise DeliveryProfileError("delivery profile contains private or secret-like data")
    return normalized


def _has_private_marker(value: str) -> bool:
    patterns = (
        EMAIL_PATTERN,
        PHONE_PATTERN,
        IP_PATTERN,
        PRIVATE_PATH_PATTERN,
        SECRET_MARKER_PATTERN,
    )
    return any(pattern.search(value) is not None for pattern in patterns)


def _as_disclaimer_mode(value: str) -> DisclaimerMode:
    if value == "pilot":
        return "pilot"
    if value == "standard":
        return "standard"
    return "strict"
