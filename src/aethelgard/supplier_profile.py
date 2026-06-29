"""Supplier profile contract for local C-SCRM cascade references."""

from __future__ import annotations

import json
import re
from collections.abc import Sequence
from pathlib import Path
from typing import Final, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from aethelgard.redaction_preflight import has_sensitive_markers

SUPPLIER_PROFILE_SCHEMA_VERSION: Final[str] = "1.0"
MAX_SUPPLIER_ID_CHARS: Final[int] = 80
MAX_RELATIONSHIP_REF_CHARS: Final[int] = 120
MAX_PROFILE_REFS: Final[int] = 200
SUPPLIER_REF_PATTERN: Final[str] = r"^[A-Za-z0-9_.:-]+$"
SUPPLIER_RISK_REF_PATTERN: Final[str] = r"^[A-Za-z0-9_.:-]+\.json$"
FORBIDDEN_SUPPLIER_PROFILE_MARKERS: Final[tuple[str, ...]] = (
    ".env",
    "api_key",
    "audit_passed",
    "c:/users/",
    "c:\\users\\",
    "certified",
    "compliance_status",
    "cookie",
    "cookies",
    "debug.log",
    "internal_url",
    "nis2_compliant",
    "raw_evidence",
    "raw_notes",
    "raw_snippet",
    "secret",
    "source_path",
    "token" "=",
)

SupplierCriticality = Literal["low", "medium", "high", "critical"]
SupplierRelationshipType = Literal[
    "direct",
    "subcontractor",
    "managed_service_provider",
    "software_vendor",
    "other",
]


class SupplierProfileContractError(ValueError):
    """Raised when a supplier profile contract is unsafe or invalid."""


class SupplierProfileContract(BaseModel):
    """Metadata-only supplier cascade contract."""

    model_config = ConfigDict(
        frozen=True,
        extra="forbid",
        str_strip_whitespace=True,
    )

    schema_version: str = SUPPLIER_PROFILE_SCHEMA_VERSION
    supplier_id: str = Field(
        min_length=1,
        max_length=MAX_SUPPLIER_ID_CHARS,
        pattern=SUPPLIER_REF_PATTERN,
    )
    criticality: SupplierCriticality
    relationship_type: SupplierRelationshipType
    evidence_refs: tuple[str, ...] = Field(default=(), max_length=MAX_PROFILE_REFS)
    questionnaire_refs: tuple[str, ...] = Field(default=(), max_length=MAX_PROFILE_REFS)
    sbom_refs: tuple[str, ...] = Field(default=(), max_length=MAX_PROFILE_REFS)
    risk_summary_ref: str = Field(
        min_length=1,
        max_length=MAX_RELATIONSHIP_REF_CHARS,
        pattern=SUPPLIER_RISK_REF_PATTERN,
    )

    @field_validator("supplier_id", "risk_summary_ref")
    @classmethod
    def _validate_safe_string(cls, value: str) -> str:
        _validate_safe_profile_text(value)
        return value

    @field_validator("evidence_refs", "questionnaire_refs", "sbom_refs", mode="before")
    @classmethod
    def _normalize_ref_tuple(cls, value: object) -> tuple[str, ...]:
        return _normalize_ref_tuple(value)

    @field_validator("evidence_refs", "questionnaire_refs", "sbom_refs")
    @classmethod
    def _validate_ref_tuple(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        for item in value:
            if len(item) > MAX_RELATIONSHIP_REF_CHARS:
                raise ValueError("supplier profile reference exceeds length limit")
            if re.fullmatch(SUPPLIER_REF_PATTERN, item) is None:
                raise ValueError("supplier profile reference has unsupported characters")
            _validate_safe_profile_text(item)
        return value


def load_supplier_profile_contract(path: Path | str) -> SupplierProfileContract:
    """Load and validate a supplier profile contract JSON document."""
    profile_path = Path(path)
    try:
        payload = json.loads(profile_path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise SupplierProfileContractError(
            "could not read supplier profile contract: %s" % profile_path
        ) from exc
    except json.JSONDecodeError as exc:
        raise SupplierProfileContractError(
            "invalid supplier profile contract JSON: %s" % profile_path
        ) from exc
    if not isinstance(payload, dict):
        raise SupplierProfileContractError("supplier profile contract must contain a JSON object")
    try:
        return SupplierProfileContract.model_validate(payload)
    except ValueError as exc:
        raise SupplierProfileContractError(
            "invalid supplier profile contract: %s" % profile_path
        ) from exc


def validate_supplier_profile_contract(
    input_path: Path | str,
    out_path: Path | str | None = None,
) -> SupplierProfileContract:
    """Validate and optionally write a normalized supplier profile contract."""
    profile = load_supplier_profile_contract(input_path)
    if out_path is not None:
        write_supplier_profile_contract(out_path, profile)
    return profile


def write_supplier_profile_contract(
    path: Path | str,
    profile: SupplierProfileContract,
) -> None:
    """Write a normalized metadata-only supplier profile contract."""
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(
        json.dumps(profile.model_dump(mode="json"), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def _normalize_ref_tuple(value: object) -> tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, str):
        stripped = value.strip()
        return (stripped,) if stripped else ()
    if isinstance(value, Sequence) and not isinstance(value, (bytes, bytearray)):
        return tuple(str(item).strip() for item in value if str(item).strip())
    raise ValueError("supplier profile references must be strings or string arrays")


def _validate_safe_profile_text(value: str) -> None:
    lowered = value.casefold()
    if has_sensitive_markers(value):
        raise ValueError("supplier profile contains sensitive marker")
    for marker in FORBIDDEN_SUPPLIER_PROFILE_MARKERS:
        if marker in lowered:
            raise ValueError("supplier profile contains forbidden private or raw marker")
