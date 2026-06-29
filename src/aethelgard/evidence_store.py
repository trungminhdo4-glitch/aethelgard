"""Metadata-only evidence store for C-SCRM questionnaire workflows."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Final, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from aethelgard.control_catalog import ControlCatalogBundle
from aethelgard.redaction_preflight import has_sensitive_markers, mask_sensitive_text

EvidenceType = Literal["document", "policy", "attestation", "finding", "questionnaire", "sbom"]
EvidenceSourceType = Literal["file", "reviewed_report"]
EvidenceValidity = Literal["current", "unknown", "expired", "superseded"]

EVIDENCE_STORE_SCHEMA_VERSION: Final[str] = "1.0"
MAX_EVIDENCE_ID_CHARS: Final[int] = 80
MAX_EVIDENCE_SOURCE_CHARS: Final[int] = 260
MAX_EVIDENCE_CLAIM_CHARS: Final[int] = 500
MAX_EVIDENCE_CLAIMS: Final[int] = 8
MAX_EVIDENCE_FILE_BYTES: Final[int] = 50_000_000
SHA256_HEX_CHARS: Final[int] = 64
EVIDENCE_ID_HASH_CHARS: Final[int] = 12
EVIDENCE_ID_PREFIX: Final[str] = "E-"
SHA256_PATTERN: Final[str] = r"^[a-f0-9]{64}$"
EVIDENCE_ID_PATTERN: Final[str] = r"^[A-Za-z0-9_.:-]+$"
FORBIDDEN_EVIDENCE_SUFFIXES: Final[frozenset[str]] = frozenset(
    {".db", ".db-shm", ".db-wal", ".sqlite", ".sqlite-shm", ".sqlite-wal", ".sqlite3", ".log"}
)
FORBIDDEN_EVIDENCE_NAME_MARKERS: Final[tuple[str, ...]] = (
    ".env",
    ".log.",
    "credential",
    "credentials",
    "cookie",
    "cookies",
    "database",
    "private-config",
    "secret",
    "secrets",
)


class EvidenceStoreError(ValueError):
    """Raised when evidence metadata cannot be loaded or validated safely."""


class EvidenceRecord(BaseModel):
    """Metadata for one evidence item without raw document contents."""

    model_config = ConfigDict(
        frozen=True,
        extra="forbid",
        str_strip_whitespace=True,
    )

    evidence_id: str = Field(
        min_length=1,
        max_length=MAX_EVIDENCE_ID_CHARS,
        pattern=EVIDENCE_ID_PATTERN,
    )
    type: EvidenceType
    source_path: str = Field(min_length=1, max_length=MAX_EVIDENCE_SOURCE_CHARS)
    source_type: EvidenceSourceType | None = None
    source_report: str | None = Field(
        default=None,
        min_length=1,
        max_length=MAX_EVIDENCE_SOURCE_CHARS,
    )
    source_finding_id: str | None = Field(
        default=None,
        min_length=1,
        max_length=MAX_EVIDENCE_ID_CHARS,
        pattern=EVIDENCE_ID_PATTERN,
    )
    sha256: str = Field(
        min_length=SHA256_HEX_CHARS,
        max_length=SHA256_HEX_CHARS,
        pattern=SHA256_PATTERN,
    )
    mapped_controls: tuple[str, ...] = Field(min_length=1)
    claims: tuple[str, ...] = Field(default=())
    validity: EvidenceValidity = "unknown"
    review_status: str | None = Field(default=None, min_length=1, max_length=MAX_EVIDENCE_ID_CHARS)
    review_required: bool = True
    requires_human_review: bool | None = None

    @field_validator("mapped_controls", "claims", mode="before")
    @classmethod
    def _normalize_text_tuple(cls, value: object) -> tuple[str, ...]:
        return _normalize_text_tuple(value)

    @field_validator("source_path", "source_report")
    @classmethod
    def _validate_safe_source_labels(cls, value: str | None) -> str | None:
        if value is not None:
            _validate_safe_source_label(value)
        return value

    @field_validator("claims")
    @classmethod
    def _validate_claims(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if len(value) > MAX_EVIDENCE_CLAIMS:
            raise ValueError("too many evidence claims")
        for claim in value:
            if len(claim) > MAX_EVIDENCE_CLAIM_CHARS:
                raise ValueError("evidence claim exceeds length limit")
        return value


class EvidenceStoreDocument(BaseModel):
    """A small metadata-only evidence store document."""

    model_config = ConfigDict(
        frozen=True,
        extra="forbid",
        str_strip_whitespace=True,
    )

    schema_version: str = EVIDENCE_STORE_SCHEMA_VERSION
    evidence: tuple[EvidenceRecord, ...] = Field(default=())


def load_evidence_store(
    path: Path | str,
    *,
    catalog_bundle: ControlCatalogBundle | None = None,
) -> EvidenceStoreDocument:
    """Load and validate an evidence store JSON document."""
    store_path = Path(path)
    try:
        payload = json.loads(store_path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise EvidenceStoreError("could not read evidence store: %s" % store_path) from exc
    except json.JSONDecodeError as exc:
        raise EvidenceStoreError("invalid evidence store JSON: %s" % store_path) from exc
    if not isinstance(payload, Mapping):
        raise EvidenceStoreError("evidence store must contain a JSON object")
    try:
        store = EvidenceStoreDocument.model_validate(payload)
    except ValueError as exc:
        raise EvidenceStoreError("invalid evidence store: %s" % store_path) from exc
    validate_evidence_store(store, catalog_bundle=catalog_bundle)
    return store


def validate_evidence_store(
    store: EvidenceStoreDocument,
    *,
    catalog_bundle: ControlCatalogBundle | None = None,
) -> None:
    """Validate evidence IDs and optional mapped control references."""
    seen: set[str] = set()
    duplicates: list[str] = []
    known_controls = set(catalog_bundle.controls_by_id) if catalog_bundle is not None else None

    for record in store.evidence:
        if record.evidence_id in seen:
            duplicates.append(record.evidence_id)
        seen.add(record.evidence_id)
        if known_controls is not None:
            unknown = sorted(
                control for control in record.mapped_controls if control not in known_controls
            )
            if unknown:
                raise EvidenceStoreError(
                    "evidence %s references unknown control IDs: %s"
                    % (record.evidence_id, ", ".join(unknown))
                )

    if duplicates:
        raise EvidenceStoreError(
            "duplicate evidence_id values: %s" % ", ".join(sorted(duplicates))
        )


def build_file_evidence_record(
    source_path: Path | str,
    *,
    mapped_controls: Sequence[str],
    evidence_type: EvidenceType = "document",
    claims: Sequence[str] = (),
    validity: EvidenceValidity = "unknown",
    review_required: bool = True,
    base_path: Path | str | None = None,
) -> EvidenceRecord:
    """Build an evidence record by hashing a local approved file without storing content."""
    path = Path(source_path)
    _guard_allowed_source_path(path)
    digest = _sha256_file(path)
    source_label = _safe_source_label(path, Path(base_path) if base_path is not None else None)
    evidence_id = _build_evidence_id(digest, mapped_controls)
    return EvidenceRecord(
        evidence_id=evidence_id,
        type=evidence_type,
        source_path=source_label,
        sha256=digest,
        mapped_controls=tuple(mapped_controls),
        claims=tuple(claims),
        validity=validity,
        review_required=review_required,
    )


def write_evidence_store(path: Path | str, store: EvidenceStoreDocument) -> None:
    """Write a metadata-only evidence store JSON document."""
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(
        json.dumps(store.model_dump(mode="json", exclude_none=True), indent=2, sort_keys=True)
        + "\n",
        encoding="utf-8",
    )


def safe_claims(record: EvidenceRecord) -> tuple[str, ...]:
    """Return bounded, masked claim text for reports and draft answers."""
    safe_values: list[str] = []
    for claim in record.claims:
        bounded = claim[:MAX_EVIDENCE_CLAIM_CHARS]
        safe_values.append(
            mask_sensitive_text(bounded) if has_sensitive_markers(bounded) else bounded
        )
    return tuple(safe_values)


def _guard_allowed_source_path(path: Path) -> None:
    if not path.is_file():
        raise EvidenceStoreError("evidence source must be an existing file: %s" % path)
    try:
        _validate_source_path_parts(path.parts)
    except ValueError as exc:
        raise EvidenceStoreError(str(exc)) from exc
    if path.stat().st_size > MAX_EVIDENCE_FILE_BYTES:
        raise EvidenceStoreError("evidence source exceeds file size limit: %s" % path)


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as input_file:
        for chunk in iter(lambda: input_file.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _safe_source_label(path: Path, base_path: Path | None) -> str:
    if base_path is None:
        return path.name
    try:
        return path.relative_to(base_path).as_posix()
    except ValueError:
        return path.name


def _build_evidence_id(digest: str, mapped_controls: Sequence[str]) -> str:
    basis = "%s\n%s" % (digest, "\n".join(sorted(mapped_controls)))
    short_hash = hashlib.sha256(basis.encode("utf-8")).hexdigest()[:EVIDENCE_ID_HASH_CHARS]
    return "%s%s" % (EVIDENCE_ID_PREFIX, short_hash)


def _validate_safe_source_label(value: str) -> None:
    label = value.strip()
    if not label:
        raise ValueError("evidence source label must not be empty")
    if PureWindowsPath(label).is_absolute() or PurePosixPath(label).is_absolute():
        raise ValueError("evidence source label must not be an absolute path")
    parts = tuple(part for part in label.replace("\\", "/").split("/") if part and part != ".")
    if not parts:
        raise ValueError("evidence source label must contain a file label")
    if any(part == ".." for part in parts):
        raise ValueError("evidence source label must not contain parent traversal")
    _validate_source_path_parts(parts)


def _validate_source_path_parts(parts: Sequence[str]) -> None:
    for part in parts:
        lowered = part.lower()
        if _is_forbidden_source_part(lowered):
            raise ValueError("forbidden secret-like evidence source path")


def _is_forbidden_source_part(lowered_part: str) -> bool:
    if lowered_part == ".env" or lowered_part.startswith(".env."):
        return True
    if any(marker in lowered_part for marker in FORBIDDEN_EVIDENCE_NAME_MARKERS):
        return True
    suffix = PureWindowsPath(lowered_part).suffix or PurePosixPath(lowered_part).suffix
    return suffix in FORBIDDEN_EVIDENCE_SUFFIXES


def _normalize_text_tuple(value: object) -> tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, str):
        normalized = value.strip()
        return (normalized,) if normalized else ()
    if isinstance(value, Sequence) and not isinstance(value, (bytes, bytearray)):
        return tuple(str(item).strip() for item in value if str(item).strip())
    raise ValueError("expected a string or sequence of strings")
