"""Metadata-only feature extraction for low-compute ML baselines."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Iterable, Mapping, Sequence
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Final, Literal, NotRequired, TypedDict, cast

FeatureItemType = Literal["document", "evidence", "finding"]

FEATURE_SCHEMA_VERSION: Final[str] = "ml-features-v1"
FEATURE_RECORD_TYPE: Final[str] = "ml_feature_record"
DOCUMENT_ID_PREFIX: Final[str] = "DOC-"
EVIDENCE_ID_PREFIX: Final[str] = "EV-"
FINDING_ID_PREFIX: Final[str] = "F-"
STABLE_ID_HASH_CHARS: Final[int] = 12
MAX_FEATURE_TEXT_BYTES: Final[int] = 1_000_000
HASH_READ_CHUNK_BYTES: Final[int] = 1_048_576
DATE_PATTERN: Final[re.Pattern[str]] = re.compile(
    r"\b(?:20\d{2}[-/.](?:0?[1-9]|1[0-2])[-/.](?:0?[1-9]|[12]\d|3[01])|"
    r"(?:0?[1-9]|[12]\d|3[01])[-/.](?:0?[1-9]|1[0-2])[-/.]20\d{2})\b"
)
TOKEN_PATTERN: Final[re.Pattern[str]] = re.compile(r"[A-Za-z0-9ÄÖÜäöüß_+-]+")
SKIPPED_DIR_NAMES: Final[frozenset[str]] = frozenset(
    {
        ".git",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        ".venv",
        ".venv-fresh",
        "__pycache__",
        "build",
        "dist",
        "env",
        "htmlcov",
        "venv",
    }
)
GENERATED_DIR_NAMES: Final[frozenset[str]] = frozenset({"reports", "dist"})
SUPPORTED_TEXT_SUFFIXES: Final[frozenset[str]] = frozenset(
    {".csv", ".json", ".jsonl", ".md", ".txt"}
)
FORBIDDEN_SUFFIXES: Final[frozenset[str]] = frozenset(
    {".db", ".db-shm", ".db-wal", ".sqlite", ".sqlite-shm", ".sqlite-wal", ".sqlite3", ".log"}
)
FORBIDDEN_NAME_MARKERS: Final[tuple[str, ...]] = (
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
    "token",
)
POLICY_OWNER_TERMS: Final[tuple[str, ...]] = (
    "owner",
    "policy owner",
    "process owner",
    "responsible",
    "verantwortlich",
    "verantwortliche",
)
BACKUP_TERMS: Final[tuple[str, ...]] = (
    "backup",
    "restore",
    "restoration",
    "disaster recovery",
    "recovery time",
    "wiederherstellung",
)
INCIDENT_TERMS: Final[tuple[str, ...]] = (
    "incident",
    "incident response",
    "incident reporting",
    "escalation",
    "vorfall",
    "meldeweg",
)
SUPPLIER_TERMS: Final[tuple[str, ...]] = (
    "supplier",
    "vendor",
    "third party",
    "third-party",
    "lieferant",
    "dienstleister",
)
REVIEW_TERMS: Final[tuple[str, ...]] = (
    "review",
    "reviewed",
    "audit",
    "tested",
    "approved",
    "überprüfung",
    "geprüft",
)
FUTURE_TENSE_TERMS: Final[tuple[str, ...]] = (
    "planned",
    "will implement",
    "will be",
    "future",
    "roadmap",
    "soll",
    "wird eingeführt",
    "geplant",
)
NEGATIVE_PHRASES: Final[tuple[str, ...]] = (
    "no evidence",
    "not documented",
    "not reviewed",
    "not tested",
    "missing",
    "intentionally avoids",
    "kein nachweis",
    "nicht dokumentiert",
)


class FeatureValues(TypedDict):
    """Compact, non-sensitive features for one item."""

    word_count: int
    has_date: bool
    has_policy_owner: bool
    has_backup_terms: bool
    has_incident_terms: bool
    has_supplier_terms: bool
    has_review_terms: bool
    contains_future_tense: bool
    contains_negative_phrase: bool
    read_error: NotRequired[bool]


class FeatureRecord(TypedDict):
    """A JSONL-safe feature record without raw text snippets."""

    record_type: str
    feature_schema_version: str
    item_id: str
    item_type: FeatureItemType
    source_ref: str
    text_hash: str
    features: FeatureValues
    warnings: NotRequired[list[str]]


class IndexItem(TypedDict):
    """Internal text-bearing item used only in memory by ML baselines."""

    item_id: str
    item_type: FeatureItemType
    source_ref: str
    text_hash: str
    text: str
    warnings: list[str]


class FeatureExtractionError(ValueError):
    """Raised when feature extraction cannot safely continue."""


def build_feature_records(
    input_path: Path | str,
    *,
    project_root: Path | str | None = None,
) -> tuple[FeatureRecord, ...]:
    """Build deterministic metadata-only feature records for an input file or directory."""
    items = collect_index_items(input_path, project_root=project_root)
    records = [_feature_record(item) for item in items]
    return tuple(sorted(records, key=lambda record: (record["source_ref"], record["item_id"])))


def write_features_jsonl(
    input_path: Path | str,
    out_path: Path | str,
    *,
    project_root: Path | str | None = None,
) -> tuple[FeatureRecord, ...]:
    """Write feature records to JSONL and return the in-memory records."""
    records = build_feature_records(input_path, project_root=project_root)
    target = Path(out_path)
    target.parent.mkdir(parents=True, exist_ok=True)
    with target.open("w", encoding="utf-8", newline="\n") as output_file:
        for record in records:
            output_file.write(json.dumps(record, sort_keys=True) + "\n")
    return records


def load_feature_records(path: Path | str) -> tuple[FeatureRecord, ...]:
    """Load feature JSONL records produced by :func:`write_features_jsonl`."""
    records: list[FeatureRecord] = []
    lines = Path(path).read_text(encoding="utf-8").splitlines()
    for line_number, line in enumerate(lines, start=1):
        if not line.strip():
            continue
        payload = json.loads(line)
        if not isinstance(payload, Mapping):
            raise FeatureExtractionError("feature JSONL row %d must be an object" % line_number)
        records.append(_coerce_feature_record(payload, line_number))
    return tuple(sorted(records, key=lambda record: (record["source_ref"], record["item_id"])))


def collect_index_items(
    input_path: Path | str,
    *,
    project_root: Path | str | None = None,
) -> tuple[IndexItem, ...]:
    """Collect text-bearing items for local scoring without writing text to disk."""
    path = Path(input_path)
    root = Path(project_root).resolve() if project_root is not None else Path.cwd().resolve()
    if not path.exists():
        source_ref = _safe_source_ref(path, path.parent, root)
        return (_error_item(source_ref, "input does not exist"),)
    source_base = path if path.is_dir() else path.parent
    if path.is_file():
        file_items = _items_from_file(path, source_base, root)
        return tuple(sorted(file_items, key=lambda item: (item["source_ref"], item["item_id"])))

    items: list[IndexItem] = []
    for child in _iter_candidate_files(path):
        items.extend(_items_from_file(child, source_base, root))
    return tuple(sorted(items, key=lambda item: (item["source_ref"], item["item_id"])))


def text_hash(text: str) -> str:
    """Return a SHA-256 digest for text without exposing the text itself."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def tokenize(text: str) -> tuple[str, ...]:
    """Tokenize text for small local baselines."""
    return tuple(match.group(0).casefold() for match in TOKEN_PATTERN.finditer(text))


def stable_id(prefix: str, *parts: str) -> str:
    """Build a stable ID from non-secret metadata or text hashes."""
    digest = hashlib.sha256(json.dumps(parts, sort_keys=True).encode("utf-8")).hexdigest()
    return "%s%s" % (prefix, digest[:STABLE_ID_HASH_CHARS])


def _feature_record(item: IndexItem) -> FeatureRecord:
    features = _features_for_text(item["text"])
    warnings = item["warnings"]
    if warnings:
        features["read_error"] = True
    record: FeatureRecord = {
        "record_type": FEATURE_RECORD_TYPE,
        "feature_schema_version": FEATURE_SCHEMA_VERSION,
        "item_id": item["item_id"],
        "item_type": item["item_type"],
        "source_ref": item["source_ref"],
        "text_hash": item["text_hash"],
        "features": features,
    }
    if warnings:
        record["warnings"] = list(warnings)
    return record


def _features_for_text(text: str) -> FeatureValues:
    lowered = text.casefold()
    return {
        "word_count": len(tokenize(text)),
        "has_date": DATE_PATTERN.search(text) is not None,
        "has_policy_owner": _contains_any(lowered, POLICY_OWNER_TERMS),
        "has_backup_terms": _contains_any(lowered, BACKUP_TERMS),
        "has_incident_terms": _contains_any(lowered, INCIDENT_TERMS),
        "has_supplier_terms": _contains_any(lowered, SUPPLIER_TERMS),
        "has_review_terms": _contains_any(lowered, REVIEW_TERMS),
        "contains_future_tense": _contains_any(lowered, FUTURE_TENSE_TERMS),
        "contains_negative_phrase": _contains_any(lowered, NEGATIVE_PHRASES),
    }


def _contains_any(lowered_text: str, terms: Sequence[str]) -> bool:
    return any(term.casefold() in lowered_text for term in terms)


def _iter_candidate_files(root: Path) -> Iterable[Path]:
    allow_generated_root = root.name.casefold() in GENERATED_DIR_NAMES
    for path in sorted(root.rglob("*"), key=lambda value: value.as_posix().casefold()):
        if path.is_dir():
            continue
        if _is_in_skipped_dir(path, root, allow_generated_root):
            continue
        if path.suffix.casefold() in SUPPORTED_TEXT_SUFFIXES:
            yield path


def _is_in_skipped_dir(path: Path, root: Path, allow_generated_root: bool) -> bool:
    try:
        parts = path.relative_to(root).parts[:-1]
    except ValueError:
        parts = path.parts[:-1]
    for part in parts:
        lowered = part.casefold()
        if lowered in SKIPPED_DIR_NAMES:
            return True
        if not allow_generated_root and lowered in GENERATED_DIR_NAMES:
            return True
    return False


def _items_from_file(path: Path, source_base: Path, project_root: Path) -> tuple[IndexItem, ...]:
    source_ref = _safe_source_ref(path, source_base, project_root)
    unsafe_reason = _unsafe_path_reason(path)
    if unsafe_reason:
        return (_error_item(source_ref, unsafe_reason),)
    if path.suffix.casefold() not in SUPPORTED_TEXT_SUFFIXES:
        return ()
    text, warnings = _read_bounded_text(path)
    document_item = _index_item(
        item_type="document",
        item_id=stable_id(DOCUMENT_ID_PREFIX, source_ref, text_hash(text)),
        source_ref=source_ref,
        text=text,
        warnings=warnings,
    )
    if warnings or path.suffix.casefold() != ".json":
        return (document_item,)
    return (document_item, *_structured_json_items(path, source_ref, text))


def _read_bounded_text(path: Path) -> tuple[str, list[str]]:
    try:
        if path.stat().st_size > MAX_FEATURE_TEXT_BYTES:
            return "", ["input exceeds feature text byte limit"]
        return path.read_text(encoding="utf-8", errors="replace"), []
    except OSError:
        return "", ["input could not be read"]


def _structured_json_items(path: Path, source_ref: str, text: str) -> tuple[IndexItem, ...]:
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        return ()
    if not isinstance(payload, Mapping):
        return ()
    items: list[IndexItem] = []
    items.extend(_report_finding_items(payload, source_ref))
    items.extend(_evidence_store_items(payload, source_ref))
    return tuple(items)


def _report_finding_items(payload: Mapping[str, object], source_ref: str) -> tuple[IndexItem, ...]:
    per_document = payload.get("per_document", ())
    if not isinstance(per_document, Sequence) or isinstance(per_document, (str, bytes, bytearray)):
        return ()
    items: list[IndexItem] = []
    for document_index, document in enumerate(per_document, start=1):
        if not isinstance(document, Mapping):
            continue
        evidence_items = document.get("evidence", ())
        if not isinstance(evidence_items, Sequence) or isinstance(
            evidence_items,
            (str, bytes, bytearray),
        ):
            continue
        document_label = str(document.get("file", "document-%d" % document_index))
        for evidence_index, evidence in enumerate(evidence_items, start=1):
            if not isinstance(evidence, Mapping):
                continue
            finding_id = str(evidence.get("finding_id", "")).strip()
            item_id = finding_id or stable_id(FINDING_ID_PREFIX, source_ref, str(evidence_index))
            item_text = _join_json_text(
                (
                    document_label,
                    str(evidence.get("category", "")),
                    str(evidence.get("quality", "")),
                    str(evidence.get("source_citation", "")),
                    str(evidence.get("recommended_manual_check", "")),
                    _join_sequence(evidence.get("quality_signals", ())),
                    _join_sequence(evidence.get("mapped_controls", ())),
                )
            )
            items.append(
                _index_item(
                    item_type="finding",
                    item_id=item_id,
                    source_ref="%s#%s" % (source_ref, item_id),
                    text=item_text,
                    warnings=[],
                )
            )
    return tuple(items)


def _evidence_store_items(payload: Mapping[str, object], source_ref: str) -> tuple[IndexItem, ...]:
    evidence_records = payload.get("evidence", ())
    if not isinstance(evidence_records, Sequence) or isinstance(
        evidence_records,
        (str, bytes, bytearray),
    ):
        return ()
    items: list[IndexItem] = []
    for evidence_index, evidence in enumerate(evidence_records, start=1):
        if not isinstance(evidence, Mapping):
            continue
        evidence_id = str(evidence.get("evidence_id", "")).strip()
        item_id = evidence_id or stable_id(EVIDENCE_ID_PREFIX, source_ref, str(evidence_index))
        item_text = _join_json_text(
            (
                str(evidence.get("type", "")),
                str(evidence.get("source_path", "")),
                str(evidence.get("validity", "")),
                str(evidence.get("review_status", "")),
                _join_sequence(evidence.get("mapped_controls", ())),
                _join_sequence(evidence.get("claims", ())),
            )
        )
        items.append(
            _index_item(
                item_type="evidence",
                item_id=item_id,
                source_ref="%s#%s" % (source_ref, item_id),
                text=item_text,
                warnings=[],
            )
        )
    return tuple(items)


def _join_sequence(value: object) -> str:
    if isinstance(value, str):
        return value
    if not isinstance(value, Sequence) or isinstance(value, (bytes, bytearray)):
        return ""
    return " ".join(str(item) for item in value)


def _join_json_text(parts: Sequence[str]) -> str:
    return " ".join(part.strip() for part in parts if part.strip())


def _index_item(
    *,
    item_type: FeatureItemType,
    item_id: str,
    source_ref: str,
    text: str,
    warnings: Sequence[str],
) -> IndexItem:
    return {
        "item_id": item_id,
        "item_type": item_type,
        "source_ref": source_ref,
        "text_hash": text_hash(text),
        "text": text,
        "warnings": list(warnings),
    }


def _error_item(source_ref: str, warning: str) -> IndexItem:
    return _index_item(
        item_type="document",
        item_id=stable_id(DOCUMENT_ID_PREFIX, source_ref, "error"),
        source_ref=source_ref,
        text="",
        warnings=[warning],
    )


def _safe_source_ref(path: Path, source_base: Path, project_root: Path) -> str:
    for base in (project_root, source_base.resolve() if source_base.exists() else source_base):
        try:
            return path.resolve().relative_to(base).as_posix()
        except (OSError, ValueError):
            continue
    return path.name


def _unsafe_path_reason(path: Path) -> str:
    try:
        parts = path.parts
    except OSError:
        parts = (path.name,)
    if _is_absolute_label(path.as_posix()):
        path_parts = parts
    else:
        path_parts = tuple(part for part in parts if part)
    for part in path_parts:
        lowered = part.casefold()
        if _is_forbidden_part(lowered):
            return "input path is secret-like or private"
    return ""


def _is_absolute_label(value: str) -> bool:
    return PureWindowsPath(value).is_absolute() or PurePosixPath(value).is_absolute()


def _is_forbidden_part(lowered_part: str) -> bool:
    if lowered_part == ".env" or lowered_part.startswith(".env."):
        return True
    if any(marker in lowered_part for marker in FORBIDDEN_NAME_MARKERS):
        return True
    suffix = PureWindowsPath(lowered_part).suffix or PurePosixPath(lowered_part).suffix
    return suffix.casefold() in FORBIDDEN_SUFFIXES


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as input_file:
        for chunk in iter(lambda: input_file.read(HASH_READ_CHUNK_BYTES), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _coerce_feature_record(payload: Mapping[str, object], line_number: int) -> FeatureRecord:
    raw_features = payload.get("features", {})
    if not isinstance(raw_features, Mapping):
        raise FeatureExtractionError("feature JSONL row %d has invalid features" % line_number)
    item_type = str(payload.get("item_type", "document"))
    if item_type not in {"document", "evidence", "finding"}:
        raise FeatureExtractionError("feature JSONL row %d has invalid item_type" % line_number)
    features: FeatureValues = {
        "word_count": int(raw_features.get("word_count", 0)),
        "has_date": bool(raw_features.get("has_date", False)),
        "has_policy_owner": bool(raw_features.get("has_policy_owner", False)),
        "has_backup_terms": bool(raw_features.get("has_backup_terms", False)),
        "has_incident_terms": bool(raw_features.get("has_incident_terms", False)),
        "has_supplier_terms": bool(raw_features.get("has_supplier_terms", False)),
        "has_review_terms": bool(raw_features.get("has_review_terms", False)),
        "contains_future_tense": bool(raw_features.get("contains_future_tense", False)),
        "contains_negative_phrase": bool(raw_features.get("contains_negative_phrase", False)),
    }
    if bool(raw_features.get("read_error", False)):
        features["read_error"] = True
    record: FeatureRecord = {
        "record_type": str(payload.get("record_type", FEATURE_RECORD_TYPE)),
        "feature_schema_version": str(
            payload.get("feature_schema_version", FEATURE_SCHEMA_VERSION)
        ),
        "item_id": str(payload.get("item_id", "")),
        "item_type": cast(FeatureItemType, item_type),
        "source_ref": str(payload.get("source_ref", "")),
        "text_hash": str(payload.get("text_hash", "")),
        "features": features,
    }
    warnings = payload.get("warnings", ())
    if isinstance(warnings, Sequence) and not isinstance(warnings, (str, bytes, bytearray)):
        record["warnings"] = [str(warning) for warning in warnings]
    return record
