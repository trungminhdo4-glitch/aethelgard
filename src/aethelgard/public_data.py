"""Offline validation for committed public-data reference fixtures."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Final, TypedDict, cast

PROJECT_ROOT: Final[Path] = Path(__file__).resolve().parents[2]
PUBLIC_DATA_SCHEMA_VERSION: Final[str] = "1.0"
PUBLIC_DATA_REPORT_TYPE: Final[str] = "public_data_validation"
PUBLIC_DATA_MARKER: Final[str] = "aethelgard-public-data-v1"
PUBLIC_DATA_READY_STATUS: Final[str] = "PUBLIC_DATA_READY"
MAX_PUBLIC_SOURCES: Final[int] = 8
MAX_PUBLIC_FIXTURE_BYTES: Final[int] = 50_000
SUPPORTED_PUBLIC_SOURCE_TYPES: Final[frozenset[str]] = frozenset(
    {"cisa_kev_sample", "cyclonedx_sample"}
)
CISA_KEV_REQUIRED_FIELDS: Final[tuple[str, ...]] = (
    "cveID",
    "vendorProject",
    "product",
    "dateAdded",
    "dueDate",
    "knownRansomwareCampaignUse",
)
CISA_KEV_ALLOWED_FIELDS: Final[frozenset[str]] = frozenset(CISA_KEV_REQUIRED_FIELDS)
FORBIDDEN_PUBLIC_DATA_MARKERS: Final[tuple[str, ...]] = (
    ".env",
    "api_key",
    "bearer ",
    "c:/users/",
    "c:\\users\\",
    "cookie",
    "/home/",
    "private_key",
    "secret",
    "token",
)
SHA256_PATTERN: Final[re.Pattern[str]] = re.compile(r"^[a-f0-9]{64}$")
CVE_PATTERN: Final[re.Pattern[str]] = re.compile(r"^CVE-\d{4}-\d{4,}$")
ISO_DATE_PATTERN: Final[re.Pattern[str]] = re.compile(r"^\d{4}-\d{2}-\d{2}$")
PUBLIC_DATA_DISCLAIMER: Final[str] = (
    "Public reference fixture validation only. This is not legal advice, not an audit, "
    "not a vulnerability assessment, and not a compliance decision."
)


class PublicDataError(ValueError):
    """Raised when a public-data fixture or manifest is unsafe or invalid."""


class PublicDataSourceSummary(TypedDict):
    source_id: str
    source_type: str
    source_url: str
    publisher: str
    retrieved_at: str
    local_path: str
    sha256: str
    upstream_sha256: str
    contains_pii: bool
    record_count: int
    license_note: str
    validation_status: str


def validate_public_data_manifest(
    manifest_path: Path | str,
    out_path: Path | str | None = None,
) -> dict[str, object]:
    """Validate public fixtures and write a metadata-only validation report."""
    manifest = Path(manifest_path)
    payload = _read_json(manifest)
    if str(payload.get("schema_version", "")).strip() != PUBLIC_DATA_SCHEMA_VERSION:
        raise PublicDataError("public-data manifest schema_version is invalid")
    if str(payload.get("public_data_marker", "")).strip() != PUBLIC_DATA_MARKER:
        raise PublicDataError("public-data manifest marker is invalid")

    sources = _source_sequence(payload.get("sources", ()))
    summaries = tuple(_validate_source(source) for source in sources)
    report: dict[str, object] = {
        "schema_version": PUBLIC_DATA_SCHEMA_VERSION,
        "report_type": PUBLIC_DATA_REPORT_TYPE,
        "public_data_marker": PUBLIC_DATA_MARKER,
        "status": PUBLIC_DATA_READY_STATUS,
        "source_count": len(summaries),
        "sources": summaries,
        "disclaimer": PUBLIC_DATA_DISCLAIMER,
    }
    if out_path is not None:
        _write_json(Path(out_path), report)
    return report


def _validate_source(source: Mapping[str, object]) -> PublicDataSourceSummary:
    source_id = _required_text(source, "id")
    source_type = _required_text(source, "source_type")
    if source_type not in SUPPORTED_PUBLIC_SOURCE_TYPES:
        raise PublicDataError("unsupported public source type: %s" % source_type)
    source_url = _required_https_url(source, "source_url")
    publisher = _required_text(source, "publisher")
    retrieved_at = _required_iso_date(source, "retrieved_at")
    license_note = _required_text(source, "license_note")
    contains_pii = bool(source.get("contains_pii", True))
    if contains_pii:
        raise PublicDataError("public source %s must not contain PII" % source_id)
    expected_hash = _required_sha256(source, "sha256")
    upstream_hash = _optional_sha256(source.get("upstream_sha256"))

    local_path = _safe_relative_path(_required_text(source, "local_path"))
    actual_hash = _file_sha256(local_path)
    if actual_hash != expected_hash:
        raise PublicDataError("public source hash mismatch: %s" % source_id)
    if local_path.stat().st_size > MAX_PUBLIC_FIXTURE_BYTES:
        raise PublicDataError("public source fixture is too large: %s" % source_id)

    text = local_path.read_text(encoding="utf-8")
    _guard_public_text(text, source_id)
    fixture = _read_json(local_path)
    record_count = _validate_fixture_payload(source_type, fixture)
    return {
        "source_id": source_id,
        "source_type": source_type,
        "source_url": source_url,
        "publisher": publisher,
        "retrieved_at": retrieved_at,
        "local_path": local_path.relative_to(PROJECT_ROOT).as_posix(),
        "sha256": actual_hash,
        "upstream_sha256": upstream_hash,
        "contains_pii": False,
        "record_count": record_count,
        "license_note": license_note,
        "validation_status": "pass",
    }


def _validate_fixture_payload(source_type: str, fixture: Mapping[str, object]) -> int:
    if source_type == "cisa_kev_sample":
        return _validate_cisa_kev_sample(fixture)
    if source_type == "cyclonedx_sample":
        return _validate_cyclonedx_sample(fixture)
    raise PublicDataError("unsupported public source type: %s" % source_type)


def _validate_cisa_kev_sample(fixture: Mapping[str, object]) -> int:
    if str(fixture.get("public_data_marker", "")).strip() != PUBLIC_DATA_MARKER:
        raise PublicDataError("CISA KEV sample marker is invalid")
    vulnerabilities = _mapping_sequence(fixture.get("vulnerabilities", ()), "vulnerabilities")
    if not 3 <= len(vulnerabilities) <= 5:
        raise PublicDataError("CISA KEV sample must contain 3 to 5 entries")
    for item in vulnerabilities:
        _validate_cisa_kev_item(item)
    return len(vulnerabilities)


def _validate_cisa_kev_item(item: Mapping[str, object]) -> None:
    if set(item) != CISA_KEV_ALLOWED_FIELDS:
        raise PublicDataError("CISA KEV sample entry has unsupported fields")
    if not CVE_PATTERN.fullmatch(_required_text(item, "cveID")):
        raise PublicDataError("CISA KEV sample entry has invalid cveID")
    _required_iso_date(item, "dateAdded")
    _required_iso_date(item, "dueDate")
    ransomware_use = _required_text(item, "knownRansomwareCampaignUse")
    if ransomware_use not in {"Known", "Unknown"}:
        raise PublicDataError("CISA KEV sample entry has invalid ransomware marker")
    for field_name in ("vendorProject", "product"):
        _required_text(item, field_name)


def _validate_cyclonedx_sample(fixture: Mapping[str, object]) -> int:
    if str(fixture.get("bomFormat", "")).strip() != "CycloneDX":
        raise PublicDataError("public CycloneDX sample must use CycloneDX format")
    spec_version = str(fixture.get("specVersion", "")).strip()
    if spec_version not in {"1.4", "1.5", "1.6"}:
        raise PublicDataError("public CycloneDX sample has unsupported specVersion")
    if not _has_public_marker_property(fixture.get("properties", ())):
        raise PublicDataError("public CycloneDX sample marker is missing")
    components = _mapping_sequence(fixture.get("components", ()), "components")
    if not components:
        raise PublicDataError("public CycloneDX sample must contain components")
    return len(components)


def _has_public_marker_property(value: object) -> bool:
    properties = _mapping_sequence(value, "properties")
    for item in properties:
        if (
            str(item.get("name", "")).strip() == "aethelgard:public-data-marker"
            and str(item.get("value", "")).strip() == PUBLIC_DATA_MARKER
        ):
            return True
    return False


def _source_sequence(value: object) -> tuple[Mapping[str, object], ...]:
    sources = _mapping_sequence(value, "sources")
    if not sources:
        raise PublicDataError("public-data manifest must list at least one source")
    if len(sources) > MAX_PUBLIC_SOURCES:
        raise PublicDataError("public-data manifest lists too many sources")
    source_ids = [str(source.get("id", "")).strip() for source in sources]
    if len(source_ids) != len(set(source_ids)):
        raise PublicDataError("public-data manifest source IDs must be unique")
    return sources


def _mapping_sequence(value: object, field_name: str) -> tuple[Mapping[str, object], ...]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        raise PublicDataError("%s must be a JSON array" % field_name)
    result: list[Mapping[str, object]] = []
    for item in value:
        if not isinstance(item, Mapping):
            raise PublicDataError("%s entries must be JSON objects" % field_name)
        result.append(cast(Mapping[str, object], item))
    return tuple(result)


def _required_text(source: Mapping[str, object], field_name: str) -> str:
    value = str(source.get(field_name, "")).strip()
    if not value:
        raise PublicDataError("public-data field is required: %s" % field_name)
    _guard_public_text(value, field_name)
    return value


def _required_https_url(source: Mapping[str, object], field_name: str) -> str:
    value = _required_text(source, field_name)
    if not value.startswith("https://"):
        raise PublicDataError("public-data source URL must use https")
    return value


def _required_iso_date(source: Mapping[str, object], field_name: str) -> str:
    value = _required_text(source, field_name)
    if not ISO_DATE_PATTERN.fullmatch(value):
        raise PublicDataError("public-data date must use YYYY-MM-DD: %s" % field_name)
    return value


def _required_sha256(source: Mapping[str, object], field_name: str) -> str:
    value = _required_text(source, field_name)
    if not SHA256_PATTERN.fullmatch(value):
        raise PublicDataError("public-data hash must be lowercase SHA256: %s" % field_name)
    return value


def _optional_sha256(value: object) -> str:
    if value is None:
        return ""
    text = str(value).strip()
    if not text:
        return ""
    if not SHA256_PATTERN.fullmatch(text):
        raise PublicDataError("public-data upstream hash must be lowercase SHA256")
    return text


def _safe_relative_path(value: str) -> Path:
    raw_path = Path(value)
    if raw_path.is_absolute() or ".." in raw_path.parts:
        raise PublicDataError("public-data local_path must stay inside the project")
    resolved = (PROJECT_ROOT / raw_path).resolve()
    try:
        resolved.relative_to(PROJECT_ROOT.resolve())
    except ValueError as exc:
        raise PublicDataError("public-data local_path must stay inside the project") from exc
    if not resolved.is_file():
        raise PublicDataError("public-data local_path does not exist: %s" % value)
    return resolved


def _guard_public_text(value: str, field_name: str) -> None:
    lowered = value.casefold()
    for marker in FORBIDDEN_PUBLIC_DATA_MARKERS:
        if marker in lowered:
            raise PublicDataError("public-data %s contains forbidden marker" % field_name)


def _read_json(path: Path) -> Mapping[str, object]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise PublicDataError("could not read public-data JSON: %s" % path.name) from exc
    except json.JSONDecodeError as exc:
        raise PublicDataError("invalid public-data JSON: %s" % path.name) from exc
    if not isinstance(payload, Mapping):
        raise PublicDataError("public-data JSON must contain an object")
    return cast(Mapping[str, object], payload)


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as input_file:
            for chunk in iter(lambda: input_file.read(1_048_576), b""):
                digest.update(chunk)
    except OSError as exc:
        raise PublicDataError("could not hash public-data fixture: %s" % path.name) from exc
    return digest.hexdigest()


def _write_json(path: Path, payload: Mapping[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
