"""Offline metadata-only SBOM inventory and gap findings."""

from __future__ import annotations

import hashlib
import json
from collections import Counter
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Final, Literal, TypedDict, cast

from aethelgard import __version__
from aethelgard.redaction_preflight import has_sensitive_markers, mask_sensitive_text

SBOM_SCHEMA_VERSION: Final[str] = "1.0"
SBOM_INVENTORY_TYPE: Final[str] = "sbom_inventory"
SBOM_FINDINGS_TYPE: Final[str] = "sbom_findings"
CYCLONEDX_FORMAT: Final[str] = "CycloneDX"
SBOM_COMPONENT_ID_PREFIX: Final[str] = "SBOM-C-"
SBOM_FINDING_ID_PREFIX: Final[str] = "SBOM-F-"
SBOM_ID_HASH_CHARS: Final[int] = 12
SBOM_HASH_CHUNK_SIZE_BYTES: Final[int] = 1_048_576
MAX_COMPONENTS: Final[int] = 2_000
MAX_COMPONENT_FIELD_CHARS: Final[int] = 256
MAX_LICENSES: Final[int] = 12
MAX_HASHES: Final[int] = 12
MAX_HASH_FIELD_CHARS: Final[int] = 160
SBOM_REVIEW_CATEGORY: Final[str] = "vulnerability_management"
SBOM_MAPPED_CONTROLS: Final[tuple[str, ...]] = ("NIS2-SCRM-03",)
SBOM_DISCLAIMER: Final[str] = (
    "Offline SBOM metadata inventory only. This is not legal advice, not an audit, "
    "not a certification, not a vulnerability assessment, and not a compliance decision."
)
FORBIDDEN_SBOM_EXPORT_MARKERS: Final[tuple[str, ...]] = (
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
    "raw_notes",
    "secret",
    "source_path",
    "token=",
)

SbomFindingType = Literal[
    "missing_version",
    "missing_license",
    "missing_checksum",
    "unknown_package_id",
    "duplicate_component",
]
SBOM_FINDING_TYPES: Final[tuple[SbomFindingType, ...]] = (
    "duplicate_component",
    "missing_checksum",
    "missing_license",
    "missing_version",
    "unknown_package_id",
)


class SbomError(ValueError):
    """Raised when SBOM input cannot be processed safely."""


class UnsupportedSbomFormatError(SbomError):
    """Raised when an SBOM format is intentionally unsupported."""


class SbomComponent(TypedDict):
    component_id: str
    name: str
    version: str
    purl: str
    licenses: tuple[str, ...]
    hashes: tuple[dict[str, str], ...]


class SbomFinding(TypedDict):
    finding_id: str
    finding_type: SbomFindingType
    component_id: str
    component_name: str
    component_version: str
    status: str
    mapped_controls: tuple[str, ...]
    recommended_manual_check: str


def build_sbom_inventory(
    input_path: Path | str,
    out_path: Path | str | None = None,
) -> dict[str, object]:
    """Build a deterministic CycloneDX component inventory without raw SBOM fields."""
    source_path = Path(input_path)
    payload = _read_sbom_json(source_path)
    components = _extract_components(payload)
    source_hash = _file_sha256(source_path)
    inventory = _inventory_document(source_path.name, source_hash, components)
    if out_path is not None:
        _write_json(Path(out_path), inventory)
    return inventory


def build_sbom_findings_report(
    input_path: Path | str,
    out_path: Path | str | None = None,
) -> dict[str, object]:
    """Build deterministic local metadata-gap findings from a CycloneDX SBOM."""
    inventory = build_sbom_inventory(input_path)
    components = cast(Sequence[Mapping[str, object]], inventory["components"])
    findings = _build_findings(components)
    report = _findings_document(inventory, findings)
    if out_path is not None:
        _write_json(Path(out_path), report)
    return report


def _inventory_document(
    source_label: str,
    source_hash: str,
    components: Sequence[SbomComponent],
) -> dict[str, object]:
    safe_source_label = _safe_export_text(source_label, "source label")
    return {
        "schema_version": SBOM_SCHEMA_VERSION,
        "inventory_type": SBOM_INVENTORY_TYPE,
        "inventory_id": _stable_id("inventory", source_hash),
        "source_label": safe_source_label,
        "sbom_sha256": source_hash,
        "component_count": len(components),
        "components": tuple(components),
        "tool_version": __version__,
        "disclaimer": SBOM_DISCLAIMER,
    }


def _findings_document(
    inventory: Mapping[str, object],
    findings: Sequence[SbomFinding],
) -> dict[str, object]:
    status_counts = Counter(str(finding["status"]) for finding in findings)
    finding_type_counts = Counter(str(finding["finding_type"]) for finding in findings)
    return {
        "schema_version": SBOM_SCHEMA_VERSION,
        "report_type": SBOM_FINDINGS_TYPE,
        "inventory_id": str(inventory["inventory_id"]),
        "sbom_sha256": str(inventory["sbom_sha256"]),
        "finding_count": len(findings),
        "status_counts": {"needs_review": status_counts.get("needs_review", 0)},
        "finding_type_counts": {
            finding_type: finding_type_counts.get(finding_type, 0)
            for finding_type in SBOM_FINDING_TYPES
        },
        "findings": tuple(findings),
        "per_document": (
            {
                "file": "sbom_inventory",
                "evidence_count": len(findings),
                "evidence": tuple(_review_compatible_finding(finding) for finding in findings),
            },
        ),
        "tool_version": __version__,
        "disclaimer": SBOM_DISCLAIMER,
    }


def _read_sbom_json(path: Path) -> Mapping[str, object]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise SbomError("could not read SBOM: %s" % path) from exc
    except json.JSONDecodeError as exc:
        raise SbomError("invalid SBOM JSON: %s" % path) from exc
    if not isinstance(payload, Mapping):
        raise SbomError("SBOM must contain a JSON object")
    _validate_supported_format(payload)
    return cast(Mapping[str, object], payload)


def _validate_supported_format(payload: Mapping[str, object]) -> None:
    if "spdxVersion" in payload or "SPDXID" in payload:
        raise UnsupportedSbomFormatError("SPDX JSON is not supported by this offline MVP")
    bom_format = str(payload.get("bomFormat", "")).strip()
    if bom_format != CYCLONEDX_FORMAT:
        raise UnsupportedSbomFormatError("only CycloneDX JSON is supported")


def _extract_components(payload: Mapping[str, object]) -> tuple[SbomComponent, ...]:
    raw_components = payload.get("components", ())
    if not isinstance(raw_components, Sequence) or isinstance(
        raw_components,
        (str, bytes, bytearray),
    ):
        raise SbomError("CycloneDX components must be an array")
    if len(raw_components) > MAX_COMPONENTS:
        raise SbomError("CycloneDX components exceed maximum count")

    components: list[SbomComponent] = []
    for index, value in enumerate(raw_components, start=1):
        if not isinstance(value, Mapping):
            raise SbomError("CycloneDX component %d must be an object" % index)
        components.append(_extract_component(value))
    return tuple(sorted(components, key=lambda component: component["component_id"]))


def _extract_component(component: Mapping[str, object]) -> SbomComponent:
    name = _safe_export_text(str(component.get("name", "")).strip(), "component name")
    version = _safe_export_text(str(component.get("version", "")).strip(), "component version")
    purl = _safe_export_text(str(component.get("purl", "")).strip(), "component purl")
    licenses = _extract_licenses(component.get("licenses", ()))
    hashes = _extract_hashes(component.get("hashes", ()))
    component_id = _component_id(name, version, purl)
    return {
        "component_id": component_id,
        "name": name,
        "version": version,
        "purl": purl,
        "licenses": licenses,
        "hashes": hashes,
    }


def _extract_licenses(value: object) -> tuple[str, ...]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        return ()
    licenses: list[str] = []
    for item in value[:MAX_LICENSES]:
        license_text = _license_text(item)
        if license_text:
            licenses.append(_safe_export_text(license_text, "component license"))
    return tuple(sorted(set(licenses)))


def _license_text(value: object) -> str:
    if isinstance(value, str):
        return value.strip()
    if not isinstance(value, Mapping):
        return ""
    expression = str(value.get("expression", "")).strip()
    if expression:
        return expression
    license_object = value.get("license", {})
    if not isinstance(license_object, Mapping):
        return ""
    for key in ("id", "name"):
        license_value = str(license_object.get(key, "")).strip()
        if license_value:
            return license_value
    return ""


def _extract_hashes(value: object) -> tuple[dict[str, str], ...]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        return ()
    hashes: list[dict[str, str]] = []
    for item in value[:MAX_HASHES]:
        if not isinstance(item, Mapping):
            continue
        algorithm = _safe_export_text(str(item.get("alg", "")).strip(), "hash algorithm")
        content = _safe_export_text(str(item.get("content", "")).strip(), "hash content")
        if algorithm and content:
            hashes.append({"alg": algorithm, "content": content})
    return tuple(sorted(hashes, key=lambda item: (item["alg"], item["content"])))


def _build_findings(components: Sequence[Mapping[str, object]]) -> tuple[SbomFinding, ...]:
    findings: list[SbomFinding] = []
    key_counts = Counter(_duplicate_key(component) for component in components)
    duplicate_keys = {key for key, count in key_counts.items() if count > 1}

    for component in components:
        component_findings = _component_findings(component, duplicate_keys)
        findings.extend(component_findings)
    return tuple(sorted(findings, key=lambda finding: finding["finding_id"]))


def _component_findings(
    component: Mapping[str, object],
    duplicate_keys: set[str],
) -> tuple[SbomFinding, ...]:
    finding_types: list[SbomFindingType] = []
    if not str(component.get("version", "")).strip():
        finding_types.append("missing_version")
    if not _string_sequence(component.get("licenses", ())):
        finding_types.append("missing_license")
    if not _hash_sequence(component.get("hashes", ())):
        finding_types.append("missing_checksum")
    if not str(component.get("purl", "")).strip():
        finding_types.append("unknown_package_id")
    if _duplicate_key(component) in duplicate_keys:
        finding_types.append("duplicate_component")
    return tuple(_finding(component, finding_type) for finding_type in finding_types)


def _finding(component: Mapping[str, object], finding_type: SbomFindingType) -> SbomFinding:
    component_id = str(component["component_id"])
    component_name = str(component.get("name", ""))
    component_version = str(component.get("version", ""))
    finding_id = _stable_id(
        "finding",
        component_id,
        finding_type,
        component_name,
        component_version,
    )
    return {
        "finding_id": "%s%s" % (SBOM_FINDING_ID_PREFIX, finding_id),
        "finding_type": finding_type,
        "component_id": component_id,
        "component_name": component_name,
        "component_version": component_version,
        "status": "needs_review",
        "mapped_controls": SBOM_MAPPED_CONTROLS,
        "recommended_manual_check": _manual_check(finding_type),
    }


def _review_compatible_finding(finding: SbomFinding) -> dict[str, object]:
    return {
        "finding_id": finding["finding_id"],
        "category": SBOM_REVIEW_CATEGORY,
        "quality": "warning",
        "quality_signals": (finding["finding_type"],),
        "strong": False,
        "source_citation": "SBOM metadata gap: %s for component %s."
        % (finding["finding_type"], finding["component_id"]),
        "source_reference": "sbom#%s" % finding["component_id"],
        "recommended_manual_check": finding["recommended_manual_check"],
        "review_status": "open",
        "mapped_controls": finding["mapped_controls"],
    }


def _manual_check(finding_type: str) -> str:
    messages = {
        "missing_version": "Confirm component version or record why it is unavailable.",
        "missing_license": "Confirm license metadata before supplier handover.",
        "missing_checksum": "Confirm component checksum or alternate integrity evidence.",
        "unknown_package_id": "Confirm package URL or another stable package identifier.",
        "duplicate_component": "Confirm whether duplicate component entries are intentional.",
    }
    return messages[finding_type]


def _component_id(name: str, version: str, purl: str) -> str:
    return "%s%s" % (SBOM_COMPONENT_ID_PREFIX, _stable_id("component", name, version, purl))


def _stable_id(*parts: str) -> str:
    canonical = json.dumps(parts, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:SBOM_ID_HASH_CHARS]


def _duplicate_key(component: Mapping[str, object]) -> str:
    return "\n".join(
        (
            str(component.get("name", "")).casefold(),
            str(component.get("version", "")).casefold(),
            str(component.get("purl", "")).casefold(),
        )
    )


def _string_sequence(value: object) -> tuple[str, ...]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        return ()
    return tuple(str(item).strip() for item in value if str(item).strip())


def _hash_sequence(value: object) -> tuple[Mapping[str, object], ...]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        return ()
    return tuple(cast(Mapping[str, object], item) for item in value if isinstance(item, Mapping))


def _safe_export_text(value: str, field_name: str) -> str:
    if len(value) > MAX_COMPONENT_FIELD_CHARS:
        raise SbomError("%s exceeds length limit" % field_name)
    if field_name.startswith("hash") and len(value) > MAX_HASH_FIELD_CHARS:
        raise SbomError("%s exceeds length limit" % field_name)
    _guard_forbidden_export_text(value, field_name)
    return mask_sensitive_text(value) if has_sensitive_markers(value) else value


def _guard_forbidden_export_text(value: str, field_name: str) -> None:
    lowered = value.casefold()
    for marker in FORBIDDEN_SBOM_EXPORT_MARKERS:
        if marker in lowered:
            raise SbomError("%s contains forbidden private or raw marker" % field_name)


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as input_file:
            for chunk in iter(lambda: input_file.read(SBOM_HASH_CHUNK_SIZE_BYTES), b""):
                digest.update(chunk)
    except OSError as exc:
        raise SbomError("could not hash SBOM: %s" % path) from exc
    return digest.hexdigest()


def _write_json(path: Path, payload: Mapping[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
