"""Bridge reviewed findings into metadata-only evidence store records."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterator, Mapping, Sequence
from pathlib import Path
from typing import Final, Literal, cast

from aethelgard.control_catalog import (
    ControlCatalogBundle,
    load_control_catalog_bundle,
)
from aethelgard.evidence_store import (
    EvidenceRecord,
    EvidenceStoreDocument,
    validate_evidence_store,
    write_evidence_store,
)

APPROVED_REVIEW_STATUSES: Final[frozenset[str]] = frozenset({"accepted", "reviewed"})
BRIDGE_SOURCE_TYPE: Final[Literal["reviewed_report"]] = "reviewed_report"
BRIDGE_EVIDENCE_TYPE: Final[Literal["finding"]] = "finding"
BRIDGE_EVIDENCE_ID_PREFIX: Final[str] = "E-RF-"
BRIDGE_EVIDENCE_ID_HASH_CHARS: Final[int] = 12

CATEGORY_CONTROL_MAP: Final[dict[str, tuple[str, ...]]] = {
    "access_control": ("NIS2-SCRM-05",),
    "asset_management": ("NIS2-SCRM-05",),
    "business_continuity": ("NIS2-SCRM-04",),
    "incident_reporting": ("NIS2-SCRM-02",),
    "secure_auth_communications": ("NIS2-SCRM-05",),
    "secure_development": ("NIS2-SCRM-03",),
    "supplier_security": ("NIS2-SCRM-01",),
    "vulnerability_management": ("NIS2-SCRM-03",),
}


class EvidenceBridgeError(ValueError):
    """Raised when reviewed findings cannot be converted into safe evidence metadata."""


def bridge_reviewed_report_to_evidence_store(
    reviewed_report_path: Path | str,
    out_path: Path | str,
    *,
    catalog_dir: Path | str | None = None,
) -> EvidenceStoreDocument:
    """Convert accepted reviewed findings into an evidence store JSON file."""
    input_path = Path(reviewed_report_path)
    catalog_bundle = (
        load_control_catalog_bundle(catalog_dir) if catalog_dir else load_control_catalog_bundle()
    )
    report = _read_json(input_path)
    store = build_evidence_store_from_reviewed_report(
        report,
        source_report=input_path.name,
        catalog_bundle=catalog_bundle,
    )
    write_evidence_store(out_path, store)
    return store


def build_evidence_store_from_reviewed_report(
    report: Mapping[str, object],
    *,
    source_report: str,
    catalog_bundle: ControlCatalogBundle,
) -> EvidenceStoreDocument:
    """Build an evidence store from accepted findings in a reviewed report."""
    seen_finding_ids: set[str] = set()
    records: list[EvidenceRecord] = []

    for finding in _iter_findings(report):
        finding_id = _required_finding_id(finding)
        if finding_id in seen_finding_ids:
            raise EvidenceBridgeError("duplicate finding_id in reviewed report: %s" % finding_id)
        seen_finding_ids.add(finding_id)

        review_status = _normalized_review_status(finding)
        if review_status not in APPROVED_REVIEW_STATUSES:
            continue

        mapped_controls = _mapped_controls(finding, catalog_bundle)
        if not mapped_controls:
            raise EvidenceBridgeError(
                "accepted finding %s has no mapped C-SCRM controls" % finding_id
            )
        records.append(
            _build_record(
                source_report=source_report,
                finding_id=finding_id,
                review_status=review_status,
                mapped_controls=mapped_controls,
            )
        )

    store = EvidenceStoreDocument(evidence=tuple(records))
    validate_evidence_store(store, catalog_bundle=catalog_bundle)
    return store


def _iter_findings(report: Mapping[str, object]) -> Iterator[Mapping[str, object]]:
    documents = cast(Sequence[Mapping[str, object]], report.get("per_document", ()))
    for document in documents:
        evidence = cast(Sequence[Mapping[str, object]], document.get("evidence", ()))
        yield from evidence


def _required_finding_id(finding: Mapping[str, object]) -> str:
    finding_id = str(finding.get("finding_id", "")).strip()
    if not finding_id:
        raise EvidenceBridgeError("reviewed report contains a finding without finding_id")
    return finding_id


def _normalized_review_status(finding: Mapping[str, object]) -> str:
    return str(finding.get("review_status", "")).strip().lower()


def _mapped_controls(
    finding: Mapping[str, object],
    catalog_bundle: ControlCatalogBundle,
) -> tuple[str, ...]:
    known_controls = set(catalog_bundle.controls_by_id)
    mapped: list[str] = []
    for value in _control_candidates(finding):
        normalized = _normalize_category(value)
        if value in known_controls:
            mapped.append(value)
        elif normalized in CATEGORY_CONTROL_MAP:
            mapped.extend(CATEGORY_CONTROL_MAP[normalized])
    return _unique_known_controls(mapped, known_controls)


def _control_candidates(finding: Mapping[str, object]) -> tuple[str, ...]:
    candidates: list[str] = []
    for key in ("mapped_controls", "category", "control_area"):
        value = finding.get(key, ())
        if isinstance(value, str):
            candidates.extend(part.strip() for part in value.split(","))
        elif isinstance(value, Sequence) and not isinstance(value, (bytes, bytearray)):
            candidates.extend(str(part).strip() for part in value)
    return tuple(candidate for candidate in candidates if candidate)


def _unique_known_controls(values: Sequence[str], known_controls: set[str]) -> tuple[str, ...]:
    unique: list[str] = []
    seen: set[str] = set()
    for value in values:
        if value in known_controls and value not in seen:
            unique.append(value)
            seen.add(value)
    return tuple(unique)


def _build_record(
    *,
    source_report: str,
    finding_id: str,
    review_status: str,
    mapped_controls: Sequence[str],
) -> EvidenceRecord:
    claims = (_build_claim(finding_id, review_status, mapped_controls),)
    digest = _metadata_hash(
        {
            "source_type": BRIDGE_SOURCE_TYPE,
            "source_report": source_report,
            "source_finding_id": finding_id,
            "mapped_controls": tuple(sorted(mapped_controls)),
            "claims": claims,
            "review_status": review_status,
        }
    )
    return EvidenceRecord(
        evidence_id="%s%s" % (BRIDGE_EVIDENCE_ID_PREFIX, digest[:BRIDGE_EVIDENCE_ID_HASH_CHARS]),
        type=BRIDGE_EVIDENCE_TYPE,
        source_path=source_report,
        source_type=BRIDGE_SOURCE_TYPE,
        source_report=source_report,
        source_finding_id=finding_id,
        sha256=digest,
        mapped_controls=tuple(mapped_controls),
        claims=claims,
        validity="current",
        review_status=review_status,
        review_required=False,
        requires_human_review=False,
    )


def _build_claim(
    finding_id: str,
    review_status: str,
    mapped_controls: Sequence[str],
) -> str:
    return (
        "Human review status %s recorded for finding %s and mapped controls %s."
        % (review_status, finding_id, ", ".join(mapped_controls))
    )


def _metadata_hash(payload: Mapping[str, object]) -> str:
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _normalize_category(value: str) -> str:
    return "_".join(value.casefold().replace("-", "_").split())


def _read_json(path: Path) -> Mapping[str, object]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise EvidenceBridgeError("could not read reviewed report: %s" % path) from exc
    except json.JSONDecodeError as exc:
        raise EvidenceBridgeError("invalid reviewed report JSON: %s" % path) from exc
    if not isinstance(payload, Mapping):
        raise EvidenceBridgeError("reviewed report must contain a JSON object")
    return cast(Mapping[str, object], payload)
