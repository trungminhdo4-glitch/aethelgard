"""Metadata-only trust bundle preview export."""

from __future__ import annotations

import hashlib
import json
from collections import Counter
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Final, Literal, cast

from aethelgard import __version__
from aethelgard.evidence_store import EvidenceRecord, load_evidence_store

TRUST_BUNDLE_SCHEMA_VERSION: Final[str] = "1.0"
TRUST_BUNDLE_MANIFEST_NAME: Final[str] = "manifest.json"
TRUST_BUNDLE_EVIDENCE_INDEX_NAME: Final[str] = "evidence_index.json"
TRUST_BUNDLE_QUESTIONNAIRE_SUMMARY_NAME: Final[str] = "questionnaire_summary.json"
TRUST_BUNDLE_SUPPLIER_RISK_SUMMARY_NAME: Final[str] = "supplier_risk_summary.json"
TRUST_BUNDLE_README_NAME: Final[str] = "README.md"
TRUST_BUNDLE_FILES: Final[tuple[str, ...]] = (
    TRUST_BUNDLE_MANIFEST_NAME,
    TRUST_BUNDLE_EVIDENCE_INDEX_NAME,
    TRUST_BUNDLE_QUESTIONNAIRE_SUMMARY_NAME,
    TRUST_BUNDLE_SUPPLIER_RISK_SUMMARY_NAME,
    TRUST_BUNDLE_README_NAME,
)
TRUST_BUNDLE_ID_HASH_CHARS: Final[int] = 16

TrustBundleStatus = Literal[
    "accepted",
    "reviewed",
    "needs_evidence",
    "needs_review",
    "not_assessed",
]

TRUST_BUNDLE_STATUSES: Final[frozenset[str]] = frozenset(
    {
        "accepted",
        "reviewed",
        "needs_evidence",
        "needs_review",
        "not_assessed",
    }
)
APPROVED_REVIEW_STATUSES: Final[frozenset[str]] = frozenset({"accepted", "reviewed"})
NOT_ASSESSED_REVIEW_STATUSES: Final[frozenset[str]] = frozenset(
    {"false_positive", "not_applicable", "resolved"}
)


class TrustBundleError(ValueError):
    """Raised when a trust bundle preview cannot be built safely."""


def build_trust_bundle_preview(
    evidence_store_path: Path | str,
    supplier_risk_path: Path | str,
    questionnaire_path: Path | str,
    out_dir: Path | str,
) -> dict[str, object]:
    """Build a deterministic metadata-only trust bundle preview directory."""
    evidence_store = load_evidence_store(evidence_store_path)
    supplier_risk = _read_json(Path(supplier_risk_path), "supplier risk report")
    questionnaire = _read_json(Path(questionnaire_path), "questionnaire report")

    evidence_index = _build_evidence_index(evidence_store.evidence)
    questionnaire_summary = _build_questionnaire_summary(questionnaire)
    supplier_risk_summary = _build_supplier_risk_summary(supplier_risk)
    readme = _render_readme()
    manifest = _build_manifest(
        evidence_index=evidence_index,
        questionnaire_summary=questionnaire_summary,
        supplier_risk_summary=supplier_risk_summary,
        readme=readme,
    )

    output_path = Path(out_dir)
    _prepare_output_dir(output_path)
    _write_json(output_path / TRUST_BUNDLE_MANIFEST_NAME, manifest)
    _write_json(output_path / TRUST_BUNDLE_EVIDENCE_INDEX_NAME, evidence_index)
    _write_json(output_path / TRUST_BUNDLE_QUESTIONNAIRE_SUMMARY_NAME, questionnaire_summary)
    _write_json(output_path / TRUST_BUNDLE_SUPPLIER_RISK_SUMMARY_NAME, supplier_risk_summary)
    _write_text(output_path / TRUST_BUNDLE_README_NAME, readme)
    return manifest


def _build_evidence_index(records: Sequence[EvidenceRecord]) -> dict[str, object]:
    items = tuple(_evidence_index_item(record) for record in records)
    status_counts = Counter(str(item["status"]) for item in items)
    return {
        "schema_version": TRUST_BUNDLE_SCHEMA_VERSION,
        "evidence_count": len(items),
        "status_counts": _status_counts(status_counts),
        "items": items,
    }


def _evidence_index_item(record: EvidenceRecord) -> dict[str, object]:
    item: dict[str, object] = {
        "evidence_id": record.evidence_id,
        "type": record.type,
        "source_type": record.source_type or "file",
        "sha256": record.sha256,
        "mapped_controls": record.mapped_controls,
        "validity": record.validity,
        "status": _evidence_status(record),
    }
    if record.source_report is not None:
        item["source_report"] = record.source_report
    if record.source_finding_id is not None:
        item["source_finding_id"] = record.source_finding_id
    return item


def _evidence_status(record: EvidenceRecord) -> TrustBundleStatus:
    review_status = (record.review_status or "").casefold()
    if record.validity != "current":
        return "needs_review"
    if review_status in APPROVED_REVIEW_STATUSES:
        return cast(TrustBundleStatus, review_status)
    if review_status == "needs_evidence":
        return "needs_evidence"
    if review_status in NOT_ASSESSED_REVIEW_STATUSES:
        return "not_assessed"
    return "needs_review"


def _build_questionnaire_summary(report: Mapping[str, object]) -> dict[str, object]:
    items = cast(Sequence[Mapping[str, object]], report.get("items", ()))
    review_statuses = _review_statuses_by_finding(report)
    summary_items = tuple(
        _questionnaire_summary_item(item, review_statuses.get(str(item.get("finding_id", ""))))
        for item in items
    )
    status_counts = Counter(str(item["status"]) for item in summary_items)
    return {
        "schema_version": TRUST_BUNDLE_SCHEMA_VERSION,
        "question_count": len(summary_items),
        "status_counts": _status_counts(status_counts),
        "items": summary_items,
    }


def _questionnaire_summary_item(
    item: Mapping[str, object],
    review_status: str | None,
) -> dict[str, object]:
    evidence_refs = _string_tuple(item.get("evidence_refs", ()))
    answer_status = str(item.get("answer_status", "needs_evidence"))
    return {
        "finding_id": str(item.get("finding_id", "")),
        "mapped_controls": _string_tuple(item.get("mapped_controls", ())),
        "evidence_refs": evidence_refs,
        "status": _questionnaire_status(answer_status, evidence_refs, review_status),
    }


def _questionnaire_status(
    answer_status: str,
    evidence_refs: Sequence[str],
    review_status: str | None,
) -> TrustBundleStatus:
    normalized_review = (review_status or "").casefold()
    if answer_status == "needs_evidence" or not evidence_refs:
        return "needs_evidence"
    if normalized_review in APPROVED_REVIEW_STATUSES:
        return cast(TrustBundleStatus, normalized_review)
    if normalized_review == "needs_evidence":
        return "needs_evidence"
    if normalized_review in NOT_ASSESSED_REVIEW_STATUSES:
        return "not_assessed"
    return "needs_review"


def _review_statuses_by_finding(report: Mapping[str, object]) -> dict[str, str]:
    statuses: dict[str, str] = {}
    documents = cast(Sequence[Mapping[str, object]], report.get("per_document", ()))
    for document in documents:
        evidence_items = cast(Sequence[Mapping[str, object]], document.get("evidence", ()))
        for item in evidence_items:
            finding_id = str(item.get("finding_id", "")).strip()
            if finding_id:
                statuses[finding_id] = str(item.get("review_status", "")).strip().casefold()
    return statuses


def _build_supplier_risk_summary(report: Mapping[str, object]) -> dict[str, object]:
    supplier = cast(Mapping[str, object], report.get("supplier", {}))
    return {
        "schema_version": TRUST_BUNDLE_SCHEMA_VERSION,
        "supplier": {
            "supplier_id": str(supplier.get("supplier_id", "")),
            "criticality": str(supplier.get("criticality", "")),
        },
        "risk_score": _int_field(report, "risk_score"),
        "risk_level": str(report.get("risk_level", "")),
        "score_components": _string_int_mapping(
            report.get("score_components", {}),
            "score_components",
        ),
        "questionnaire_status_counts": _string_int_mapping(
            report.get("questionnaire_status_counts", {}),
            "questionnaire_status_counts",
        ),
        "open_findings": _int_field(report, "open_findings"),
        "evidence_gap_count": _int_field(report, "evidence_gap_count"),
        "disclaimer": str(report.get("disclaimer", "")),
    }


def _build_manifest(
    *,
    evidence_index: Mapping[str, object],
    questionnaire_summary: Mapping[str, object],
    supplier_risk_summary: Mapping[str, object],
    readme: str,
) -> dict[str, object]:
    payloads: dict[str, object] = {
        TRUST_BUNDLE_EVIDENCE_INDEX_NAME: evidence_index,
        TRUST_BUNDLE_QUESTIONNAIRE_SUMMARY_NAME: questionnaire_summary,
        TRUST_BUNDLE_SUPPLIER_RISK_SUMMARY_NAME: supplier_risk_summary,
        TRUST_BUNDLE_README_NAME: readme,
    }
    digest = _canonical_hash(payloads)
    return {
        "schema_version": TRUST_BUNDLE_SCHEMA_VERSION,
        "bundle_type": "trust_bundle_preview",
        "bundle_id": "TB-%s" % digest[:TRUST_BUNDLE_ID_HASH_CHARS],
        "tool_version": __version__,
        "files": TRUST_BUNDLE_FILES,
        "content_sha256": digest,
    }


def _status_counts(counter: Counter[str]) -> dict[str, int]:
    return {status: counter.get(status, 0) for status in sorted(TRUST_BUNDLE_STATUSES)}


def _prepare_output_dir(path: Path) -> None:
    if path.exists() and not path.is_dir():
        raise TrustBundleError("trust bundle output path must be a directory")
    if path.exists():
        unexpected = sorted(
            child.name
            for child in path.iterdir()
            if child.is_dir() or child.name not in TRUST_BUNDLE_FILES
        )
        if unexpected:
            raise TrustBundleError(
                "trust bundle output directory contains unexpected files: %s"
                % ", ".join(unexpected)
            )
        return
    path.mkdir(parents=True, exist_ok=False)


def _string_tuple(value: object) -> tuple[str, ...]:
    if isinstance(value, str):
        stripped = value.strip()
        return (stripped,) if stripped else ()
    if isinstance(value, Sequence) and not isinstance(value, (bytes, bytearray)):
        return tuple(str(item).strip() for item in value if str(item).strip())
    return ()


def _string_int_mapping(value: object, field_name: str) -> dict[str, int]:
    if not isinstance(value, Mapping):
        raise TrustBundleError("%s must contain an object" % field_name)
    result: dict[str, int] = {}
    for key, item in value.items():
        try:
            result[str(key)] = int(cast(int, item))
        except (TypeError, ValueError) as exc:
            raise TrustBundleError("%s must contain integer values" % field_name) from exc
    return result


def _int_field(report: Mapping[str, object], field_name: str) -> int:
    try:
        return int(cast(int, report[field_name]))
    except KeyError as exc:
        raise TrustBundleError("supplier risk report is missing %s" % field_name) from exc
    except (TypeError, ValueError) as exc:
        raise TrustBundleError("supplier risk field %s must be an integer" % field_name) from exc


def _read_json(path: Path, label: str) -> Mapping[str, object]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise TrustBundleError("could not read %s: %s" % (label, path)) from exc
    except json.JSONDecodeError as exc:
        raise TrustBundleError("invalid %s JSON: %s" % (label, path)) from exc
    if not isinstance(payload, Mapping):
        raise TrustBundleError("%s must contain a JSON object" % label)
    return cast(Mapping[str, object], payload)


def _canonical_hash(payload: Mapping[str, object]) -> str:
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _write_json(path: Path, payload: Mapping[str, object]) -> None:
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _write_text(path: Path, text: str) -> None:
    path.write_text(text, encoding="utf-8")


def _render_readme() -> str:
    return "\n".join(
        (
            "# AethelGard Trust Bundle Preview",
            "",
            "This preview contains only metadata selected for review handover.",
            "",
            "Included files:",
            "- manifest.json",
            "- evidence_index.json",
            "- questionnaire_summary.json",
            "- supplier_risk_summary.json",
            "",
            "Status values are limited to accepted, reviewed, needs_evidence, "
            "needs_review, and not_assessed.",
            "",
            "No raw document text, citations, draft answers, database files, logs, "
            "cookies, or private local paths are included.",
            "",
            "This is not legal advice, not an audit, and not a certification.",
        )
    ) + "\n"
