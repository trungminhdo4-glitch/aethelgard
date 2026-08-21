"""Fail-closed public evidence benchmark and controlled export workflow.

This module is intentionally local-only. It processes project-created or
license-approved fixtures, emits evidence candidates rather than compliance
decisions, and requires separate reviewer and auditor audit identities before
export. The supported containment boundary is the CLI; direct callers must supply
trusted local paths and must not treat caller-provided identities as authentication.
"""

from __future__ import annotations

import csv
import hashlib
import json
import os
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import Final, Literal, TypeVar, cast

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from aethelgard import __version__
from aethelgard.document_ingest import (
    CONCRETE_EVIDENCE_TERMS,
    CONFLICTING_EVIDENCE_TERMS,
    NEGATIVE_EVIDENCE_TERMS,
    STALE_EVIDENCE_TERMS,
    SourceType,
    chunk_document_text,
    detect_document_type,
    detect_topics_for_text,
    parse_docx_document,
    parse_json_csv_if_applicable,
    parse_markdown_document,
    parse_pdf_document,
    parse_text_document,
    parse_xlsx_document,
)

BENCHMARK_SCHEMA_VERSION: Final[str] = "1.0"
BENCHMARK_PARSER_VERSION: Final[str] = "public-evidence-parser-1.0"
BENCHMARK_RULESET_VERSION: Final[str] = "public-evidence-rules-1.0"
ANALYSIS_REPORT_NAME: Final[str] = "analysis_report.json"
BENCHMARK_REPORT_NAME: Final[str] = "benchmark_report.json"
REVIEW_TEMPLATE_NAME: Final[str] = "review_template.json"
REVIEWED_REPORT_NAME: Final[str] = "reviewed_report.json"
AUDIT_LEDGER_NAME: Final[str] = "audit.jsonl"
TRUST_MANIFEST_NAME: Final[str] = "manifest.json"
TRUST_EVIDENCE_INDEX_NAME: Final[str] = "evidence_index.json"
TRUST_APPROVED_REPORT_NAME: Final[str] = "approved_report.json"
TRUST_README_NAME: Final[str] = "README.md"
TRUST_AUTHORIZATION_NAME: Final[str] = "EXPORT_AUTHORIZATION.json"
SOURCE_REGISTER_RELATIVE_PATH: Final[Path] = Path("licenses") / "source_register.csv"
HASH_CHUNK_SIZE: Final[int] = 1_048_576
MAX_JSON_BYTES: Final[int] = 5_000_000
MAX_AUDIT_BYTES: Final[int] = 10_000_000
MAX_ID_CHARS: Final[int] = 64
MAX_COMMENT_CHARS: Final[int] = 500
MAX_QUOTE_CHARS: Final[int] = 2_000
MIN_SOURCE_COUNT: Final[int] = 10
MIN_CASE_COUNT: Final[int] = 20
MAX_SOURCE_COUNT: Final[int] = 100
MAX_CASE_COUNT: Final[int] = 500
MAX_FINDING_COUNT: Final[int] = 500
MAX_SOURCE_FILE_BYTES: Final[int] = 50_000_000
MAX_AGGREGATE_SOURCE_BYTES: Final[int] = 200_000_000
FINDING_HASH_CHARS: Final[int] = 16
RUN_HASH_CHARS: Final[int] = 16

Role = Literal["operator", "reviewer", "auditor", "admin"]
ConfidenceCategory = Literal["high", "medium", "low", "insufficient"]
EvidenceStatus = Literal["positive", "partial", "ambiguous", "insufficient"]
ReviewDecisionStatus = Literal["accepted", "rejected", "needs_evidence"]
AuditEventType = Literal[
    "analysis_started",
    "configuration_frozen",
    "input_registered",
    "parser_completed",
    "finding_created",
    "analysis_completed",
    "review_applied",
    "review_completed",
    "export_authorized",
    "export_created",
    "blocked_action",
]

AUDIT_EVENT_TYPES: Final[frozenset[str]] = frozenset(
    {
        "analysis_started",
        "configuration_frozen",
        "input_registered",
        "parser_completed",
        "finding_created",
        "analysis_completed",
        "review_applied",
        "review_completed",
        "export_authorized",
        "export_created",
        "blocked_action",
    }
)

APPROVED_LOCAL_LICENSE_STATUSES: Final[frozenset[str]] = frozenset(
    {"project_created", "approved_public_license"}
)
SAFE_LOCAL_PERMISSION: Final[str] = "yes"
FORBIDDEN_PATH_MARKERS: Final[tuple[str, ...]] = (
    ".env",
    "credential",
    "cookie",
    "database",
    "private",
    "secret",
)
FORBIDDEN_SUFFIXES: Final[frozenset[str]] = frozenset({".db", ".log", ".sqlite", ".sqlite3"})
FORBIDDEN_ALLOWED_CLAIM_PATTERNS: Final[tuple[re.Pattern[str], ...]] = (
    re.compile(r"\bnis\s*-?\s*2\s*(?:compliant|konform)\b", re.IGNORECASE),
    re.compile(r"\biso\s*(?:27001\s*)?(?:certified|zertifiziert)\b", re.IGNORECASE),
    re.compile(r"\bcontrol\s+(?:fulfilled|erf(?:u|ue)llt)\b", re.IGNORECASE),
)
SOURCE_REGISTER_COLUMNS: Final[tuple[str, ...]] = (
    "source_id",
    "title",
    "publisher",
    "public_url",
    "retrieved_at",
    "document_version",
    "sha256",
    "file_type",
    "source_class",
    "license_status",
    "redistribution_allowed",
    "local_storage_allowed",
    "local_path",
    "used_excerpt_or_pages",
    "inclusion_reason",
    "review_status",
    "known_limitations",
)
EXPECTED_FILE_TYPES: Final[dict[SourceType, str]] = {
    "text": "txt",
    "markdown": "md",
    "csv": "csv",
    "json": "json",
    "docx": "docx",
    "xlsx": "xlsx",
    "pdf": "pdf",
    "image": "image",
    "unsupported": "unsupported",
}
ANALYSIS_REPORT_FIELDS: Final[frozenset[str]] = frozenset(
    {
        "schema_version",
        "report_type",
        "dataset_id",
        "reference_status",
        "tenant_id",
        "run_id",
        "operator_actor_id",
        "configuration",
        "configuration_sha256",
        "manifest_sha256",
        "sources",
        "findings",
        "finding_count",
        "decision_boundary",
        "requires_human_review",
        "disclaimer",
        "content_sha256",
    }
)
SOURCE_RECORD_FIELDS: Final[frozenset[str]] = frozenset(
    {
        "source_id",
        "document_id",
        "file_name",
        "file_type",
        "sha256",
        "source_class",
        "license_status",
        "review_status",
        "parser_status",
        "finding_count",
    }
)
FINDING_FIELDS: Final[frozenset[str]] = frozenset(
    {
        "tenant_id",
        "run_id",
        "finding_id",
        "source_id",
        "document_id",
        "file_name",
        "document_sha256",
        "page",
        "paragraph",
        "table_position",
        "char_start",
        "char_end",
        "normalized_quote",
        "quote_sha256",
        "locator_basis",
        "mapped_control",
        "evidence_status",
        "confidence_category",
        "allowed_statement",
        "forbidden_statement",
        "decision",
        "review_status",
        "requires_human_review",
    }
)
REVIEWED_FINDING_FIELDS: Final[frozenset[str]] = FINDING_FIELDS | {"review_comment"}
REVIEWED_REPORT_FIELDS: Final[frozenset[str]] = ANALYSIS_REPORT_FIELDS | {
    "analysis_sha256",
    "review",
}
CONFIDENCE_CRITERIA: Final[dict[str, str]] = {
    "high": (
        "Traceable source plus at least two concrete implementation signals; "
        "no negative, stale, or conflict signal."
    ),
    "medium": (
        "Traceable source plus one concrete implementation signal; "
        "no negative, stale, or conflict signal."
    ),
    "low": (
        "Traceable but ambiguous, stale, conflicting, or lacking a concrete implementation signal."
    ),
    "insufficient": (
        "No traceable candidate or an explicit negative-evidence signal; no finding is emitted."
    ),
}
DISCLAIMER: Final[str] = (
    "Automated evidence pre-assessment only. No legal advice, audit opinion, certification, "
    "NIS-2 compliance decision, ISO certification claim, or final control-fulfilment decision. "
    "Qualified human review is mandatory before controlled export."
)
ModelT = TypeVar("ModelT", bound=BaseModel)


class PublicEvidenceError(ValueError):
    """Raised when the public evidence workflow cannot continue safely."""


class ExecutionContext(BaseModel):
    """Mandatory tenant, actor, role, and offline execution context."""

    model_config = ConfigDict(frozen=True, extra="forbid", str_strip_whitespace=True)

    tenant_id: str = Field(
        min_length=3, max_length=MAX_ID_CHARS, pattern=r"^[A-Za-z0-9][A-Za-z0-9_-]+$"
    )
    actor_id: str = Field(
        min_length=3, max_length=MAX_ID_CHARS, pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]+$"
    )
    role: Role
    offline: Literal[True]
    deterministic: Literal[True]


class SourceEntry(BaseModel):
    """One vendored public or generated-lab source."""

    model_config = ConfigDict(frozen=True, extra="forbid", str_strip_whitespace=True)

    source_id: str = Field(min_length=3, max_length=MAX_ID_CHARS, pattern=r"^[a-z0-9][a-z0-9-]+$")
    title: str = Field(min_length=1, max_length=200)
    publisher: str = Field(min_length=1, max_length=120)
    public_url: str | None = Field(default=None, max_length=500)
    retrieved_at: str = Field(min_length=1, max_length=40)
    document_version: str = Field(min_length=1, max_length=80)
    sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    file_type: str = Field(min_length=1, max_length=20)
    source_class: Literal["generated_lab_evidence", "public_document"]
    license_status: Literal["project_created", "approved_public_license", "unclear"]
    redistribution_allowed: Literal["yes", "no", "unclear"]
    local_storage_allowed: Literal["yes", "no", "unclear"]
    local_path: str = Field(min_length=1, max_length=260)
    used_excerpt_or_pages: str = Field(min_length=1, max_length=200)
    inclusion_reason: str = Field(min_length=1, max_length=500)
    review_status: Literal["provisional_internal_reference", "externally_reviewed"]
    known_limitations: tuple[str, ...] = Field(min_length=1, max_length=8)

    @field_validator("local_path")
    @classmethod
    def _validate_local_path(cls, value: str) -> str:
        _validate_relative_safe_path(value, "source local_path")
        return value


class BenchmarkManifest(BaseModel):
    """Validated dataset manifest."""

    model_config = ConfigDict(frozen=True, extra="forbid", str_strip_whitespace=True)

    schema_version: Literal["1.0"]
    dataset_id: str = Field(min_length=3, max_length=MAX_ID_CHARS, pattern=r"^[a-z0-9][a-z0-9-]+$")
    reference_status: Literal["provisional_internal_reference"]
    parser_version: str = Field(min_length=1, max_length=80)
    ruleset_version: str = Field(min_length=1, max_length=80)
    expected_cases_path: str = Field(min_length=1, max_length=260)
    sources: tuple[SourceEntry, ...] = Field(
        min_length=MIN_SOURCE_COUNT,
        max_length=MAX_SOURCE_COUNT,
    )

    @field_validator("expected_cases_path")
    @classmethod
    def _validate_expected_path(cls, value: str) -> str:
        _validate_relative_safe_path(value, "expected_cases_path")
        return value

    @model_validator(mode="after")
    def _unique_source_ids(self) -> BenchmarkManifest:
        source_ids = [source.source_id for source in self.sources]
        if len(source_ids) != len(set(source_ids)):
            raise ValueError("manifest contains duplicate source_id values")
        return self


class ExpectedCase(BaseModel):
    """Provisional internal benchmark reference case, never an expert gold claim."""

    model_config = ConfigDict(frozen=True, extra="forbid", str_strip_whitespace=True)

    case_id: str = Field(min_length=3, max_length=MAX_ID_CHARS, pattern=r"^[A-Z0-9-]+$")
    source_id: str = Field(min_length=3, max_length=MAX_ID_CHARS)
    expected_control: str = Field(min_length=1, max_length=100)
    expected_text: str = Field(min_length=1, max_length=MAX_QUOTE_CHARS)
    expected_page: int | None = Field(default=None, ge=1)
    expected_evidence_status: EvidenceStatus
    allowed_statement: str = Field(min_length=1, max_length=500)
    forbidden_statement: str = Field(min_length=1, max_length=500)
    expected_confidence_category: ConfidenceCategory
    rationale: str = Field(min_length=1, max_length=800)
    reviewer: str = Field(min_length=1, max_length=120)
    review_status: Literal["provisional_internal_reference", "externally_reviewed"]
    reviewed_at: str = Field(min_length=1, max_length=80)
    second_review: str | None = Field(default=None, max_length=200)


class ExpectedCasesDocument(BaseModel):
    """Container for at least twenty provisional reference cases."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    schema_version: Literal["1.0"]
    reference_status: Literal["provisional_internal_reference"]
    cases: tuple[ExpectedCase, ...] = Field(
        min_length=MIN_CASE_COUNT,
        max_length=MAX_CASE_COUNT,
    )

    @model_validator(mode="after")
    def _unique_cases(self) -> ExpectedCasesDocument:
        case_ids = [case.case_id for case in self.cases]
        if len(case_ids) != len(set(case_ids)):
            raise ValueError("expected cases contain duplicate case_id values")
        return self


class ReviewDecision(BaseModel):
    """One explicit decision for one finding."""

    model_config = ConfigDict(frozen=True, extra="forbid", str_strip_whitespace=True)

    finding_id: str = Field(min_length=3, max_length=MAX_ID_CHARS)
    status: ReviewDecisionStatus
    comment: str = Field(min_length=1, max_length=MAX_COMMENT_CHARS)


class ReviewSubmission(BaseModel):
    """Human-confirmed, tenant-bound review submission."""

    model_config = ConfigDict(frozen=True, extra="forbid", str_strip_whitespace=True)

    schema_version: Literal["1.0"]
    tenant_id: str = Field(min_length=3, max_length=MAX_ID_CHARS)
    run_id: str = Field(min_length=3, max_length=MAX_ID_CHARS)
    reviewer_id: str = Field(min_length=3, max_length=MAX_ID_CHARS)
    reviewer_role: Literal["reviewer", "admin"]
    reviewed_at: str = Field(min_length=1, max_length=80)
    human_review_confirmed: Literal[True]
    decisions: tuple[ReviewDecision, ...] = Field(min_length=1)

    @field_validator("reviewed_at")
    @classmethod
    def _validate_reviewed_at(cls, value: str) -> str:
        try:
            normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
            return datetime.fromisoformat(normalized).isoformat()
        except ValueError as exc:
            raise ValueError("reviewed_at must be ISO-8601") from exc

    @model_validator(mode="after")
    def _unique_decisions(self) -> ReviewSubmission:
        finding_ids = [decision.finding_id for decision in self.decisions]
        if len(finding_ids) != len(set(finding_ids)):
            raise ValueError("review submission contains duplicate finding_id values")
        return self


@dataclass(frozen=True)
class TextUnit:
    """One reliably locatable normalized text unit."""

    text: str
    page: int | None
    locator_basis: str


def run_public_evidence_benchmark(
    dataset_path: Path | str,
    out_dir: Path | str,
    context: ExecutionContext,
) -> dict[str, object]:
    """Run the dataset twice in-memory and write deterministic benchmark outputs."""
    _require_role(context, {"operator", "admin"}, "benchmark run")
    dataset = _resolve_without_symlinks(Path(dataset_path), "benchmark dataset")
    output = _resolve_without_symlinks(Path(out_dir), "benchmark output")
    _prepare_output_dir(
        output,
        {ANALYSIS_REPORT_NAME, BENCHMARK_REPORT_NAME, REVIEW_TEMPLATE_NAME, AUDIT_LEDGER_NAME},
    )
    ledger = output / AUDIT_LEDGER_NAME
    try:
        tentative_run_id = _declared_run_id(dataset, context)
    except PublicEvidenceError:
        tentative_run_id = (
            "PEV-%s" % _sha256_text("%s\n%s" % (context.tenant_id, dataset.name))[:RUN_HASH_CHARS]
        )
    append_audit_event(
        ledger,
        context,
        tentative_run_id,
        "analysis_started",
        {"dataset_label": dataset.name},
    )
    try:
        first = analyze_public_evidence_dataset(dataset, context)
        second = analyze_public_evidence_dataset(dataset, context)
        if first["content_sha256"] != second["content_sha256"]:
            raise PublicEvidenceError("identical deterministic analyses produced different hashes")
        run_id = str(first["run_id"])
        config = cast(Mapping[str, object], first["configuration"])
        append_audit_event(
            ledger,
            context,
            run_id,
            "configuration_frozen",
            {
                "config_sha256": str(first["configuration_sha256"]),
                "parser_version": str(config["parser_version"]),
                "ruleset_version": str(config["ruleset_version"]),
                "software_version": str(config["software_version"]),
            },
        )
        for item in cast(Sequence[Mapping[str, object]], first["sources"]):
            append_audit_event(
                ledger,
                context,
                run_id,
                "input_registered",
                {
                    "source_id": str(item["source_id"]),
                    "document_id": str(item["document_id"]),
                    "sha256": str(item["sha256"]),
                    "parser_status": str(item["parser_status"]),
                },
            )
            append_audit_event(
                ledger,
                context,
                run_id,
                "parser_completed",
                {
                    "source_id": str(item["source_id"]),
                    "parser_status": str(item["parser_status"]),
                },
            )
        for finding in cast(Sequence[Mapping[str, object]], first["findings"]):
            append_audit_event(
                ledger,
                context,
                run_id,
                "finding_created",
                {
                    "finding_id": str(finding["finding_id"]),
                    "source_id": str(finding["source_id"]),
                    "mapped_control": str(finding["mapped_control"]),
                    "confidence_category": str(finding["confidence_category"]),
                },
            )
        benchmark_report = evaluate_public_evidence_benchmark(
            dataset,
            first,
            reproducible=True,
        )
        review_template = build_review_template(first)
        _write_json(output / ANALYSIS_REPORT_NAME, first)
        _write_json(output / BENCHMARK_REPORT_NAME, benchmark_report)
        _write_json(output / REVIEW_TEMPLATE_NAME, review_template)
        append_audit_event(
            ledger,
            context,
            run_id,
            "analysis_completed",
            {
                "analysis_sha256": str(first["content_sha256"]),
                "finding_count": len(cast(Sequence[object], first["findings"])),
                "reproducible": True,
            },
        )
        return benchmark_report
    except (OSError, ValueError) as exc:
        _record_blocked_event(
            ledger,
            context,
            tentative_run_id,
            {"action": "benchmark_run", "reason": _safe_reason(str(exc))},
        )
        if isinstance(exc, PublicEvidenceError):
            raise
        raise PublicEvidenceError("benchmark run blocked: %s" % _safe_reason(str(exc))) from exc


def analyze_public_evidence_dataset(
    dataset_path: Path | str,
    context: ExecutionContext,
) -> dict[str, object]:
    """Build a deterministic source-backed analysis without using expected labels."""
    _require_role(context, {"operator", "admin"}, "benchmark analysis")
    dataset = _resolve_without_symlinks(Path(dataset_path), "benchmark dataset")
    manifest_path = _validated_dataset_file(dataset, Path("manifest.json"), "manifest")
    manifest = _load_model(manifest_path, BenchmarkManifest)
    if manifest.parser_version != BENCHMARK_PARSER_VERSION:
        raise PublicEvidenceError("dataset parser_version does not match runtime parser")
    if manifest.ruleset_version != BENCHMARK_RULESET_VERSION:
        raise PublicEvidenceError("dataset ruleset_version does not match runtime ruleset")
    _validate_source_register(dataset, manifest)
    configuration: dict[str, object] = {
        "offline": context.offline,
        "deterministic": context.deterministic,
        "parser_version": BENCHMARK_PARSER_VERSION,
        "ruleset_version": BENCHMARK_RULESET_VERSION,
        "software_version": __version__,
        "seed": "not_used",
        "confidence_categories": CONFIDENCE_CRITERIA,
    }
    configuration_sha256 = _canonical_hash(configuration)
    source_records: list[dict[str, object]] = []
    findings: list[dict[str, object]] = []
    source_hashes: list[str] = []
    aggregate_source_bytes = 0
    for source in sorted(manifest.sources, key=lambda item: item.source_id):
        source_path = _validated_source_path(dataset, source)
        aggregate_source_bytes += source_path.stat().st_size
        if aggregate_source_bytes > MAX_AGGREGATE_SOURCE_BYTES:
            raise PublicEvidenceError("benchmark sources exceed the aggregate size limit")
        digest = _sha256_file(source_path)
        if digest != source.sha256:
            raise PublicEvidenceError("source hash mismatch for %s" % source.source_id)
        source_hashes.append("%s:%s" % (source.source_id, digest))
        source_type = detect_document_type(source_path)
        if source_type in {"unsupported", "image"}:
            raise PublicEvidenceError(
                "benchmark source type is not locally parseable: %s" % source.source_id
            )
        if EXPECTED_FILE_TYPES[source_type] != source.file_type.lower():
            raise PublicEvidenceError(
                "declared file_type does not match detected source type: %s" % source.source_id
            )
        units = _parse_text_units(source_path, source_type)
        document_id = (
            "DOC-%s"
            % _sha256_text("%s\n%s\n%s" % (source.source_id, digest, source_type))[
                :FINDING_HASH_CHARS
            ]
        )
        source_findings: list[dict[str, object]] = []
        for unit in units:
            source_findings.extend(
                _findings_for_unit(
                    manifest.dataset_id,
                    context,
                    source,
                    source_path,
                    source_type,
                    digest,
                    document_id,
                    unit,
                )
            )
        source_findings.sort(key=lambda item: str(item["finding_id"]))
        findings.extend(source_findings)
        if len(findings) > MAX_FINDING_COUNT:
            raise PublicEvidenceError("benchmark exceeds the global finding limit")
        source_records.append(
            {
                "source_id": source.source_id,
                "document_id": document_id,
                "file_name": source_path.name,
                "file_type": source.file_type,
                "sha256": digest,
                "source_class": source.source_class,
                "license_status": source.license_status,
                "review_status": source.review_status,
                "parser_status": "parsed",
                "finding_count": len(source_findings),
            }
        )
    run_basis = {
        "tenant_id": context.tenant_id,
        "dataset_id": manifest.dataset_id,
        "configuration_sha256": configuration_sha256,
        "source_hashes": source_hashes,
    }
    run_id = "PEV-%s" % _canonical_hash(run_basis)[:RUN_HASH_CHARS]
    for finding in findings:
        finding["run_id"] = run_id
    findings.sort(key=lambda item: str(item["finding_id"]))
    report: dict[str, object] = {
        "schema_version": BENCHMARK_SCHEMA_VERSION,
        "report_type": "public_evidence_analysis",
        "dataset_id": manifest.dataset_id,
        "reference_status": manifest.reference_status,
        "tenant_id": context.tenant_id,
        "run_id": run_id,
        "operator_actor_id": context.actor_id,
        "configuration": configuration,
        "configuration_sha256": configuration_sha256,
        "manifest_sha256": _sha256_file(manifest_path),
        "sources": source_records,
        "findings": findings,
        "finding_count": len(findings),
        "decision_boundary": "evidence_candidates_only",
        "requires_human_review": True,
        "disclaimer": DISCLAIMER,
    }
    report["content_sha256"] = _canonical_hash(report)
    return report


def evaluate_public_evidence_benchmark(
    dataset_path: Path | str,
    analysis: Mapping[str, object],
    *,
    reproducible: bool,
) -> dict[str, object]:
    """Evaluate mappings and locators against provisional internal references."""
    dataset = _resolve_without_symlinks(Path(dataset_path), "benchmark dataset")
    manifest_path = _validated_dataset_file(dataset, Path("manifest.json"), "manifest")
    manifest = _load_model(manifest_path, BenchmarkManifest)
    expected_path = _validated_dataset_file(
        dataset,
        Path(manifest.expected_cases_path),
        "expected cases",
    )
    expected = _load_model(expected_path, ExpectedCasesDocument)
    source_ids = {source.source_id for source in manifest.sources}
    for case in expected.cases:
        if case.source_id not in source_ids:
            raise PublicEvidenceError(
                "expected case references unknown source_id: %s" % case.case_id
            )
    findings = cast(Sequence[Mapping[str, object]], analysis.get("findings", ()))
    actual_by_pair: dict[tuple[str, str], Mapping[str, object]] = {}
    duplicate_pairs: list[str] = []
    for candidate in findings:
        pair = (
            str(candidate.get("source_id", "")),
            str(candidate.get("mapped_control", "")),
        )
        if pair in actual_by_pair:
            duplicate_pairs.append("%s:%s" % pair)
        actual_by_pair[pair] = candidate
    if duplicate_pairs:
        raise PublicEvidenceError("analysis contains duplicate source/control findings")
    expected_relevant = {
        (case.source_id, case.expected_control)
        for case in expected.cases
        if case.expected_evidence_status != "insufficient"
    }
    actual_pairs = set(actual_by_pair)
    true_positives = len(actual_pairs & expected_relevant)
    false_positives = len(actual_pairs - expected_relevant)
    false_negatives = len(expected_relevant - actual_pairs)
    case_results: list[dict[str, object]] = []
    confidence_hits = 0
    source_hits = 0
    locator_hits = 0
    relevant_case_count = 0
    page_cases = 0
    page_hits = 0
    for case in expected.cases:
        matched_finding = actual_by_pair.get((case.source_id, case.expected_control))
        actual_status: EvidenceStatus = (
            cast(EvidenceStatus, matched_finding["evidence_status"])
            if matched_finding is not None
            else "insufficient"
        )
        actual_confidence: ConfidenceCategory = (
            cast(ConfidenceCategory, matched_finding["confidence_category"])
            if matched_finding is not None
            else "insufficient"
        )
        source_match: bool | None = None
        locator_match: bool | None = None
        expected_text = _normalize_text(case.expected_text)
        if case.expected_evidence_status != "insufficient":
            relevant_case_count += 1
            source_match = (
                matched_finding is not None and str(matched_finding["source_id"]) == case.source_id
            )
            locator_match = matched_finding is not None and expected_text in str(
                matched_finding["normalized_quote"]
            )
            source_hits += int(source_match)
            locator_hits += int(locator_match)
        if case.expected_page is not None:
            page_cases += 1
            if matched_finding is not None and matched_finding.get("page") == case.expected_page:
                page_hits += 1
        status_match = actual_status == case.expected_evidence_status
        confidence_match = actual_confidence == case.expected_confidence_category
        confidence_hits += int(confidence_match)
        reference_match = (
            matched_finding is None
            if case.expected_evidence_status == "insufficient"
            else bool(source_match and locator_match)
        )
        case_results.append(
            {
                "case_id": case.case_id,
                "source_id": case.source_id,
                "expected_control": case.expected_control,
                "finding_id": (
                    None if matched_finding is None else str(matched_finding["finding_id"])
                ),
                "expected_evidence_status": case.expected_evidence_status,
                "actual_evidence_status": actual_status,
                "expected_confidence_category": case.expected_confidence_category,
                "actual_confidence_category": actual_confidence,
                "source_id_correct": source_match,
                "locator_correct": locator_match,
                "status_correct": status_match,
                "confidence_correct": confidence_match,
                "passed": reference_match and status_match and confidence_match,
            }
        )
    unsupported_findings = sum(
        1 for finding in findings if not _finding_has_complete_source_reference(finding)
    )
    forbidden_claims = sum(
        1
        for finding in findings
        if _contains_forbidden_allowed_claim(str(finding.get("allowed_statement", "")))
    )
    case_count = len(expected.cases)
    metrics: dict[str, object] = {
        "control_mapping_precision": _ratio(true_positives, true_positives + false_positives),
        "control_mapping_recall": _ratio(true_positives, true_positives + false_negatives),
        "correct_source_id_rate": _ratio(source_hits, relevant_case_count),
        "correct_locator_rate": _ratio(locator_hits, relevant_case_count),
        "page_accuracy": (
            _ratio(page_hits, page_cases)
            if page_cases
            else {"status": "not_measured", "reason": "no provisionally reviewed page references"}
        ),
        "unsubstantiated_findings": unsupported_findings,
        "false_positive_evidence": false_positives,
        "missed_evidence": false_negatives,
        "correct_confidence_category_rate": _ratio(confidence_hits, case_count),
        "forbidden_compliance_claims": forbidden_claims,
        "findings_without_source_reference": unsupported_findings,
        "reproducibility": {
            "identical_normalized_output": reproducible,
            "analysis_sha256": str(analysis.get("content_sha256", "")),
        },
        "review_gate_violations": {
            "status": "not_measured",
            "reason": "covered by adversarial workflow tests, not inferred from this dataset run",
        },
        "cross_tenant_violations": {
            "status": "not_measured",
            "reason": "covered by adversarial workflow tests, not inferred from this dataset run",
        },
    }
    report: dict[str, object] = {
        "schema_version": BENCHMARK_SCHEMA_VERSION,
        "report_type": "public_evidence_benchmark",
        "dataset_id": manifest.dataset_id,
        "tenant_id": str(analysis.get("tenant_id", "")),
        "run_id": str(analysis.get("run_id", "")),
        "reference_status": expected.reference_status,
        "case_count": case_count,
        "source_count": len(manifest.sources),
        "metrics": metrics,
        "case_results": sorted(case_results, key=lambda item: str(item["case_id"])),
        "passed": all(bool(item["passed"]) for item in case_results)
        and false_positives == 0
        and false_negatives == 0
        and unsupported_findings == 0
        and forbidden_claims == 0
        and reproducible,
        "expert_validation_required": True,
        "disclaimer": DISCLAIMER,
    }
    report["content_sha256"] = _canonical_hash(report)
    return report


def build_review_template(analysis: Mapping[str, object]) -> dict[str, object]:
    """Build a deterministic template that cannot be mistaken for approval."""
    findings = cast(Sequence[Mapping[str, object]], analysis.get("findings", ()))
    return {
        "schema_version": BENCHMARK_SCHEMA_VERSION,
        "tenant_id": str(analysis.get("tenant_id", "")),
        "run_id": str(analysis.get("run_id", "")),
        "reviewer_id": "",
        "reviewer_role": "reviewer",
        "reviewed_at": "",
        "human_review_confirmed": False,
        "decisions": [
            {"finding_id": str(item["finding_id"]), "status": "pending", "comment": ""}
            for item in findings
        ],
        "instruction": "Replace every pending status and explicitly confirm human review.",
    }


def apply_public_evidence_review(
    analysis_path: Path | str,
    decisions_path: Path | str,
    out_dir: Path | str,
    audit_ledger_path: Path | str,
    context: ExecutionContext,
) -> dict[str, object]:
    """Apply complete human review decisions and write a tenant-bound reviewed report."""
    _require_role(context, {"reviewer", "admin"}, "benchmark review")
    output = _resolve_without_symlinks(Path(out_dir), "review output")
    _prepare_output_dir(output, {REVIEWED_REPORT_NAME})
    analysis = _validate_analysis_report(_read_json_object(Path(analysis_path)))
    run_id = str(analysis.get("run_id", ""))
    ledger = Path(audit_ledger_path)
    try:
        _require_tenant(analysis, context)
        _require_analysis_audit(ledger, analysis)
        if str(analysis["operator_actor_id"]) == context.actor_id:
            raise PublicEvidenceError("operator and reviewer identities must be distinct")
        submission = _load_model(Path(decisions_path), ReviewSubmission)
        if submission.tenant_id != context.tenant_id:
            raise PublicEvidenceError("cross-tenant review is blocked")
        if submission.run_id != run_id:
            raise PublicEvidenceError("review run_id does not match analysis")
        if submission.reviewer_id != context.actor_id or submission.reviewer_role != context.role:
            raise PublicEvidenceError("reviewer identity or role does not match execution context")
        findings = cast(Sequence[Mapping[str, object]], analysis.get("findings", ()))
        expected_ids = {str(item.get("finding_id", "")) for item in findings}
        decisions = {decision.finding_id: decision for decision in submission.decisions}
        if set(decisions) != expected_ids:
            raise PublicEvidenceError("review must decide every finding exactly once")
        reviewed_findings: list[dict[str, object]] = []
        analysis_sha256 = str(analysis["content_sha256"])
        for finding in findings:
            finding_id = str(finding["finding_id"])
            decision = decisions[finding_id]
            reviewed = dict(finding)
            reviewed["review_status"] = decision.status
            reviewed["review_comment"] = decision.comment
            reviewed_findings.append(reviewed)
            append_audit_event(
                ledger,
                context,
                run_id,
                "review_applied",
                {
                    "analysis_sha256": analysis_sha256,
                    "finding_id": finding_id,
                    "review_status": decision.status,
                },
            )
        reviewed_report: dict[str, object] = {
            **{
                key: value
                for key, value in analysis.items()
                if key not in {"findings", "content_sha256"}
            },
            "report_type": "public_evidence_reviewed_report",
            "analysis_sha256": analysis_sha256,
            "findings": reviewed_findings,
            "review": {
                "reviewer_id": submission.reviewer_id,
                "reviewer_role": submission.reviewer_role,
                "reviewed_at": submission.reviewed_at,
                "human_review_confirmed": submission.human_review_confirmed,
            },
        }
        reviewed_report["content_sha256"] = _canonical_hash(reviewed_report)
        _write_json(output / REVIEWED_REPORT_NAME, reviewed_report)
        append_audit_event(
            ledger,
            context,
            run_id,
            "review_completed",
            {
                "analysis_sha256": analysis_sha256,
                "reviewed_report_sha256": str(reviewed_report["content_sha256"]),
                "decision_count": len(reviewed_findings),
            },
        )
        return reviewed_report
    except (OSError, ValueError) as exc:
        _record_blocked_event(
            ledger,
            context,
            run_id or "unknown-run",
            {"action": "benchmark_review", "reason": _safe_reason(str(exc))},
        )
        if isinstance(exc, PublicEvidenceError):
            raise
        raise PublicEvidenceError("benchmark review blocked: %s" % _safe_reason(str(exc))) from exc


def export_public_evidence_trust_bundle(
    reviewed_report_path: Path | str,
    out_dir: Path | str,
    audit_ledger_path: Path | str,
    context: ExecutionContext,
) -> dict[str, object]:
    """Export only accepted reviewed findings as a metadata-first trust bundle."""
    _require_role(context, {"auditor", "admin"}, "benchmark export")
    output = _resolve_without_symlinks(Path(out_dir), "export output")
    reviewed = _validate_reviewed_report(_read_json_object(Path(reviewed_report_path)))
    run_id = str(reviewed.get("run_id", ""))
    ledger = Path(audit_ledger_path)
    try:
        _require_tenant(reviewed, context)
        review = cast(Mapping[str, object], reviewed.get("review", {}))
        if review.get("human_review_confirmed") is not True:
            raise PublicEvidenceError("human review confirmation is required before export")
        stage_actors = {
            str(reviewed["operator_actor_id"]),
            str(review.get("reviewer_id", "")),
            context.actor_id,
        }
        if len(stage_actors) != 3:
            raise PublicEvidenceError("operator, reviewer, and auditor identities must be distinct")
        audit_events = _require_review_audit(ledger, reviewed)
        findings = cast(Sequence[Mapping[str, object]], reviewed.get("findings", ()))
        allowed_statuses = {"accepted", "rejected", "needs_evidence"}
        invalid = sorted(
            str(item.get("finding_id", ""))
            for item in findings
            if str(item.get("review_status", "")) not in allowed_statuses
        )
        if invalid:
            raise PublicEvidenceError("export blocked by missing or invalid review status")
        accepted = [
            _exportable_finding(item)
            for item in findings
            if item.get("review_status") == "accepted"
        ]
        approved_report: dict[str, object] = {
            "schema_version": BENCHMARK_SCHEMA_VERSION,
            "report_type": "public_evidence_approved_report",
            "tenant_id": context.tenant_id,
            "run_id": run_id,
            "review": dict(review),
            "accepted_findings": accepted,
            "accepted_count": len(accepted),
            "disclaimer": DISCLAIMER,
        }
        approved_report["content_sha256"] = _canonical_hash(approved_report)
        evidence_items = [
            {
                "finding_id": str(item["finding_id"]),
                "source_id": str(item["source_id"]),
                "document_id": str(item["document_id"]),
                "document_sha256": str(item["document_sha256"]),
                "mapped_control": str(item["mapped_control"]),
                "confidence_category": str(item["confidence_category"]),
                "review_status": "accepted",
                "source_locator": {
                    "page": item.get("page"),
                    "paragraph": item.get("paragraph"),
                    "table_position": item.get("table_position"),
                    "char_start": item.get("char_start"),
                    "char_end": item.get("char_end"),
                    "quote_sha256": item.get("quote_sha256"),
                    "locator_basis": item.get("locator_basis"),
                },
            }
            for item in accepted
        ]
        evidence_index: dict[str, object] = {
            "schema_version": BENCHMARK_SCHEMA_VERSION,
            "tenant_id": context.tenant_id,
            "run_id": run_id,
            "evidence_count": len(evidence_items),
            "items": evidence_items,
        }
        readme = _trust_bundle_readme()
        payload_hashes = {
            TRUST_APPROVED_REPORT_NAME: _canonical_hash(approved_report),
            TRUST_EVIDENCE_INDEX_NAME: _canonical_hash(evidence_index),
            TRUST_README_NAME: _sha256_text(readme),
        }
        manifest: dict[str, object] = {
            "schema_version": BENCHMARK_SCHEMA_VERSION,
            "bundle_type": "public_evidence_trust_bundle_preview",
            "tenant_id": context.tenant_id,
            "run_id": run_id,
            "reviewed_report_sha256": _sha256_file(Path(reviewed_report_path)),
            "files": sorted(
                {
                    TRUST_MANIFEST_NAME,
                    TRUST_EVIDENCE_INDEX_NAME,
                    TRUST_APPROVED_REPORT_NAME,
                    TRUST_README_NAME,
                    TRUST_AUTHORIZATION_NAME,
                }
            ),
            "payload_hashes": payload_hashes,
            "accepted_count": len(accepted),
            "rejected_or_needs_evidence_omitted": len(findings) - len(accepted),
            "tool_version": __version__,
            "audit_anchor_before_export": str(audit_events[-1]["event_hash"]),
            "authorization_proof_file": TRUST_AUTHORIZATION_NAME,
            "disclaimer": DISCLAIMER,
        }
        manifest["content_sha256"] = _canonical_hash(manifest)
        staging = _prepare_staged_export(output)
        _write_json(staging / TRUST_MANIFEST_NAME, manifest)
        _write_json(staging / TRUST_EVIDENCE_INDEX_NAME, evidence_index)
        _write_json(staging / TRUST_APPROVED_REPORT_NAME, approved_report)
        _write_text_file(staging / TRUST_README_NAME, readme)
        authorization = append_audit_event(
            ledger,
            context,
            run_id,
            "export_authorized",
            {
                "bundle_sha256": str(manifest["content_sha256"]),
                "accepted_count": len(accepted),
            },
        )
        authorization_proof: dict[str, object] = {
            "schema_version": BENCHMARK_SCHEMA_VERSION,
            "tenant_id": context.tenant_id,
            "run_id": run_id,
            "bundle_sha256": str(manifest["content_sha256"]),
            "authorization_event_hash": str(authorization["event_hash"]),
            "instruction": (
                "Treat this bundle as controlled only when the matching audit chain "
                "validates and contains export_created."
            ),
        }
        authorization_proof["content_sha256"] = _canonical_hash(authorization_proof)
        _write_json(staging / TRUST_AUTHORIZATION_NAME, authorization_proof)
        staging.replace(output)
        append_audit_event(
            ledger,
            context,
            run_id,
            "export_created",
            {
                "bundle_sha256": str(manifest["content_sha256"]),
                "accepted_count": len(accepted),
                "authorization_event_hash": str(authorization["event_hash"]),
            },
        )
        return manifest
    except (OSError, ValueError) as exc:
        _record_blocked_event(
            ledger,
            context,
            run_id or "unknown-run",
            {"action": "benchmark_export", "reason": _safe_reason(str(exc))},
        )
        if isinstance(exc, PublicEvidenceError):
            raise
        raise PublicEvidenceError("benchmark export blocked: %s" % _safe_reason(str(exc))) from exc


def validate_source_locator(
    finding: Mapping[str, object],
    normalized_text: str,
    source_type: SourceType,
    *,
    actual_page: int | None = None,
) -> None:
    """Validate an exact normalized span and any claimed page/table locator."""
    quote = str(finding.get("normalized_quote", ""))
    try:
        start = int(cast(int, finding["char_start"]))
        end = int(cast(int, finding["char_end"]))
    except (KeyError, TypeError, ValueError) as exc:
        raise PublicEvidenceError("source reference is missing a valid character span") from exc
    if not quote or start < 0 or end <= start or end > len(normalized_text):
        raise PublicEvidenceError("source reference contains an invalid normalized span")
    if normalized_text[start:end] != quote:
        raise PublicEvidenceError("source quote does not match the normalized character span")
    claimed_page = finding.get("page")
    if claimed_page is not None:
        if source_type != "pdf" or actual_page is None or claimed_page != actual_page:
            raise PublicEvidenceError("source reference contains an unverified page number")
    elif actual_page is not None and source_type == "pdf":
        raise PublicEvidenceError("reliable PDF page number was omitted")
    table_position = finding.get("table_position")
    if table_position is not None and source_type not in {"csv", "xlsx"}:
        raise PublicEvidenceError("table position is only valid for tabular source types")
    if _sha256_text(quote) != str(finding.get("quote_sha256", "")):
        raise PublicEvidenceError("source quote hash does not match")


def append_audit_event(
    ledger_path: Path | str,
    context: ExecutionContext,
    run_id: str,
    event_type: AuditEventType,
    details: Mapping[str, object],
    *,
    timestamp: str | None = None,
) -> dict[str, object]:
    """Append one hash-chained metadata-only event after validating the prior chain."""
    ledger = _resolve_without_symlinks(Path(ledger_path), "audit ledger")
    prior = _read_validated_audit_events(ledger)
    if prior:
        if any(str(event.get("tenant_id", "")) != context.tenant_id for event in prior):
            raise PublicEvidenceError("cross-tenant audit append is blocked")
        if any(str(event.get("run_id", "")) != run_id for event in prior):
            raise PublicEvidenceError("cross-run audit append is blocked")
    prior_types = [str(event["event_type"]) for event in prior]
    _validate_audit_stage_role(event_type, context.role)
    _validate_audit_transition(
        event_type,
        len(prior) + 1,
        analysis_started="analysis_started" in prior_types,
        configuration_seen="configuration_frozen" in prior_types,
        analysis_completed="analysis_completed" in prior_types,
        review_events_seen=prior_types.count("review_applied"),
        review_completed="review_completed" in prior_types,
        export_authorized="export_authorized" in prior_types,
        export_created="export_created" in prior_types,
    )
    previous_hash = str(prior[-1]["event_hash"]) if prior else "0" * 64
    event: dict[str, object] = {
        "schema_version": BENCHMARK_SCHEMA_VERSION,
        "sequence": len(prior) + 1,
        "timestamp": timestamp or datetime.now(UTC).isoformat(),
        "tenant_id": context.tenant_id,
        "actor_id": context.actor_id,
        "role": context.role,
        "run_id": run_id,
        "event_type": event_type,
        "previous_hash": previous_hash,
        "details": dict(details),
    }
    event["event_hash"] = _canonical_hash(event)
    ledger.parent.mkdir(parents=True, exist_ok=True)
    with ledger.open("a", encoding="utf-8") as output:
        output.write(json.dumps(event, sort_keys=True, separators=(",", ":")) + "\n")
    return event


def _findings_for_unit(
    dataset_id: str,
    context: ExecutionContext,
    source: SourceEntry,
    source_path: Path,
    source_type: SourceType,
    digest: str,
    document_id: str,
    unit: TextUnit,
) -> list[dict[str, object]]:
    normalized_text = _normalize_text(unit.text)
    findings: list[dict[str, object]] = []
    for chunk in chunk_document_text(normalized_text):
        quote = str(chunk["text"])
        matches = detect_topics_for_text(quote)
        if not matches:
            continue
        normalized_quote = _normalize_text(quote)
        negative_hits = _hits(normalized_quote, NEGATIVE_EVIDENCE_TERMS)
        if negative_hits:
            continue
        stale_hits = _hits(normalized_quote, STALE_EVIDENCE_TERMS)
        conflict_hits = _hits(normalized_quote, CONFLICTING_EVIDENCE_TERMS)
        concrete_hits = _hits(normalized_quote, CONCRETE_EVIDENCE_TERMS)
        status, confidence = _categorize_candidate(concrete_hits, stale_hits, conflict_hits)
        start = int(cast(int, chunk["start_char"]))
        end = int(cast(int, chunk["end_char"]))
        for control in sorted(matches):
            finding_id = (
                "PEF-%s"
                % _sha256_text(
                    "\n".join(
                        (
                            dataset_id,
                            context.tenant_id,
                            source.source_id,
                            digest,
                            control,
                            str(start),
                            str(end),
                            normalized_quote,
                        )
                    )
                )[:FINDING_HASH_CHARS]
            )
            finding: dict[str, object] = {
                "tenant_id": context.tenant_id,
                "run_id": "pending",
                "finding_id": finding_id,
                "source_id": source.source_id,
                "document_id": document_id,
                "file_name": source_path.name,
                "document_sha256": digest,
                "page": unit.page,
                "paragraph": None,
                "table_position": None,
                "char_start": start,
                "char_end": end,
                "normalized_quote": normalized_quote,
                "quote_sha256": _sha256_text(normalized_quote),
                "locator_basis": unit.locator_basis,
                "mapped_control": control,
                "evidence_status": status,
                "confidence_category": confidence,
                "allowed_statement": (
                    "A traceable evidence candidate maps to the %s topic and requires human review."
                )
                % control,
                "forbidden_statement": (
                    "Do not state that the control is fulfilled, NIS-2 compliant, or ISO certified."
                ),
                "decision": "evidence_candidate_only",
                "review_status": "pending",
                "requires_human_review": True,
            }
            validate_source_locator(finding, normalized_text, source_type, actual_page=unit.page)
            if _contains_forbidden_allowed_claim(str(finding["allowed_statement"])):
                raise PublicEvidenceError("generated allowed statement contains a forbidden claim")
            findings.append(finding)
    return findings


def _parse_text_units(path: Path, source_type: SourceType) -> tuple[TextUnit, ...]:
    if source_type == "text":
        text = parse_text_document(path)
    elif source_type == "markdown":
        text = parse_markdown_document(path)
    elif source_type in {"csv", "json"}:
        text = parse_json_csv_if_applicable(path)
    elif source_type == "docx":
        text = parse_docx_document(path)
    elif source_type == "xlsx":
        text = parse_xlsx_document(path)
    elif source_type == "pdf":
        text = parse_pdf_document(path)
    else:
        raise PublicEvidenceError("unsupported benchmark source type")
    normalized = _normalize_text(text)
    if not normalized:
        raise PublicEvidenceError("parsed benchmark source is empty: %s" % path.name)
    return (TextUnit(normalized, None, "normalized_extracted_text"),)


def _categorize_candidate(
    concrete_hits: Sequence[str],
    stale_hits: Sequence[str],
    conflict_hits: Sequence[str],
) -> tuple[EvidenceStatus, ConfidenceCategory]:
    if stale_hits or conflict_hits:
        return "ambiguous", "low"
    if len(concrete_hits) >= 2:
        return "positive", "high"
    if len(concrete_hits) == 1:
        return "partial", "medium"
    return "partial", "low"


def _validated_dataset_file(dataset: Path, relative: Path, label: str) -> Path:
    _validate_relative_safe_path(relative.as_posix(), label)
    unresolved = dataset / relative
    current = dataset
    for part in PurePosixPath(relative.as_posix()).parts:
        current = current / part
        if current.is_symlink():
            raise PublicEvidenceError("%s symlinks are blocked" % label)
    path = unresolved.resolve()
    try:
        path.relative_to(dataset)
    except ValueError as exc:
        raise PublicEvidenceError("%s path escapes benchmark dataset" % label) from exc
    if not path.is_file():
        raise PublicEvidenceError("required benchmark %s file is missing" % label)
    if path.stat().st_size > MAX_JSON_BYTES:
        raise PublicEvidenceError("benchmark %s file exceeds the size limit" % label)
    return path


def _resolve_without_symlinks(path: Path, label: str) -> Path:
    absolute = path if path.is_absolute() else Path.cwd() / path
    for component in (absolute, *absolute.parents):
        if component.is_symlink():
            raise PublicEvidenceError("%s symlinks are blocked" % label)
    return absolute.resolve()


def _validated_source_path(dataset: Path, source: SourceEntry) -> Path:
    if source.license_status not in APPROVED_LOCAL_LICENSE_STATUSES:
        raise PublicEvidenceError(
            "local source has unclear or unapproved license: %s" % source.source_id
        )
    if source.redistribution_allowed != SAFE_LOCAL_PERMISSION:
        raise PublicEvidenceError(
            "local source redistribution is not approved: %s" % source.source_id
        )
    if source.local_storage_allowed != SAFE_LOCAL_PERMISSION:
        raise PublicEvidenceError("local source storage is not approved: %s" % source.source_id)
    unresolved = dataset / source.local_path
    if unresolved.is_symlink():
        raise PublicEvidenceError("benchmark source symlinks are blocked")
    path = unresolved.resolve()
    try:
        path.relative_to(dataset)
    except ValueError as exc:
        raise PublicEvidenceError("source path escapes benchmark dataset") from exc
    if not path.is_file():
        raise PublicEvidenceError(
            "offline mode requires an approved local source; network retrieval is blocked"
        )
    if path.stat().st_size > MAX_SOURCE_FILE_BYTES:
        raise PublicEvidenceError("benchmark source exceeds the file-size limit")
    return path


def _declared_run_id(dataset: Path, context: ExecutionContext) -> str:
    manifest_path = _validated_dataset_file(dataset, Path("manifest.json"), "manifest")
    manifest = _load_model(manifest_path, BenchmarkManifest)
    configuration: dict[str, object] = {
        "offline": context.offline,
        "deterministic": context.deterministic,
        "parser_version": BENCHMARK_PARSER_VERSION,
        "ruleset_version": BENCHMARK_RULESET_VERSION,
        "software_version": __version__,
        "seed": "not_used",
        "confidence_categories": CONFIDENCE_CRITERIA,
    }
    run_basis: dict[str, object] = {
        "tenant_id": context.tenant_id,
        "dataset_id": manifest.dataset_id,
        "configuration_sha256": _canonical_hash(configuration),
        "source_hashes": [
            "%s:%s" % (source.source_id, source.sha256)
            for source in sorted(manifest.sources, key=lambda item: item.source_id)
        ],
    }
    return "PEV-%s" % _canonical_hash(run_basis)[:RUN_HASH_CHARS]


def _record_blocked_event(
    ledger: Path,
    context: ExecutionContext,
    run_id: str,
    details: Mapping[str, object],
) -> bool:
    try:
        append_audit_event(ledger, context, run_id, "blocked_action", details)
    except PublicEvidenceError:
        # A foreign tenant/run must not be allowed to pollute the target ledger.
        return False
    return True


def _validate_source_register(dataset: Path, manifest: BenchmarkManifest) -> None:
    register_path = _validated_dataset_file(
        dataset,
        SOURCE_REGISTER_RELATIVE_PATH,
        "source register",
    )
    try:
        with register_path.open(encoding="utf-8", newline="") as source_file:
            reader = csv.DictReader(source_file)
            if tuple(reader.fieldnames or ()) != SOURCE_REGISTER_COLUMNS:
                raise PublicEvidenceError(
                    "source register columns do not match the required schema"
                )
            rows = list(reader)
    except OSError as exc:
        raise PublicEvidenceError("could not read source register") from exc
    rows_by_id = {str(row.get("source_id", "")): row for row in rows}
    if len(rows_by_id) != len(rows):
        raise PublicEvidenceError("source register contains duplicate source_id values")
    if set(rows_by_id) != {source.source_id for source in manifest.sources}:
        raise PublicEvidenceError("source register and manifest source IDs differ")
    for source in manifest.sources:
        row = rows_by_id[source.source_id]
        expected = {
            "source_id": source.source_id,
            "title": source.title,
            "publisher": source.publisher,
            "public_url": source.public_url or "",
            "retrieved_at": source.retrieved_at,
            "document_version": source.document_version,
            "sha256": source.sha256,
            "file_type": source.file_type,
            "source_class": source.source_class,
            "license_status": source.license_status,
            "redistribution_allowed": source.redistribution_allowed,
            "local_storage_allowed": source.local_storage_allowed,
            "local_path": source.local_path,
            "used_excerpt_or_pages": source.used_excerpt_or_pages,
            "inclusion_reason": source.inclusion_reason,
            "review_status": source.review_status,
            "known_limitations": " | ".join(source.known_limitations),
        }
        if any(str(row.get(key, "")) != value for key, value in expected.items()):
            raise PublicEvidenceError("source register metadata mismatch for %s" % source.source_id)


def _read_validated_audit_events(  # noqa: PLR0912
    path: Path,
) -> list[dict[str, object]]:
    path = _resolve_without_symlinks(path, "audit ledger")
    if not path.exists():
        return []
    if not path.is_file() or path.stat().st_size > MAX_AUDIT_BYTES:
        raise PublicEvidenceError("audit ledger is invalid or exceeds the size limit")
    events: list[dict[str, object]] = []
    previous_hash = "0" * 64
    tenant_id: str | None = None
    run_id: str | None = None
    analysis_started = False
    configuration_seen = False
    analysis_completed = False
    review_events_seen = 0
    review_completed = False
    export_authorized = False
    export_created = False
    try:
        with path.open(encoding="utf-8") as input_file:
            for sequence, line in enumerate(input_file, start=1):
                payload = json.loads(line)
                if not isinstance(payload, dict):
                    raise PublicEvidenceError("audit ledger entry must be an object")
                event = cast(dict[str, object], payload)
                required_fields = {
                    "schema_version",
                    "sequence",
                    "timestamp",
                    "tenant_id",
                    "actor_id",
                    "role",
                    "run_id",
                    "event_type",
                    "previous_hash",
                    "details",
                    "event_hash",
                }
                if set(event) != required_fields:
                    raise PublicEvidenceError("audit ledger entry schema is invalid")
                claimed_hash = str(event.pop("event_hash", ""))
                if event.get("sequence") != sequence or event.get("previous_hash") != previous_hash:
                    raise PublicEvidenceError("audit ledger chain is inconsistent")
                calculated = _canonical_hash(event)
                if calculated != claimed_hash:
                    raise PublicEvidenceError("audit ledger hash verification failed")
                event["event_hash"] = claimed_hash
                current_tenant = str(event.get("tenant_id", ""))
                current_run = str(event.get("run_id", ""))
                if not current_tenant or not current_run or not str(event.get("actor_id", "")):
                    raise PublicEvidenceError("audit ledger identity fields are invalid")
                if tenant_id is None:
                    tenant_id = current_tenant
                    run_id = current_run
                elif current_tenant != tenant_id or current_run != run_id:
                    raise PublicEvidenceError("audit ledger mixes tenant or run identities")
                if str(event.get("role", "")) not in {"operator", "reviewer", "auditor", "admin"}:
                    raise PublicEvidenceError("audit ledger role is invalid")
                event_type = str(event.get("event_type", ""))
                if event_type not in AUDIT_EVENT_TYPES:
                    raise PublicEvidenceError("audit ledger event type is invalid")
                if not isinstance(event.get("details"), dict):
                    raise PublicEvidenceError("audit ledger event details must be an object")
                _validate_audit_stage_role(event_type, str(event["role"]))
                _validate_audit_transition(
                    event_type,
                    sequence,
                    analysis_started=analysis_started,
                    configuration_seen=configuration_seen,
                    analysis_completed=analysis_completed,
                    review_events_seen=review_events_seen,
                    review_completed=review_completed,
                    export_authorized=export_authorized,
                    export_created=export_created,
                )
                analysis_started = analysis_started or event_type == "analysis_started"
                configuration_seen = configuration_seen or event_type == "configuration_frozen"
                analysis_completed = analysis_completed or event_type == "analysis_completed"
                review_events_seen += int(event_type == "review_applied")
                review_completed = review_completed or event_type == "review_completed"
                export_authorized = export_authorized or event_type == "export_authorized"
                export_created = export_created or event_type == "export_created"
                events.append(event)
                previous_hash = claimed_hash
    except (OSError, json.JSONDecodeError) as exc:
        raise PublicEvidenceError("could not validate audit ledger") from exc
    return events


def _validate_audit_transition(  # noqa: PLR0911,PLR0912
    event_type: str,
    sequence: int,
    *,
    analysis_started: bool,
    configuration_seen: bool,
    analysis_completed: bool,
    review_events_seen: int,
    review_completed: bool,
    export_authorized: bool,
    export_created: bool,
) -> None:
    if event_type == "blocked_action":
        if not analysis_started:
            raise PublicEvidenceError("audit blocked action requires an analysis start")
        return
    if event_type == "analysis_started":
        if sequence != 1:
            raise PublicEvidenceError("audit analysis_started must be the first event")
        return
    if event_type == "configuration_frozen":
        if not analysis_started or configuration_seen or analysis_completed:
            raise PublicEvidenceError("audit configuration transition is invalid")
        return
    if event_type in {"input_registered", "parser_completed", "finding_created"}:
        if not configuration_seen or analysis_completed:
            raise PublicEvidenceError("audit analysis-stage transition is invalid")
        return
    if event_type == "analysis_completed":
        if not configuration_seen or analysis_completed:
            raise PublicEvidenceError("audit analysis completion transition is invalid")
        return
    if event_type == "review_applied":
        if not analysis_completed or review_completed or export_created:
            raise PublicEvidenceError("audit review transition is invalid")
        return
    if event_type == "review_completed":
        if not analysis_completed or not review_events_seen or review_completed or export_created:
            raise PublicEvidenceError("audit review completion transition is invalid")
        return
    if event_type == "export_authorized":
        if not review_completed or export_authorized or export_created:
            raise PublicEvidenceError("audit export authorization transition is invalid")
        return
    if event_type == "export_created" and (not export_authorized or export_created):
        raise PublicEvidenceError("audit export transition is invalid")


def _validate_audit_stage_role(event_type: str, role: str) -> None:
    if role == "admin" or event_type == "blocked_action":
        return
    if event_type.startswith("analysis_") or event_type in {
        "configuration_frozen",
        "input_registered",
        "parser_completed",
        "finding_created",
    }:
        if role != "operator":
            raise PublicEvidenceError("audit analysis event role is invalid")
        return
    if event_type.startswith("review_"):
        if role != "reviewer":
            raise PublicEvidenceError("audit review event role is invalid")
        return
    if event_type.startswith("export_") and role != "auditor":
        raise PublicEvidenceError("audit export event role is invalid")


def _validate_analysis_report(payload: dict[str, object]) -> dict[str, object]:
    _require_exact_fields(payload, ANALYSIS_REPORT_FIELDS, "analysis report")
    if payload.get("schema_version") != BENCHMARK_SCHEMA_VERSION:
        raise PublicEvidenceError("analysis report schema_version is invalid")
    if payload.get("report_type") != "public_evidence_analysis":
        raise PublicEvidenceError("analysis report type is invalid")
    if payload.get("requires_human_review") is not True:
        raise PublicEvidenceError("analysis report must require human review")
    configuration = cast(Mapping[str, object], payload.get("configuration", {}))
    if _canonical_hash(configuration) != str(payload.get("configuration_sha256", "")):
        raise PublicEvidenceError("analysis configuration hash verification failed")
    sources = cast(Sequence[Mapping[str, object]], payload.get("sources", ()))
    findings = cast(Sequence[Mapping[str, object]], payload.get("findings", ()))
    if len(sources) > MAX_SOURCE_COUNT or len(findings) > MAX_FINDING_COUNT:
        raise PublicEvidenceError("analysis report exceeds record limits")
    source_records: dict[str, Mapping[str, object]] = {}
    for source in sources:
        _require_exact_fields(source, SOURCE_RECORD_FIELDS, "analysis source record")
        source_id = str(source.get("source_id", ""))
        if not source_id or source_id in source_records:
            raise PublicEvidenceError("analysis source IDs must be unique")
        source_records[source_id] = source
    finding_ids: set[str] = set()
    for finding in findings:
        _validate_finding_record(
            finding,
            payload,
            source_records,
            expected_fields=FINDING_FIELDS,
            reviewed=False,
        )
        finding_id = str(finding["finding_id"])
        if finding_id in finding_ids:
            raise PublicEvidenceError("analysis finding IDs must be unique")
        finding_ids.add(finding_id)
    if payload.get("finding_count") != len(findings):
        raise PublicEvidenceError("analysis finding_count is inconsistent")
    _verify_content_hash(payload, "analysis report")
    return payload


def _validate_reviewed_report(payload: dict[str, object]) -> dict[str, object]:
    _require_exact_fields(payload, REVIEWED_REPORT_FIELDS, "reviewed report")
    if payload.get("report_type") != "public_evidence_reviewed_report":
        raise PublicEvidenceError("reviewed report type is invalid")
    review = payload.get("review")
    if not isinstance(review, dict) or set(review) != {
        "reviewer_id",
        "reviewer_role",
        "reviewed_at",
        "human_review_confirmed",
    }:
        raise PublicEvidenceError("reviewed report review metadata is invalid")
    if review.get("human_review_confirmed") is not True:
        raise PublicEvidenceError("human review confirmation is required before export")
    sources = cast(Sequence[Mapping[str, object]], payload.get("sources", ()))
    findings = cast(Sequence[Mapping[str, object]], payload.get("findings", ()))
    source_records: dict[str, Mapping[str, object]] = {}
    for source in sources:
        _require_exact_fields(source, SOURCE_RECORD_FIELDS, "reviewed source record")
        source_id = str(source.get("source_id", ""))
        if not source_id or source_id in source_records:
            raise PublicEvidenceError("reviewed source IDs must be unique")
        source_records[source_id] = source
    finding_ids: set[str] = set()
    for finding in findings:
        _validate_finding_record(
            finding,
            payload,
            source_records,
            expected_fields=REVIEWED_FINDING_FIELDS,
            reviewed=True,
        )
        finding_id = str(finding["finding_id"])
        if finding_id in finding_ids:
            raise PublicEvidenceError("reviewed finding IDs must be unique")
        finding_ids.add(finding_id)
    if payload.get("finding_count") != len(findings):
        raise PublicEvidenceError("reviewed finding_count is inconsistent")
    _verify_content_hash(payload, "reviewed report")
    return payload


def _validate_finding_record(
    finding: Mapping[str, object],
    report: Mapping[str, object],
    source_records: Mapping[str, Mapping[str, object]],
    *,
    expected_fields: frozenset[str],
    reviewed: bool,
) -> None:
    _require_exact_fields(finding, expected_fields, "finding")
    if finding.get("tenant_id") != report.get("tenant_id"):
        raise PublicEvidenceError("finding tenant does not match report")
    if finding.get("run_id") != report.get("run_id"):
        raise PublicEvidenceError("finding run does not match report")
    source = source_records.get(str(finding.get("source_id", "")))
    if source is None:
        raise PublicEvidenceError("finding references an unknown source")
    if finding.get("document_id") != source.get("document_id"):
        raise PublicEvidenceError("finding document_id does not match source")
    if finding.get("document_sha256") != source.get("sha256"):
        raise PublicEvidenceError("finding document hash does not match source")
    if not _finding_has_complete_source_reference(finding):
        raise PublicEvidenceError("finding source reference is incomplete")
    quote = str(finding.get("normalized_quote", ""))
    if _sha256_text(quote) != str(finding.get("quote_sha256", "")):
        raise PublicEvidenceError("finding quote hash verification failed")
    if reviewed:
        if str(finding.get("review_status", "")) not in {
            "accepted",
            "rejected",
            "needs_evidence",
        }:
            raise PublicEvidenceError("reviewed finding status is invalid")
        if not str(finding.get("review_comment", "")):
            raise PublicEvidenceError("reviewed finding comment is missing")
    elif finding.get("review_status") != "pending":
        raise PublicEvidenceError("analysis finding must remain pending")


def _require_exact_fields(
    payload: Mapping[str, object],
    expected: frozenset[str] | set[str],
    label: str,
) -> None:
    if set(payload) != set(expected):
        raise PublicEvidenceError("%s contains missing or unknown fields" % label)


def _verify_content_hash(payload: Mapping[str, object], label: str) -> None:
    unhashed = dict(payload)
    claimed = str(unhashed.pop("content_sha256", ""))
    if not claimed or _canonical_hash(unhashed) != claimed:
        raise PublicEvidenceError("%s content hash verification failed" % label)


def _require_analysis_audit(
    ledger: Path,
    analysis: Mapping[str, object],
) -> list[dict[str, object]]:
    events = _read_validated_audit_events(ledger)
    tenant_id = str(analysis["tenant_id"])
    run_id = str(analysis["run_id"])
    actor_id = str(analysis["operator_actor_id"])
    analysis_sha256 = str(analysis["content_sha256"])
    if not events:
        raise PublicEvidenceError("analysis audit trail is missing")
    if any(
        str(event["tenant_id"]) != tenant_id or str(event["run_id"]) != run_id for event in events
    ):
        raise PublicEvidenceError("analysis audit tenant or run does not match")
    completed = [
        event
        for event in events
        if event["event_type"] == "analysis_completed"
        and str(cast(Mapping[str, object], event["details"]).get("analysis_sha256", ""))
        == analysis_sha256
    ]
    if len(completed) != 1 or str(completed[0]["actor_id"]) != actor_id:
        raise PublicEvidenceError("analysis audit completion proof is invalid")
    return events


def _require_review_audit(
    ledger: Path,
    reviewed: Mapping[str, object],
) -> list[dict[str, object]]:
    events = _read_validated_audit_events(ledger)
    tenant_id = str(reviewed["tenant_id"])
    run_id = str(reviewed["run_id"])
    analysis_sha256 = str(reviewed["analysis_sha256"])
    reviewed_sha256 = str(reviewed["content_sha256"])
    review = cast(Mapping[str, object], reviewed["review"])
    if any(
        str(event["tenant_id"]) != tenant_id or str(event["run_id"]) != run_id for event in events
    ):
        raise PublicEvidenceError("review audit tenant or run does not match")
    analysis_events = [
        event
        for event in events
        if event["event_type"] == "analysis_completed"
        and str(cast(Mapping[str, object], event["details"]).get("analysis_sha256", ""))
        == analysis_sha256
    ]
    if len(analysis_events) != 1:
        raise PublicEvidenceError("review audit lacks the bound analysis completion")
    expected_decisions = {
        str(item["finding_id"]): str(item["review_status"])
        for item in cast(Sequence[Mapping[str, object]], reviewed["findings"])
    }
    audited_decisions: dict[str, str] = {}
    for event in events:
        if event["event_type"] != "review_applied":
            continue
        details = cast(Mapping[str, object], event["details"])
        if str(details.get("analysis_sha256", "")) != analysis_sha256:
            raise PublicEvidenceError("review audit decision is bound to another analysis")
        finding_id = str(details.get("finding_id", ""))
        if finding_id in audited_decisions:
            raise PublicEvidenceError("review audit contains duplicate decisions")
        audited_decisions[finding_id] = str(details.get("review_status", ""))
    if audited_decisions != expected_decisions:
        raise PublicEvidenceError("review audit decisions do not match reviewed report")
    completed = [event for event in events if event["event_type"] == "review_completed"]
    if len(completed) != 1:
        raise PublicEvidenceError("review completion audit proof is missing")
    details = cast(Mapping[str, object], completed[0]["details"])
    if (
        str(details.get("analysis_sha256", "")) != analysis_sha256
        or str(details.get("reviewed_report_sha256", "")) != reviewed_sha256
        or str(completed[0]["actor_id"]) != str(review.get("reviewer_id", ""))
    ):
        raise PublicEvidenceError("review completion audit proof is invalid")
    if any(event["event_type"] == "export_created" for event in events):
        raise PublicEvidenceError("this reviewed run has already been exported")
    return events


def _exportable_finding(finding: Mapping[str, object]) -> dict[str, object]:
    return {
        "finding_id": finding["finding_id"],
        "source_id": finding["source_id"],
        "document_id": finding["document_id"],
        "document_sha256": finding["document_sha256"],
        "page": finding.get("page"),
        "paragraph": finding.get("paragraph"),
        "table_position": finding.get("table_position"),
        "char_start": finding["char_start"],
        "char_end": finding["char_end"],
        "quote_sha256": finding["quote_sha256"],
        "locator_basis": finding["locator_basis"],
        "mapped_control": finding["mapped_control"],
        "evidence_status": finding["evidence_status"],
        "confidence_category": finding["confidence_category"],
        "allowed_statement": finding["allowed_statement"],
        "forbidden_statement": finding["forbidden_statement"],
        "decision": finding["decision"],
        "review_status": "accepted",
    }


def _load_model(path: Path, model: type[ModelT]) -> ModelT:
    payload = _read_json_object(path)
    try:
        return model.model_validate(payload)
    except ValueError as exc:
        raise PublicEvidenceError("invalid %s" % path.name) from exc


def _read_json_object(path: Path) -> dict[str, object]:
    path = _resolve_without_symlinks(path, "JSON input")
    lowered_name = path.name.casefold()
    if path.is_symlink() or any(marker in lowered_name for marker in FORBIDDEN_PATH_MARKERS):
        raise PublicEvidenceError("JSON input path is forbidden")
    if path.suffix.casefold() != ".json":
        raise PublicEvidenceError("JSON input must use the .json suffix")
    if not path.is_file() or path.stat().st_size > MAX_JSON_BYTES:
        raise PublicEvidenceError("JSON input is missing or exceeds the size limit: %s" % path.name)
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise PublicEvidenceError("could not read JSON input: %s" % path.name) from exc
    if not isinstance(payload, dict):
        raise PublicEvidenceError("JSON input must contain an object: %s" % path.name)
    return cast(dict[str, object], payload)


def _prepare_output_dir(path: Path, allowed_files: set[str]) -> None:
    if path.is_symlink():
        raise PublicEvidenceError("output directory symlinks are blocked")
    if path.exists() and not path.is_dir():
        raise PublicEvidenceError("output path must be a directory")
    if path.exists():
        unexpected = sorted(
            item.name
            for item in path.iterdir()
            if item.is_symlink() or item.is_dir() or item.name not in allowed_files
        )
        if unexpected:
            raise PublicEvidenceError("output directory contains unexpected files")
        return
    path.mkdir(parents=True, exist_ok=False)


def _prepare_staged_export(path: Path) -> Path:
    if path.exists() or path.is_symlink():
        raise PublicEvidenceError("export output directory must be new")
    path.parent.mkdir(parents=True, exist_ok=True)
    staging = path.with_name(path.name + ".pending")
    if staging.exists() or staging.is_symlink():
        raise PublicEvidenceError("pending export directory already exists")
    staging.mkdir(exist_ok=False)
    return staging


def _require_role(context: ExecutionContext, allowed: set[str], action: str) -> None:
    if context.role not in allowed:
        raise PublicEvidenceError("role %s is not permitted for %s" % (context.role, action))


def _require_tenant(report: Mapping[str, object], context: ExecutionContext) -> None:
    if str(report.get("tenant_id", "")) != context.tenant_id:
        raise PublicEvidenceError("cross-tenant read or export is blocked")


def _finding_has_complete_source_reference(finding: Mapping[str, object]) -> bool:
    required = (
        "source_id",
        "document_id",
        "file_name",
        "document_sha256",
        "char_start",
        "char_end",
        "normalized_quote",
        "quote_sha256",
        "locator_basis",
    )
    return all(finding.get(field) not in {None, ""} for field in required)


def _validate_relative_safe_path(value: str, field_name: str) -> None:
    normalized = value.replace("\\", "/")
    path = PurePosixPath(normalized)
    lowered_parts = tuple(part.casefold() for part in path.parts)
    if path.is_absolute() or not path.parts or any(part in {"", ".", ".."} for part in path.parts):
        raise ValueError("%s must be a safe relative path" % field_name)
    if any(any(marker in part for marker in FORBIDDEN_PATH_MARKERS) for part in lowered_parts):
        raise ValueError("%s contains a forbidden path marker" % field_name)
    if path.suffix.casefold() in FORBIDDEN_SUFFIXES:
        raise ValueError("%s has a forbidden file suffix" % field_name)


def _hits(text: str, terms: Sequence[str]) -> tuple[str, ...]:
    normalized = text.casefold()
    return tuple(term for term in terms if term.casefold() in normalized)


def _contains_forbidden_allowed_claim(value: str) -> bool:
    return any(pattern.search(value) is not None for pattern in FORBIDDEN_ALLOWED_CLAIM_PATTERNS)


def _ratio(numerator: int, denominator: int) -> dict[str, object]:
    if denominator == 0:
        return {"status": "not_measured", "reason": "metric denominator is zero"}
    return {
        "value": round(numerator / denominator, 4),
        "numerator": numerator,
        "denominator": denominator,
    }


def _normalize_text(value: str) -> str:
    return " ".join(value.split())


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as input_file:
            for chunk in iter(lambda: input_file.read(HASH_CHUNK_SIZE), b""):
                digest.update(chunk)
    except OSError as exc:
        raise PublicEvidenceError("could not hash local source: %s" % path.name) from exc
    return digest.hexdigest()


def _canonical_hash(value: Mapping[str, object]) -> str:
    canonical = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return _sha256_text(canonical)


def _write_json(path: Path, payload: Mapping[str, object]) -> None:
    _write_text_file(
        path,
        json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=True) + "\n",
    )


def _write_text_file(path: Path, content: str) -> None:
    if path.is_symlink():
        raise PublicEvidenceError("output file symlinks are blocked")
    temporary = path.with_name(path.name + ".tmp")
    if temporary.exists() or temporary.is_symlink():
        raise PublicEvidenceError("temporary output path already exists")
    try:
        descriptor = os.open(
            temporary,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
            0o600,
        )
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="") as output_file:
            output_file.write(content)
            output_file.flush()
            os.fsync(output_file.fileno())
        temporary.replace(path)
    except OSError as exc:
        temporary.unlink(missing_ok=True)
        raise PublicEvidenceError("could not write output file: %s" % path.name) from exc


def _safe_reason(value: str) -> str:
    return re.sub(r"[\r\n]+", " ", value)[:300]


def _trust_bundle_readme() -> str:
    return (
        "# AethelGard Public Evidence Trust Bundle Preview\n\n"
        "Only findings explicitly accepted through the tenant-bound human-review "
        "gate are included.\n"
        "The evidence index contains hashes and normalized locators, not raw private documents.\n\n"
        "%s\n" % DISCLAIMER
    )
