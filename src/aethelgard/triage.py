"""Local evidence-triage and evaluation helpers for AethelGard.

This module contains the reusable implementation behind ``python -m
aethelgard.cli``. It intentionally stays local-only: no network calls, no
customer data assumptions, and no legal compliance claims.
"""

from __future__ import annotations

import json
import time
from collections import defaultdict
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Final, cast

from aethelgard import __version__
from aethelgard.mvp1 import (
    ComplianceEvidence,
    LocalDocumentParser,
)

REPORT_JSON_NAME: Final[str] = "evidence_report.json"
REPORT_MD_NAME: Final[str] = "evidence_report.md"
RUN_SUMMARY_NAME: Final[str] = "run_summary.json"
EVAL_JSON_NAME: Final[str] = "eval_report.json"
EVAL_MD_NAME: Final[str] = "eval_report.md"
CALIBRATION_JSON_NAME: Final[str] = "calibration_report.json"
CALIBRATION_MD_NAME: Final[str] = "calibration_report.md"

SUPPORTED_DOCUMENT_SUFFIXES: Final[frozenset[str]] = frozenset({".md", ".txt", ".pdf"})
STRONG_EVIDENCE_THRESHOLD: Final[float] = 0.7
MEDIUM_EVIDENCE_THRESHOLD: Final[float] = 0.6
MAX_REPORT_CITATION_CHARS: Final[int] = 280
MIN_STRONG_FEATURES: Final[int] = 3
MIN_MEDIUM_FEATURES: Final[int] = 2
OUTDATED_YEAR_CUTOFF: Final[int] = 2024

CATEGORY_KEYWORDS: Final[dict[str, tuple[str, ...]]] = {
    "risk_management": (
        "risk assessment",
        "risk management",
        "risk register",
        "risk owner",
        "risk review",
        "risikoanalyse",
    ),
    "incident_reporting": (
        "incident response",
        "incident reporting",
        "incident timeline",
        "24 hours",
        "72 hours",
        "meldepflicht",
    ),
    "business_continuity": (
        "business continuity",
        "backup restore",
        "recovery time",
        "continuity exercise",
        "disaster recovery",
    ),
    "supplier_security": (
        "supplier security",
        "supplier review",
        "vendor security",
        "third party",
        "contractual security",
    ),
    "access_control": (
        "access control",
        "least privilege",
        "multi-factor authentication",
        "mfa",
        "access review",
        "privileged access",
    ),
    "vulnerability_management": (
        "vulnerability management",
        "patch management",
        "security patch",
        "remediation timeline",
        "vulnerability scan",
    ),
}

GAP_TERMS: Final[tuple[str, ...]] = (
    "ad hoc",
    "gap",
    "missing",
    "no owner",
    "no review",
    "not defined",
    "not documented",
    "not implemented",
    "planned only",
    "unclear",
    "vague",
)

NEGATIVE_SIGNAL_TERMS: Final[dict[str, tuple[str, ...]]] = {
    "marketing_only": (
        "brochure",
        "marketing",
        "market-leading",
        "world class",
        "world-class",
        "we care",
        "we value security",
        "strategic priority",
        "intentionally avoids",
    ),
    "template_only": (
        "template",
        "placeholder",
        "planned only",
        "to be completed",
        "tbd",
        "not defined",
    ),
    "outdated": (
        "outdated",
        "expired",
        "last reviewed 2021",
        "last reviewed 2022",
        "last reviewed 2023",
        "review date: 2021",
        "review date: 2022",
        "review date: 2023",
    ),
    "vague_control": (
        "ad hoc",
        "best effort",
        "important",
        "should",
        "vague",
        "not documented",
        "no evidence",
    ),
}

OWNER_TERMS: Final[tuple[str, ...]] = (
    "accountable",
    "assigned to",
    "ciso",
    "committee",
    "owner",
    "responsible",
    "role",
    "team",
)
REVIEW_OR_FREQUENCY_TERMS: Final[tuple[str, ...]] = (
    "annually",
    "biannual",
    "cadence",
    "daily",
    "every six months",
    "monthly",
    "quarterly",
    "review",
    "review date",
    "reviewed",
    "twice per year",
    "weekly",
)
PROCESS_OR_CONTROL_TERMS: Final[tuple[str, ...]] = (
    "approved",
    "control",
    "documented",
    "implemented",
    "procedure",
    "process",
    "richtlinie",
    "runbook",
    "tested",
    "workflow",
)
OUTPUT_OR_EVIDENCE_TERMS: Final[tuple[str, ...]] = (
    "evidence",
    "export",
    "log",
    "notes",
    "record",
    "records",
    "report",
    "result",
    "ticket",
)
TIMELINE_TERMS: Final[tuple[str, ...]] = (
    "24 hours",
    "72 hours",
    "escalation",
    "meldepflicht",
    "timeline",
    "within",
)
SUPPLIER_CONTROL_TERMS: Final[tuple[str, ...]] = (
    "contractual",
    "due diligence",
    "onboarding",
    "questionnaire",
    "review",
    "security requirements",
)

DISCLAIMER: Final[str] = (
    "This report is an automated evidence triage aid. It is not legal advice, "
    "does not provide legal advice, not an audit opinion, and not a certification "
    "of NIS-2 compliance. Human review is required. Dieser Bericht ist eine automatisierte "
    "Vorpruefung von Evidenzen. Er ist keine Rechtsberatung, kein Auditurteil "
    "und keine Zertifizierung von NIS-2-Konformitaet. Eine menschliche Pruefung "
    "ist erforderlich."
)


@dataclass(frozen=True)
class EvaluationThresholds:
    """Pilot-readiness thresholds for the public synthetic corpus."""

    min_category_hit_rate: float = 0.8
    required_parser_failures: int = 0
    required_processed_ratio: float = 1.0
    max_marketing_strong_evidence: int = 0


def build_keyword_map() -> dict[str, str]:
    """Build a keyword-to-category map for parser ``requirement_map``."""
    keyword_map: dict[str, str] = {}
    for category, keywords in CATEGORY_KEYWORDS.items():
        for keyword in keywords:
            keyword_map[keyword] = category
    return keyword_map


def iter_document_paths(input_path: Path) -> list[Path]:
    """Return supported document files under ``input_path`` in stable order."""
    path = Path(input_path)
    if path.is_file():
        return [path] if path.suffix.lower() in SUPPORTED_DOCUMENT_SUFFIXES else []
    return sorted(
        candidate
        for candidate in path.rglob("*")
        if candidate.is_file() and candidate.suffix.lower() in SUPPORTED_DOCUMENT_SUFFIXES
    )


def run_triage(input_path: Path | str, out_dir: Path | str | None = None) -> dict[str, Any]:
    """Run local evidence triage and optionally write JSON/Markdown reports."""
    start = time.perf_counter()
    input_root = Path(input_path)
    out_path = Path(out_dir) if out_dir is not None else None
    parser = LocalDocumentParser(
        keywords=tuple(build_keyword_map().keys()),
        chunk_radius=320,
        min_confidence=0.0,
        requirement_map=build_keyword_map(),
    )

    warnings: list[str] = []
    errors: list[dict[str, str]] = []
    documents: list[dict[str, Any]] = []
    categories: dict[str, int] = {category: 0 for category in CATEGORY_KEYWORDS}
    evidence_count = 0
    parsed_count = 0

    document_paths = iter_document_paths(input_root)
    for document_path in document_paths:
        try:
            evidence_items = list(parser.parse_and_classify(document_path))
        except (OSError, ValueError) as exc:
            errors.append({"file": _safe_relative(document_path, input_root), "error": str(exc)})
            continue

        parsed_count += 1
        document_result = _build_document_result(document_path, input_root, evidence_items)
        evidence_count += document_result["evidence_count"]
        for category, count in document_result["categories"].items():
            categories[category] = categories.get(category, 0) + count
        if document_result["warnings"]:
            warnings.extend(
                "%s: %s" % (_safe_relative(document_path, input_root), warning)
                for warning in document_result["warnings"]
            )
        documents.append(document_result)

    elapsed_seconds = round(time.perf_counter() - start, 6)
    report = {
        "run_id": _build_run_id("triage"),
        "timestamp": datetime.now(UTC).isoformat(),
        "input_path": str(input_root),
        "document_count": len(document_paths),
        "parsed_count": parsed_count,
        "failed_count": len(errors),
        "evidence_count": evidence_count,
        "categories": categories,
        "per_document": documents,
        "warnings": warnings,
        "errors": errors,
        "tool_version": __version__,
        "disclaimer": DISCLAIMER,
    }
    summary = {
        "run_id": report["run_id"],
        "elapsed_seconds": elapsed_seconds,
        "document_count": report["document_count"],
        "parsed_count": parsed_count,
        "failed_count": len(errors),
        "evidence_count": evidence_count,
        "parser_errors": errors,
        "evaluation": None,
        "exit_code": 0 if not errors else 1,
    }

    if out_path is not None:
        out_path.mkdir(parents=True, exist_ok=True)
        _write_json(out_path / REPORT_JSON_NAME, report)
        _write_text(out_path / REPORT_MD_NAME, render_triage_markdown(report))
        _write_json(out_path / RUN_SUMMARY_NAME, summary)

    return {"report": report, "summary": summary}


def run_eval(
    fixtures_path: Path | str,
    labels_path: Path | str,
    out_dir: Path | str | None = None,
) -> dict[str, Any]:
    """Evaluate fixtures against golden labels."""
    fixtures_root = Path(fixtures_path)
    labels = _read_json(Path(labels_path))
    thresholds = EvaluationThresholds()
    triage_result = run_triage(fixtures_root, out_dir=None)
    report = triage_result["report"]
    documents_by_file = {doc["file"]: doc for doc in report["per_document"]}

    per_document: list[dict[str, Any]] = []
    parser_failures = report["failed_count"]
    category_expected_total = 0
    category_hits_total = 0
    evidence_min_passes = 0
    false_positive_cases: list[str] = []
    false_negative_cases: list[str] = []
    missing_expected_categories: dict[str, list[str]] = {}
    unexpected_categories: dict[str, list[str]] = {}

    for expected in labels.get("documents", []):
        file_name = str(expected["file"])
        document = documents_by_file.get(file_name)
        if document is None:
            false_negative_cases.append(file_name)
            per_document.append(
                {
                    "file": file_name,
                    "passed": False,
                    "reason": "document was not processed",
                }
            )
            continue

        expected_categories = set(expected.get("expected_categories", []))
        actual_strong = set(document["strong_categories"])
        must_not = set(expected.get("must_not_include_categories", []))
        missing = sorted(expected_categories - actual_strong)
        unexpected = sorted(actual_strong & must_not)
        category_expected_total += len(expected_categories)
        category_hits_total += len(expected_categories) - len(missing)

        expected_min = int(expected.get("expected_evidence_min", 0))
        evidence_min_pass = document["strong_evidence_count"] >= expected_min
        if evidence_min_pass:
            evidence_min_passes += 1

        marketing_limit = expected.get("max_strong_evidence")
        marketing_ok = (
            marketing_limit is None or document["strong_evidence_count"] <= int(marketing_limit)
        )
        gap_terms_expected = bool(expected.get("expected_gaps"))
        gap_pass = True
        if gap_terms_expected:
            gap_pass = document["strong_evidence_count"] == 0 or bool(document["gap_warnings"])

        terms_missing = _missing_terms_in_evidence(
            document["evidence"],
            expected.get("must_include_terms", []),
        )

        passed = (
            not missing
            and not unexpected
            and evidence_min_pass
            and marketing_ok
            and gap_pass
        )
        passed = passed and not terms_missing

        if missing:
            missing_expected_categories[file_name] = missing
            false_negative_cases.append(file_name)
        if unexpected or not marketing_ok:
            unexpected_categories[file_name] = unexpected or document["strong_categories"]
            false_positive_cases.append(file_name)

        per_document.append(
            {
                "file": file_name,
                "passed": passed,
                "expected_categories": sorted(expected_categories),
                "actual_strong_categories": sorted(actual_strong),
                "missing_expected_categories": missing,
                "unexpected_categories": unexpected,
                "strong_evidence_count": document["strong_evidence_count"],
                "expected_evidence_min": expected_min,
                "gap_warnings": document["gap_warnings"],
                "missing_terms": terms_missing,
            }
        )

    documents_total = len(labels.get("documents", []))
    documents_passed = sum(1 for item in per_document if item.get("passed"))
    category_hit_rate = (
        category_hits_total / category_expected_total if category_expected_total else 1.0
    )
    evidence_min_pass_rate = evidence_min_passes / documents_total if documents_total else 1.0
    processed_ratio = (
        report["parsed_count"] / report["document_count"] if report["document_count"] else 0.0
    )

    marketing_doc = documents_by_file.get("misleading_security_marketing.md")
    marketing_strong = int(marketing_doc["strong_evidence_count"]) if marketing_doc else 0
    threshold_status = {
        "parser_failures": parser_failures == thresholds.required_parser_failures,
        "processed_ratio": processed_ratio >= thresholds.required_processed_ratio,
        "category_hit_rate": category_hit_rate >= thresholds.min_category_hit_rate,
        "marketing_false_positive": marketing_strong <= thresholds.max_marketing_strong_evidence,
        "gap_documents": _gap_documents_pass(per_document, labels.get("documents", [])),
        "per_document_pass": documents_passed == documents_total,
    }
    pilot_ready = all(threshold_status.values())
    eval_report = {
        "run_id": _build_run_id("eval"),
        "timestamp": datetime.now(UTC).isoformat(),
        "triage_run_id": report["run_id"],
        "fixtures_path": str(fixtures_root),
        "labels_path": str(labels_path),
        "status": "PILOT_READY" if pilot_ready else "NOT_PILOT_READY",
        "document_count": report["document_count"],
        "parsed_count": report["parsed_count"],
        "failed_count": report["failed_count"],
        "evidence_count": report["evidence_count"],
        "documents_total": documents_total,
        "documents_passed": documents_passed,
        "documents_failed": documents_total - documents_passed,
        "category_hits": {
            "hit": category_hits_total,
            "expected": category_expected_total,
            "rate": round(category_hit_rate, 4),
        },
        "missing_expected_categories": missing_expected_categories,
        "unexpected_categories": unexpected_categories,
        "evidence_min_pass_rate": round(evidence_min_pass_rate, 4),
        "false_positive_cases": sorted(set(false_positive_cases)),
        "false_negative_cases": sorted(set(false_negative_cases)),
        "parser_failures": parser_failures,
        "processed_ratio": round(processed_ratio, 4),
        "thresholds": {
            "min_category_hit_rate": thresholds.min_category_hit_rate,
            "required_parser_failures": thresholds.required_parser_failures,
            "required_processed_ratio": thresholds.required_processed_ratio,
            "max_marketing_strong_evidence": thresholds.max_marketing_strong_evidence,
        },
        "threshold_status": threshold_status,
        "per_document": per_document,
        "tool_version": __version__,
        "disclaimer": DISCLAIMER,
    }
    calibration_report = build_calibration_report(eval_report, report, labels)
    eval_report["calibration"] = calibration_report

    if out_dir is not None:
        out_path = Path(out_dir)
        out_path.mkdir(parents=True, exist_ok=True)
        _write_json(out_path / EVAL_JSON_NAME, eval_report)
        _write_text(out_path / EVAL_MD_NAME, render_eval_markdown(eval_report))
        _write_json(out_path / CALIBRATION_JSON_NAME, calibration_report)
        _write_text(out_path / CALIBRATION_MD_NAME, render_calibration_markdown(calibration_report))

    return eval_report


def build_calibration_report(
    eval_report: Mapping[str, Any],
    triage_report: Mapping[str, Any],
    labels: Mapping[str, Any],
) -> dict[str, Any]:
    """Build synthetic calibration indicators without claiming scientific metrics."""
    documents = cast(list[Mapping[str, Any]], triage_report["per_document"])
    labels_list = cast(list[Mapping[str, Any]], labels.get("documents", []))
    documents_by_file = {str(document["file"]): document for document in documents}
    expected_categories = sorted(
        {
            str(category)
            for label in labels_list
            for category in cast(Sequence[object], label.get("expected_categories", []))
        }
    )
    detected_categories = sorted(
        {
            str(category)
            for document in documents
            for category in cast(Sequence[object], document.get("strong_categories", []))
        }
    )
    quality_counts = _sum_quality_counts(documents)
    expected_gaps = {
        str(label["file"]): [str(gap) for gap in cast(Sequence[object], label["expected_gaps"])]
        for label in labels_list
        if label.get("expected_gaps")
    }
    missed_gaps = _find_missed_gaps(expected_gaps, documents_by_file)
    false_positive_cases = sorted(
        set(cast(Sequence[str], eval_report["false_positive_cases"]))
        | set(_quality_false_positive_watchlist(documents))
    )
    false_negative_cases = sorted(
        set(cast(Sequence[str], eval_report["false_negative_cases"])) | set(missed_gaps)
    )
    calibration = {
        "run_id": eval_report["run_id"],
        "timestamp": eval_report["timestamp"],
        "fixtures_path": eval_report["fixtures_path"],
        "labels_path": eval_report["labels_path"],
        "metric_note": (
            "Synthetic calibration indicators only. These are proxy metrics for local "
            "heuristic tuning, not scientific precision/recall or a compliance measure."
        ),
        "total_documents": eval_report["documents_total"],
        "expected_categories": expected_categories,
        "detected_categories": detected_categories,
        "strong_evidence_count": quality_counts["strong"],
        "medium_evidence_count": quality_counts["medium"],
        "weak_evidence_count": quality_counts["weak"],
        "warning_count": quality_counts["warning"],
        "expected_gaps": expected_gaps,
        "missed_gaps": missed_gaps,
        "likely_false_positives": false_positive_cases,
        "likely_false_negatives": false_negative_cases,
        "per_category_precision_proxy": _build_category_proxy(
            labels_list,
            eval_report,
            "precision",
        ),
        "per_category_recall_proxy": _build_category_proxy(labels_list, eval_report, "recall"),
        "recommended_threshold_changes": _recommend_threshold_changes(
            false_positive_cases,
            false_negative_cases,
            quality_counts,
        ),
        "human_review_required": (
            "Human review is required for every warning, every medium/weak item, and every "
            "strong item before customer handover. This report is not legal advice, an audit, "
            "a certification, or a NIS-2 compliance guarantee."
        ),
    }
    return calibration


def render_triage_markdown(report: Mapping[str, Any]) -> str:
    """Render a pilot-friendly Markdown evidence report."""
    lines = [
        "# AethelGard Evidence Triage Report",
        "",
        "## Scope",
        "- Input path: `%s`" % report["input_path"],
        "- Tool version: `%s`" % report["tool_version"],
        "- Processing mode: local evidence triage for non-sensitive documents.",
        "- Human review required before any customer handover or compliance conclusion.",
        "",
        "## Important Disclaimer",
        str(report["disclaimer"]),
        "",
        "## Executive Summary",
        "- Documents discovered: %d" % report["document_count"],
        "- Documents parsed: %d" % report["parsed_count"],
        "- Parser failures: %d" % report["failed_count"],
        "- Evidence items: %d" % report["evidence_count"],
        "",
        "## Documents Processed",
    ]
    for document in report["per_document"]:
        lines.append("- `%s`: %d evidence items, %d strong" % (
            document["file"],
            document["evidence_count"],
            document["strong_evidence_count"],
        ))

    lines.extend(["", "## Evidence by Category"])
    for category, count in report["categories"].items():
        lines.append("- `%s`: %d" % (category, count))

    lines.extend(["", "## Potential Gaps"])
    if report["warnings"]:
        lines.extend("- %s" % warning for warning in report["warnings"])
    else:
        lines.append("- No gap warnings emitted by this local heuristic.")

    lines.extend(["", "## Items Requiring Human Review"])
    for document in report["per_document"]:
        lines.append("### `%s`" % document["file"])
        if not document["evidence"]:
            lines.append("- No evidence emitted; check whether the document is out of scope.")
            continue
        for item in document["evidence"]:
            lines.append(
                "- `%s` score %.2f compliant=%s: %s"
                % (
                    item["category"],
                    item["confidence_score"],
                    item["is_compliant"],
                    item["source_citation"],
                )
            )

    lines.extend(
        [
            "",
            "## False Positive Watchlist",
            "- Marketing-only claims, empty templates, outdated policies, vague supplier language, "
            "and missing incident timelines must not be accepted as final evidence.",
            "",
            "## Recommended Next Manual Checks",
            "- Confirm that strong evidence maps to a real implemented control.",
            "- Check whether every gap warning is a true gap or a wording issue.",
            "- Look for missing categories that this keyword-based pass may not detect.",
            "- Record reviewer notes before sharing the report with a customer.",
            "",
            "## Technical Run Metadata",
            "- Run ID: `%s`" % report["run_id"],
            "- Timestamp: `%s`" % report["timestamp"],
            "- Tool version: `%s`" % report["tool_version"],
            "- Local output contains snippets only; source documents are not embedded in full.",
        ]
    )
    return "\n".join(lines) + "\n"


def render_eval_markdown(report: Mapping[str, Any]) -> str:
    """Render Markdown for evaluation results."""
    lines = [
        "# AethelGard Public NIS2 Evaluation Report",
        "",
        "## Disclaimer",
        str(report["disclaimer"]),
        "",
        "## Status",
        "- Pilot readiness: `%s`" % report["status"],
        "- Documents total: %d" % report["documents_total"],
        "- Documents passed: %d" % report["documents_passed"],
        "- Documents failed: %d" % report["documents_failed"],
        "- Parser failures: %d" % report["parser_failures"],
        "",
        "## Metrics",
        "| Metric | Value | Threshold | Status |",
        "|---|---:|---:|---|",
        "| Processed ratio | %.2f | %.2f | %s |"
        % (
            report["processed_ratio"],
            report["thresholds"]["required_processed_ratio"],
            _status_label(report["threshold_status"]["processed_ratio"]),
        ),
        "| Category hit rate | %.2f | %.2f | %s |"
        % (
            report["category_hits"]["rate"],
            report["thresholds"]["min_category_hit_rate"],
            _status_label(report["threshold_status"]["category_hit_rate"]),
        ),
        "| Evidence minimum pass rate | %.2f | n/a | %s |"
        % (
            report["evidence_min_pass_rate"],
            _status_label(report["evidence_min_pass_rate"] == 1.0),
        ),
        "| Marketing strong evidence | %d | %d | %s |"
        % (
            len(report["false_positive_cases"]),
            report["thresholds"]["max_marketing_strong_evidence"],
            _status_label(report["threshold_status"]["marketing_false_positive"]),
        ),
        "",
        "## Per Document",
    ]
    for item in report["per_document"]:
        lines.append(
            "- `%s`: %s, strong=%d, missing=%s, unexpected=%s"
            % (
                item["file"],
                _status_label(bool(item["passed"])),
                item.get("strong_evidence_count", 0),
                item.get("missing_expected_categories", []),
                item.get("unexpected_categories", []),
            )
        )
    return "\n".join(lines) + "\n"


def render_calibration_markdown(report: Mapping[str, Any]) -> str:
    """Render Markdown for calibration indicators."""
    quality_lines = [
        "- Strong evidence: %d" % report["strong_evidence_count"],
        "- Medium evidence: %d" % report["medium_evidence_count"],
        "- Weak evidence: %d" % report["weak_evidence_count"],
        "- Warnings: %d" % report["warning_count"],
    ]
    lines = [
        "# AethelGard Calibration Report",
        "",
        "## Scope",
        "- Fixtures: `%s`" % report["fixtures_path"],
        "- Labels: `%s`" % report["labels_path"],
        "- Total documents: %d" % report["total_documents"],
        "",
        "## Metric Note",
        str(report["metric_note"]),
        "",
        "## Quality Counts",
        *quality_lines,
        "",
        "## Category Coverage",
        "- Expected categories: `%s`" % ", ".join(report["expected_categories"]),
        "- Detected strong categories: `%s`" % ", ".join(report["detected_categories"]),
        "",
        "## Gap Indicators",
        "- Expected gap documents: %d" % len(report["expected_gaps"]),
        "- Missed gap documents: `%s`" % ", ".join(report["missed_gaps"]),
        "",
        "## False Positive / False Negative Watchlist",
        "- Likely false positives: `%s`" % ", ".join(report["likely_false_positives"]),
        "- Likely false negatives: `%s`" % ", ".join(report["likely_false_negatives"]),
        "",
        "## Recommended Threshold Changes",
    ]
    lines.extend("- %s" % item for item in report["recommended_threshold_changes"])
    lines.extend(
        [
            "",
            "## Human Review Required",
            str(report["human_review_required"]),
        ]
    )
    return "\n".join(lines) + "\n"


def _build_document_result(
    document_path: Path,
    input_root: Path,
    evidence_items: Sequence[ComplianceEvidence],
) -> dict[str, Any]:
    evidence: list[dict[str, Any]] = []
    categories: dict[str, int] = defaultdict(int)
    strong_categories: set[str] = set()
    gap_warnings: list[str] = []
    quality_counts: dict[str, int] = {"strong": 0, "medium": 0, "weak": 0, "warning": 0}

    for item in evidence_items:
        category = item.requirement_id
        citation = _bounded_citation(" ".join(item.source_citation.split()))
        quality_result = _evaluate_evidence_quality(
            category,
            citation,
            item.is_compliant,
            item.confidence_score,
        )
        quality = str(quality_result["quality"])
        quality_counts[quality] += 1
        evidence.append(
            {
                "category": category,
                "is_compliant": item.is_compliant,
                "confidence_score": item.confidence_score,
                "quality": quality,
                "quality_signals": quality_result["signals"],
                "concrete_features": quality_result["features"],
                "strong": quality == "strong",
                "source_citation": citation,
            }
        )
        categories[category] += 1
        if quality == "strong":
            strong_categories.add(category)
        if quality == "warning" or _contains_gap_term(citation):
            signal_text = ", ".join(cast(list[str], quality_result["signals"])[:3])
            suffix = ": %s" % signal_text if signal_text else ""
            gap_warnings.append("%s evidence needs review%s" % (category, suffix))

    deduped_warnings = sorted(set(gap_warnings))
    return {
        "file": _safe_relative(document_path, input_root),
        "evidence_count": len(evidence),
        "strong_evidence_count": sum(1 for item in evidence if item["strong"]),
        "quality_counts": quality_counts,
        "categories": dict(sorted(categories.items())),
        "strong_categories": sorted(strong_categories),
        "gap_warnings": deduped_warnings,
        "warnings": deduped_warnings,
        "evidence": evidence,
    }


def _evaluate_evidence_quality(
    category: str,
    citation: str,
    is_compliant: bool,
    confidence_score: float,
) -> dict[str, object]:
    text = citation.lower()
    signals = _detect_negative_signals(category, text)
    features = _detect_concrete_features(category, text)
    hard_signals = {
        "marketing_only",
        "template_only",
        "outdated",
        "missing_timeline",
        "vague_supplier_controls",
    }
    if "owner" not in features:
        signals.append("missing_owner")
    if "review_or_frequency" not in features:
        signals.append("missing_review_date")

    if not is_compliant or any(signal in hard_signals for signal in signals):
        quality = "warning"
    elif confidence_score >= STRONG_EVIDENCE_THRESHOLD and len(features) >= MIN_STRONG_FEATURES:
        quality = "strong"
    elif confidence_score >= MEDIUM_EVIDENCE_THRESHOLD and len(features) >= MIN_MEDIUM_FEATURES:
        quality = "medium"
    else:
        quality = "weak"

    return {
        "quality": quality,
        "signals": sorted(set(signals)),
        "features": sorted(set(features)),
    }


def _detect_negative_signals(category: str, text: str) -> list[str]:
    signals = [
        signal
        for signal, terms in NEGATIVE_SIGNAL_TERMS.items()
        if any(term in text for term in terms)
    ]
    for year in range(2000, OUTDATED_YEAR_CUTOFF):
        if str(year) in text and "review" in text:
            signals.append("outdated")
            break
    if category == "incident_reporting" and not any(term in text for term in TIMELINE_TERMS):
        signals.append("missing_timeline")
    if category == "supplier_security" and not any(
        term in text for term in SUPPLIER_CONTROL_TERMS
    ):
        signals.append("vague_supplier_controls")
    return sorted(set(signals))


def _detect_concrete_features(category: str, text: str) -> list[str]:
    features: list[str] = []
    if any(term in text for term in OWNER_TERMS):
        features.append("owner")
    if any(term in text for term in REVIEW_OR_FREQUENCY_TERMS):
        features.append("review_or_frequency")
    if any(term in text for term in PROCESS_OR_CONTROL_TERMS):
        features.append("process_or_control")
    if any(term in text for term in OUTPUT_OR_EVIDENCE_TERMS):
        features.append("output_or_evidence")
    if category == "incident_reporting" and any(term in text for term in TIMELINE_TERMS):
        features.append("timeline")
    if category == "supplier_security" and any(term in text for term in SUPPLIER_CONTROL_TERMS):
        features.append("supplier_control")
    return features


def _sum_quality_counts(documents: Sequence[Mapping[str, Any]]) -> dict[str, int]:
    totals = {"strong": 0, "medium": 0, "weak": 0, "warning": 0}
    for document in documents:
        counts = cast(Mapping[str, int], document.get("quality_counts", {}))
        for quality in totals:
            totals[quality] += int(counts.get(quality, 0))
    return totals


def _find_missed_gaps(
    expected_gaps: Mapping[str, Sequence[str]],
    documents_by_file: Mapping[str, Mapping[str, Any]],
) -> list[str]:
    missed: list[str] = []
    for file_name in expected_gaps:
        document = documents_by_file.get(file_name)
        if document is None:
            missed.append(file_name)
            continue
        warning_count = int(cast(Mapping[str, int], document["quality_counts"]).get("warning", 0))
        if not document.get("gap_warnings") and warning_count == 0:
            missed.append(file_name)
    return sorted(missed)


def _quality_false_positive_watchlist(documents: Sequence[Mapping[str, Any]]) -> list[str]:
    watchlist: list[str] = []
    noisy_signals = {"marketing_only", "template_only", "outdated", "vague_supplier_controls"}
    for document in documents:
        has_noisy_strong = any(
            bool(item.get("strong"))
            and bool(noisy_signals & set(cast(Sequence[str], item.get("quality_signals", []))))
            for item in cast(Sequence[Mapping[str, Any]], document.get("evidence", []))
        )
        if has_noisy_strong:
            watchlist.append(str(document["file"]))
    return watchlist


def _build_category_proxy(
    labels: Sequence[Mapping[str, Any]],
    eval_report: Mapping[str, Any],
    metric: str,
) -> dict[str, dict[str, float | int | None]]:
    per_document = cast(Sequence[Mapping[str, Any]], eval_report["per_document"])
    label_by_file = {str(label["file"]): label for label in labels}
    totals: dict[str, dict[str, int]] = {
        category: {"tp": 0, "fp": 0, "fn": 0} for category in CATEGORY_KEYWORDS
    }
    for result in per_document:
        file_name = str(result["file"])
        label = label_by_file.get(file_name, {})
        expected = {
            str(item)
            for item in cast(Sequence[object], label.get("expected_categories", []))
        }
        actual = {
            str(item)
            for item in cast(Sequence[object], result.get("actual_strong_categories", []))
        }
        must_not = {
            str(item)
            for item in cast(Sequence[object], label.get("must_not_include_categories", []))
        }
        for category in CATEGORY_KEYWORDS:
            if category in expected and category in actual:
                totals[category]["tp"] += 1
            if category in actual and (category not in expected or category in must_not):
                totals[category]["fp"] += 1
            if category in expected and category not in actual:
                totals[category]["fn"] += 1

    proxies: dict[str, dict[str, float | int | None]] = {}
    for category, counts in totals.items():
        if metric == "precision":
            denominator = counts["tp"] + counts["fp"]
        else:
            denominator = counts["tp"] + counts["fn"]
        value = round(counts["tp"] / denominator, 4) if denominator else None
        proxies[category] = {
            "%s_proxy" % metric: value,
            "true_positive_proxy": counts["tp"],
            "false_positive_proxy": counts["fp"],
            "false_negative_proxy": counts["fn"],
        }
    return proxies


def _recommend_threshold_changes(
    false_positive_cases: Sequence[str],
    false_negative_cases: Sequence[str],
    quality_counts: Mapping[str, int],
) -> list[str]:
    recommendations: list[str] = []
    if false_positive_cases:
        recommendations.append(
            "Keep the strong threshold at %.2f and require concrete quality features before "
            "handover; review noisy files manually." % STRONG_EVIDENCE_THRESHOLD
        )
    if false_negative_cases:
        recommendations.append(
            "Do not lower the threshold globally; first expand category keywords or labels for "
            "missed synthetic cases."
        )
    if quality_counts.get("warning", 0) > 0:
        recommendations.append(
            "Route all warning evidence to human review; warnings are expected for ambiguous "
            "pilot documents."
        )
    if not recommendations:
        recommendations.append(
            "No threshold change recommended for this synthetic pack; keep quality guards active."
        )
    return recommendations


def _contains_gap_term(text: str) -> bool:
    lower = text.lower()
    return any(term in lower for term in GAP_TERMS)


def _bounded_citation(text: str) -> str:
    if len(text) <= MAX_REPORT_CITATION_CHARS:
        return text
    head_length = MAX_REPORT_CITATION_CHARS // 2
    separator = " ... "
    tail_length = MAX_REPORT_CITATION_CHARS - head_length - len(separator)
    return "%s%s%s" % (
        text[:head_length].rstrip(),
        separator,
        text[-tail_length:].lstrip(),
    )


def _missing_terms_in_evidence(
    evidence: Sequence[Mapping[str, Any]],
    terms: Iterable[str],
) -> list[str]:
    citation_blob = " ".join(str(item.get("source_citation", "")) for item in evidence).lower()
    return sorted(term for term in terms if term.lower() not in citation_blob)


def _gap_documents_pass(
    per_document: Sequence[Mapping[str, Any]],
    labels: Sequence[Mapping[str, Any]],
) -> bool:
    by_file = {item["file"]: item for item in per_document}
    for label in labels:
        if not label.get("expected_gaps"):
            continue
        result = by_file.get(str(label["file"]))
        if result is None:
            return False
        if result.get("strong_evidence_count", 0) > 0 and not result.get("gap_warnings"):
            return False
    return True


def _safe_relative(path: Path, root: Path) -> str:
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return path.name


def _build_run_id(prefix: str) -> str:
    return "%s-%s" % (prefix, datetime.now(UTC).strftime("%Y%m%dT%H%M%S%fZ"))


def _read_json(path: Path) -> dict[str, Any]:
    return cast(dict[str, Any], json.loads(path.read_text(encoding="utf-8")))


def _write_json(path: Path, payload: Mapping[str, Any]) -> None:
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _write_text(path: Path, text: str) -> None:
    path.write_text(text, encoding="utf-8")


def _status_label(ok: bool) -> str:
    return "PASS" if ok else "FAIL"
