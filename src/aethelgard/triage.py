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

SUPPORTED_DOCUMENT_SUFFIXES: Final[frozenset[str]] = frozenset({".md", ".txt", ".pdf"})
STRONG_EVIDENCE_THRESHOLD: Final[float] = 0.7
MAX_REPORT_CITATION_CHARS: Final[int] = 280

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
    """Evaluate public fixtures against golden labels."""
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

    if out_dir is not None:
        out_path = Path(out_dir)
        out_path.mkdir(parents=True, exist_ok=True)
        _write_json(out_path / EVAL_JSON_NAME, eval_report)
        _write_text(out_path / EVAL_MD_NAME, render_eval_markdown(eval_report))

    return eval_report


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


def _build_document_result(
    document_path: Path,
    input_root: Path,
    evidence_items: Sequence[ComplianceEvidence],
) -> dict[str, Any]:
    evidence: list[dict[str, Any]] = []
    categories: dict[str, int] = defaultdict(int)
    strong_categories: set[str] = set()
    gap_warnings: list[str] = []

    for item in evidence_items:
        category = item.requirement_id
        citation = _bounded_citation(" ".join(item.source_citation.split()))
        evidence.append(
            {
                "category": category,
                "is_compliant": item.is_compliant,
                "confidence_score": item.confidence_score,
                "strong": item.is_compliant and item.confidence_score >= STRONG_EVIDENCE_THRESHOLD,
                "source_citation": citation,
            }
        )
        categories[category] += 1
        if item.is_compliant and item.confidence_score >= STRONG_EVIDENCE_THRESHOLD:
            strong_categories.add(category)
        if not item.is_compliant or _contains_gap_term(citation):
            gap_warnings.append("%s evidence needs review" % category)

    deduped_warnings = sorted(set(gap_warnings))
    return {
        "file": _safe_relative(document_path, input_root),
        "evidence_count": len(evidence),
        "strong_evidence_count": sum(1 for item in evidence if item["strong"]),
        "categories": dict(sorted(categories.items())),
        "strong_categories": sorted(strong_categories),
        "gap_warnings": deduped_warnings,
        "warnings": deduped_warnings,
        "evidence": evidence,
    }


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
