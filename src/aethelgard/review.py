"""Human-review import helpers for AethelGard evidence reports."""

from __future__ import annotations

import csv
import json
import re
from collections.abc import Mapping, Sequence
from copy import deepcopy
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Final, TypedDict, cast

from aethelgard.redaction_preflight import has_sensitive_markers, mask_sensitive_text

REVIEWED_REPORT_JSON_NAME: Final[str] = "reviewed_report.json"
REVIEWED_REPORT_MD_NAME: Final[str] = "reviewed_report.md"
REVIEW_SUMMARY_JSON_NAME: Final[str] = "review_summary.json"

REVIEW_STATUS_VALUES: Final[tuple[str, ...]] = (
    "open",
    "accepted",
    "false_positive",
    "needs_evidence",
    "not_applicable",
    "resolved",
)
REVIEW_STATUS_SET: Final[frozenset[str]] = frozenset(REVIEW_STATUS_VALUES)

MAX_REVIEW_NOTE_CHARS: Final[int] = 4_000
MAX_REVIEWER_CHARS: Final[int] = 120
MAX_REVIEWED_AT_CHARS: Final[int] = 80


class ReviewApplyError(ValueError):
    """Raised when a review CSV cannot be applied safely."""


class ReviewSummary(TypedDict):
    total_findings: int
    status_counts: dict[str, int]
    unknown_review_ids: list[str]
    warnings: list[str]
    generated_at: str


class ReviewApplyResult(TypedDict):
    reviewed_report: dict[str, Any]
    summary: ReviewSummary


def apply_review_csv(
    report_path: Path | str,
    review_csv_path: Path | str,
    out_dir: Path | str,
    *,
    strict: bool = False,
) -> ReviewApplyResult:
    """Apply a human-review CSV to an existing evidence report and write outputs."""
    report = _read_json(Path(report_path))
    rows = _read_review_rows(Path(review_csv_path))
    reviewed_report = deepcopy(report)
    summary = apply_review_rows(reviewed_report, rows, strict=strict)

    output_path = Path(out_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    _write_json(output_path / REVIEWED_REPORT_JSON_NAME, reviewed_report)
    _write_text(
        output_path / REVIEWED_REPORT_MD_NAME,
        render_reviewed_markdown(reviewed_report, summary),
    )
    _write_json(output_path / REVIEW_SUMMARY_JSON_NAME, summary)
    return {"reviewed_report": reviewed_report, "summary": summary}


def apply_review_rows(
    report: dict[str, Any],
    rows: Sequence[Mapping[str, str]],
    *,
    strict: bool = False,
) -> ReviewSummary:
    """Apply normalized review rows to an in-memory report."""
    findings = _index_report_findings(report)
    _initialize_review_fields(list(findings.values()))

    seen_ids: set[str] = set()
    unknown_review_ids: list[str] = []
    warnings: list[str] = []

    for row_number, row in enumerate(rows, start=2):
        finding_id = str(row.get("finding_id", "")).strip()
        if not finding_id:
            raise ReviewApplyError("review CSV row %d is missing finding_id" % row_number)
        if finding_id in seen_ids:
            raise ReviewApplyError("duplicate finding_id in review CSV: %s" % finding_id)
        seen_ids.add(finding_id)

        status = _normalize_review_status(
            str(row.get("review_status", "")),
            finding_id,
            row_number,
            strict,
            warnings,
        )
        item = findings.get(finding_id)
        if item is None:
            message = "unknown finding_id in review CSV row %d: %s" % (row_number, finding_id)
            if strict:
                raise ReviewApplyError(message)
            unknown_review_ids.append(finding_id)
            warnings.append(message)
            continue

        review_note = _sanitize_review_note(str(row.get("review_note", "")), finding_id, warnings)
        item["review_status"] = status
        item["review_note"] = review_note
        item["reviewer"] = _bounded_field(str(row.get("reviewer", "")), MAX_REVIEWER_CHARS)
        item["reviewed_at"] = _bounded_field(str(row.get("reviewed_at", "")), MAX_REVIEWED_AT_CHARS)

    return _build_summary(list(findings.values()), unknown_review_ids, warnings)


def render_reviewed_markdown(report: Mapping[str, Any], summary: Mapping[str, Any]) -> str:
    """Render the reviewed report as human-readable Markdown."""
    status_counts = cast(Mapping[str, int], summary["status_counts"])
    lines = [
        "# Aethelgard Reviewed Evidence Report",
        "",
        "## Scope / Disclaimer",
        "- Keine Rechtsberatung",
        "- Kein Audit",
        "- Keine Compliance-Garantie",
        "- Human Review erforderlich",
        "",
        "## Review Summary",
        "- Total Findings: %d" % summary["total_findings"],
    ]
    for status in REVIEW_STATUS_VALUES:
        lines.append("- %s: %d" % (_status_label(status), status_counts[status]))

    lines.extend(["", "## Findings by Status"])
    for status in REVIEW_STATUS_VALUES:
        lines.extend(["", "### %s" % _status_label(status)])
        rendered_any = False
        for document, item in _iter_document_findings(report):
            review_status = str(item.get("review_status", "open"))
            if review_status != status:
                continue
            rendered_any = True
            lines.extend(_render_finding(document, item))
        if not rendered_any:
            lines.append("- None.")
    return "\n".join(lines) + "\n"


def _read_review_rows(path: Path) -> list[dict[str, str]]:
    with path.open(encoding="utf-8", newline="") as csv_file:
        reader = csv.DictReader(csv_file)
        fieldnames = reader.fieldnames or []
        if "finding_id" not in fieldnames:
            raise ReviewApplyError("review CSV is missing finding_id column")
        if "review_status" not in fieldnames:
            raise ReviewApplyError("review CSV is missing review_status column")

        rows: list[dict[str, str]] = []
        for row in reader:
            normalized: dict[str, str] = {}
            for key, value in row.items():
                if key is not None:
                    normalized[key] = "" if value is None else value
            rows.append(normalized)
        return rows


def _index_report_findings(report: Mapping[str, Any]) -> dict[str, dict[str, Any]]:
    indexed: dict[str, dict[str, Any]] = {}
    for _document, item in _iter_document_findings(report):
        finding_id = str(item.get("finding_id", "")).strip()
        if not finding_id:
            raise ReviewApplyError("evidence report contains a finding without finding_id")
        if finding_id in indexed:
            raise ReviewApplyError("evidence report contains duplicate finding_id: %s" % finding_id)
        indexed[finding_id] = cast(dict[str, Any], item)
    return indexed


def _iter_document_findings(
    report: Mapping[str, Any],
) -> list[tuple[Mapping[str, Any], Mapping[str, Any]]]:
    findings: list[tuple[Mapping[str, Any], Mapping[str, Any]]] = []
    documents = cast(Sequence[Mapping[str, Any]], report.get("per_document", []))
    for document in documents:
        evidence_items = cast(Sequence[Mapping[str, Any]], document.get("evidence", []))
        for item in evidence_items:
            findings.append((document, item))
    return findings


def _initialize_review_fields(findings: Sequence[dict[str, Any]]) -> None:
    for item in findings:
        item["review_status"] = "open"
        item["review_note"] = ""
        item["reviewer"] = ""
        item["reviewed_at"] = ""


def _normalize_review_status(
    raw_status: str,
    finding_id: str,
    row_number: int,
    strict: bool,
    warnings: list[str],
) -> str:
    status = raw_status.strip().lower()
    if not status:
        return "open"
    if status in REVIEW_STATUS_SET:
        return status
    message = (
        "unknown review_status %r for %s on review CSV row %d; coerced to open"
        % (raw_status, finding_id, row_number)
    )
    if strict:
        raise ReviewApplyError(message)
    warnings.append(message)
    return "open"


def _sanitize_review_note(note: str, finding_id: str, warnings: list[str]) -> str:
    bounded_note = _bounded_field(note, MAX_REVIEW_NOTE_CHARS)
    if not has_sensitive_markers(bounded_note):
        return bounded_note
    warnings.append("sensitive marker masked in review_note for %s" % finding_id)
    return mask_sensitive_text(bounded_note)


def _bounded_field(value: str, max_chars: int) -> str:
    if len(value) <= max_chars:
        return value
    return value[:max_chars]


def _build_summary(
    findings: Sequence[Mapping[str, Any]],
    unknown_review_ids: Sequence[str],
    warnings: Sequence[str],
) -> ReviewSummary:
    status_counts = {status: 0 for status in REVIEW_STATUS_VALUES}
    for item in findings:
        status = str(item.get("review_status", "open"))
        if status not in REVIEW_STATUS_SET:
            status = "open"
        status_counts[status] += 1
    return {
        "total_findings": len(findings),
        "status_counts": status_counts,
        "unknown_review_ids": sorted(unknown_review_ids),
        "warnings": list(warnings),
        "generated_at": datetime.now(UTC).isoformat(),
    }


def _render_finding(document: Mapping[str, Any], item: Mapping[str, Any]) -> list[str]:
    category = str(item.get("category", ""))
    return [
        "",
        "#### %s" % _escape_markdown(str(item.get("finding_id", ""))),
        "- Finding ID: %s" % _escape_markdown(str(item.get("finding_id", ""))),
        "- Category: %s" % _escape_markdown(category),
        "- Control Area: %s" % _escape_markdown(category.replace("_", " ")),
        "- Document: %s" % _escape_markdown(str(document.get("file", ""))),
        "- Evidence Level: %s" % _escape_markdown(str(item.get("quality", ""))),
        "- Original Status: %s" % _escape_markdown(_original_status(item)),
        "- Review Status: %s" % _escape_markdown(str(item.get("review_status", "open"))),
        "- Review Note: %s" % _escape_markdown(str(item.get("review_note", "")) or "-"),
        "- Recommended Manual Check: %s"
        % _escape_markdown(str(item.get("recommended_manual_check", "")) or "-"),
        "- Source Reference: %s" % _escape_markdown(str(item.get("source_reference", "")) or "-"),
    ]


def _original_status(item: Mapping[str, Any]) -> str:
    if bool(item.get("strong", False)):
        return "candidate_evidence"
    if str(item.get("quality", "")) == "warning":
        return "warning_review"
    return "manual_review"


def _status_label(status: str) -> str:
    return status.replace("_", " ").title()


def _escape_markdown(value: str) -> str:
    return re.sub(r"([`*_\[\]<>|])", r"\\\1", value)


def _read_json(path: Path) -> dict[str, Any]:
    return cast(dict[str, Any], json.loads(path.read_text(encoding="utf-8")))


def _write_json(path: Path, payload: Mapping[str, Any]) -> None:
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _write_text(path: Path, text: str) -> None:
    path.write_text(text, encoding="utf-8")
