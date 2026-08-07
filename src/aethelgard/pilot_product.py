"""Integrated local pilot-product workflow for documents, evidence, and answers."""

from __future__ import annotations

import html
import json
import shutil
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Final, cast

from aethelgard import __version__
from aethelgard.answer_vault import (
    CASE_REVIEW_QUEUE_CSV_NAME,
    MISSING_EVIDENCE_CSV_NAME,
    QUESTIONNAIRE_DRAFT_CSV_NAME,
    build_questionnaire_draft,
    import_answer_library_json,
    init_answer_vault,
    store_ingest_result,
)
from aethelgard.document_ingest import (
    DOCUMENT_INVENTORY_NAME,
    DOCUMENT_SUMMARIES_NAME,
    EVIDENCE_MAP_NAME,
    render_document_summaries_markdown,
    run_document_ingest,
)
from aethelgard.redaction_preflight import (
    PREFLIGHT_JSON_NAME,
    run_redaction_preflight,
    write_preflight_reports,
)
from aethelgard.triage import DISCLAIMER
from aethelgard.diagnostics import (
    LOCAL_PRIVATE_DIR_NAME,
    PILOT_READINESS_REPORT_NAME,
    SHAREABLE_REDACTED_DIR_NAME,
)

DEFAULT_SQLITE_NAME: Final[str] = "aethelgard.sqlite"
DEFAULT_CASE_ID: Final[str] = "case001"
DEFAULT_CLIENT_ID: Final[str] = "synthetic-client"
ANSWER_LIBRARY_DEMO_NAME: Final[str] = "answer_library_demo.json"
COVERAGE_REPORT_MD_NAME: Final[str] = "coverage_report.md"
COVERAGE_REPORT_HTML_NAME: Final[str] = "coverage_report.html"
REVIEW_ITEMS_CSV_NAME: Final[str] = "review_items.csv"
QUESTIONNAIRE_DRAFT_JSON_NAME: Final[str] = "questionnaire_draft.json"
MAX_SHAREABLE_SCAN_BYTES: Final[int] = 2_000_000

PRIVATE_PATH_MARKERS: Final[tuple[str, ...]] = (
    "C:/Users",
    "C:\\Users",
    "/home/",
    ".env",
    "api_key",
    "authorization",
    "bearer ",
    "cookie",
    "password",
    "source_citation",
    "redacted_excerpt",
    "candidate_text",
)
OVERCLAIM_MARKERS: Final[tuple[str, ...]] = (
    "audit_passed",
    "certified",
    "compliance guaranteed",
    "nis2 compliant",
    "nis-2 compliant",
    "rechtssicher",
)
PRIVATE_WORKSPACE_MARKERS: Final[tuple[str, ...]] = (
    "customer",
    "kunde",
    "live",
    "private",
    "prod",
)


class PilotProductError(ValueError):
    """Raised when the integrated pilot-product slice cannot run safely."""


def run_pilot_product_slice(
    workspace: Path | str,
    out_dir: Path | str,
    *,
    client_id: str = DEFAULT_CLIENT_ID,
    case_id: str = DEFAULT_CASE_ID,
    docs_path: Path | str | None = None,
    questionnaire_path: Path | str | None = None,
    db_path: Path | str | None = None,
) -> dict[str, object]:
    """Run the local product slice from sample/approved inputs to review-ready outputs."""
    workspace_path = Path(workspace)
    output_path = Path(out_dir)
    documents_dir = Path(docs_path) if docs_path is not None else workspace_path / "documents"
    questions_csv = (
        Path(questionnaire_path)
        if questionnaire_path is not None
        else workspace_path / "questionnaire_demo.csv"
    )
    _require_input_dir(documents_dir)
    _require_input_file(questions_csv)
    output_path.mkdir(parents=True, exist_ok=True)
    local_private_dir = output_path / LOCAL_PRIVATE_DIR_NAME
    shareable_dir = output_path / SHAREABLE_REDACTED_DIR_NAME
    local_private_dir.mkdir(parents=True, exist_ok=True)
    shareable_dir.mkdir(parents=True, exist_ok=True)

    preflight_report = run_redaction_preflight(documents_dir)
    write_preflight_reports(local_private_dir, preflight_report)
    if preflight_report["status"] == "block":
        raise PilotProductError("preflight blocked the input documents")

    ingest_report = run_document_ingest(documents_dir, local_private_dir)
    (shareable_dir / DOCUMENT_SUMMARIES_NAME).write_text(
        render_document_summaries_markdown(ingest_report),
        encoding="utf-8",
    )

    sqlite_path = Path(db_path) if db_path is not None else local_private_dir / DEFAULT_SQLITE_NAME
    init_answer_vault(sqlite_path, client_id=client_id)
    store_ingest_result(sqlite_path, client_id=client_id, ingest_report=ingest_report)

    answer_library_path = workspace_path / ANSWER_LIBRARY_DEMO_NAME
    imported_answers = 0
    if answer_library_path.is_file():
        imported = import_answer_library_json(
            sqlite_path,
            answer_library_path,
            client_id=client_id,
        )
        imported_answers = _to_int(imported["imported"])

    evidence_map = cast(Mapping[str, object], ingest_report["evidence_map"])
    draft_report = build_questionnaire_draft(
        sqlite_path,
        questions_csv,
        evidence_map,
        shareable_dir,
        client_id=client_id,
        case_id=case_id,
    )
    _write_json(shareable_dir / QUESTIONNAIRE_DRAFT_JSON_NAME, draft_report)
    _write_review_items_alias(shareable_dir)

    coverage_markdown = render_coverage_report_markdown(ingest_report, draft_report)
    (shareable_dir / COVERAGE_REPORT_MD_NAME).write_text(coverage_markdown, encoding="utf-8")
    (shareable_dir / COVERAGE_REPORT_HTML_NAME).write_text(
        render_coverage_report_html(coverage_markdown),
        encoding="utf-8",
    )

    readiness = build_pilot_product_readiness_report(
        output_path,
        ingest_report,
        draft_report,
        sqlite_path=sqlite_path,
        imported_answers=imported_answers,
        preflight_status=str(preflight_report["status"]),
    )
    _write_json(shareable_dir / PILOT_READINESS_REPORT_NAME, readiness)
    return {
        "status": readiness["status"],
        "client_id": client_id,
        "case_id": case_id,
        "db_path": str(sqlite_path),
        "local_private": str(local_private_dir),
        "shareable_redacted": str(shareable_dir),
        "outputs": {
            "document_inventory": str(local_private_dir / DOCUMENT_INVENTORY_NAME),
            "evidence_map": str(local_private_dir / EVIDENCE_MAP_NAME),
            "document_summaries": str(shareable_dir / DOCUMENT_SUMMARIES_NAME),
            "questionnaire_draft": str(shareable_dir / QUESTIONNAIRE_DRAFT_CSV_NAME),
            "case_review_queue": str(shareable_dir / CASE_REVIEW_QUEUE_CSV_NAME),
            "missing_evidence": str(shareable_dir / MISSING_EVIDENCE_CSV_NAME),
            "coverage_report": str(shareable_dir / COVERAGE_REPORT_MD_NAME),
            "coverage_report_html": str(shareable_dir / COVERAGE_REPORT_HTML_NAME),
            "pilot_readiness": str(shareable_dir / PILOT_READINESS_REPORT_NAME),
        },
    }


def build_pilot_product_readiness_report(
    output_path: Path,
    ingest_report: Mapping[str, object],
    draft_report: Mapping[str, object],
    *,
    sqlite_path: Path | None = None,
    imported_answers: int,
    preflight_status: str,
) -> dict[str, object]:
    """Build local readiness checks for the integrated product slice."""
    inventory = cast(Mapping[str, object], ingest_report["inventory"])
    evidence_map = cast(Mapping[str, object], ingest_report["evidence_map"])
    documents = cast(Sequence[Mapping[str, object]], inventory["documents"])
    evidence = cast(Sequence[Mapping[str, object]], evidence_map["evidence"])
    draft_answers = cast(Sequence[Mapping[str, object]], draft_report["draft_answers"])
    review_queue = cast(Sequence[Mapping[str, object]], draft_report["review_queue"])
    missing_evidence = cast(Sequence[Mapping[str, object]], draft_report["missing_evidence"])
    shareable_dir = output_path / SHAREABLE_REDACTED_DIR_NAME
    db_check_path = sqlite_path or output_path / LOCAL_PRIVATE_DIR_NAME / DEFAULT_SQLITE_NAME
    checks = [
        _check(
            "preflight_not_blocking",
            preflight_status != "block",
            "Redaction preflight did not block the approved/synthetic input documents.",
        ),
        _check(
            "document_inventory_created",
            (output_path / LOCAL_PRIVATE_DIR_NAME / DOCUMENT_INVENTORY_NAME).is_file(),
            "Document inventory is written in local_private.",
        ),
        _check(
            "all_files_statused",
            len(documents) == _to_int(inventory["document_count"]),
            "Every scanned file has a structured status.",
        ),
        _check(
            "unsupported_files_do_not_crash",
            all(str(document["status"]) in _allowed_document_statuses() for document in documents),
            "Unsupported and OCR-needed files are represented as statuses.",
        ),
        _check(
            "evidence_ids_unique",
            _unique_ids(evidence, "evidence_id"),
            "Evidence IDs are stable and unique within the run.",
        ),
        _check(
            "answer_vault_db_created",
            db_check_path.is_file(),
            "SQLite answer vault exists at the configured local path.",
        ),
        _check(
            "baseline_answers_imported",
            imported_answers > 0,
            "At least one reviewed baseline answer was imported for reuse.",
        ),
        _check(
            "questionnaire_draft_created",
            bool(draft_answers) and (shareable_dir / QUESTIONNAIRE_DRAFT_CSV_NAME).is_file(),
            "Questionnaire draft CSV is written.",
        ),
        _check(
            "human_review_queue_created",
            bool(review_queue) and (shareable_dir / CASE_REVIEW_QUEUE_CSV_NAME).is_file(),
            "Case review queue is written for unresolved questions.",
        ),
        _check(
            "missing_evidence_report_created",
            bool(missing_evidence) and (shareable_dir / MISSING_EVIDENCE_CSV_NAME).is_file(),
            "Missing evidence report is written.",
        ),
        _check(
            "shareable_outputs_redacted",
            _shareable_outputs_are_redacted(shareable_dir),
            "Shareable outputs avoid raw snippets, private paths, and secret markers.",
        ),
        _check(
            "no_compliance_overclaim",
            not _shareable_contains_any(shareable_dir, OVERCLAIM_MARKERS),
            "Shareable outputs avoid certification/compliance guarantees.",
        ),
    ]
    status = (
        "PILOT_PRODUCT_SLICE_READY"
        if all(bool(check["passed"]) for check in checks if bool(check["required"]))
        else "PILOT_PRODUCT_SLICE_NEEDS_REVIEW"
    )
    return {
        "status": status,
        "tool_version": __version__,
        "checks": checks,
        "document_count": inventory["document_count"],
        "evidence_count": evidence_map["evidence_count"],
        "question_count": draft_report["question_count"],
        "review_queue_count": len(review_queue),
        "missing_evidence_count": len(missing_evidence),
        "disclaimer": DISCLAIMER,
    }


def render_coverage_report_markdown(
    ingest_report: Mapping[str, object],
    draft_report: Mapping[str, object],
) -> str:
    """Render a shareable redacted coverage report."""
    evidence_map = cast(Mapping[str, object], ingest_report["evidence_map"])
    coverage = cast(Sequence[Mapping[str, object]], evidence_map["coverage"])
    draft_answers = cast(Sequence[Mapping[str, object]], draft_report["draft_answers"])
    review_queue = cast(Sequence[Mapping[str, object]], draft_report["review_queue"])
    missing_evidence = cast(Sequence[Mapping[str, object]], draft_report["missing_evidence"])
    lines = [
        "# AethelGard Pilot Product Slice Report",
        "",
        "## Scope",
        DISCLAIMER,
        "",
        "## What Was Produced",
        "- Document inventory in `local_private/document_inventory.json`.",
        "- Evidence map in `local_private/evidence_map.json`.",
        "- SQLite answer vault in `local_private/aethelgard.sqlite`.",
        "- Questionnaire draft, review queue, and missing-evidence report in this folder.",
        "",
        "## Coverage",
        "| Cluster | Status | Evidence Refs | Confidence |",
        "|---|---|---:|---:|",
    ]
    for item in coverage:
        evidence_refs = cast(Sequence[str], item["evidence_refs"])
        lines.append(
            "| `%s` | `%s` | %d | %.2f |"
            % (
                item["control"],
                item["status"],
                len(evidence_refs),
                _to_float(item["confidence"]),
            )
        )
    lines.extend(
        [
            "",
            "## Questionnaire Draft",
            "| Question | Cluster | Status | Evidence Refs | Reason |",
            "|---|---|---|---:|---|",
        ]
    )
    for item in draft_answers:
        refs = cast(Sequence[str], item["evidence_refs"])
        lines.append(
            "| `%s` | `%s` | `%s` | %d | %s |"
            % (
                item["question_id"],
                item["matched_cluster"],
                item["review_status"],
                len(refs),
                _escape_markdown(str(item["reason"])),
            )
        )
    lines.extend(
        [
            "",
            "## Human Review Queue",
            "- Items requiring review: `%d`" % len(review_queue),
            "- Missing/partial evidence clusters: `%d`" % len(missing_evidence),
            "",
            "## Boundary",
            "- This output is local triage only; human review required before handover.",
            "- This review draft has no compliance guarantee.",
            "- `covered` means evidence candidate coverage for review, not compliance.",
            "- Draft answers are not final unless they reuse a reviewed Answer Vault entry.",
            "- OCR is not performed; images are flagged for a human/OCR step.",
        ]
    )
    return "\n".join(lines) + "\n"


def render_coverage_report_html(markdown: str) -> str:
    """Render a tiny static HTML preview without external assets."""
    escaped = html.escape(markdown)
    rows = "".join("<p>%s</p>" % line if line else "" for line in escaped.splitlines())
    return (
        "<!doctype html>\n"
        '<html lang="en">\n'
        '<head><meta charset="utf-8"><title>AethelGard Pilot Report</title>'
        "<style>body{font-family:Segoe UI,Arial,sans-serif;max-width:1040px;margin:32px auto;"
        "line-height:1.45;color:#1c2430}p{margin:4px 0;white-space:pre-wrap}"
        "code{background:#eef2f5;padding:1px 4px;border-radius:3px}</style></head>\n"
        "<body>%s</body>\n"
        "</html>\n" % rows
    )


def inspect_workspace(workspace: Path | str) -> dict[str, object]:
    """Inspect a local pilot workspace without reading raw source documents."""
    workspace_path = Path(workspace)
    warnings = []
    lowered = workspace_path.as_posix().casefold()
    if any(marker in lowered for marker in PRIVATE_WORKSPACE_MARKERS):
        warnings.append("workspace_path_looks_private_or_customer_like")
    local_private = workspace_path / LOCAL_PRIVATE_DIR_NAME
    shareable = workspace_path / SHAREABLE_REDACTED_DIR_NAME
    inventory_path = local_private / DOCUMENT_INVENTORY_NAME
    inventory: Mapping[str, object] = {}
    if inventory_path.is_file():
        inventory = cast(
            Mapping[str, object],
            json.loads(inventory_path.read_text(encoding="utf-8")),
        )
    return {
        "workspace": str(workspace_path),
        "exists": workspace_path.exists(),
        "local_private_exists": local_private.is_dir(),
        "shareable_redacted_exists": shareable.is_dir(),
        "document_count": inventory.get("document_count", 0),
        "status_counts": inventory.get("status_counts", {}),
        "warnings": warnings,
    }


def purge_workspace(
    workspace: Path | str,
    *,
    dry_run: bool = True,
    confirm: bool = False,
) -> dict[str, object]:
    """Delete known generated pilot outputs when explicitly confirmed."""
    workspace_path = Path(workspace).resolve()
    targets = _purge_targets(workspace_path)
    if not dry_run and not confirm:
        raise PilotProductError("workspace purge requires --confirm or --dry-run")
    for target in targets:
        _ensure_inside_workspace(workspace_path, target)
    deleted: list[str] = []
    if not dry_run:
        for target in targets:
            if target.is_dir():
                shutil.rmtree(target)
            elif target.is_file():
                target.unlink()
            deleted.append(str(target))
    return {
        "workspace": str(workspace_path),
        "dry_run": dry_run,
        "targets": tuple(str(target) for target in targets),
        "deleted": tuple(deleted),
    }


def _write_review_items_alias(shareable_dir: Path) -> None:
    source = shareable_dir / CASE_REVIEW_QUEUE_CSV_NAME
    target = shareable_dir / REVIEW_ITEMS_CSV_NAME
    target.write_text(source.read_text(encoding="utf-8"), encoding="utf-8")


def _require_input_dir(path: Path) -> None:
    if not path.is_dir():
        raise PilotProductError("document directory is missing: %s" % path)


def _require_input_file(path: Path) -> None:
    if not path.is_file():
        raise PilotProductError("questionnaire CSV is missing: %s" % path)


def _allowed_document_statuses() -> frozenset[str]:
    return frozenset({"parsed", "unsupported", "ocr_required", "parse_error"})


def _unique_ids(items: Sequence[Mapping[str, object]], key: str) -> bool:
    values = [str(item[key]) for item in items]
    return len(values) == len(set(values))


def _check(
    check_id: str,
    passed: bool,
    message: str,
    *,
    required: bool = True,
) -> dict[str, object]:
    return {
        "id": check_id,
        "passed": passed,
        "required": required,
        "message": message,
    }


def _shareable_outputs_are_redacted(shareable_dir: Path) -> bool:
    return not _shareable_contains_any(shareable_dir, PRIVATE_PATH_MARKERS)


def _shareable_contains_any(shareable_dir: Path, markers: Sequence[str]) -> bool:
    lowered_markers = tuple(marker.casefold() for marker in markers)
    for path in sorted(shareable_dir.rglob("*")):
        if not path.is_file():
            continue
        text = path.read_text(encoding="utf-8")[:MAX_SHAREABLE_SCAN_BYTES].casefold()
        if any(marker in text for marker in lowered_markers):
            return True
    return False


def _purge_targets(workspace_path: Path) -> list[Path]:
    names = (
        LOCAL_PRIVATE_DIR_NAME,
        SHAREABLE_REDACTED_DIR_NAME,
        PREFLIGHT_JSON_NAME,
        DOCUMENT_INVENTORY_NAME,
        DOCUMENT_SUMMARIES_NAME,
        EVIDENCE_MAP_NAME,
        QUESTIONNAIRE_DRAFT_CSV_NAME,
        CASE_REVIEW_QUEUE_CSV_NAME,
        MISSING_EVIDENCE_CSV_NAME,
        REVIEW_ITEMS_CSV_NAME,
        COVERAGE_REPORT_MD_NAME,
        COVERAGE_REPORT_HTML_NAME,
        PILOT_READINESS_REPORT_NAME,
        QUESTIONNAIRE_DRAFT_JSON_NAME,
        DEFAULT_SQLITE_NAME,
    )
    return [workspace_path / name for name in names if (workspace_path / name).exists()]


def _ensure_inside_workspace(workspace_path: Path, target: Path) -> None:
    try:
        target.resolve().relative_to(workspace_path)
    except ValueError as exc:
        raise PilotProductError("purge target escapes workspace: %s" % target) from exc


def _escape_markdown(value: str) -> str:
    return (
        value.replace("\\", "\\\\")
        .replace("`", "\\`")
        .replace("*", "\\*")
        .replace("_", "\\_")
        .replace("[", "\\[")
        .replace("]", "\\]")
        .replace("<", "\\<")
        .replace(">", "\\>")
    )


def _write_json(path: Path, payload: Mapping[str, object]) -> None:
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _to_int(value: object) -> int:
    if isinstance(value, int):
        return value
    if isinstance(value, float | str):
        return int(value)
    raise PilotProductError("expected numeric value")


def _to_float(value: object) -> float:
    if isinstance(value, int | float):
        return float(value)
    if isinstance(value, str):
        return float(value)
    raise PilotProductError("expected numeric value")


__all__ = [
    "CASE_REVIEW_QUEUE_CSV_NAME",
    "COVERAGE_REPORT_HTML_NAME",
    "COVERAGE_REPORT_MD_NAME",
    "DEFAULT_CASE_ID",
    "DEFAULT_CLIENT_ID",
    "DEFAULT_SQLITE_NAME",
    "LOCAL_PRIVATE_DIR_NAME",
    "MISSING_EVIDENCE_CSV_NAME",
    "PILOT_READINESS_REPORT_NAME",
    "QUESTIONNAIRE_DRAFT_CSV_NAME",
    "REVIEW_ITEMS_CSV_NAME",
    "SHAREABLE_REDACTED_DIR_NAME",
    "PilotProductError",
    "build_pilot_product_readiness_report",
    "inspect_workspace",
    "purge_workspace",
    "render_coverage_report_html",
    "render_coverage_report_markdown",
    "run_pilot_product_slice",
]
