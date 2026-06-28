"""Command line interface for AethelGard local evidence triage."""

from __future__ import annotations

import argparse
import csv
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any, Final, cast

from aethelgard.audit import append_audit_entry, build_audit_entry
from aethelgard.redaction_preflight import (
    build_skipped_preflight_report,
    run_redaction_preflight,
    write_preflight_reports,
)
from aethelgard.review import ReviewApplyError, apply_review_csv
from aethelgard.triage import run_eval, run_triage

REVIEW_CSV_NAME: Final[str] = "review_items.csv"
PREFLIGHT_BLOCK_EXIT_CODE: Final[int] = 3
REVIEW_APPLY_ERROR_EXIT_CODE: Final[int] = 4
REVIEW_CSV_COLUMNS: Final[tuple[str, ...]] = (
    "finding_id",
    "category",
    "control_area",
    "document",
    "evidence_level",
    "status",
    "finding",
    "recommended_manual_check",
    "source_reference",
    "review_status",
    "review_note",
    "reviewer",
    "reviewed_at",
)


def build_parser() -> argparse.ArgumentParser:
    """Build the top-level CLI parser."""
    parser = argparse.ArgumentParser(
        prog="python -m aethelgard.cli",
        description="Local NIS-2 evidence triage for synthetic or owner-approved documents.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    triage_parser = subparsers.add_parser("triage", help="Create evidence JSON/Markdown reports.")
    triage_parser.add_argument("--input", required=True, type=Path, help="Input file or directory.")
    triage_parser.add_argument("--out", required=True, type=Path, help="Output directory.")
    triage_parser.add_argument(
        "--audit",
        action="store_true",
        help="Append run metadata to reports/audit/aethelgard_runs.jsonl.",
    )

    eval_parser = subparsers.add_parser("eval", help="Evaluate fixtures against golden labels.")
    eval_parser.add_argument("--fixtures", required=True, type=Path, help="Fixture directory.")
    eval_parser.add_argument("--labels", required=True, type=Path, help="Golden labels JSON file.")
    eval_parser.add_argument("--out", required=True, type=Path, help="Output directory.")
    eval_parser.add_argument(
        "--audit",
        action="store_true",
        help="Append run metadata to reports/audit/aethelgard_runs.jsonl.",
    )

    pilot_parser = subparsers.add_parser(
        "pilot-run",
        help="Run preflight, triage, and review CSV export for demo/pilot preparation.",
    )
    pilot_parser.add_argument("--input", required=True, type=Path, help="Input file or directory.")
    pilot_parser.add_argument("--out", required=True, type=Path, help="Output directory.")
    pilot_parser.add_argument(
        "--audit",
        action="store_true",
        help="Append run metadata to reports/audit/aethelgard_runs.jsonl.",
    )
    pilot_parser.add_argument(
        "--fail-on-sensitive",
        action="store_true",
        help="Block medium sensitive findings such as e-mail addresses and phone numbers.",
    )
    pilot_parser.add_argument(
        "--no-preflight",
        action="store_true",
        help="Skip redaction preflight and write an explicit skipped preflight report.",
    )

    review_parser = subparsers.add_parser(
        "review-apply",
        help="Apply human review CSV data to an evidence report.",
    )
    review_parser.add_argument("--report", required=True, type=Path, help="Evidence report JSON.")
    review_parser.add_argument("--review-csv", required=True, type=Path, help="Review CSV file.")
    review_parser.add_argument("--out", required=True, type=Path, help="Output directory.")
    review_parser.add_argument(
        "--strict",
        action="store_true",
        help="Fail on unknown review statuses or unknown finding IDs.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    """Run the AethelGard CLI."""
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "triage":
        result = run_triage(args.input, args.out)
        if args.audit:
            _append_triage_audit(args.input, args.out, result)
        return int(result["summary"]["exit_code"])

    if args.command == "eval":
        report = run_eval(args.fixtures, args.labels, args.out)
        if args.audit:
            _append_eval_audit(args.fixtures, args.out, report)
        return 0 if report["status"] == "PILOT_READY" else 2

    if args.command == "pilot-run":
        return _run_pilot(args)

    if args.command == "review-apply":
        return _run_review_apply(args)

    parser.error("unknown command: %s" % args.command)
    return 1


def _run_pilot(args: argparse.Namespace) -> int:
    input_path = cast(Path, args.input)
    output_path = cast(Path, args.out)
    output_path.mkdir(parents=True, exist_ok=True)

    if bool(args.no_preflight):
        preflight_report = build_skipped_preflight_report()
    else:
        preflight_report = run_redaction_preflight(
            input_path,
            fail_on_sensitive=bool(args.fail_on_sensitive),
        )
    write_preflight_reports(output_path, preflight_report)

    if preflight_report["status"] == "block":
        return PREFLIGHT_BLOCK_EXIT_CODE

    result = run_triage(input_path, output_path)
    report = cast(dict[str, Any], result["report"])
    _write_review_items_csv(output_path / REVIEW_CSV_NAME, report)
    if args.audit:
        _append_triage_audit(input_path, output_path, result)
    return int(result["summary"]["exit_code"])


def _run_review_apply(args: argparse.Namespace) -> int:
    try:
        output_path = _resolve_output_path(cast(Path, args.out))
        apply_review_csv(
            cast(Path, args.report),
            cast(Path, args.review_csv),
            output_path,
            strict=bool(args.strict),
        )
    except ReviewApplyError as exc:
        print("review-apply failed: %s" % exc, file=sys.stderr)
        return REVIEW_APPLY_ERROR_EXIT_CODE
    return 0


def _resolve_output_path(path: Path) -> Path:
    resolved = Path(path).resolve()
    safe_base = Path.cwd().resolve()
    try:
        resolved.relative_to(safe_base)
    except ValueError as exc:
        raise ReviewApplyError("--out must stay inside the current project folder") from exc
    return resolved


def _append_triage_audit(
    input_path: Path,
    output_path: Path,
    result: dict[str, Any],
) -> None:
    report = cast(dict[str, Any], result["report"])
    entry = build_audit_entry(
        command="triage",
        input_path=input_path,
        output_path=output_path,
        document_count=int(report["document_count"]),
        parsed_count=int(report["parsed_count"]),
        failed_count=int(report["failed_count"]),
        evidence_count=int(report["evidence_count"]),
        run_id=str(report["run_id"]),
        evaluation_status=None,
        tool_version=str(report["tool_version"]),
        warnings=[str(warning) for warning in report["warnings"]],
        errors=[cast(dict[str, str], error) for error in report["errors"]],
    )
    append_audit_entry(entry)


def _append_eval_audit(
    fixtures_path: Path,
    output_path: Path,
    report: dict[str, Any],
) -> None:
    entry = build_audit_entry(
        command="eval",
        input_path=fixtures_path,
        output_path=output_path,
        document_count=int(report["document_count"]),
        parsed_count=int(report["parsed_count"]),
        failed_count=int(report["failed_count"]),
        evidence_count=int(report["evidence_count"]),
        run_id=str(report["run_id"]),
        evaluation_status=str(report["status"]),
        tool_version=str(report["tool_version"]),
        warnings=[],
        errors=[],
    )
    append_audit_entry(entry)


def _write_review_items_csv(path: Path, report: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as csv_file:
        writer = csv.DictWriter(csv_file, fieldnames=list(REVIEW_CSV_COLUMNS), lineterminator="\n")
        writer.writeheader()
        for row in _build_review_rows(report):
            writer.writerow(row)


def _build_review_rows(report: Mapping[str, Any]) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    documents = cast(Sequence[Mapping[str, Any]], report["per_document"])
    for document in documents:
        document_name = str(document["file"])
        evidence_items = cast(Sequence[Mapping[str, Any]], document["evidence"])
        for item_index, item in enumerate(evidence_items, start=1):
            category = str(item["category"])
            quality = str(item["quality"])
            signals = [str(signal) for signal in cast(Sequence[object], item["quality_signals"])]
            rows.append(
                {
                    "finding_id": str(item["finding_id"]),
                    "category": category,
                    "control_area": _humanize_category(category),
                    "document": document_name,
                    "evidence_level": quality,
                    "status": _review_status(quality),
                    "finding": str(item["source_citation"]),
                    "recommended_manual_check": str(
                        item.get(
                            "recommended_manual_check",
                            _manual_check_for_item(quality, signals),
                        )
                    ),
                    "source_reference": str(
                        item.get("source_reference", "%s#evidence-%d" % (document_name, item_index))
                    ),
                    "review_status": "",
                    "review_note": "",
                    "reviewer": "",
                    "reviewed_at": "",
                }
            )
    return rows


def _humanize_category(category: str) -> str:
    return category.replace("_", " ")


def _review_status(quality: str) -> str:
    if quality == "strong":
        return "candidate_evidence"
    if quality == "warning":
        return "warning_review"
    return "manual_review"


def _manual_check_for_item(quality: str, signals: Sequence[str]) -> str:
    if signals:
        return "Review quality signals: %s." % ", ".join(signals[:4])
    if quality == "strong":
        return "Confirm implemented control, owner, review cadence, and evidence freshness."
    return "Confirm whether this is real control evidence or only weak wording."


if __name__ == "__main__":
    raise SystemExit(main())
