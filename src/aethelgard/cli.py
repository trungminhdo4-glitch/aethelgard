"""Command line interface for AethelGard local evidence triage."""

from __future__ import annotations

import argparse
import csv
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any, Final, cast

from aethelgard import review as review_module
from aethelgard.audit import append_audit_entry, build_audit_entry
from aethelgard.control_catalog import (
    ControlCatalogError,
    build_catalog_validation_report,
    load_control_catalog_bundle,
)
from aethelgard.evidence_store import EvidenceStoreError
from aethelgard.questionnaire import QuestionnaireError, run_questionnaire
from aethelgard.redaction_preflight import (
    build_skipped_preflight_report,
    run_redaction_preflight,
    write_preflight_reports,
)
from aethelgard.review import ReviewApplyError, apply_review_csv
from aethelgard.supplier_risk import SupplierRiskError, run_supplier_risk
from aethelgard.triage import run_eval, run_triage

REVIEW_CSV_NAME: Final[str] = review_module.REVIEW_CSV_NAME
REVIEW_CSV_COLUMNS: Final[tuple[str, ...]] = review_module.REVIEW_CSV_COLUMNS
PREFLIGHT_BLOCK_EXIT_CODE: Final[int] = 3
REVIEW_APPLY_ERROR_EXIT_CODE: Final[int] = 4
C_SCRM_ERROR_EXIT_CODE: Final[int] = 5


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

    catalog_parser = subparsers.add_parser(
        "validate-controls",
        help="Validate local C-SCRM control catalogs and cross-framework mappings.",
    )
    catalog_parser.add_argument(
        "--catalog-dir",
        type=Path,
        default=None,
        help="Control catalog directory. Defaults to data/control_catalogs.",
    )

    questionnaire_parser = subparsers.add_parser(
        "questionnaire",
        help="Map security-question CSV rows to controls and draft answers from evidence.",
    )
    questionnaire_parser.add_argument("--questions", required=True, type=Path, help="Question CSV.")
    questionnaire_parser.add_argument(
        "--evidence-store",
        required=True,
        type=Path,
        help="Metadata-only evidence store JSON.",
    )
    questionnaire_parser.add_argument("--out", required=True, type=Path, help="Output directory.")
    questionnaire_parser.add_argument(
        "--catalog-dir",
        type=Path,
        default=None,
        help="Control catalog directory. Defaults to data/control_catalogs.",
    )

    supplier_parser = subparsers.add_parser(
        "supplier-risk",
        help="Score supplier risk from profile, questionnaire status, and open findings.",
    )
    supplier_parser.add_argument(
        "--profile",
        required=True,
        type=Path,
        help="Supplier profile JSON.",
    )
    supplier_parser.add_argument(
        "--questionnaire-report",
        required=True,
        type=Path,
        help="questionnaire_answers.json from the questionnaire command.",
    )
    supplier_parser.add_argument(
        "--findings-report",
        type=Path,
        default=None,
        help="Optional evidence or reviewed report JSON for open finding counts.",
    )
    supplier_parser.add_argument("--out", required=True, type=Path, help="Output directory.")
    return parser


def main(argv: list[str] | None = None) -> int:
    """Run the AethelGard CLI."""
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "triage":
        result = run_triage(args.input, args.out)
        if args.audit:
            _append_triage_audit(args.input, args.out, result)
        exit_code = int(result["summary"]["exit_code"])
    elif args.command == "eval":
        report = run_eval(args.fixtures, args.labels, args.out)
        if args.audit:
            _append_eval_audit(args.fixtures, args.out, report)
        exit_code = 0 if report["status"] == "PILOT_READY" else 2
    elif args.command == "pilot-run":
        exit_code = _run_pilot(args)
    elif args.command == "review-apply":
        exit_code = _run_review_apply(args)
    elif args.command == "validate-controls":
        exit_code = _run_validate_controls(args)
    elif args.command == "questionnaire":
        exit_code = _run_questionnaire(args)
    elif args.command == "supplier-risk":
        exit_code = _run_supplier_risk(args)
    else:
        parser.error("unknown command: %s" % args.command)
        exit_code = 1
    return exit_code


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


def _run_validate_controls(args: argparse.Namespace) -> int:
    try:
        catalog_dir = cast(Path | None, args.catalog_dir)
        bundle = (
            load_control_catalog_bundle(catalog_dir)
            if catalog_dir
            else load_control_catalog_bundle()
        )
        print(build_catalog_validation_report(bundle))
    except ControlCatalogError as exc:
        print("validate-controls failed: %s" % exc, file=sys.stderr)
        return C_SCRM_ERROR_EXIT_CODE
    return 0


def _run_questionnaire(args: argparse.Namespace) -> int:
    try:
        output_path = _resolve_output_path(cast(Path, args.out))
        catalog_dir = cast(Path | None, args.catalog_dir)
        run_questionnaire(
            cast(Path, args.questions),
            cast(Path, args.evidence_store),
            output_path,
            catalog_dir=catalog_dir,
        )
    except (ControlCatalogError, EvidenceStoreError, QuestionnaireError, ReviewApplyError) as exc:
        print("questionnaire failed: %s" % exc, file=sys.stderr)
        return C_SCRM_ERROR_EXIT_CODE
    return 0


def _run_supplier_risk(args: argparse.Namespace) -> int:
    try:
        output_path = _resolve_output_path(cast(Path, args.out))
        run_supplier_risk(
            cast(Path, args.profile),
            cast(Path, args.questionnaire_report),
            output_path,
            findings_report_path=cast(Path | None, args.findings_report),
        )
    except (SupplierRiskError, ReviewApplyError) as exc:
        print("supplier-risk failed: %s" % exc, file=sys.stderr)
        return C_SCRM_ERROR_EXIT_CODE
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
