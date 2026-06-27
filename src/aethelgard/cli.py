"""Command line interface for AethelGard local evidence triage."""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any, cast

from aethelgard.audit import append_audit_entry, build_audit_entry
from aethelgard.triage import run_eval, run_triage


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

    parser.error("unknown command: %s" % args.command)
    return 1


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


if __name__ == "__main__":
    raise SystemExit(main())
