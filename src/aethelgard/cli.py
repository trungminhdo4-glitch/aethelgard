"""Command line interface for AethelGard local evidence triage."""

from __future__ import annotations

import argparse
from pathlib import Path

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

    eval_parser = subparsers.add_parser("eval", help="Evaluate fixtures against golden labels.")
    eval_parser.add_argument("--fixtures", required=True, type=Path, help="Fixture directory.")
    eval_parser.add_argument("--labels", required=True, type=Path, help="Golden labels JSON file.")
    eval_parser.add_argument("--out", required=True, type=Path, help="Output directory.")
    return parser


def main(argv: list[str] | None = None) -> int:
    """Run the AethelGard CLI."""
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "triage":
        result = run_triage(args.input, args.out)
        return int(result["summary"]["exit_code"])

    if args.command == "eval":
        report = run_eval(args.fixtures, args.labels, args.out)
        return 0 if report["status"] == "PILOT_READY" else 2

    parser.error("unknown command: %s" % args.command)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
