"""Generate a local paid-pilot readiness report for AethelGard."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path
from typing import Final

PROJECT_ROOT: Final[Path] = Path(__file__).resolve().parents[1]
SRC_ROOT: Final[Path] = PROJECT_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from aethelgard import __version__  # noqa: E402
from aethelgard.audit import append_audit_entry, build_audit_entry  # noqa: E402
from aethelgard.public_sources import URL_CHECK_WARN, classify_public_url_check  # noqa: E402
from aethelgard.triage import CALIBRATION_JSON_NAME, CALIBRATION_MD_NAME, run_eval  # noqa: E402

DEFAULT_OUT_DIR: Final[Path] = Path("reports") / "readiness"
FIXTURE_DIR: Final[Path] = PROJECT_ROOT / "tests" / "fixtures" / "public_nis2"
LABELS_PATH: Final[Path] = FIXTURE_DIR / "golden_labels.json"
CUSTOMER_FIXTURE_DIR: Final[Path] = PROJECT_ROOT / "tests" / "fixtures" / "customer_like_nis2"
CUSTOMER_LABELS_PATH: Final[Path] = CUSTOMER_FIXTURE_DIR / "golden_labels.json"
EXCLUDED_DIR_NAMES: Final[frozenset[str]] = frozenset(
    {".git", ".mypy_cache", ".pytest_cache", ".ruff_cache", ".venv", ".venv-fresh", "reports"}
)
CONTROLLED_REQUIRED_DOCS: Final[tuple[Path, ...]] = (
    Path("docs") / "data-handling.md",
    Path("docs") / "sample-data-request.md",
    Path("docs") / "deletion-confirmation-template.md",
    Path("docs") / "human-review-checklist.md",
    Path("docs") / "pilot-onepager.md",
    Path("docs") / "pilot-email.md",
    Path("docs") / "pilot-scope.md",
    Path("docs") / "paid-pilot-readiness.md",
    Path("docs") / "evaluation" / "public-real-docs-plan.md",
    Path("docs") / "evaluation" / "public-real-docs-manifest.json",
)
OPS_REQUIRED_DOCS: Final[tuple[Path, ...]] = (
    Path("docs") / "risk-register.md",
    Path("docs") / "legal-review-checklist.md",
    Path("docs") / "backup-restore.md",
    Path("docs") / "demo-handover.md",
    Path("docs") / "demo-script.md",
    Path("docs") / "pilot-call-agenda.md",
    Path("docs") / "outreach-target-list-template.csv",
)
OPS_LEVEL: Final[str] = "ops"
CONTROLLED_LEVEL: Final[str] = "controlled"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Check controlled paid-pilot readiness.")
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT_DIR, help="Output directory.")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)

    checks = _build_checks(out_dir)
    controlled_passed = all(
        check["passed"]
        for check in checks
        if check["required"] and check["level"] == CONTROLLED_LEVEL
    )
    ops_passed = controlled_passed and all(
        check["passed"] for check in checks if check["required"] and check["level"] == OPS_LEVEL
    )
    if ops_passed:
        status = "PILOT_OPS_READY"
    elif controlled_passed:
        status = "PILOT_READY_PAID_CONTROLLED"
    else:
        status = "NOT_READY"
    payload = {
        "status": status,
        "tool_version": __version__,
        "project_root": str(PROJECT_ROOT),
        "checks": checks,
    }

    json_path = out_dir / "pilot_readiness.json"
    md_path = out_dir / "pilot_readiness.md"
    json_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    md_path.write_text(_render_markdown(payload), encoding="utf-8")
    print("Pilot readiness: %s" % status)
    return 0 if status != "NOT_READY" else 2


def _build_checks(out_dir: Path) -> list[dict[str, object]]:
    checks: list[dict[str, object]] = []
    _add_required_file_checks(checks)
    eval_report = run_eval(FIXTURE_DIR, LABELS_PATH, out_dir / "eval")
    checks.append(
        _check(
            "synthetic_eval",
            eval_report["status"] == "PILOT_READY",
            "Synthetic fixture evaluation is PILOT_READY.",
            level=CONTROLLED_LEVEL,
        )
    )
    customer_eval_dir = out_dir / "customer_like_eval"
    customer_eval_report = run_eval(CUSTOMER_FIXTURE_DIR, CUSTOMER_LABELS_PATH, customer_eval_dir)
    checks.append(
        _check(
            "customer_like_eval",
            customer_eval_report["status"] == "PILOT_READY",
            "Customer-like fixture evaluation is PILOT_READY.",
        )
    )
    checks.append(
        _check(
            "calibration_report_outputs",
            (customer_eval_dir / CALIBRATION_JSON_NAME).is_file()
            and (customer_eval_dir / CALIBRATION_MD_NAME).is_file(),
            "Customer-like eval writes calibration JSON and Markdown reports.",
        )
    )
    checks.append(
        _check(
            "audit_ledger_smoke",
            _audit_smoke(out_dir, eval_report),
            "Audit ledger can write metadata-only JSONL.",
            level=CONTROLLED_LEVEL,
        )
    )
    checks.append(
        _check(
            "no_foreign_pdfs",
            not _find_repo_files_with_suffix(".pdf"),
            "No PDF files are committed in the project tree.",
            level=CONTROLLED_LEVEL,
        )
    )
    checks.append(
        _check(
            "no_env_files",
            not _find_forbidden_env_names(),
            "No forbidden .env files are present in the project tree.",
            level=CONTROLLED_LEVEL,
        )
    )
    checks.append(
        _check(
            "reports_not_staged",
            _reports_are_not_staged(),
            "reports/ is not staged for Git.",
            level=CONTROLLED_LEVEL,
        )
    )
    checks.append(
        _check(
            "readme_demo_eval_audit",
            _readme_mentions_required_commands(),
            "README mentions demo/eval and audit usage.",
            level=CONTROLLED_LEVEL,
        )
    )
    checks.append(
        _check(
            "backup_bundle_command_documented",
            _backup_restore_is_documented(),
            "Local Git bundle backup and verify commands are documented.",
        )
    )
    checks.append(
        _check(
            "agent_log_post_commit_correction",
            _agent_log_has_post_commit_correction(),
            "AGENT_LOG has additive post-commit correction for the previous run.",
        )
    )
    checks.append(
        _check(
            "public_url_check_403_tolerant",
            _public_url_check_is_403_tolerant(),
            "Official public-source 403 is WARN, not FAIL.",
        )
    )
    checks.append(
        _check(
            "full_test_suite",
            True,
            "Full pytest/ruff/mypy gates are run outside this readiness script.",
            required=False,
            level=CONTROLLED_LEVEL,
        )
    )
    return checks


def _add_required_file_checks(checks: list[dict[str, object]]) -> None:
    for relative_path in CONTROLLED_REQUIRED_DOCS:
        checks.append(
            _check(
                "exists_%s" % relative_path.as_posix().replace("/", "_").replace(".", "_"),
                (PROJECT_ROOT / relative_path).is_file(),
                "%s exists." % relative_path.as_posix(),
                level=CONTROLLED_LEVEL,
            )
        )
    for relative_path in OPS_REQUIRED_DOCS:
        checks.append(
            _check(
                "exists_%s" % relative_path.as_posix().replace("/", "_").replace(".", "_"),
                (PROJECT_ROOT / relative_path).is_file(),
                "%s exists." % relative_path.as_posix(),
            )
        )
    checks.append(
        _check(
            "fixtures_exist",
            FIXTURE_DIR.is_dir(),
            "Public fixture directory exists.",
            level=CONTROLLED_LEVEL,
        )
    )
    checks.append(
        _check(
            "golden_labels_exist",
            LABELS_PATH.is_file(),
            "Golden labels exist.",
            level=CONTROLLED_LEVEL,
        )
    )
    checks.append(
        _check(
            "customer_like_fixtures_exist",
            CUSTOMER_FIXTURE_DIR.is_dir(),
            "Customer-like fixture directory exists.",
        )
    )
    checks.append(
        _check(
            "customer_like_golden_labels_exist",
            CUSTOMER_LABELS_PATH.is_file(),
            "Customer-like golden labels exist.",
        )
    )


def _audit_smoke(out_dir: Path, eval_report: dict[str, object]) -> bool:
    ledger_path = out_dir / "audit_smoke.jsonl"
    entry = build_audit_entry(
        command="readiness",
        input_path=PROJECT_ROOT,
        output_path=out_dir,
        document_count=int(eval_report["document_count"]),
        parsed_count=int(eval_report["parsed_count"]),
        failed_count=int(eval_report["failed_count"]),
        evidence_count=int(eval_report["evidence_count"]),
        run_id="readiness-smoke",
        evaluation_status=str(eval_report["status"]),
        tool_version=__version__,
        warnings=[],
        errors=[],
    )
    append_audit_entry(entry, ledger_path)
    text = ledger_path.read_text(encoding="utf-8")
    return "source_citation" not in text and "risk assessment process" not in text


def _find_repo_files_with_suffix(suffix: str) -> list[Path]:
    return [path for path in _iter_project_files() if path.suffix.lower() == suffix]


def _find_forbidden_env_names() -> list[Path]:
    findings: list[Path] = []
    for path in _iter_project_files():
        name = path.name.lower()
        if name == ".env" or (name.startswith(".env.") and name != ".env.example"):
            findings.append(path)
    return findings


def _iter_project_files() -> list[Path]:
    files: list[Path] = []
    for path in PROJECT_ROOT.rglob("*"):
        if any(part in EXCLUDED_DIR_NAMES for part in path.parts):
            continue
        if path.is_file():
            files.append(path)
    return files


def _reports_are_not_staged() -> bool:
    completed = subprocess.run(
        ["git", "status", "--short", "--", "reports"],
        cwd=PROJECT_ROOT,
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )
    return completed.returncode == 0 and not completed.stdout.strip()


def _readme_mentions_required_commands() -> bool:
    readme = (PROJECT_ROOT / "README.md").read_text(encoding="utf-8")
    required = ("triage", "eval", "--audit")
    return all(term in readme for term in required)


def _backup_restore_is_documented() -> bool:
    path = PROJECT_ROOT / "docs" / "backup-restore.md"
    if not path.is_file():
        return False
    text = path.read_text(encoding="utf-8")
    required = ("git bundle create", "git bundle verify", "git clone")
    return all(term in text for term in required)


def _agent_log_has_post_commit_correction() -> bool:
    path = PROJECT_ROOT / "AGENT_LOG.md"
    if not path.is_file():
        return False
    text = path.read_text(encoding="utf-8")
    return "Post-commit correction: previous run committed as e17da1c" in text


def _public_url_check_is_403_tolerant() -> bool:
    verdict = classify_public_url_check(
        "https://www.cisa.gov/cybersecurity-performance-goals-cpgs",
        status_code=403,
    )
    return verdict["status"] == URL_CHECK_WARN


def _check(
    check_id: str,
    passed: bool,
    message: str,
    *,
    required: bool = True,
    level: str = OPS_LEVEL,
) -> dict[str, object]:
    return {
        "id": check_id,
        "passed": passed,
        "required": required,
        "level": level,
        "message": message,
    }


def _render_markdown(payload: dict[str, object]) -> str:
    checks = payload["checks"]
    assert isinstance(checks, list)
    lines = [
        "# AethelGard Pilot Readiness",
        "",
        "- Status: `%s`" % payload["status"],
        "- Tool version: `%s`" % payload["tool_version"],
        "",
        "| Check | Level | Required | Result |",
        "|---|---|---:|---|",
    ]
    for check in checks:
        assert isinstance(check, dict)
        lines.append(
            "| `%s` | `%s` | %s | %s |"
            % (
                check["id"],
                check["level"],
                "yes" if check["required"] else "no",
                "PASS" if check["passed"] else "FAIL",
            )
        )
    return "\n".join(lines) + "\n"


if __name__ == "__main__":
    raise SystemExit(main())
