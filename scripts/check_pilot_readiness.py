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
SCRIPTS_ROOT: Final[Path] = PROJECT_ROOT / "scripts"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))
if str(SCRIPTS_ROOT) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_ROOT))

from check_docker_delivery import build_report as build_docker_delivery_report  # noqa: E402

from aethelgard import __version__  # noqa: E402
from aethelgard.audit import append_audit_entry, build_audit_entry  # noqa: E402
from aethelgard.public_data import (  # noqa: E402
    PUBLIC_DATA_MARKER,
    PUBLIC_DATA_READY_STATUS,
    PublicDataError,
    validate_public_data_manifest,
)
from aethelgard.public_sources import URL_CHECK_WARN, classify_public_url_check  # noqa: E402
from aethelgard.triage import CALIBRATION_JSON_NAME, CALIBRATION_MD_NAME, run_eval  # noqa: E402

DEFAULT_OUT_DIR: Final[Path] = Path("reports") / "readiness"
FIXTURE_DIR: Final[Path] = PROJECT_ROOT / "tests" / "fixtures" / "public_nis2"
LABELS_PATH: Final[Path] = FIXTURE_DIR / "golden_labels.json"
CUSTOMER_FIXTURE_DIR: Final[Path] = PROJECT_ROOT / "tests" / "fixtures" / "customer_like_nis2"
CUSTOMER_LABELS_PATH: Final[Path] = CUSTOMER_FIXTURE_DIR / "golden_labels.json"
PUBLIC_DATA_MANIFEST: Final[Path] = (
    PROJECT_ROOT / "examples" / "public" / "public_data_manifest.json"
)
DOCKER_RUNTIME_PROOF_NAME: Final[str] = "docker_runtime_proof.json"
DOCKER_ML_RUNTIME_PROOF_NAME: Final[str] = "docker_ml_runtime_proof.json"
EXCLUDED_DIR_NAMES: Final[frozenset[str]] = frozenset(
    {
        ".git",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        ".tmp",
        ".venv",
        ".venv-fresh",
        "reports",
    }
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
    Path("docs") / "pilot-outreach-readiness.md",
    Path("docs") / "pilot_support.md",
    Path("docs") / "outreach-target-list-template.csv",
)
OPS_LEVEL: Final[str] = "ops"
CONTROLLED_LEVEL: Final[str] = "controlled"
DOCKER_LEVEL: Final[str] = "docker"
PUBLIC_DATA_LEVEL: Final[str] = "public_data"


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
    docker_static_passed = ops_passed and all(
        check["passed"] for check in checks if check["required"] and check["level"] == DOCKER_LEVEL
    )
    docker_runtime_passed = docker_static_passed and any(
        check["id"] == "docker_runtime_verified" and check["passed"] for check in checks
    )
    docker_ml_runtime_passed = docker_static_passed and any(
        check["id"] == "docker_ml_runtime_verified" and check["passed"] for check in checks
    )
    public_data_passed = all(
        check["passed"]
        for check in checks
        if check["required"] and check["level"] == PUBLIC_DATA_LEVEL
    )
    if docker_runtime_passed and docker_ml_runtime_passed and public_data_passed:
        status = "PILOT_PUBLIC_DATA_READY"
    elif docker_runtime_passed and docker_ml_runtime_passed:
        status = "PILOT_DOCKER_RUNTIME_READY"
    elif docker_runtime_passed:
        status = "PILOT_DOCKER_RUNTIME_READY_ML_UNVERIFIED"
    elif docker_static_passed:
        status = "PILOT_DOCKER_STATIC_READY_RUNTIME_UNVERIFIED"
    elif ops_passed:
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
            "review_metadata_safety_tests_present",
            _test_file_mentions(
                Path("tests") / "test_review_workflow.py",
                (
                    "test_review_apply_sanitizes_reviewer_metadata",
                    "test_review_apply_rejects_free_text_reviewed_at",
                ),
            ),
            "Review metadata sanitization regressions are present.",
        )
    )
    checks.append(
        _check(
            "pilot_full_local_flow_test_present",
            _test_file_mentions(
                Path("tests") / "test_pilot_full_local_flow.py",
                ("test_demo_pilot_cli_builds_full_metadata_only_flow",),
            ),
            "Full synthetic pilot flow regression is present.",
        )
    )
    checks.append(
        _check(
            "pilot_demo_examples_present",
            _pilot_demo_examples_present(),
            "Synthetic examples/pilot demo pack is present.",
        )
    )
    checks.append(
        _check(
            "pilot_product_sample_pack_present",
            _pilot_product_sample_pack_present(),
            "Pilot product slice sample pack includes documents, questionnaire, and answers.",
        )
    )
    checks.append(
        _check(
            "pilot_product_cli_present",
            _path_contains(
                PROJECT_ROOT / "src" / "aethelgard" / "cli.py",
                (
                    "pilot-product",
                    "answer-vault",
                    "document-ingest",
                    "workspace",
                ),
            ),
            "CLI exposes product-slice, answer-vault, document-ingest, and workspace commands.",
        )
    )
    checks.append(
        _check(
            "pilot_product_tests_present",
            _test_file_mentions(
                Path("tests") / "test_pilot_product_slice.py",
                ("test_pilot_product_cli_builds_answer_vault_and_review_outputs",),
            ),
            "Integrated pilot-product slice regression test is present.",
        )
    )
    checks.append(
        _check(
            "diagnostics_cli_present",
            _path_contains(
                PROJECT_ROOT / "src" / "aethelgard" / "cli.py",
                (
                    "doctor",
                    "support-bundle",
                    "--debug",
                ),
            ),
            "CLI exposes doctor, support-bundle, and debug logging switches.",
        )
    )
    checks.append(
        _check(
            "diagnostics_error_taxonomy_present",
            _path_contains(
                PROJECT_ROOT / "src" / "aethelgard" / "errors.py",
                (
                    "DOC_PARSE_FAILED",
                    "PRIVACY_GUARD_BLOCKED",
                    "INTERNAL_ERROR",
                    "ERROR_EXIT_CODES",
                ),
            ),
            "Stable diagnostics error taxonomy and exit-code mapping are present.",
        )
    )
    checks.append(
        _check(
            "support_bundle_redaction_tests_present",
            _test_file_mentions(
                Path("tests") / "test_support_bundle.py",
                (
                    "test_support_bundle_zip_excludes_private_outputs",
                    "test_support_bundle_privacy_guard_blocks_forbidden_summary",
                ),
            ),
            "Support bundle privacy regression tests are present.",
        )
    )
    checks.append(
        _check(
            "doctor_debug_logging_tests_present",
            _test_file_mentions(
                Path("tests") / "test_diagnostics.py",
                (
                    "test_doctor_creates_json_and_markdown_without_raw_content",
                    "run_debug.jsonl",
                    "run_summary.jsonl",
                ),
            ),
            "Doctor and debug logging regression tests are present.",
        )
    )
    checks.append(
        _check(
            "pilot_support_docs_present",
            _path_contains(
                PROJECT_ROOT / "docs" / "pilot_support.md",
                (
                    "doctor",
                    "support-bundle",
                    "--debug",
                    "Human Review",
                ),
            ),
            "Pilot support documentation explains doctor, bundles, debug, and review gates.",
        )
    )
    checks.append(
        _check(
            "answer_vault_tests_present",
            _test_file_mentions(
                Path("tests") / "test_answer_vault.py",
                ("test_answer_vault_init_is_idempotent_and_seeds_schema",),
            ),
            "SQLite answer-vault regression tests are present.",
        )
    )
    checks.append(
        _check(
            "generated_sqlite_outputs_ignored",
            _gitignore_mentions_generated_private_outputs(),
            ".gitignore excludes generated SQLite and private/shareable output folders.",
        )
    )
    checks.append(
        _check(
            "public_data_manifest_present",
            (PROJECT_ROOT / "examples" / "pilot" / "public_data_manifest.json").is_file(),
            "Public-data decision manifest is present and offline.",
        )
    )
    checks.append(
        _check(
            "real_public_data_manifest_present",
            PUBLIC_DATA_MANIFEST.is_file(),
            "Real public-data fixture manifest is present and offline.",
            level=PUBLIC_DATA_LEVEL,
        )
    )
    checks.append(
        _check(
            "real_public_data_validation",
            _public_data_validation_is_ready(),
            "CISA KEV and CycloneDX public fixtures validate by local hash and schema.",
            level=PUBLIC_DATA_LEVEL,
        )
    )
    checks.append(
        _check(
            "public_data_cli_test_present",
            _test_file_mentions(
                Path("tests") / "test_public_data_workflow.py",
                ("test_public_data_validate_cli_writes_metadata_only_report",),
            ),
            "Public-data CLI regression test is present.",
            level=PUBLIC_DATA_LEVEL,
        )
    )
    checks.append(
        _check(
            "docker_static_delivery",
            _docker_static_delivery_is_ready(),
            "Dockerfile, compose, .dockerignore, and static Docker delivery gates pass.",
            level=DOCKER_LEVEL,
        )
    )
    checks.append(
        _check(
            "docker_smoke_script_present",
            (PROJECT_ROOT / "scripts" / "docker_smoke.ps1").is_file(),
            "Opt-in Docker runtime smoke script is present.",
            level=DOCKER_LEVEL,
        )
    )
    checks.append(
        _check(
            "docker_ml_smoke_script_present",
            _docker_ml_smoke_script_is_present(),
            "Opt-in Docker ML runtime smoke script is present and covers ML commands.",
            level=DOCKER_LEVEL,
        )
    )
    checks.append(
        _check(
            "readme_docker_quickstart",
            _readme_mentions_docker_quickstart(),
            "README documents local consultant Docker quickstart.",
            level=DOCKER_LEVEL,
        )
    )
    checks.append(
        _check(
            "readme_docker_ml_smoke",
            _readme_mentions_docker_ml_smoke(),
            "README documents Docker ML smoke for post-ML delivery proof.",
            level=DOCKER_LEVEL,
        )
    )
    checks.append(
        _check(
            "docker_runtime_verified",
            _docker_runtime_is_verified(out_dir / DOCKER_RUNTIME_PROOF_NAME),
            "Docker runtime proof is written by scripts/docker_smoke.ps1.",
            required=False,
            level=DOCKER_LEVEL,
        )
    )
    checks.append(
        _check(
            "docker_ml_runtime_verified",
            _docker_ml_runtime_is_verified(out_dir / DOCKER_ML_RUNTIME_PROOF_NAME),
            "Docker ML runtime proof is written by scripts/docker_ml_smoke.ps1.",
            required=False,
            level=DOCKER_LEVEL,
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


def _test_file_mentions(relative_path: Path, expected_terms: tuple[str, ...]) -> bool:
    path = PROJECT_ROOT / relative_path
    if not path.is_file():
        return False
    text = path.read_text(encoding="utf-8")
    return all(term in text for term in expected_terms)


def _pilot_demo_examples_present() -> bool:
    base = PROJECT_ROOT / "examples" / "pilot"
    required = (
        base / "documents" / "supplier_security_annex.md",
        base / "documents" / "incident_response_playbook.md",
        base / "documents" / "continuity_and_access.md",
        base / "questionnaire_demo.csv",
        base / "supplier_profile_demo.json",
        base / "supplier_profile_contract_demo.json",
        base / "sbom" / "cyclonedx_demo.json",
    )
    return all(path.is_file() for path in required)


def _pilot_product_sample_pack_present() -> bool:
    base = PROJECT_ROOT / "examples" / "pilot"
    required = (
        base / "documents" / "supplier_security_annex.md",
        base / "documents" / "incident_response_playbook.md",
        base / "documents" / "continuity_and_access.md",
        base / "questionnaire_demo.csv",
        base / "answer_library_demo.json",
    )
    return all(path.is_file() for path in required)


def _gitignore_mentions_generated_private_outputs() -> bool:
    return _path_contains(
        PROJECT_ROOT / ".gitignore",
        (
            "*.sqlite",
            "*.sqlite3",
            "local_private/",
            "shareable_redacted/",
        ),
    )


def _public_data_validation_is_ready() -> bool:
    try:
        report = validate_public_data_manifest(PUBLIC_DATA_MANIFEST)
    except PublicDataError:
        return False
    return (
        report["status"] == PUBLIC_DATA_READY_STATUS
        and report["public_data_marker"] == PUBLIC_DATA_MARKER
        and int(report["source_count"]) >= 2
    )


def _docker_static_delivery_is_ready() -> bool:
    return build_docker_delivery_report()["status"] == "DOCKER_STATIC_READY"


def _docker_runtime_is_verified(proof_path: Path) -> bool:
    if not proof_path.is_file():
        return False
    try:
        payload = json.loads(proof_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return False
    if not isinstance(payload, dict):
        return False
    return (
        payload.get("status") == "DOCKER_RUNTIME_READY"
        and payload.get("help") == "pass"
        and payload.get("demo_pilot") == "pass"
        and payload.get("network_none_demo") is True
        and payload.get("output_mount") == "pass"
    )


def _docker_ml_runtime_is_verified(proof_path: Path) -> bool:
    if not proof_path.is_file():
        return False
    try:
        payload = json.loads(proof_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return False
    if not isinstance(payload, dict):
        return False
    return (
        payload.get("status") == "DOCKER_ML_RUNTIME_READY"
        and payload.get("help") == "pass"
        and payload.get("ml_help") == "pass"
        and payload.get("features") == "pass"
        and payload.get("search") == "pass"
        and payload.get("dedupe") == "pass"
        and payload.get("weak_labels") == "pass"
        and payload.get("train_baselines") == "pass"
        and payload.get("classify_docs") == "pass"
        and payload.get("suggest_controls") == "pass"
        and payload.get("rank_findings") == "pass"
        and payload.get("active_review") == "pass"
        and payload.get("network_none_ml") is True
        and payload.get("output_mount") == "pass"
        and payload.get("safety_scan") == "pass"
    )


def _docker_ml_smoke_script_is_present() -> bool:
    return _path_contains(
        PROJECT_ROOT / "scripts" / "docker_ml_smoke.ps1",
        (
            "docker build -t $Image .",
            "docker run --rm --network none $Image ml --help",
            "ml\", \"features",
            "ml\", \"active-review",
            "Assert-CleanMlOutput",
            "DOCKER_ML_RUNTIME_READY",
        ),
    )


def _readme_mentions_docker_quickstart() -> bool:
    readme = (PROJECT_ROOT / "README.md").read_text(encoding="utf-8")
    required = (
        "Consultant Laptop Delivery",
        "No VM is required",
        "docker build -t aethelgard:local .",
        "docker compose run --rm aethelgard demo-pilot",
        "public-data validate",
    )
    return all(term in readme for term in required)


def _readme_mentions_docker_ml_smoke() -> bool:
    readme = (PROJECT_ROOT / "README.md").read_text(encoding="utf-8")
    required = (
        "Docker ML smoke",
        ".\\scripts\\docker_ml_smoke.ps1",
        "ml features",
        "ml active-review",
    )
    return all(term in readme for term in required)


def _path_contains(path: Path, markers: tuple[str, ...]) -> bool:
    if not path.is_file():
        return False
    text = path.read_text(encoding="utf-8")
    return all(marker in text for marker in markers)


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
