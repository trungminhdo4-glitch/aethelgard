"""Local diagnostics, redacted support bundles, and structured run logs."""

from __future__ import annotations

import contextlib
import importlib.util
import json
import platform
import re
import shutil
import sqlite3
import subprocess
import sys
import uuid
import zipfile
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Final, Literal, cast

from aethelgard import __version__
from aethelgard.document_ingest import (
    EXCLUDED_DIR_NAMES,
    chunk_document_text,
    detect_document_type,
)
from aethelgard.errors import AethelgardDiagnosticError, ErrorCode, ErrorSeverity
from aethelgard.mvp1.pdf_handler import is_pypdf_available
from aethelgard.redaction_preflight import mask_sensitive_text

DOCTOR_JSON_NAME: Final[str] = "doctor_report.json"
DOCTOR_MD_NAME: Final[str] = "doctor_report.md"
RUN_DEBUG_JSONL_NAME: Final[str] = "run_debug.jsonl"
RUN_SUMMARY_JSONL_NAME: Final[str] = "run_summary.jsonl"
README_SUPPORT_NAME: Final[str] = "README_SUPPORT.md"
DOCUMENT_INVENTORY_REDACTED_NAME: Final[str] = "document_inventory_redacted.json"
DEPENDENCY_REPORT_NAME: Final[str] = "dependency_report.json"
COMMAND_INFO_NAME: Final[str] = "command_info.json"
ERROR_REPORT_NAME: Final[str] = "error_report.json"
PILOT_READINESS_REPORT_NAME: Final[str] = "pilot_readiness_report.json"
LOCAL_PRIVATE_DIR_NAME: Final[str] = "local_private"
SHAREABLE_REDACTED_DIR_NAME: Final[str] = "shareable_redacted"

_PROJECT_ROOT: Final[Path] = Path(__file__).resolve().parents[2]

GIT_COMMAND_TIMEOUT_SECONDS: Final[int] = 5
MAX_LOG_MESSAGE_CHARS: Final[int] = 400
MAX_TECHNICAL_DETAIL_CHARS: Final[int] = 4_000
MAX_SUPPORT_FILE_BYTES: Final[int] = 500_000
MAX_INVENTORY_FILES: Final[int] = 500
STAGING_ID_CHARS: Final[int] = 12

DoctorStatus = Literal["OK", "WARN", "FAIL"]

ALLOWED_SUPPORT_FILES: Final[frozenset[str]] = frozenset(
    {
        DOCTOR_JSON_NAME,
        DOCTOR_MD_NAME,
        RUN_SUMMARY_JSONL_NAME,
        PILOT_READINESS_REPORT_NAME,
        DOCUMENT_INVENTORY_REDACTED_NAME,
        ERROR_REPORT_NAME,
        DEPENDENCY_REPORT_NAME,
        COMMAND_INFO_NAME,
        README_SUPPORT_NAME,
    }
)
FORBIDDEN_SUPPORT_SUFFIXES: Final[frozenset[str]] = frozenset(
    {
        ".db",
        ".doc",
        ".docx",
        ".env",
        ".jpeg",
        ".jpg",
        ".log",
        ".pdf",
        ".png",
        ".sqlite",
        ".sqlite3",
        ".txt",
        ".xls",
        ".xlsx",
    }
)
FORBIDDEN_SUPPORT_MARKERS: Final[tuple[str, ...]] = (
    ".env",
    "c:/users",
    "c:\\users",
    "api_key",
    "apikey",
    "authorization",
    "bearer ",
    "cookie",
    "local_private",
    "password=",
    "password:",
    "private key",
    "secret=",
    "secret:",
    "token=",
    "token:",
)
SUPPORT_EMAIL_PATTERN: Final[re.Pattern[str]] = re.compile(
    r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b",
    re.IGNORECASE,
)
SUPPORT_SECRET_ASSIGNMENT_PATTERN: Final[re.Pattern[str]] = re.compile(
    r"\b(api[_-]?key|authorization|cookie|password|secret|token)\b\s*[:=]",
    re.IGNORECASE,
)
SUPPORT_TOKEN_VALUE_PATTERN: Final[re.Pattern[str]] = re.compile(
    r"\b(?:ghp|github_pat|glpat|sk|xox[baprs])[-_][A-Za-z0-9_=-]{12,}\b",
    re.IGNORECASE,
)


class DiagnosticLogWriter:
    """Write local-private and redacted-shareable JSONL records for one CLI run."""

    def __init__(
        self,
        out_dir: Path | str,
        *,
        command: str,
        debug: bool = False,
        run_id: str | None = None,
    ) -> None:
        self.out_dir = Path(out_dir)
        self.command = command
        self.debug = debug
        self.run_id = run_id or uuid.uuid4().hex
        self.local_private_dir = self.out_dir / LOCAL_PRIVATE_DIR_NAME
        self.shareable_redacted_dir = self.out_dir / SHAREABLE_REDACTED_DIR_NAME
        self.local_private_dir.mkdir(parents=True, exist_ok=True)
        self.shareable_redacted_dir.mkdir(parents=True, exist_ok=True)
        self.local_debug_path = self.local_private_dir / RUN_DEBUG_JSONL_NAME
        self.shareable_summary_path = self.shareable_redacted_dir / RUN_SUMMARY_JSONL_NAME

    def write_event(
        self,
        *,
        phase: str,
        event: str,
        severity: ErrorSeverity = "info",
        message: str,
        error_code: ErrorCode | None = None,
        document_id: str | None = None,
        safe_to_share: bool = True,
        technical_detail: str = "",
        stacktrace: str = "",
    ) -> None:
        """Append a local-private record and a redacted shareable summary record."""
        base_record = {
            "run_id": self.run_id,
            "timestamp": _utc_now(),
            "command": self.command,
            "phase": phase,
            "event": event,
            "severity": severity,
            "error_code": error_code.value if error_code is not None else None,
            "document_id": document_id,
            "safe_to_share": safe_to_share,
            "message": _bounded_text(message, MAX_LOG_MESSAGE_CHARS),
        }
        local_record = dict(base_record)
        if technical_detail:
            local_record["technical_detail"] = _bounded_text(
                technical_detail,
                MAX_TECHNICAL_DETAIL_CHARS,
            )
        if stacktrace and self.debug:
            local_record["stacktrace"] = _bounded_text(stacktrace, MAX_TECHNICAL_DETAIL_CHARS)
        shareable_record = {
            **base_record,
            "message": _redacted_message(message),
        }
        _append_jsonl(self.local_debug_path, local_record)
        _append_jsonl(self.shareable_summary_path, shareable_record)

    def write_error(
        self,
        error: AethelgardDiagnosticError,
        *,
        event: str = "failed",
        stacktrace: str = "",
    ) -> None:
        """Append a diagnostic error using the local/shareable split."""
        self.write_event(
            phase=error.phase,
            event=event,
            severity=error.severity,
            message=error.safe_message,
            error_code=error.error_code,
            safe_to_share=error.safe_to_share,
            technical_detail=error.technical_detail,
            stacktrace=stacktrace,
        )


def run_doctor(workspace: Path | str, out_dir: Path | str) -> dict[str, object]:
    """Run passive local diagnostics without reading raw customer document content."""
    workspace_path = Path(workspace)
    output_path = Path(out_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    checks = [
        _doctor_check(
            "python_version",
            "OK" if sys.version_info >= (3, 11) else "FAIL",
            "Python 3.11+ is available.",
            details={"version": platform.python_version()},
        ),
        _doctor_check(
            "platform",
            "OK",
            "OS/platform detected locally.",
            required=False,
            details={"platform": platform.platform()},
        ),
        _doctor_check(
            "aethelgard_package_import",
            "OK" if importlib.util.find_spec("aethelgard") is not None else "FAIL",
            "aethelgard package import is available.",
        ),
        _doctor_check(
            "aethelgard_cli_import",
            "OK" if importlib.util.find_spec("aethelgard.cli") is not None else "FAIL",
            "CLI module is importable.",
        ),
        _doctor_check(
            "workspace_exists",
            "OK" if workspace_path.exists() else "FAIL",
            "Workspace path exists.",
            details={"workspace": _project_label(workspace_path)},
        ),
        _doctor_check(
            "output_dir_writable",
            "OK" if _output_dir_is_writable(output_path) else "FAIL",
            "Output directory is writable.",
            details={"out": _project_label(output_path)},
        ),
        _doctor_check(
            "pilot_workspace_structure",
            "OK" if _workspace_structure_is_ready(workspace_path) else "FAIL",
            "Workspace has pilot input structure or generated shareable output structure.",
        ),
        _doctor_check(
            "sqlite_available",
            "OK" if _sqlite_available() else "FAIL",
            "SQLite is available for the local answer vault.",
        ),
        _doctor_check(
            "document_parser_basic",
            "OK" if _document_parser_basic_capability() else "FAIL",
            "Document parser can chunk a synthetic local string.",
        ),
        _doctor_check(
            "pdf_support",
            "OK" if is_pypdf_available() else "WARN",
            "Optional PDF support status detected.",
            required=False,
        ),
        _doctor_check(
            "docx_support",
            "OK",
            "DOCX support uses stdlib ZIP/XML parsing.",
            required=False,
        ),
        _doctor_check(
            "docker_passive_detection",
            "OK" if shutil.which("docker") else "WARN",
            "Docker executable passively detected without running Docker.",
            required=False,
        ),
        _doctor_check(
            "readiness_script_present",
            "OK" if (_PROJECT_ROOT / "scripts" / "check_pilot_readiness.py").is_file() else "FAIL",
            "Pilot readiness script is present.",
        ),
        _doctor_check(
            "marketing_claim_check_present",
            "OK" if (_PROJECT_ROOT / "scripts" / "check_marketing_claims.py").is_file() else "FAIL",
            "Marketing claim check is present.",
        ),
        _doctor_check(
            "pilot_product_command_can_be_formed",
            "OK",
            "pilot-product command can be formed for the workspace.",
            details={
                "command": (
                    "python -m aethelgard.cli pilot-product --workspace %s "
                    "--out reports/pilot-product-demo --debug"
                )
                % _project_label(workspace_path)
            },
        ),
    ]
    payload: dict[str, object] = {
        "status": _overall_doctor_status(checks),
        "tool_version": __version__,
        "git_commit": git_commit(),
        "generated_at": _utc_now(),
        "workspace": _project_label(workspace_path),
        "checks": checks,
        "document_inventory_redacted": build_redacted_document_inventory(workspace_path),
    }
    _write_json(output_path / DOCTOR_JSON_NAME, payload)
    (output_path / DOCTOR_MD_NAME).write_text(render_doctor_markdown(payload), encoding="utf-8")
    return payload


def build_support_bundle(
    workspace: Path | str,
    out_zip: Path | str,
    *,
    redacted: bool = True,
) -> dict[str, object]:
    """Build a redacted support ZIP without private logs, DBs, or raw documents."""
    if not redacted:
        raise AethelgardDiagnosticError(
            error_code=ErrorCode.PRIVACY_GUARD_BLOCKED,
            severity="critical",
            phase="support_bundle",
            safe_message="Private support bundles are not implemented.",
            technical_detail="support-bundle was called without redacted=True",
            remediation_hint=(
                "Run again with redacted outputs only or inspect local_private manually."
            ),
            safe_to_share=True,
        )

    workspace_path = Path(workspace)
    output_path = Path(out_zip)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    staging_dir = _staging_dir(output_path)
    staging_dir.mkdir(parents=True)
    try:
        doctor_dir = staging_dir / "doctor"
        run_doctor(workspace_path, doctor_dir)
        shutil.copyfile(doctor_dir / DOCTOR_JSON_NAME, staging_dir / DOCTOR_JSON_NAME)
        shutil.copyfile(doctor_dir / DOCTOR_MD_NAME, staging_dir / DOCTOR_MD_NAME)
        shutil.rmtree(doctor_dir)
        _write_run_summary(workspace_path, staging_dir)
        _copy_optional_shareable(
            workspace_path,
            PILOT_READINESS_REPORT_NAME,
            staging_dir / PILOT_READINESS_REPORT_NAME,
        )
        _write_json(
            staging_dir / DOCUMENT_INVENTORY_REDACTED_NAME,
            build_redacted_document_inventory(workspace_path),
        )
        _write_error_report(workspace_path, staging_dir / ERROR_REPORT_NAME)
        _write_json(staging_dir / DEPENDENCY_REPORT_NAME, build_dependency_report())
        _write_json(
            staging_dir / COMMAND_INFO_NAME,
            {
                "schema_version": "1.0",
                "tool_version": __version__,
                "generated_at": _utc_now(),
                "command": "support-bundle",
                "workspace": _project_label(workspace_path),
                "redacted": True,
                "safe_to_share": True,
            },
        )
        (staging_dir / README_SUPPORT_NAME).write_text(render_support_readme(), encoding="utf-8")
        validate_support_bundle_staging(staging_dir)
        _write_zip_from_staging(staging_dir, output_path)
    finally:
        _cleanup_staging(staging_dir)

    return {
        "status": "SUPPORT_BUNDLE_READY",
        "bundle": _project_label(output_path),
        "redacted": True,
        "safe_to_share": True,
    }


def validate_support_bundle_staging(staging_dir: Path | str) -> None:
    """Fail closed if a redacted support bundle staging directory contains private data."""
    staging_path = Path(staging_dir)
    for path in sorted(staging_path.rglob("*")):
        if not path.is_file():
            continue
        relative = path.relative_to(staging_path).as_posix()
        if relative not in ALLOWED_SUPPORT_FILES:
            _raise_privacy_block("unexpected support bundle file: %s" % relative)
        if path.suffix.lower() in FORBIDDEN_SUPPORT_SUFFIXES:
            _raise_privacy_block("forbidden support bundle suffix: %s" % relative)
        if path.stat().st_size > MAX_SUPPORT_FILE_BYTES:
            _raise_privacy_block("support bundle file too large: %s" % relative)
        text = path.read_text(encoding="utf-8")
        lowered = text.casefold()
        if any(marker in lowered for marker in FORBIDDEN_SUPPORT_MARKERS):
            _raise_privacy_block("support bundle contains forbidden marker in %s" % relative)
        if _support_text_has_sensitive_marker(text):
            _raise_privacy_block("support bundle contains sensitive marker in %s" % relative)


def build_dependency_report() -> dict[str, object]:
    """Build a local dependency/status report without external calls."""
    return {
        "schema_version": "1.0",
        "tool_version": __version__,
        "python_version": platform.python_version(),
        "platform": platform.platform(),
        "sqlite_available": _sqlite_available(),
        "pypdf_available": is_pypdf_available(),
        "docker_executable_detected": shutil.which("docker") is not None,
        "network_calls_performed": False,
    }


def build_redacted_document_inventory(workspace: Path | str) -> dict[str, object]:
    """Build a filename/metadata-only inventory without reading document bodies."""
    workspace_path = Path(workspace)
    documents_root = (
        workspace_path / "documents" if (workspace_path / "documents").is_dir() else workspace_path
    )
    documents: list[dict[str, object]] = []
    if documents_root.exists():
        for path in sorted(documents_root.rglob("*"), key=lambda item: item.as_posix().casefold()):
            if len(documents) >= MAX_INVENTORY_FILES:
                break
            if not path.is_file() or any(
                part in _inventory_excluded_parts() for part in path.parts
            ):
                continue
            documents.append(
                {
                    "source_path": _safe_relative(path, documents_root),
                    "source_type": detect_document_type(path),
                    "suffix": path.suffix.lower(),
                    "size_bytes": path.stat().st_size,
                    "content_hash": "",
                    "raw_content_included": False,
                }
            )
    return {
        "schema_version": "1.0",
        "workspace": _project_label(workspace_path),
        "documents_root": _project_label(documents_root),
        "document_count": len(documents),
        "truncated": len(documents) >= MAX_INVENTORY_FILES,
        "documents": documents,
    }


def render_doctor_markdown(payload: Mapping[str, object]) -> str:
    """Render a compact human-readable doctor report."""
    checks = cast(Sequence[Mapping[str, object]], payload["checks"])
    lines = [
        "# AethelGard Doctor Report",
        "",
        "- Status: `%s`" % payload["status"],
        "- Tool version: `%s`" % payload["tool_version"],
        "- Git commit: `%s`" % payload["git_commit"],
        "- Workspace: `%s`" % payload["workspace"],
        "",
        "| Check | Required | Status | Message |",
        "|---|---:|---|---|",
    ]
    for check in checks:
        lines.append(
            "| `%s` | %s | `%s` | %s |"
            % (
                check["id"],
                "yes" if check["required"] else "no",
                check["status"],
                _escape_markdown(str(check["message"])),
            )
        )
    lines.extend(
        [
            "",
            "## Boundary",
            "- This report is local diagnostics only.",
            "- Raw customer document content is not included.",
            "- Human review is required before sharing support material.",
        ]
    )
    return "\n".join(lines) + "\n"


def render_support_readme() -> str:
    """Render the README included in redacted support bundles."""
    return (
        "# AethelGard Support Bundle\n\n"
        "This bundle is redacted and should not contain customer documents. "
        "Human review required.\n\n"
        "Included files are limited to local diagnostics, redacted run summaries, "
        "dependency status, command metadata, and redacted document inventory.\n\n"
        "Do not add private local outputs, databases, raw documents, credentials, "
        "or machine-local debug folders to this archive.\n"
    )


def diagnostic_error_from_exception(
    exc: Exception,
    *,
    phase: str,
    fallback_code: ErrorCode = ErrorCode.INTERNAL_ERROR,
) -> AethelgardDiagnosticError:
    """Map an implementation exception to the stable support taxonomy."""
    message = str(exc) or exc.__class__.__name__
    lowered = message.casefold()
    error_code = fallback_code
    if "sqlite" in lowered or "answer vault" in lowered:
        error_code = ErrorCode.DB_INIT_FAILED
    elif "schema version" in lowered:
        error_code = ErrorCode.DB_SCHEMA_MISMATCH
    elif "questionnaire" in lowered or "csv" in lowered:
        error_code = ErrorCode.QUESTIONNAIRE_PARSE_FAILED
    elif "document" in lowered or "parse" in lowered:
        error_code = ErrorCode.DOC_PARSE_FAILED
    elif "output" in lowered or "write" in lowered:
        error_code = ErrorCode.OUTPUT_WRITE_FAILED
    return AethelgardDiagnosticError(
        error_code=error_code,
        severity="error",
        phase=phase,
        safe_message="The local run failed during %s." % phase,
        technical_detail="%s: %s" % (exc.__class__.__name__, message),
        remediation_hint="Run doctor, then create a redacted support bundle if the issue persists.",
        safe_to_share=True,
    )


def _doctor_check(
    check_id: str,
    status: DoctorStatus,
    message: str,
    *,
    required: bool = True,
    details: Mapping[str, object] | None = None,
) -> dict[str, object]:
    return {
        "id": check_id,
        "status": status,
        "required": required,
        "message": message,
        "details": dict(details or {}),
    }


def _overall_doctor_status(checks: Sequence[Mapping[str, object]]) -> DoctorStatus:
    if any(check["required"] and check["status"] == "FAIL" for check in checks):
        return "FAIL"
    if any(check["status"] != "OK" for check in checks):
        return "WARN"
    return "OK"


def _output_dir_is_writable(path: Path) -> bool:
    try:
        path.mkdir(parents=True, exist_ok=True)
        probe = path / ".doctor_write_test.tmp"
        probe.write_text("ok\n", encoding="utf-8")
        probe.unlink()
    except OSError:
        return False
    return True


def _workspace_structure_is_ready(path: Path) -> bool:
    return ((path / "documents").is_dir() and (path / "questionnaire_demo.csv").is_file()) or (
        path / SHAREABLE_REDACTED_DIR_NAME
    ).is_dir()


def _inventory_excluded_parts() -> frozenset[str]:
    return EXCLUDED_DIR_NAMES | frozenset({LOCAL_PRIVATE_DIR_NAME, SHAREABLE_REDACTED_DIR_NAME})


def _sqlite_available() -> bool:
    try:
        with contextlib.closing(sqlite3.connect(":memory:")) as connection:
            row = cast(tuple[int] | None, connection.execute("SELECT 1").fetchone())
    except sqlite3.Error:
        return False
    return row == (1,)


def _document_parser_basic_capability() -> bool:
    chunks = chunk_document_text("Access control owner reviewed.", max_chars=80, overlap=10)
    return bool(chunks) and detect_document_type(Path("sample.md")) == "markdown"


def git_commit() -> str:
    try:
        completed = subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"],
            check=False,
            capture_output=True,
            text=True,
            timeout=GIT_COMMAND_TIMEOUT_SECONDS,
        )
    except (OSError, subprocess.SubprocessError):
        return "unknown"
    if completed.returncode != 0:
        return "unknown"
    return completed.stdout.strip() or "unknown"


def _write_run_summary(workspace_path: Path, staging_dir: Path) -> None:
    source = _find_shareable_file(workspace_path, RUN_SUMMARY_JSONL_NAME)
    target = staging_dir / RUN_SUMMARY_JSONL_NAME
    if source is not None:
        shutil.copyfile(source, target)
        return
    _append_jsonl(
        target,
        {
            "run_id": "not-available",
            "timestamp": _utc_now(),
            "command": "support-bundle",
            "phase": "collect",
            "event": "run_summary_not_found",
            "severity": "warning",
            "error_code": None,
            "document_id": None,
            "safe_to_share": True,
            "message": "No redacted run summary was found in the selected workspace.",
        },
    )


def _copy_optional_shareable(workspace_path: Path, name: str, target: Path) -> None:
    source = _find_shareable_file(workspace_path, name)
    if source is not None:
        text = source.read_text(encoding="utf-8")
        if name == PILOT_READINESS_REPORT_NAME:
            text = text.replace("local_private", "[private-output]").replace(
                "aethelgard.sqlite",
                "[database]",
            )
        target.write_text(text, encoding="utf-8")


def _write_error_report(workspace_path: Path, target: Path) -> None:
    source = _find_shareable_file(workspace_path, ERROR_REPORT_NAME)
    if source is not None:
        shutil.copyfile(source, target)
        return
    _write_json(
        target,
        {
            "schema_version": "1.0",
            "errors": [],
            "source": _project_label(workspace_path),
            "safe_to_share": True,
        },
    )


def _find_shareable_file(workspace_path: Path, name: str) -> Path | None:
    candidates = (
        workspace_path / SHAREABLE_REDACTED_DIR_NAME / name,
        workspace_path / name,
    )
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    return None


def _write_zip_from_staging(staging_dir: Path, output_path: Path) -> None:
    if output_path.exists():
        output_path.unlink()
    with zipfile.ZipFile(output_path, "w", compression=zipfile.ZIP_DEFLATED) as bundle:
        for path in sorted(staging_dir.iterdir(), key=lambda item: item.name):
            if path.is_file():
                bundle.write(path, path.name)


def _staging_dir(output_path: Path) -> Path:
    unique = uuid.uuid4().hex[:STAGING_ID_CHARS]
    return output_path.parent / ("%s_staging_%s" % (output_path.stem, unique))


def _cleanup_staging(staging_dir: Path) -> None:
    if not staging_dir.exists():
        return
    try:
        shutil.rmtree(staging_dir)
    except OSError:
        # Best effort only: a leftover staging directory is safer than hiding the primary result.
        return


def _raise_privacy_block(detail: str) -> None:
    raise AethelgardDiagnosticError(
        error_code=ErrorCode.PRIVACY_GUARD_BLOCKED,
        severity="critical",
        phase="support_bundle",
        safe_message="Support bundle creation was blocked by the privacy guard.",
        technical_detail=detail,
        remediation_hint="Run again with redacted outputs only or inspect local_private manually.",
        safe_to_share=True,
    )


def _support_text_has_sensitive_marker(text: str) -> bool:
    return bool(
        SUPPORT_EMAIL_PATTERN.search(text)
        or SUPPORT_SECRET_ASSIGNMENT_PATTERN.search(text)
        or SUPPORT_TOKEN_VALUE_PATTERN.search(text)
    )


def _append_jsonl(path: Path, record: Mapping[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as output_file:
        output_file.write(json.dumps(record, sort_keys=True) + "\n")


def _write_json(path: Path, payload: Mapping[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _bounded_text(value: str, max_chars: int) -> str:
    single_line = " ".join(value.split())
    if len(single_line) <= max_chars:
        return single_line
    return single_line[: max_chars - 3].rstrip() + "..."


def _redacted_message(value: str) -> str:
    return mask_sensitive_text(_bounded_text(value, MAX_LOG_MESSAGE_CHARS))


def _project_label(path: Path) -> str:
    resolved = path.resolve()
    project_root = Path.cwd().resolve()
    try:
        return resolved.relative_to(project_root).as_posix()
    except ValueError:
        return path.name


def _safe_relative(path: Path, root: Path) -> str:
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return path.name


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
        .replace("|", "\\|")
    )


def _utc_now() -> str:
    return datetime.now(UTC).isoformat()


__all__ = [
    "COMMAND_INFO_NAME",
    "DEPENDENCY_REPORT_NAME",
    "DOCTOR_JSON_NAME",
    "DOCTOR_MD_NAME",
    "DOCUMENT_INVENTORY_REDACTED_NAME",
    "ERROR_REPORT_NAME",
    "PILOT_READINESS_REPORT_NAME",
    "README_SUPPORT_NAME",
    "RUN_DEBUG_JSONL_NAME",
    "RUN_SUMMARY_JSONL_NAME",
    "DiagnosticLogWriter",
    "build_dependency_report",
    "build_redacted_document_inventory",
    "build_support_bundle",
    "diagnostic_error_from_exception",
    "render_doctor_markdown",
    "render_support_readme",
    "run_doctor",
    "validate_support_bundle_staging",
]
