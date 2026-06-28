"""Local sensitive-content preflight for pilot/demo input folders."""

from __future__ import annotations

import ipaddress
import json
import re
from collections.abc import Callable, Iterator, Mapping, Sequence
from pathlib import Path
from typing import Final, Literal, TypedDict, cast

PREFLIGHT_JSON_NAME: Final[str] = "preflight_report.json"
PREFLIGHT_MD_NAME: Final[str] = "preflight_report.md"

MAX_PREFLIGHT_FILE_BYTES: Final[int] = 1_000_000
MAX_PREFLIGHT_LINE_CHARS: Final[int] = 4_000
MAX_FINDINGS_PER_FILE: Final[int] = 25
SNIPPET_RADIUS: Final[int] = 36
MAX_SNIPPET_CHARS: Final[int] = 160

TEXT_SUFFIXES: Final[frozenset[str]] = frozenset(
    {".csv", ".json", ".md", ".rst", ".txt", ".yaml", ".yml"}
)
EXCLUDED_DIR_NAMES: Final[frozenset[str]] = frozenset(
    {".git", ".mypy_cache", ".pytest_cache", ".ruff_cache", ".venv", "__pycache__", "venv"}
)
SECRET_FILENAME_MARKERS: Final[tuple[str, ...]] = (
    ".env",
    "credential",
    "credentials",
    "private-config",
    "secret",
    "secrets",
)

EMAIL_PATTERN: Final[re.Pattern[str]] = re.compile(
    r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b",
    re.IGNORECASE,
)
PHONE_PATTERN: Final[re.Pattern[str]] = re.compile(
    r"(?<![\w])(?:\+?\d[\d\s()./-]{6,}\d)(?![\w])"
)
IBAN_PATTERN: Final[re.Pattern[str]] = re.compile(
    r"\b[A-Z]{2}\d{2}(?:\s?[A-Z0-9]){11,30}\b",
    re.IGNORECASE,
)
IPV4_PATTERN: Final[re.Pattern[str]] = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
INTERNAL_HOST_PATTERN: Final[re.Pattern[str]] = re.compile(
    r"\b[a-z0-9][a-z0-9-]{0,62}(?:\.[a-z0-9][a-z0-9-]{0,62})*"
    r"\.(?:corp|internal|intranet|lan|local)\b",
    re.IGNORECASE,
)
SECRET_ASSIGNMENT_PATTERN: Final[re.Pattern[str]] = re.compile(
    r"\b(?P<key>api[_-]?key|authorization|cookie|password|passwd|refresh[_-]?token|"
    r"secret|token|access[_-]?token)\b\s*[:=]\s*(?P<value>['\"]?[^\s'\"`]+['\"]?)",
    re.IGNORECASE,
)
TOKEN_VALUE_PATTERN: Final[re.Pattern[str]] = re.compile(
    r"\b(?:ghp|github_pat|glpat|sk|xox[baprs])[-_][A-Za-z0-9_=-]{12,}\b",
    re.IGNORECASE,
)
KEYWORD_PATTERN: Final[re.Pattern[str]] = re.compile(
    r"\b(api[_-]?key|authorization|cookie|password|secret|token)\b",
    re.IGNORECASE,
)

Status = Literal["pass", "warn", "block"]
Severity = Literal["low", "medium", "high"]
FindingType = Literal[
    "email",
    "phone",
    "secret",
    "token",
    "iban",
    "private_network",
    "keyword",
    "unsupported",
]
MatchPredicate = Callable[[str], bool]


class PreflightFinding(TypedDict):
    file: str
    type: FindingType
    severity: Severity
    line: int | None
    snippet: str


class PreflightSummary(TypedDict):
    low: int
    medium: int
    high: int


class PreflightReport(TypedDict):
    status: Status
    files_scanned: int
    findings: list[PreflightFinding]
    summary: PreflightSummary
    preflight_skipped: bool
    notes: list[str]


def run_redaction_preflight(
    input_path: Path | str,
    *,
    fail_on_sensitive: bool = False,
) -> PreflightReport:
    """Scan local text inputs for obvious sensitive-content markers."""
    root = Path(input_path)
    if not root.exists():
        finding = _finding(str(root), "unsupported", "high", None, "input path does not exist")
        return _report([finding], 0, fail_on_sensitive, [])

    findings: list[PreflightFinding] = []
    files_scanned = 0
    for file_path in _iter_input_files(root):
        relative_file = _safe_relative(file_path, root)
        if _is_forbidden_secret_path(file_path):
            findings.append(
                _finding(
                    relative_file,
                    "secret",
                    "high",
                    None,
                    "[secret-file:redacted] skipped without reading",
                )
            )
            continue
        if file_path.suffix.lower() not in TEXT_SUFFIXES:
            findings.append(_unsupported(relative_file, "unsupported or non-text file skipped"))
            continue

        file_findings, scanned = _scan_text_file(file_path, relative_file)
        files_scanned += int(scanned)
        findings.extend(file_findings)
    return _report(findings, files_scanned, fail_on_sensitive, [])


def build_skipped_preflight_report() -> PreflightReport:
    """Build an explicit report for ``--no-preflight`` runs."""
    return {
        "status": "pass",
        "files_scanned": 0,
        "findings": [],
        "summary": {"low": 0, "medium": 0, "high": 0},
        "preflight_skipped": True,
        "notes": ["Preflight skipped by --no-preflight."],
    }


def write_preflight_reports(out_dir: Path | str, report: PreflightReport) -> None:
    """Write JSON and Markdown preflight reports."""
    target_dir = Path(out_dir)
    target_dir.mkdir(parents=True, exist_ok=True)
    (target_dir / PREFLIGHT_JSON_NAME).write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    (target_dir / PREFLIGHT_MD_NAME).write_text(render_preflight_markdown(report), encoding="utf-8")


def render_preflight_markdown(report: Mapping[str, object]) -> str:
    """Render a compact Markdown preflight report with escaped file content."""
    summary = cast(Mapping[str, int], report["summary"])
    findings = cast(list[PreflightFinding], report["findings"])
    lines = [
        "# AethelGard Redaction Preflight",
        "",
        "## Status",
        "- Status: `%s`" % report["status"],
        "- Files scanned: `%s`" % report["files_scanned"],
        "- Preflight skipped: `%s`" % report["preflight_skipped"],
        "- Low/medium/high findings: `%d` / `%d` / `%d`"
        % (summary["low"], summary["medium"], summary["high"]),
        "",
        "## Findings",
    ]
    if not findings:
        lines.append("- No sensitive markers detected by this local preflight.")
    else:
        lines.extend(
            ["| File | Type | Severity | Line | Masked snippet |", "|---|---|---|---:|---|"]
        )
        for finding in findings:
            line_label = "-" if finding["line"] is None else str(finding["line"])
            lines.append(
                "| `%s` | `%s` | `%s` | %s | %s |"
                % (
                    _escape_markdown(finding["file"]),
                    finding["type"],
                    finding["severity"],
                    line_label,
                    _escape_markdown(finding["snippet"]),
                )
            )
    notes = [str(note) for note in cast(list[object], report["notes"])]
    if notes:
        lines.extend(["", "## Notes", *("- %s" % _escape_markdown(note) for note in notes)])
    lines.extend(
        [
            "",
            "## Boundary",
            "- Local static preflight only; no OCR, SaaS, external APIs, or legal assessment.",
            "- Findings are masked and require human review before customer handover.",
        ]
    )
    return "\n".join(lines) + "\n"


def _iter_input_files(root: Path) -> Iterator[Path]:
    if root.is_file():
        yield root
        return
    for candidate in sorted(root.rglob("*")):
        if candidate.is_file() and not any(part in EXCLUDED_DIR_NAMES for part in candidate.parts):
            yield candidate


def _is_forbidden_secret_path(path: Path) -> bool:
    lowered = path.name.lower()
    return lowered == ".env" or lowered.startswith(".env.") or any(
        marker in lowered for marker in SECRET_FILENAME_MARKERS
    )


def _scan_text_file(file_path: Path, relative_file: str) -> tuple[list[PreflightFinding], bool]:
    try:
        with file_path.open("rb") as input_file:
            raw_content = input_file.read(MAX_PREFLIGHT_FILE_BYTES + 1)
    except OSError:
        return [_unsupported(relative_file, "file could not be read")], False

    if len(raw_content) > MAX_PREFLIGHT_FILE_BYTES:
        return [_unsupported(relative_file, "file exceeds preflight scan size limit")], False
    if b"\x00" in raw_content:
        return [_unsupported(relative_file, "binary-like file skipped")], False
    try:
        content = raw_content.decode("utf-8")
    except UnicodeDecodeError:
        return [_unsupported(relative_file, "non-utf-8 text skipped")], False

    findings: list[PreflightFinding] = []
    for line_number, line in enumerate(content.splitlines(), start=1):
        findings.extend(_scan_line(relative_file, line_number, line[:MAX_PREFLIGHT_LINE_CHARS]))
        if len(findings) >= MAX_FINDINGS_PER_FILE:
            return findings[:MAX_FINDINGS_PER_FILE], True
    return findings, True


def _scan_line(file_name: str, line_number: int, line: str) -> list[PreflightFinding]:
    findings: list[PreflightFinding] = []
    secret_spans: list[tuple[int, int]] = []
    for match in SECRET_ASSIGNMENT_PATTERN.finditer(line):
        secret_spans.append(match.span())
        findings.append(
            _match_finding(
                file_name,
                _secret_finding_type(match.group("key")),
                "high",
                line_number,
                line,
                match.start("value"),
                match.end("value"),
            )
        )

    specs: tuple[tuple[re.Pattern[str], FindingType, Severity, MatchPredicate | None], ...] = (
        (TOKEN_VALUE_PATTERN, "token", "high", None),
        (EMAIL_PATTERN, "email", "medium", None),
        (PHONE_PATTERN, "phone", "medium", _is_plausible_phone),
        (IBAN_PATTERN, "iban", "medium", None),
        (IPV4_PATTERN, "private_network", "low", _is_private_ip),
        (INTERNAL_HOST_PATTERN, "private_network", "low", None),
    )
    for pattern, finding_type, severity, predicate in specs:
        findings.extend(
            _pattern_findings(
                file_name,
                line_number,
                line,
                pattern,
                finding_type,
                severity,
                predicate,
            )
        )
    for match in KEYWORD_PATTERN.finditer(line):
        if not _span_overlaps(match.span(), secret_spans):
            findings.append(
                _match_finding(
                    file_name,
                    "keyword",
                    "medium",
                    line_number,
                    line,
                    match.start(),
                    match.end(),
                )
            )
    return findings


def _pattern_findings(
    file_name: str,
    line_number: int,
    line: str,
    pattern: re.Pattern[str],
    finding_type: FindingType,
    severity: Severity,
    predicate: MatchPredicate | None,
) -> list[PreflightFinding]:
    return [
        _match_finding(
            file_name,
            finding_type,
            severity,
            line_number,
            line,
            match.start(),
            match.end(),
        )
        for match in pattern.finditer(line)
        if predicate is None or predicate(match.group(0))
    ]


def _match_finding(
    file_name: str,
    finding_type: FindingType,
    severity: Severity,
    line_number: int,
    line: str,
    start: int,
    end: int,
) -> PreflightFinding:
    return _finding(
        file_name,
        finding_type,
        severity,
        line_number,
        _redacted_snippet(line, start, end, finding_type),
    )


def _finding(
    file_name: str,
    finding_type: FindingType,
    severity: Severity,
    line: int | None,
    snippet: str,
) -> PreflightFinding:
    return {
        "file": file_name,
        "type": finding_type,
        "severity": severity,
        "line": line,
        "snippet": snippet,
    }


def _unsupported(file_name: str, snippet: str) -> PreflightFinding:
    return _finding(file_name, "unsupported", "low", None, snippet)


def _report(
    findings: list[PreflightFinding],
    files_scanned: int,
    fail_on_sensitive: bool,
    notes: list[str],
) -> PreflightReport:
    summary: PreflightSummary = {"low": 0, "medium": 0, "high": 0}
    for finding in findings:
        summary[finding["severity"]] += 1
    status = _status(summary, fail_on_sensitive)
    if fail_on_sensitive and status == "block" and summary["high"] == 0:
        notes = [*notes, "--fail-on-sensitive escalated medium findings to block."]
    return {
        "status": status,
        "files_scanned": files_scanned,
        "findings": findings,
        "summary": summary,
        "preflight_skipped": False,
        "notes": notes,
    }


def _status(summary: PreflightSummary, fail_on_sensitive: bool) -> Status:
    if summary["high"] > 0 or (fail_on_sensitive and summary["medium"] > 0):
        return "block"
    if summary["medium"] > 0 or summary["low"] > 0:
        return "warn"
    return "pass"


def _secret_finding_type(key: str) -> FindingType:
    lowered = key.lower().replace("-", "_")
    if "token" in lowered or "api" in lowered or lowered in {"authorization", "cookie"}:
        return "token"
    return "secret"


def _is_plausible_phone(value: str) -> bool:
    digits = "".join(character for character in value if character.isdigit())
    return 7 <= len(digits) <= 15


def _is_private_ip(value: str) -> bool:
    try:
        return bool(ipaddress.ip_address(value).is_private)
    except ValueError:
        return False


def _span_overlaps(span: tuple[int, int], existing_spans: Sequence[tuple[int, int]]) -> bool:
    start, end = span
    return any(
        start < existing_end and existing_start < end
        for existing_start, existing_end in existing_spans
    )


def _redacted_snippet(line: str, start: int, end: int, label: str) -> str:
    prefix = line[max(0, start - SNIPPET_RADIUS) : start]
    suffix = line[end : end + SNIPPET_RADIUS]
    snippet = "%s[%s:redacted]%s" % (prefix, label, suffix)
    masked = _mask_known_values(" ".join(snippet.split()))
    if len(masked) <= MAX_SNIPPET_CHARS:
        return masked
    return masked[: MAX_SNIPPET_CHARS - 3] + "..."


def _mask_known_values(text: str) -> str:
    masked = SECRET_ASSIGNMENT_PATTERN.sub(_mask_secret_assignment, text)
    masked = PHONE_PATTERN.sub(_mask_phone_match, masked)
    masked = IPV4_PATTERN.sub(_mask_ip_match, masked)
    for pattern, replacement in (
        (TOKEN_VALUE_PATTERN, "[token:redacted]"),
        (EMAIL_PATTERN, "[email:redacted]"),
        (IBAN_PATTERN, "[iban:redacted]"),
        (INTERNAL_HOST_PATTERN, "[private_network:redacted]"),
    ):
        masked = pattern.sub(replacement, masked)
    return masked


def _mask_secret_assignment(match: re.Match[str]) -> str:
    return "%s=[%s:redacted]" % (match.group("key"), _secret_finding_type(match.group("key")))


def _mask_phone_match(match: re.Match[str]) -> str:
    return "[phone:redacted]" if _is_plausible_phone(match.group(0)) else match.group(0)


def _mask_ip_match(match: re.Match[str]) -> str:
    return "[private_network:redacted]" if _is_private_ip(match.group(0)) else match.group(0)


def _safe_relative(path: Path, root: Path) -> str:
    base = root if root.is_dir() else root.parent
    try:
        return path.relative_to(base).as_posix()
    except ValueError:
        return path.name


def _escape_markdown(value: str) -> str:
    return re.sub(r"([`*_\[\]<>|])", r"\\\1", value)
