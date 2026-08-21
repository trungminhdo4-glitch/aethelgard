"""Static safety check for Aethelgard marketing claims and contact placeholders."""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path
from typing import Final
from urllib.parse import urlparse

PROJECT_ROOT: Final[Path] = Path(__file__).resolve().parents[1]
DEFAULT_SCAN_PATHS: Final[tuple[Path, ...]] = (
    PROJECT_ROOT / "marketing",
    PROJECT_ROOT / "docs" / "pilot_quickstart.md",
    PROJECT_ROOT / "README.md",
)
TEXT_SUFFIXES: Final[frozenset[str]] = frozenset({".css", ".csv", ".html", ".md", ".txt"})
MAX_FILE_BYTES: Final[int] = 300_000
ALLOWED_EMAILS: Final[frozenset[str]] = frozenset({"pilot@aethelgard.local"})
ALLOWED_URL_HOSTS: Final[frozenset[str]] = frozenset({"example.invalid"})

FORBIDDEN_CLAIM_PATTERNS: Final[tuple[tuple[str, re.Pattern[str]], ...]] = (
    (
        "nis2_conform_guarantee",
        re.compile(r"(?i)\b(?:nis[-\s]?2|nis2)[-\s]?konform\s+garantiert\b"),
    ),
    (
        "makes_nis2_conform",
        re.compile(r"(?i)\bmacht\b.{0,80}\b(?:nis[-\s]?2|nis2)[-\s]?konform\b"),
    ),
    ("legal_certain", re.compile(r"(?i)\brechtssicher\b")),
    ("audit_passed", re.compile(r"(?i)\baudit\s+bestanden\b")),
    ("certified", re.compile(r"(?i)\bzertifiziert\b")),
    ("replaces_consulting", re.compile(r"(?i)\bersetzt\s+beratung\b")),
    ("fully_automatic_compliant", re.compile(r"(?i)\bvollautomatisch\s+compliant\b")),
    ("guarantees_compliance", re.compile(r"(?i)\bguarantees?\s+nis[-\s]?2\s+compliance\b")),
    ("nis2_compliant", re.compile(r"(?i)\bnis[-\s]?2\s+compliant\b")),
)
EMAIL_PATTERN: Final[re.Pattern[str]] = re.compile(
    r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"
)
URL_PATTERN: Final[re.Pattern[str]] = re.compile(r"https?://[^\s)\"'>]+")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Check marketing files for unsafe claims.")
    parser.add_argument(
        "paths",
        nargs="*",
        type=Path,
        default=list(DEFAULT_SCAN_PATHS),
        help="Files or directories to scan.",
    )
    return parser


def iter_files(paths: list[Path]) -> list[Path]:
    files: list[Path] = []
    for path in paths:
        if path.is_file() and path.suffix.lower() in TEXT_SUFFIXES:
            files.append(path)
        elif path.is_dir():
            files.extend(
                candidate
                for candidate in path.rglob("*")
                if candidate.is_file() and candidate.suffix.lower() in TEXT_SUFFIXES
            )
    return sorted(files)


def scan_paths(paths: list[Path]) -> list[str]:
    findings: list[str] = []
    files = iter_files(paths)
    if not files:
        return ["no marketing files found"]
    for path in files:
        findings.extend(scan_file(path))
    return findings


def scan_file(path: Path) -> list[str]:
    if path.stat().st_size > MAX_FILE_BYTES:
        return ["%s: file too large for marketing claim check" % path]

    text = path.read_text(encoding="utf-8")
    findings: list[str] = []
    for claim_id, pattern in FORBIDDEN_CLAIM_PATTERNS:
        for match in pattern.finditer(text):
            findings.append(
                "%s:%d: forbidden claim %s" % (path, _line_number(text, match.start()), claim_id)
            )
    findings.extend(_check_emails(path, text))
    findings.extend(_check_urls(path, text))
    return findings


def _check_emails(path: Path, text: str) -> list[str]:
    findings: list[str] = []
    for match in EMAIL_PATTERN.finditer(text):
        email = match.group(0).casefold()
        if email not in ALLOWED_EMAILS:
            findings.append(
                "%s:%d: non-placeholder email %s"
                % (path, _line_number(text, match.start()), email)
            )
    return findings


def _check_urls(path: Path, text: str) -> list[str]:
    findings: list[str] = []
    for match in URL_PATTERN.finditer(text):
        parsed_url = urlparse(match.group(0))
        host = (parsed_url.hostname or "").casefold()
        if host not in ALLOWED_URL_HOSTS:
            findings.append(
                "%s:%d: external URL %s" % (path, _line_number(text, match.start()), host)
            )
    return findings


def _line_number(text: str, index: int) -> int:
    return text.count("\n", 0, index) + 1


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    findings = scan_paths([Path(path) for path in args.paths])
    if findings:
        for finding in findings:
            print("FAIL: %s" % finding, file=sys.stderr)
        return 1
    print("OK: marketing claims passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
