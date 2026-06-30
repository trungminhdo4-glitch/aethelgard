"""Static safety check for public and demo AethelGard fixtures."""

from __future__ import annotations

import argparse
import ipaddress
import re
import sys
from pathlib import Path

DEFAULT_SCAN_ROOTS = (
    Path("tests") / "fixtures" / "public_nis2",
    Path("tests") / "fixtures" / "customer_like_nis2",
    Path("examples") / "public",
)
MAX_FILE_BYTES = 200_000
ALLOWED_EMAIL_DOMAINS = ("example.com", "example.invalid")
ALLOWED_DOMAIN_SUFFIXES = (".invalid",)
ALLOWED_DOMAINS = {"example.com", "example.invalid"}
ALLOWED_PUBLIC_DOMAIN_SUFFIXES = (
    ".cisa.gov",
    ".cyclonedx.org",
    ".github.com",
    ".githubusercontent.com",
)
ALLOWED_PUBLIC_DOMAINS = {
    "cisa.gov",
    "cyclonedx.org",
    "github.com",
    "raw.githubusercontent.com",
    "www.cisa.gov",
    "www.cyclonedx.org",
}
ALLOWED_EXAMPLE_NETWORKS = (
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
)

SECRET_PATTERNS = (
    ("private_key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("bearer_token", re.compile(r"\bBearer\s+[A-Za-z0-9._~+/=-]{20,}")),
    ("aws_access_key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    (
        "api_key_assignment",
        re.compile(r"(?i)\b(api[_-]?key|token|secret)\s*[:=]\s*[A-Za-z0-9._~+/=-]{12,}"),
    ),
    ("openai_key", re.compile(r"\bsk-[A-Za-z0-9]{20,}\b")),
)
EMAIL_PATTERN = re.compile(r"\b[A-Za-z0-9._%+-]+@([A-Za-z0-9.-]+\.[A-Za-z]{2,})\b")
DOMAIN_PATTERN = re.compile(r"\b(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}\b")
IPV4_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
PHONE_PATTERN = re.compile(r"(?<!\d)(?:\+?\d[\d .()/-]{7,}\d)(?!\d)")
ISO_DATE_PATTERN = re.compile(r"^\d{4}-\d{2}-\d{2}$")
DOT_DATE_PATTERN = re.compile(r"^\d{4}\.\d{2}\.\d{2}$")
CVE_ID_FRAGMENT_PATTERN = re.compile(r"^\d{4}-\d{4,}$")
HEX_CHAR_PATTERN = re.compile(r"[a-fA-F0-9]")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Check synthetic fixtures for secrets/PII.")
    parser.add_argument(
        "paths",
        nargs="*",
        type=Path,
        default=list(DEFAULT_SCAN_ROOTS),
        help="Files or directories to scan.",
    )
    return parser


def iter_files(paths: list[Path]) -> list[Path]:
    files: list[Path] = []
    for path in paths:
        if path.is_file():
            files.append(path)
        elif path.is_dir():
            files.extend(
                candidate
                for candidate in path.rglob("*")
                if candidate.is_file() and candidate.suffix.lower() in {".md", ".json"}
            )
    return sorted(files)


def check_file(path: Path) -> list[str]:
    findings: list[str] = []
    if path.stat().st_size > MAX_FILE_BYTES:
        return ["%s: file too large for public fixture check" % path]
    text = path.read_text(encoding="utf-8")
    for name, pattern in SECRET_PATTERNS:
        if pattern.search(text):
            findings.append("%s: possible %s" % (path, name))
    findings.extend(_check_emails(path, text))
    findings.extend(_check_domains(path, text))
    findings.extend(_check_ips(path, text))
    findings.extend(_check_phone_numbers(path, text))
    return findings


def _check_emails(path: Path, text: str) -> list[str]:
    findings: list[str] = []
    for match in EMAIL_PATTERN.finditer(text):
        domain = match.group(1).lower()
        if domain not in ALLOWED_EMAIL_DOMAINS:
            findings.append("%s: non-example email domain %s" % (path, domain))
    return findings


def _check_domains(path: Path, text: str) -> list[str]:
    findings: list[str] = []
    for match in DOMAIN_PATTERN.finditer(text):
        domain = match.group(0).lower()
        if "@" in domain or _looks_like_file_name(domain):
            continue
        if _domain_is_allowed(domain):
            continue
        findings.append("%s: non-example domain %s" % (path, domain))
    return findings


def _check_ips(path: Path, text: str) -> list[str]:
    findings: list[str] = []
    for match in IPV4_PATTERN.finditer(text):
        try:
            address = ipaddress.ip_address(match.group(0))
        except ValueError:
            findings.append("%s: invalid IPv4-like value %s" % (path, match.group(0)))
            continue
        if any(address in network for network in ALLOWED_EXAMPLE_NETWORKS):
            continue
        if address.is_private:
            findings.append("%s: private IP address %s" % (path, address))
    return findings


def _check_phone_numbers(path: Path, text: str) -> list[str]:
    findings: list[str] = []
    for match in PHONE_PATTERN.finditer(text):
        value = match.group(0)
        if "192.0.2." in value or "198.51.100." in value or "203.0.113." in value:
            continue
        if (
            ISO_DATE_PATTERN.fullmatch(value)
            or DOT_DATE_PATTERN.fullmatch(value)
            or CVE_ID_FRAGMENT_PATTERN.fullmatch(value)
            or _looks_embedded_in_hash(text, match.start(), match.end())
        ):
            continue
        findings.append("%s: possible phone number %s" % (path, value))
    return findings


def _looks_like_file_name(value: str) -> bool:
    return value.endswith((".md", ".json", ".txt", ".py"))


def _domain_is_allowed(domain: str) -> bool:
    return (
        domain in ALLOWED_DOMAINS
        or domain in ALLOWED_PUBLIC_DOMAINS
        or domain.endswith(ALLOWED_DOMAIN_SUFFIXES)
        or domain.endswith(ALLOWED_PUBLIC_DOMAIN_SUFFIXES)
    )


def _looks_embedded_in_hash(text: str, start: int, end: int) -> bool:
    previous_char = text[start - 1] if start > 0 else ""
    next_char = text[end] if end < len(text) else ""
    return bool(
        (previous_char and HEX_CHAR_PATTERN.fullmatch(previous_char))
        or (next_char and HEX_CHAR_PATTERN.fullmatch(next_char))
    )


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    findings: list[str] = []
    files = iter_files(args.paths)
    if not files:
        print("FAIL: no fixture files found", file=sys.stderr)
        return 1
    for path in files:
        findings.extend(check_file(path))
    if findings:
        for finding in findings:
            print("FAIL: %s" % finding, file=sys.stderr)
        return 1
    print("OK: %d public/demo fixture files passed safety checks" % len(files))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
