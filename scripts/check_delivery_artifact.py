"""Check a pilot delivery artifact for forbidden files and false source claims."""

from __future__ import annotations

import argparse
import codecs
import json
import re
import sys
from pathlib import Path, PurePosixPath
from typing import BinaryIO, Final, TypedDict

REPORT_JSON_NAME: Final[str] = "delivery_check_report.json"
REPORT_MD_NAME: Final[str] = "delivery_check_report.md"
MANIFEST_NAME: Final[str] = "build_manifest.json"
MAX_SCAN_BYTES: Final[int] = 1_000_000
MAX_TEXT_FILE_BYTES: Final[int] = 64 * 1024 * 1024
MAX_MANIFEST_BYTES: Final[int] = 1_000_000
SCAN_OVERLAP_CHARS: Final[int] = 128
STATUS_OK: Final[str] = "OK"
STATUS_BLOCKED: Final[str] = "BLOCKED"

FORBIDDEN_PARTS: Final[frozenset[str]] = frozenset(
    {
        ".git",
        "tests",
        "reports",
        "local_private",
        "__pycache__",
        ".pytest_cache",
        ".mypy_cache",
        ".ruff_cache",
    }
)
FORBIDDEN_FILENAMES: Final[frozenset[str]] = frozenset(
    {
        "AGENTS.md",
        "AGENT_LOG.md",
        "CLAUDE.md",
    }
)
FORBIDDEN_SUFFIXES: Final[tuple[str, ...]] = (
    ".sqlite",
    ".sqlite3",
    ".db",
)
SOURCE_SUFFIXES: Final[tuple[str, ...]] = (
    ".py",
    ".pyi",
    ".pyw",
)
TEXT_SUFFIXES: Final[frozenset[str]] = frozenset(
    {
        ".c",
        ".cfg",
        ".conf",
        ".cpp",
        ".cs",
        ".css",
        ".csv",
        ".go",
        ".h",
        ".hpp",
        ".htm",
        ".html",
        ".ini",
        ".java",
        ".js",
        ".json",
        ".jsonl",
        ".jsx",
        ".key",
        ".lock",
        ".log",
        ".md",
        ".pem",
        ".properties",
        ".ps1",
        ".py",
        ".pyi",
        ".pyw",
        ".rb",
        ".rst",
        ".sh",
        ".sql",
        ".svg",
        ".toml",
        ".ts",
        ".tsv",
        ".tsx",
        ".txt",
        ".xml",
        ".yaml",
        ".yml",
    }
)
TEXT_FILENAMES: Final[frozenset[str]] = frozenset(
    {
        "dockerfile",
        "license",
        "makefile",
        "notice",
        "requirements.txt",
    }
)
KNOWN_BINARY_MAGIC: Final[tuple[bytes, ...]] = (
    b"MZ",
    b"\x7fELF",
    b"PK\x03\x04",
    b"PK\x05\x06",
    b"PK\x07\x08",
    b"\x89PNG\r\n\x1a\n",
    b"\xff\xd8\xff",
    b"GIF87a",
    b"GIF89a",
    b"%PDF-",
    b"\x1f\x8b",
    b"BZh",
    b"7z\xbc\xaf\x27\x1c",
    b"SQLite format 3\x00",
    b"\xca\xfe\xba\xbe",
    b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1",
    b"\x00asm",
)
INTERNAL_NAME_MARKERS: Final[tuple[str, ...]] = (
    "prompt",
    ".codex",
    ".opencode",
    "agent_log",
)
RAW_CUSTOMER_NAME_MARKERS: Final[tuple[str, ...]] = (
    "customer_like",
    "customer-like",
    "customer_raw",
    "kundendokument",
)
SECRET_MARKERS: Final[tuple[tuple[str, re.Pattern[str]], ...]] = (
    ("private_key_marker", re.compile(r"-----BEGIN PRIVATE KEY-----", re.IGNORECASE)),
    ("token_assignment", re.compile(r"\bTOKEN[ \t]*=[ \t]*['\"]?[^\s'\"),]+", re.IGNORECASE)),
    ("password_assignment", re.compile(r"\bPASSWORD[ \t]*=[ \t]*['\"]?[^\s'\"),]+", re.IGNORECASE)),
    ("secret_assignment", re.compile(r"\bSECRET[ \t]*=[ \t]*['\"]?[^\s'\"),]+", re.IGNORECASE)),
    ("api_key_assignment", re.compile(r"\bAPI_KEY[ \t]*=[ \t]*['\"]?[^\s'\"),]+", re.IGNORECASE)),
)
SELF_REPORT_NAMES: Final[frozenset[str]] = frozenset({REPORT_JSON_NAME, REPORT_MD_NAME})


class Finding(TypedDict):
    id: str
    path: str
    detail: str


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Check a pilot delivery artifact.")
    parser.add_argument("--path", required=True, type=Path, help="Artifact directory to check.")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    artifact_path = Path(args.path)
    report = build_report(artifact_path)
    if artifact_path.is_dir():
        _write_reports(artifact_path, report)
    print("Delivery artifact: %s" % report["status"])
    return 0 if report["status"] == STATUS_OK else 2


def build_report(artifact_path: Path) -> dict[str, object]:
    root = artifact_path.resolve()
    blockers: list[Finding] = []
    warnings: list[Finding] = []
    manifest = _load_manifest(root, blockers)

    if not root.is_dir():
        blockers.append(
            _finding(
                "artifact_missing",
                ".",
                "Artifact path does not exist or is not a directory.",
            )
        )
        return _report(blockers, warnings, manifest)

    source_files: list[str] = []
    for path in sorted(root.rglob("*")):
        relative_path = _relative_path(root, path)
        if path.name in SELF_REPORT_NAMES:
            continue
        blockers.extend(_path_blockers(path, relative_path))
        if path.is_file() and _is_source_file(path):
            source_files.append(relative_path)
        if path.is_file() and not _is_forbidden_by_name(path):
            blockers.extend(_content_blockers(path, relative_path))

    blockers.extend(_manifest_source_claim_blockers(manifest, source_files))
    return _report(blockers, warnings, manifest)


def _report(
    blockers: list[Finding],
    warnings: list[Finding],
    manifest: dict[str, object],
) -> dict[str, object]:
    status = STATUS_OK if not blockers else STATUS_BLOCKED
    return {
        "status": status,
        "artifact_path": ".",
        "blocker_count": len(blockers),
        "warning_count": len(warnings),
        "blockers": blockers,
        "warnings": warnings,
        "manifest": _manifest_summary(manifest),
    }


def _load_manifest(root: Path, blockers: list[Finding]) -> dict[str, object]:
    manifest_path = root / MANIFEST_NAME
    if not manifest_path.is_file():
        blockers.append(_finding("manifest_missing", MANIFEST_NAME, "build manifest is required."))
        return {}
    try:
        with manifest_path.open("rb") as stream:
            raw_manifest = stream.read(MAX_MANIFEST_BYTES + 1)
        if len(raw_manifest) > MAX_MANIFEST_BYTES:
            blockers.append(
                _finding(
                    "manifest_too_large",
                    MANIFEST_NAME,
                    "build manifest exceeds the 1000000-byte parsing limit.",
                )
            )
            return {}
        loaded: object = json.loads(raw_manifest.decode("utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        blockers.append(
            _finding("manifest_invalid", MANIFEST_NAME, "build manifest could not be parsed.")
        )
        return {"manifest_error": type(exc).__name__}
    if not isinstance(loaded, dict):
        blockers.append(_finding("manifest_invalid", MANIFEST_NAME, "build manifest must be JSON."))
        return {}
    manifest: dict[str, object] = {}
    for key, value in loaded.items():
        if isinstance(key, str):
            manifest[key] = value
    return manifest


def _manifest_summary(manifest: dict[str, object]) -> dict[str, object]:
    summary_keys = (
        "build_id",
        "git_commit",
        "git_branch",
        "package_mode",
        "no_source_claim",
        "source_visible",
        "not_for_customer_delivery",
    )
    return {key: manifest[key] for key in summary_keys if key in manifest}


def _path_blockers(path: Path, relative_path: str) -> list[Finding]:
    blockers: list[Finding] = []
    lowered_parts = {part.casefold() for part in PurePosixPath(relative_path).parts}
    lowered_name = path.name.casefold()
    if FORBIDDEN_PARTS.intersection(lowered_parts):
        blockers.append(_finding("forbidden_path", relative_path, "forbidden directory present."))
    if path.name in FORBIDDEN_FILENAMES:
        blockers.append(_finding("forbidden_file", relative_path, "internal agent file present."))
    if lowered_name == ".env" or lowered_name.startswith(".env."):
        blockers.append(_finding("env_file", relative_path, "environment file present."))
    if path.is_file() and lowered_name.endswith(FORBIDDEN_SUFFIXES):
        blockers.append(_finding("database_file", relative_path, "database file present."))
    if any(marker in relative_path.casefold() for marker in INTERNAL_NAME_MARKERS):
        blockers.append(
            _finding(
                "internal_prompt_or_agent_file",
                relative_path,
                "internal file marker present.",
            )
        )
    if any(marker in relative_path.casefold() for marker in RAW_CUSTOMER_NAME_MARKERS):
        blockers.append(
            _finding("raw_customer_like_file", relative_path, "raw customer-like file.")
        )
    return blockers


def _content_blockers(path: Path, relative_path: str) -> list[Finding]:
    try:
        file_size = path.stat().st_size
        with path.open("rb") as stream:
            return _opened_content_blockers(stream, path, relative_path, file_size)
    except OSError:
        return [_finding("unreadable_file", relative_path, "file could not be scanned.")]


def _opened_content_blockers(
    stream: BinaryIO,
    path: Path,
    relative_path: str,
    file_size: int,
) -> list[Finding]:
    first_chunk = stream.read(MAX_SCAN_BYTES)
    if any(first_chunk.startswith(magic) for magic in KNOWN_BINARY_MAGIC):
        return []
    is_text, encoding = _classify_text(path, first_chunk)
    if not is_text:
        return []
    if encoding is None:
        return [
            _finding(
                "unsupported_text_encoding",
                relative_path,
                "text-like file is not valid UTF-8 or UTF-16.",
            )
        ]
    if file_size > MAX_TEXT_FILE_BYTES:
        return [
            _finding(
                "oversized_text_file",
                relative_path,
                "text file exceeds the 64 MiB scan limit.",
            )
        ]
    return _scan_text_stream(stream, first_chunk, encoding, relative_path)


def _classify_text(path: Path, data: bytes) -> tuple[bool, str | None]:
    known_text = _is_known_text_file(path)
    encoding: str | None
    if data.startswith((codecs.BOM_UTF32_LE, codecs.BOM_UTF32_BE)):
        return True, None
    if data.startswith(codecs.BOM_UTF8):
        encoding = "utf-8-sig"
    elif data.startswith((codecs.BOM_UTF16_LE, codecs.BOM_UTF16_BE)):
        encoding = "utf-16"
    else:
        encoding = _bomless_utf16_encoding(data)
        if encoding is None:
            try:
                decoder = codecs.getincrementaldecoder("utf-8")(errors="strict")
                decoded = decoder.decode(data, final=False)
            except UnicodeDecodeError:
                return known_text or _looks_like_single_byte_text(data), None
            if not known_text and not _looks_like_text(decoded):
                return False, None
            encoding = "utf-8"
    return True, encoding


def _scan_text_stream(
    stream: BinaryIO,
    first_chunk: bytes,
    encoding: str,
    relative_path: str,
) -> list[Finding]:
    decoder = codecs.getincrementaldecoder(encoding)(errors="strict")
    blockers: list[Finding] = []
    detected_markers: set[str] = set()
    overlap = ""
    bytes_scanned = 0
    chunk = first_chunk
    try:
        while chunk:
            bytes_scanned += len(chunk)
            if bytes_scanned > MAX_TEXT_FILE_BYTES:
                return [
                    _finding(
                        "oversized_text_file",
                        relative_path,
                        "text file exceeds the 64 MiB scan limit.",
                    )
                ]
            decoded = decoder.decode(chunk, final=False)
            if "\x00" in decoded:
                return [_decoded_nul_blocker(relative_path, encoding)]
            overlap = _scan_text_window(
                overlap + decoded,
                relative_path,
                detected_markers,
                blockers,
            )
            chunk = stream.read(MAX_SCAN_BYTES)

        final_text = decoder.decode(b"", final=True)
        if "\x00" in final_text:
            return [_decoded_nul_blocker(relative_path, encoding)]
        _scan_text_window(
            overlap + final_text,
            relative_path,
            detected_markers,
            blockers,
        )
    except UnicodeDecodeError:
        return [
            _finding(
                "unscannable_text_file",
                relative_path,
                "text file could not be decoded completely as %s." % encoding,
            )
        ]
    return blockers


def _decoded_nul_blocker(relative_path: str, encoding: str) -> Finding:
    return _finding(
        "unscannable_text_file",
        relative_path,
        "text file contains an unexpected NUL after %s decoding." % encoding,
    )


def _scan_text_window(
    text: str,
    relative_path: str,
    detected_markers: set[str],
    blockers: list[Finding],
) -> str:
    for marker_id, pattern in SECRET_MARKERS:
        if marker_id not in detected_markers and pattern.search(text):
            detected_markers.add(marker_id)
            blockers.append(
                _finding(
                    "secret_marker",
                    relative_path,
                    "secret-like marker detected: %s." % marker_id,
                )
            )
    return text[-SCAN_OVERLAP_CHARS:]


def _bomless_utf16_encoding(data: bytes) -> str | None:
    if len(data) < 4:
        return None
    even_bytes = data[0::2]
    odd_bytes = data[1::2]
    even_nul_ratio = even_bytes.count(0) / len(even_bytes)
    odd_nul_ratio = odd_bytes.count(0) / len(odd_bytes)
    if odd_nul_ratio >= 0.3 and even_nul_ratio <= 0.05:
        return "utf-16-le"
    if even_nul_ratio >= 0.3 and odd_nul_ratio <= 0.05:
        return "utf-16-be"
    return None


def _looks_like_text(text: str) -> bool:
    if not text:
        return True
    allowed_controls = "\t\n\r\f"
    control_count = sum(
        1 for character in text if ord(character) < 32 and character not in allowed_controls
    )
    control_count += text.count("\x7f")
    return control_count / len(text) <= 0.02


def _looks_like_single_byte_text(data: bytes) -> bool:
    if not data:
        return True
    control_count = sum(
        1 for value in data if value < 32 and value not in {9, 10, 12, 13}
    )
    control_count += data.count(b"\x7f")
    return control_count / len(data) <= 0.02


def _is_known_text_file(path: Path) -> bool:
    return path.suffix.casefold() in TEXT_SUFFIXES or path.name.casefold() in TEXT_FILENAMES


def _manifest_source_claim_blockers(
    manifest: dict[str, object],
    source_files: list[str],
) -> list[Finding]:
    blockers: list[Finding] = []
    no_source_claim = manifest.get("no_source_claim")
    source_visible = manifest.get("source_visible")
    if not isinstance(no_source_claim, bool):
        blockers.append(
            _finding(
                "manifest_no_source_claim_invalid",
                MANIFEST_NAME,
                "no_source_claim must be bool.",
            )
        )
        no_source_claim = False
    if not isinstance(source_visible, bool):
        blockers.append(
            _finding(
                "manifest_source_visible_invalid",
                MANIFEST_NAME,
                "source_visible must be bool.",
            )
        )
        source_visible = True
    if no_source_claim and source_visible:
        blockers.append(
            _finding(
                "source_claim_conflict",
                MANIFEST_NAME,
                "no_source_claim=true conflicts with source_visible=true.",
            )
        )
    if no_source_claim and source_files:
        blockers.append(
            _finding(
                "source_files_with_no_source_claim",
                source_files[0],
                "source files are present while no_source_claim=true.",
            )
        )
    if source_files and not source_visible and not no_source_claim:
        blockers.append(
            _finding(
                "source_visibility_conflict",
                source_files[0],
                "source files are present while source_visible=false.",
            )
        )
    return blockers


def _is_source_file(path: Path) -> bool:
    return path.suffix.casefold() in SOURCE_SUFFIXES or path.name == "pyproject.toml"


def _is_forbidden_by_name(path: Path) -> bool:
    lowered_name = path.name.casefold()
    return (
        path.name in FORBIDDEN_FILENAMES
        or lowered_name == ".env"
        or lowered_name.startswith(".env.")
    )


def _write_reports(artifact_path: Path, report: dict[str, object]) -> None:
    (artifact_path / REPORT_JSON_NAME).write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    (artifact_path / REPORT_MD_NAME).write_text(_render_markdown(report), encoding="utf-8")


def _render_markdown(report: dict[str, object]) -> str:
    lines = [
        "# Delivery Check Report",
        "",
        "Status: `%s`" % report["status"],
        "",
        "Blockers: `%s`" % report["blocker_count"],
        "",
    ]
    blockers = report.get("blockers")
    if isinstance(blockers, list) and blockers:
        lines.append("## Blockers")
        lines.append("")
        for item in blockers:
            if isinstance(item, dict):
                lines.append(
                    "- `%s` at `%s`: %s"
                    % (
                        item.get("id", "unknown"),
                        item.get("path", "."),
                        item.get("detail", "blocked"),
                    )
                )
        lines.append("")
    return "\n".join(lines)


def _relative_path(root: Path, path: Path) -> str:
    try:
        return path.resolve().relative_to(root).as_posix()
    except ValueError:
        return path.name


def _finding(finding_id: str, path: str, detail: str) -> Finding:
    return {"id": finding_id, "path": path, "detail": detail}


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
