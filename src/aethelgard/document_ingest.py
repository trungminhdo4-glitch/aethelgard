"""Local document inventory, parsing, and deterministic evidence mapping."""

from __future__ import annotations

import csv
import hashlib
import json
import re
import zipfile
from collections import Counter
from collections.abc import Mapping, Sequence
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Final, Literal, cast
from xml.etree import ElementTree

from aethelgard.mvp1 import DocumentParserError
from aethelgard.mvp1.pdf_handler import extract_pdf_text, is_pypdf_available
from aethelgard.redaction_preflight import has_sensitive_markers, mask_sensitive_text

DOCUMENT_INVENTORY_NAME: Final[str] = "document_inventory.json"
DOCUMENT_SUMMARIES_NAME: Final[str] = "document_summaries.md"
EVIDENCE_MAP_NAME: Final[str] = "evidence_map.json"

MAX_INGEST_FILE_BYTES: Final[int] = 50_000_000
MAX_TEXT_CHARS: Final[int] = 1_000_000
MAX_JSON_SCALARS: Final[int] = 500
MAX_CSV_ROWS: Final[int] = 300
MAX_CSV_CELLS: Final[int] = 20
MAX_CELL_CHARS: Final[int] = 240
MAX_EXCERPT_CHARS: Final[int] = 240
DEFAULT_CHUNK_CHARS: Final[int] = 900
DEFAULT_CHUNK_OVERLAP: Final[int] = 120
DOC_ID_HASH_CHARS: Final[int] = 12
CHUNK_ID_HASH_CHARS: Final[int] = 10
EVIDENCE_ID_HASH_CHARS: Final[int] = 14
MIN_EVIDENCE_CONFIDENCE: Final[float] = 0.55
STRONG_EVIDENCE_CONFIDENCE: Final[float] = 0.74
PARTIAL_EVIDENCE_CONFIDENCE: Final[float] = 0.62
BASE_CONFIDENCE: Final[float] = 0.48
TERM_CONFIDENCE_DELTA: Final[float] = 0.06
CONCRETE_CONFIDENCE_DELTA: Final[float] = 0.04
NEGATIVE_CONFIDENCE_DELTA: Final[float] = 0.14
MAX_TERM_BOOST: Final[float] = 0.24
MAX_CONCRETE_BOOST: Final[float] = 0.16
MAX_NEGATIVE_PENALTY: Final[float] = 0.32
SCORE_MIN: Final[float] = 0.0
SCORE_MAX: Final[float] = 1.0

DocumentStatus = Literal["parsed", "unsupported", "ocr_required", "parse_error"]
SourceType = Literal[
    "text",
    "markdown",
    "csv",
    "json",
    "docx",
    "xlsx",
    "pdf",
    "image",
    "unsupported",
]
CoverageStatus = Literal[
    "covered",
    "partial",
    "missing",
    "needs_review",
    "conflicting",
    "stale_evidence",
    "unsupported",
]

TEXT_SUFFIXES: Final[frozenset[str]] = frozenset({".txt"})
MARKDOWN_SUFFIXES: Final[frozenset[str]] = frozenset({".md", ".markdown"})
CSV_SUFFIXES: Final[frozenset[str]] = frozenset({".csv"})
JSON_SUFFIXES: Final[frozenset[str]] = frozenset({".json"})
DOCX_SUFFIXES: Final[frozenset[str]] = frozenset({".docx"})
XLSX_SUFFIXES: Final[frozenset[str]] = frozenset({".xlsx"})
PDF_SUFFIXES: Final[frozenset[str]] = frozenset({".pdf"})
IMAGE_SUFFIXES: Final[frozenset[str]] = frozenset({".jpg", ".jpeg", ".png"})
SUPPORTED_PARSE_SUFFIXES: Final[frozenset[str]] = frozenset(
    TEXT_SUFFIXES
    | MARKDOWN_SUFFIXES
    | CSV_SUFFIXES
    | JSON_SUFFIXES
    | DOCX_SUFFIXES
    | XLSX_SUFFIXES
    | PDF_SUFFIXES
)

EXCLUDED_DIR_NAMES: Final[frozenset[str]] = frozenset(
    {
        ".git",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        ".tmp",
        ".venv",
        ".venv-fresh",
        "__pycache__",
        "build",
        "dist",
        "reports",
        "venv",
    }
)
FORBIDDEN_SOURCE_SUFFIXES: Final[frozenset[str]] = frozenset(
    {".db", ".db-shm", ".db-wal", ".log", ".sqlite", ".sqlite-shm", ".sqlite-wal", ".sqlite3"}
)
FORBIDDEN_SOURCE_NAME_MARKERS: Final[tuple[str, ...]] = (
    ".env",
    "credential",
    "credentials",
    "cookie",
    "cookies",
    "private-config",
    "secret",
    "secrets",
)

TOPIC_CLUSTERS: Final[tuple[str, ...]] = (
    "access_control",
    "mfa",
    "identity_lifecycle",
    "privileged_access",
    "backup",
    "restore_test",
    "incident_response",
    "business_continuity",
    "patch_management",
    "vulnerability_management",
    "logging_monitoring",
    "asset_inventory",
    "supplier_management",
    "data_protection",
    "encryption",
    "awareness_training",
    "risk_management",
    "policy_governance",
    "sbom",
    "secure_development",
    "change_management",
)

CONTROL_ALIASES: Final[dict[str, tuple[str, ...]]] = {
    "access_control": (
        "access control",
        "access review",
        "least privilege",
        "role based access",
        "rollen und rechte",
        "zugriffskontrolle",
    ),
    "mfa": (
        "2fa",
        "mfa",
        "multi factor",
        "multi-factor",
        "multifaktor",
        "strong authentication",
    ),
    "identity_lifecycle": (
        "deprovision",
        "identity lifecycle",
        "joiner mover leaver",
        "leaver",
        "onboarding and offboarding",
        "user lifecycle",
    ),
    "privileged_access": (
        "admin account",
        "pam",
        "privileged access",
        "privileged account",
        "service account",
    ),
    "backup": (
        "backup",
        "backup policy",
        "datensicherung",
        "immutable backup",
        "offsite backup",
    ),
    "restore_test": (
        "disaster recovery test",
        "restore test",
        "restoration test",
        "recovery test",
        "wiederherstellungstest",
    ),
    "incident_response": (
        "72 hours",
        "incident response",
        "incident timeline",
        "meldepflicht",
        "security incident",
    ),
    "business_continuity": (
        "business continuity",
        "bcm",
        "continuity exercise",
        "emergency plan",
        "notfallplan",
    ),
    "patch_management": (
        "patch management",
        "patch schedule",
        "security patch",
        "update cadence",
        "update management",
    ),
    "vulnerability_management": (
        "remediation timeline",
        "vulnerability management",
        "vulnerability scan",
        "vulnerability tracking",
        "weakness remediation",
    ),
    "logging_monitoring": (
        "audit log",
        "central logging",
        "log monitoring",
        "monitoring alert",
        "siem",
    ),
    "asset_inventory": (
        "asset inventory",
        "asset register",
        "device inventory",
        "inventarisierung",
        "software inventory",
    ),
    "supplier_management": (
        "supplier review",
        "supplier security",
        "third party",
        "vendor assessment",
        "vendor security",
    ),
    "data_protection": (
        "data protection",
        "data processing",
        "dpa",
        "dsgvo",
        "personal data",
        "privacy",
    ),
    "encryption": (
        "encryption",
        "encryption at rest",
        "key management",
        "tls",
        "verschluesselung",
    ),
    "awareness_training": (
        "awareness training",
        "cybersecurity training",
        "phishing training",
        "security awareness",
        "sicherheitsschulung",
    ),
    "risk_management": (
        "risk assessment",
        "risk management",
        "risk owner",
        "risk register",
        "risikoanalyse",
    ),
    "policy_governance": (
        "annual review",
        "approved policy",
        "governance",
        "policy owner",
        "review cadence",
        "richtlinie",
    ),
    "sbom": (
        "bill of materials",
        "cyclonedx",
        "sbom",
        "software bill of materials",
        "software supply chain",
    ),
    "secure_development": (
        "secure coding",
        "secure development",
        "secure maintenance",
        "security review",
        "software security",
    ),
    "change_management": (
        "change approval",
        "change control",
        "change management",
        "release approval",
        "rollback plan",
    ),
}

CONCRETE_EVIDENCE_TERMS: Final[tuple[str, ...]] = (
    "approved",
    "assigned",
    "documented",
    "evidence",
    "implemented",
    "monthly",
    "owner",
    "quarterly",
    "record",
    "reviewed",
    "tested",
)
NEGATIVE_EVIDENCE_TERMS: Final[tuple[str, ...]] = (
    "ad hoc",
    "missing",
    "no evidence",
    "not defined",
    "not documented",
    "planned only",
    "placeholder",
    "tbd",
)
STALE_EVIDENCE_TERMS: Final[tuple[str, ...]] = (
    "expired",
    "last reviewed 2021",
    "last reviewed 2022",
    "last reviewed 2023",
    "outdated",
    "superseded",
)
CONFLICTING_EVIDENCE_TERMS: Final[tuple[str, ...]] = (
    "conflicting evidence",
    "contradicts",
    "exception not approved",
    "however no",
    "not consistently",
)


class DocumentIngestError(ValueError):
    """Raised when document ingest cannot be completed safely."""


def scan_input_dir(path: Path | str) -> list[Path]:
    """Return local input files in stable order without entering generated/cached folders."""
    root = Path(path)
    if root.is_file():
        return [root]
    if not root.exists():
        raise DocumentIngestError("input path does not exist: %s" % root)
    if not root.is_dir():
        raise DocumentIngestError("input path must be a file or directory: %s" % root)
    return [
        candidate
        for candidate in sorted(root.rglob("*"), key=lambda item: item.as_posix().casefold())
        if candidate.is_file() and not any(part in EXCLUDED_DIR_NAMES for part in candidate.parts)
    ]


def detect_document_type(path: Path | str) -> SourceType:
    """Classify a document by extension without reading contents."""
    suffix = Path(path).suffix.lower()
    suffix_map: tuple[tuple[frozenset[str], SourceType], ...] = (
        (TEXT_SUFFIXES, "text"),
        (MARKDOWN_SUFFIXES, "markdown"),
        (CSV_SUFFIXES, "csv"),
        (JSON_SUFFIXES, "json"),
        (DOCX_SUFFIXES, "docx"),
        (XLSX_SUFFIXES, "xlsx"),
        (PDF_SUFFIXES, "pdf"),
        (IMAGE_SUFFIXES, "image"),
    )
    source_type: SourceType = "unsupported"
    for suffixes, candidate_type in suffix_map:
        if suffix in suffixes:
            source_type = candidate_type
            break
    return source_type


def compute_document_hash(path: Path | str) -> str:
    """Compute a SHA-256 fingerprint for a local non-secret file."""
    source = Path(path)
    _guard_readable_non_secret_file(source)
    digest = hashlib.sha256()
    with source.open("rb") as input_file:
        for chunk in iter(lambda: input_file.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def parse_text_document(path: Path | str) -> str:
    """Read UTF-8-ish plain text with replacement fallback."""
    source = Path(path)
    raw_content = _read_bounded_bytes(source)
    return _decode_text(raw_content)


def parse_markdown_document(path: Path | str) -> str:
    """Read Markdown as text; rendering is intentionally out of scope."""
    return parse_text_document(path)


def parse_json_csv_if_applicable(path: Path | str) -> str:
    """Parse CSV/JSON into bounded deterministic text for local matching."""
    source = Path(path)
    source_type = detect_document_type(source)
    if source_type == "csv":
        return _parse_csv_document(source)
    if source_type == "json":
        return _parse_json_document(source)
    raise DocumentIngestError("file is not CSV or JSON: %s" % source)


def parse_docx_document(path: Path | str) -> str:
    """Extract DOCX body text with stdlib ZIP/XML parsing."""
    source = Path(path)
    _guard_readable_non_secret_file(source)
    try:
        with zipfile.ZipFile(source) as docx:
            xml_bytes = docx.read("word/document.xml")
    except (KeyError, OSError, zipfile.BadZipFile) as exc:
        raise DocumentIngestError("could not parse docx document: %s" % source.name) from exc
    if len(xml_bytes) > MAX_TEXT_CHARS:
        raise DocumentIngestError("docx document.xml exceeds text size limit")
    try:
        root = ElementTree.fromstring(xml_bytes)
    except ElementTree.ParseError as exc:
        raise DocumentIngestError("docx document.xml is not valid XML") from exc
    texts = [
        element.text.strip()
        for element in root.iter()
        if element.tag.endswith("}t") and element.text and element.text.strip()
    ]
    return "\n".join(texts)


_XLSX_SHARED_STRINGS_PATH: Final[str] = "xl/sharedStrings.xml"
_XLSX_WORKSHEET_PREFIX: Final[str] = "xl/worksheets/"


def parse_xlsx_document(path: Path | str) -> str:
    """Extract XLSX cell text with stdlib ZIP/XML parsing (no external deps)."""
    source = Path(path)
    _guard_readable_non_secret_file(source)
    try:
        with zipfile.ZipFile(source) as workbook:
            shared_strings = _read_xlsx_shared_strings(workbook)
            cell_values = _read_xlsx_cell_values(workbook, shared_strings)
    except (KeyError, OSError, zipfile.BadZipFile, ElementTree.ParseError) as exc:
        raise DocumentIngestError("could not parse xlsx document: %s" % source.name) from exc
    return "\n".join(cell_values)


def _xlsx_text_runs(element: ElementTree.Element) -> str:
    """Concatenate the text of every ``<t>`` descendant of an element."""
    parts: list[str] = []
    for node in element.iter():
        if node.tag.endswith("}t") and node.text:
            parts.append(node.text)
    return "".join(parts)


def _xlsx_child_text(element: ElementTree.Element, local_tag_suffix: str) -> str | None:
    """Return the text of the first direct child whose tag matches the suffix."""
    for child in element:
        if child.tag.endswith(local_tag_suffix):
            return child.text
    return None


def _read_xlsx_shared_strings(workbook: zipfile.ZipFile) -> list[str]:
    """Return the workbook's shared-string table, empty when the part is absent."""
    if _XLSX_SHARED_STRINGS_PATH not in workbook.namelist():
        return []
    xml_bytes = workbook.read(_XLSX_SHARED_STRINGS_PATH)
    if len(xml_bytes) > MAX_TEXT_CHARS:
        raise DocumentIngestError("xlsx sharedStrings.xml exceeds text size limit")
    root = ElementTree.fromstring(xml_bytes)
    return [_xlsx_text_runs(item) for item in root if item.tag.endswith("}si")]


def _read_xlsx_cell_values(workbook: zipfile.ZipFile, shared_strings: list[str]) -> list[str]:
    """Extract non-empty worksheet cell values in a bounded, deterministic order."""
    worksheet_names = sorted(
        name
        for name in workbook.namelist()
        if name.startswith(_XLSX_WORKSHEET_PREFIX) and name.endswith(".xml")
    )
    values: list[str] = []
    total_chars = 0
    for worksheet_name in worksheet_names:
        xml_bytes = workbook.read(worksheet_name)
        if len(xml_bytes) > MAX_TEXT_CHARS:
            raise DocumentIngestError("xlsx worksheet exceeds text size limit")
        root = ElementTree.fromstring(xml_bytes)
        for cell in root.iter():
            if not cell.tag.endswith("}c"):
                continue
            value = _xlsx_cell_value(cell, shared_strings)
            if not value:
                continue
            values.append(value)
            total_chars += len(value)
            if total_chars > MAX_TEXT_CHARS:
                return values
    return values


def _xlsx_cell_value(cell: ElementTree.Element, shared_strings: list[str]) -> str:
    """Resolve one worksheet cell to text, honoring the shared-string table."""
    cell_type = cell.get("t")
    if cell_type == "s":
        raw_index = _xlsx_child_text(cell, "}v")
        if raw_index is None or not raw_index.isdigit():
            return ""
        index = int(raw_index)
        return shared_strings[index].strip() if 0 <= index < len(shared_strings) else ""
    if cell_type == "inlineStr":
        return _xlsx_text_runs(cell).strip()
    return (_xlsx_child_text(cell, "}v") or "").strip()


def parse_pdf_document(path: Path | str) -> str:
    """Extract PDF text only when the optional pypdf support is available."""
    if not is_pypdf_available():
        raise DocumentIngestError("pdf parsing requires optional pypdf support")
    try:
        return extract_pdf_text(Path(path))
    except DocumentParserError as exc:
        raise DocumentIngestError("could not parse pdf document: %s" % Path(path).name) from exc


def mark_image_requires_ocr(path: Path | str) -> dict[str, object]:
    """Return a structured OCR-needed inventory marker for image files."""
    source = Path(path)
    return {
        "source_path": source.name,
        "source_type": "image",
        "status": "ocr_required",
        "reason": "image_ocr_required",
    }


def chunk_document_text(
    text: str,
    *,
    max_chars: int = DEFAULT_CHUNK_CHARS,
    overlap: int = DEFAULT_CHUNK_OVERLAP,
) -> tuple[dict[str, object], ...]:
    """Chunk text with deterministic character windows."""
    if max_chars <= overlap:
        raise DocumentIngestError("max_chars must be greater than overlap")
    normalized = _normalize_whitespace(text)
    if not normalized:
        return ()
    chunks: list[dict[str, object]] = []
    start = 0
    while start < len(normalized):
        end = min(start + max_chars, len(normalized))
        chunk_text = normalized[start:end].strip()
        if chunk_text:
            chunks.append(
                {
                    "chunk_index": len(chunks) + 1,
                    "start_char": start,
                    "end_char": end,
                    "text": chunk_text,
                    "snippet_hash": _sha256_text(chunk_text),
                }
            )
        if end >= len(normalized):
            break
        start = max(end - overlap, start + 1)
    return tuple(chunks)


def summarize_document_deterministic(
    document: Mapping[str, object],
    chunks: Sequence[Mapping[str, object]],
    evidence: Sequence[Mapping[str, object]],
) -> dict[str, object]:
    """Build a deterministic metadata-only summary for one document."""
    topic_counts = Counter(
        topic for item in evidence for topic in cast(Sequence[str], item.get("detected_topics", ()))
    )
    return {
        "document_id": document.get("document_id", ""),
        "source_path": document.get("source_path", ""),
        "source_type": document.get("source_type", ""),
        "status": document.get("status", ""),
        "chunk_count": len(chunks),
        "evidence_count": len(evidence),
        "detected_topics": tuple(sorted(topic_counts)),
        "top_topics": tuple(topic for topic, _count in topic_counts.most_common(5)),
        "reason": document.get("reason", ""),
        "truncated": document.get("truncated", False),
        "original_chars": document.get("original_chars", 0),
    }


def extract_evidence_candidates(
    chunks: Sequence[Mapping[str, object]],
    *,
    document_id: str,
    source_path: str,
    source_type: SourceType,
    include_local_excerpts: bool = True,
) -> tuple[dict[str, object], ...]:
    """Extract deterministic evidence candidates from parsed chunks."""
    candidates: list[dict[str, object]] = []
    for chunk in chunks:
        chunk_text = str(chunk["text"])
        matches = detect_topics_for_text(chunk_text)
        if not matches:
            continue
        signal = _score_chunk(chunk_text, matches)
        confidence = _to_float(signal["confidence"])
        if confidence < MIN_EVIDENCE_CONFIDENCE:
            continue
        chunk_id = _build_stable_id(
            "CH",
            (document_id, str(chunk["chunk_index"]), str(chunk["snippet_hash"])),
            CHUNK_ID_HASH_CHARS,
        )
        snippet_hash = str(chunk["snippet_hash"])
        topics = tuple(sorted(matches))
        evidence_id = _build_stable_id(
            "EV",
            (document_id, chunk_id, snippet_hash, "\n".join(topics)),
            EVIDENCE_ID_HASH_CHARS,
        )
        item: dict[str, object] = {
            "evidence_id": evidence_id,
            "document_id": document_id,
            "source_path": source_path,
            "source_type": source_type,
            "page_or_section": "chunk:%s" % chunk["chunk_index"],
            "chunk_id": chunk_id,
            "snippet_hash": snippet_hash,
            "detected_topics": topics,
            "mapped_controls": topics,
            "confidence": confidence,
            "status": signal["status"],
            "reason": signal["reason"],
            "matched_terms": tuple(sorted({term for terms in matches.values() for term in terms})),
            "requires_human_review": signal["status"] != "covered",
        }
        if include_local_excerpts:
            item["redacted_excerpt"] = _redacted_excerpt(chunk_text)
        candidates.append(item)
    return tuple(sorted(candidates, key=lambda item: str(item["evidence_id"])))


def detect_topics_for_text(text: str) -> dict[str, tuple[str, ...]]:
    """Return matched topic clusters and the exact aliases that triggered them."""
    normalized = _normalize_for_match(text)
    matches: dict[str, tuple[str, ...]] = {}
    for topic, aliases in CONTROL_ALIASES.items():
        hits = tuple(alias for alias in aliases if _normalize_for_match(alias) in normalized)
        if hits:
            matches[topic] = hits
    return matches


def run_document_ingest(
    input_path: Path | str,
    out_dir: Path | str | None = None,
    *,
    include_local_excerpts: bool = True,
) -> dict[str, object]:
    """Scan documents, parse supported files, and build deterministic evidence metadata."""
    root = Path(input_path)
    files = scan_input_dir(root)
    documents: list[dict[str, object]] = []
    all_chunks: list[dict[str, object]] = []
    all_evidence: list[dict[str, object]] = []
    summaries: list[dict[str, object]] = []

    for file_path in files:
        document, chunks, evidence = _process_document(
            file_path,
            root,
            include_local_excerpts=include_local_excerpts,
        )
        documents.append(document)
        all_chunks.extend(chunks)
        all_evidence.extend(evidence)
        summaries.append(summarize_document_deterministic(document, chunks, evidence))

    status_counts = Counter(str(document["status"]) for document in documents)
    evidence_map = {
        "schema_version": "1.0",
        "evidence_count": len(all_evidence),
        "coverage": build_topic_coverage(all_evidence, documents),
        "evidence": all_evidence,
    }
    inventory = {
        "schema_version": "1.0",
        "input_label": root.name if root.name else str(root),
        "document_count": len(documents),
        "status_counts": {
            "parsed": status_counts.get("parsed", 0),
            "unsupported": status_counts.get("unsupported", 0),
            "ocr_required": status_counts.get("ocr_required", 0),
            "parse_error": status_counts.get("parse_error", 0),
        },
        "documents": documents,
    }
    report: dict[str, object] = {
        "schema_version": "1.0",
        "inventory": inventory,
        "chunks": all_chunks,
        "evidence_map": evidence_map,
        "summaries": summaries,
    }
    if out_dir is not None:
        write_document_ingest_outputs(report, Path(out_dir))
    return report


def build_topic_coverage(
    evidence: Sequence[Mapping[str, object]],
    documents: Sequence[Mapping[str, object]],
) -> list[dict[str, object]]:
    """Build conservative topic coverage without making compliance claims."""
    unsupported_count = sum(1 for document in documents if document.get("status") != "parsed")
    coverage: list[dict[str, object]] = []
    for topic in TOPIC_CLUSTERS:
        topic_items = [
            item
            for item in evidence
            if topic in cast(Sequence[str], item.get("mapped_controls", ()))
        ]
        if not topic_items:
            status: CoverageStatus = (
                "unsupported" if unsupported_count and not evidence else "missing"
            )
            reason = "No local evidence candidate mapped to %s." % topic
            max_confidence = 0.0
        else:
            statuses = {str(item.get("status", "")) for item in topic_items}
            max_confidence = max(_to_float(item.get("confidence", 0.0)) for item in topic_items)
            if "conflicting" in statuses:
                status = "conflicting"
            elif "stale_evidence" in statuses:
                status = "stale_evidence"
            elif max_confidence >= STRONG_EVIDENCE_CONFIDENCE:
                status = "covered"
            elif max_confidence >= PARTIAL_EVIDENCE_CONFIDENCE:
                status = "partial"
            else:
                status = "needs_review"
            reason = "Mapped %d local evidence candidate(s) to %s." % (len(topic_items), topic)
        coverage.append(
            {
                "control": topic,
                "status": status,
                "evidence_refs": tuple(str(item["evidence_id"]) for item in topic_items),
                "confidence": round(max_confidence, 4),
                "reason": reason,
            }
        )
    return coverage


def render_document_summaries_markdown(report: Mapping[str, object]) -> str:
    """Render a metadata-only document summary."""
    inventory = cast(Mapping[str, object], report["inventory"])
    summaries = cast(Sequence[Mapping[str, object]], report["summaries"])
    status_counts = cast(Mapping[str, int], inventory["status_counts"])
    document_count = _to_int(inventory["document_count"])
    lines = [
        "# AethelGard Document Inventory",
        "",
        "## Status",
        "- Documents: `%d`" % document_count,
        "- Parsed: `%d`" % status_counts["parsed"],
        "- Unsupported: `%d`" % status_counts["unsupported"],
        "- OCR required: `%d`" % status_counts["ocr_required"],
        "- Parse errors: `%d`" % status_counts["parse_error"],
        "",
        "## Documents",
        "| Document | Type | Status | Chunks | Evidence | Topics |",
        "|---|---|---:|---:|---:|---|",
    ]
    for summary in summaries:
        topics = ", ".join(cast(Sequence[str], summary["detected_topics"])) or "-"
        lines.append(
            "| `%s` | `%s` | `%s` | %d | %d | `%s` |"
            % (
                _escape_markdown(str(summary["source_path"])),
                _escape_markdown(str(summary["source_type"])),
                _escape_markdown(str(summary["status"])),
                _to_int(summary["chunk_count"]),
                _to_int(summary["evidence_count"]),
                _escape_markdown(topics),
            )
        )
    lines.extend(
        [
            "",
            "## Boundary",
            "- Unsupported files are inventoried instead of guessed.",
            "- Images are marked `ocr_required`; no OCR is attempted in this local slice.",
            "- This summary is a review aid, not a legal or audit conclusion.",
        ]
    )
    return "\n".join(lines) + "\n"


def write_document_ingest_outputs(report: Mapping[str, object], out_dir: Path) -> None:
    """Write document inventory, evidence map, and summary files."""
    out_dir.mkdir(parents=True, exist_ok=True)
    _write_json(out_dir / DOCUMENT_INVENTORY_NAME, cast(Mapping[str, object], report["inventory"]))
    _write_json(
        out_dir / EVIDENCE_MAP_NAME,
        cast(Mapping[str, object], report["evidence_map"]),
    )
    _write_text(out_dir / DOCUMENT_SUMMARIES_NAME, render_document_summaries_markdown(report))


def _process_document(
    path: Path,
    root: Path,
    *,
    include_local_excerpts: bool,
) -> tuple[dict[str, object], list[dict[str, object]], list[dict[str, object]]]:
    source_type = detect_document_type(path)
    source_path = _safe_relative(path, root)
    if _is_forbidden_source_path(path):
        document = _document_record(
            path=path,
            root=root,
            source_type=source_type,
            status="unsupported",
            reason="forbidden_secret_like_path",
            sha256="",
            evidence_count=0,
        )
        return document, [], []
    if source_type == "image":
        digest = _safe_hash_or_empty(path)
        document = _document_record(
            path=path,
            root=root,
            source_type=source_type,
            status="ocr_required",
            reason="image_ocr_required",
            sha256=digest,
            evidence_count=0,
        )
        return document, [], []
    if source_type == "unsupported":
        digest = _safe_hash_or_empty(path)
        document = _document_record(
            path=path,
            root=root,
            source_type=source_type,
            status="unsupported",
            reason="unsupported_extension",
            sha256=digest,
            evidence_count=0,
        )
        return document, [], []

    try:
        digest = compute_document_hash(path)
        raw_text = _parse_by_type(path, source_type)
        text = _bounded_text(raw_text)
        if not text.strip():
            raise DocumentIngestError("parsed document contains no text")
    except (OSError, UnicodeError, DocumentIngestError) as exc:
        document = _document_record(
            path=path,
            root=root,
            source_type=source_type,
            status="parse_error",
            reason=_safe_error_reason(str(exc)),
            sha256="",
            evidence_count=0,
        )
        return document, [], []

    document_id = _build_document_id(source_path, digest, source_type)
    chunks = [
        {
            **chunk,
            "chunk_id": _build_stable_id(
                "CH",
                (document_id, str(chunk["chunk_index"]), str(chunk["snippet_hash"])),
                CHUNK_ID_HASH_CHARS,
            ),
            "document_id": document_id,
        }
        for chunk in chunk_document_text(text)
    ]
    evidence = list(
        extract_evidence_candidates(
            chunks,
            document_id=document_id,
            source_path=source_path,
            source_type=source_type,
            include_local_excerpts=include_local_excerpts,
        )
    )
    document = _document_record(
        path=path,
        root=root,
        source_type=source_type,
        status="parsed",
        reason="parsed",
        sha256=digest,
        evidence_count=len(evidence),
        document_id=document_id,
        text_hash=_sha256_text(_normalize_whitespace(text)),
        chunk_count=len(chunks),
        truncated=len(raw_text) > len(text),
        original_chars=len(raw_text),
    )
    stored_chunks = [_strip_private_chunk_text(chunk) for chunk in chunks]
    return document, stored_chunks, evidence


def _parse_by_type(path: Path, source_type: SourceType) -> str:
    if source_type == "text":
        return parse_text_document(path)
    if source_type == "markdown":
        return parse_markdown_document(path)
    if source_type in {"csv", "json"}:
        return parse_json_csv_if_applicable(path)
    if source_type == "docx":
        return parse_docx_document(path)
    if source_type == "xlsx":
        return parse_xlsx_document(path)
    if source_type == "pdf":
        return parse_pdf_document(path)
    raise DocumentIngestError("unsupported source type: %s" % source_type)


def _document_record(
    *,
    path: Path,
    root: Path,
    source_type: SourceType,
    status: DocumentStatus,
    reason: str,
    sha256: str,
    evidence_count: int,
    document_id: str | None = None,
    text_hash: str = "",
    chunk_count: int = 0,
    truncated: bool = False,
    original_chars: int = 0,
) -> dict[str, object]:
    source_path = _safe_relative(path, root)
    stable_id = document_id or _build_document_id(source_path, sha256 or reason, source_type)
    return {
        "document_id": stable_id,
        "source_path": source_path,
        "source_type": source_type,
        "status": status,
        "reason": reason,
        "sha256": sha256,
        "text_hash": text_hash,
        "chunk_count": chunk_count,
        "evidence_count": evidence_count,
        "truncated": truncated,
        "original_chars": original_chars,
    }


def _score_chunk(text: str, matches: Mapping[str, Sequence[str]]) -> dict[str, object]:
    normalized = _normalize_for_match(text)
    matched_terms = tuple({term for terms in matches.values() for term in terms})
    concrete_hits = tuple(term for term in CONCRETE_EVIDENCE_TERMS if term in normalized)
    negative_hits = tuple(term for term in NEGATIVE_EVIDENCE_TERMS if term in normalized)
    stale_hits = tuple(term for term in STALE_EVIDENCE_TERMS if term in normalized)
    conflicting_hits = tuple(term for term in CONFLICTING_EVIDENCE_TERMS if term in normalized)
    confidence = (
        BASE_CONFIDENCE
        + min(len(matched_terms) * TERM_CONFIDENCE_DELTA, MAX_TERM_BOOST)
        + min(len(concrete_hits) * CONCRETE_CONFIDENCE_DELTA, MAX_CONCRETE_BOOST)
        - min(
            (len(negative_hits) + len(stale_hits) + len(conflicting_hits))
            * NEGATIVE_CONFIDENCE_DELTA,
            MAX_NEGATIVE_PENALTY,
        )
    )
    confidence = round(min(max(confidence, SCORE_MIN), SCORE_MAX), 4)
    if conflicting_hits:
        status: CoverageStatus = "conflicting"
    elif stale_hits:
        status = "stale_evidence"
    elif negative_hits or confidence < STRONG_EVIDENCE_CONFIDENCE:
        status = "needs_review"
    else:
        status = "covered"
    reason_parts = [
        "matched_terms=%s" % ", ".join(sorted(matched_terms)),
        "concrete_terms=%s" % (", ".join(concrete_hits) or "-"),
    ]
    if negative_hits:
        reason_parts.append("negative_terms=%s" % ", ".join(negative_hits))
    if stale_hits:
        reason_parts.append("stale_terms=%s" % ", ".join(stale_hits))
    if conflicting_hits:
        reason_parts.append("conflicting_terms=%s" % ", ".join(conflicting_hits))
    return {
        "confidence": confidence,
        "status": status,
        "reason": "; ".join(reason_parts),
    }


def _parse_csv_document(path: Path) -> str:
    rows: list[str] = []
    with path.open(encoding="utf-8", newline="") as csv_file:
        reader = csv.reader(csv_file)
        for row_index, row in enumerate(reader, start=1):
            if row_index > MAX_CSV_ROWS:
                break
            bounded_cells = [
                _truncate(cell.strip(), MAX_CELL_CHARS)
                for cell in row[:MAX_CSV_CELLS]
                if cell.strip()
            ]
            if bounded_cells:
                rows.append(" | ".join(bounded_cells))
    return "\n".join(rows)


def _parse_json_document(path: Path) -> str:
    payload = json.loads(_read_bounded_bytes(path).decode("utf-8"))
    scalars: list[str] = []
    _collect_json_scalars(payload, scalars)
    return "\n".join(scalars[:MAX_JSON_SCALARS])


def _collect_json_scalars(value: object, scalars: list[str]) -> None:
    if len(scalars) >= MAX_JSON_SCALARS:
        return
    if isinstance(value, Mapping):
        for key in sorted(value, key=str):
            scalars.append(_truncate(str(key), MAX_CELL_CHARS))
            _collect_json_scalars(value[key], scalars)
            if len(scalars) >= MAX_JSON_SCALARS:
                break
    elif isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        for item in value:
            _collect_json_scalars(item, scalars)
            if len(scalars) >= MAX_JSON_SCALARS:
                break
    elif value is not None:
        scalars.append(_truncate(str(value), MAX_CELL_CHARS))


def _read_bounded_bytes(path: Path) -> bytes:
    _guard_readable_non_secret_file(path)
    with path.open("rb") as input_file:
        data = input_file.read(MAX_INGEST_FILE_BYTES + 1)
    if len(data) > MAX_INGEST_FILE_BYTES:
        raise DocumentIngestError("file exceeds ingest size limit: %s" % path.name)
    if b"\x00" in data and path.suffix.lower() not in DOCX_SUFFIXES:
        raise DocumentIngestError("binary-like file cannot be parsed as text: %s" % path.name)
    return data


def _decode_text(raw_content: bytes) -> str:
    try:
        return raw_content.decode("utf-8")
    except UnicodeDecodeError:
        return raw_content.decode("utf-8", errors="replace")


def _bounded_text(text: str) -> str:
    if len(text) <= MAX_TEXT_CHARS:
        return text
    return text[:MAX_TEXT_CHARS]


def _guard_readable_non_secret_file(path: Path) -> None:
    if not path.is_file():
        raise DocumentIngestError("document source is not a file: %s" % path)
    if _is_forbidden_source_path(path):
        raise DocumentIngestError("forbidden secret-like document source path")
    if path.stat().st_size > MAX_INGEST_FILE_BYTES:
        raise DocumentIngestError("file exceeds ingest size limit: %s" % path.name)


def _is_forbidden_source_path(path: Path) -> bool:
    for part in path.parts:
        lowered = part.lower()
        if lowered == ".env" or lowered.startswith(".env."):
            return True
        if any(marker in lowered for marker in FORBIDDEN_SOURCE_NAME_MARKERS):
            return True
    suffix = PureWindowsPath(path.name.lower()).suffix or PurePosixPath(path.name.lower()).suffix
    return suffix in FORBIDDEN_SOURCE_SUFFIXES


def _safe_hash_or_empty(path: Path) -> str:
    try:
        return compute_document_hash(path)
    except DocumentIngestError:
        return ""


def _build_document_id(source_path: str, digest_or_reason: str, source_type: SourceType) -> str:
    return _build_stable_id("DOC", (source_path, digest_or_reason, source_type), DOC_ID_HASH_CHARS)


def _build_stable_id(prefix: str, parts: Sequence[str], hash_chars: int) -> str:
    basis = "\n".join(_normalize_for_match(part) for part in parts)
    digest = hashlib.sha256(basis.encode("utf-8")).hexdigest()[:hash_chars]
    return "%s-%s" % (prefix, digest)


def _sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _safe_relative(path: Path, root: Path) -> str:
    base = root if root.is_dir() else root.parent
    try:
        return path.relative_to(base).as_posix()
    except ValueError:
        return path.name


def _strip_private_chunk_text(chunk: Mapping[str, object]) -> dict[str, object]:
    return {
        "chunk_id": chunk["chunk_id"],
        "document_id": chunk["document_id"],
        "chunk_index": chunk["chunk_index"],
        "start_char": chunk["start_char"],
        "end_char": chunk["end_char"],
        "snippet_hash": chunk["snippet_hash"],
    }


def _redacted_excerpt(text: str) -> str:
    excerpt = _truncate(" ".join(text.split()), MAX_EXCERPT_CHARS)
    return mask_sensitive_text(excerpt) if has_sensitive_markers(excerpt) else excerpt


def _safe_error_reason(reason: str) -> str:
    single_line = " ".join(reason.split())
    return mask_sensitive_text(_truncate(single_line, MAX_CELL_CHARS))


def _normalize_whitespace(text: str) -> str:
    return " ".join(text.split())


def _normalize_for_match(text: str) -> str:
    return " ".join(text.casefold().replace("-", " ").replace("_", " ").split())


def _truncate(value: str, max_chars: int) -> str:
    if len(value) <= max_chars:
        return value
    return value[: max_chars - 3].rstrip() + "..."


def _to_int(value: object) -> int:
    if isinstance(value, int):
        return value
    if isinstance(value, float | str):
        return int(value)
    raise DocumentIngestError("expected numeric value")


def _to_float(value: object) -> float:
    if isinstance(value, int | float):
        return float(value)
    if isinstance(value, str):
        return float(value)
    raise DocumentIngestError("expected numeric value")


def _escape_markdown(value: str) -> str:
    return re.sub(r"([`*_\[\]<>|])", r"\\\1", value)


def _write_json(path: Path, payload: Mapping[str, object]) -> None:
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _write_text(path: Path, text: str) -> None:
    path.write_text(text, encoding="utf-8")
