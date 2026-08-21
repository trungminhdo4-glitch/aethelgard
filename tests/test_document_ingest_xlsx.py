"""Tests for stdlib XLSX questionnaire ingest (no external spreadsheet deps)."""

from __future__ import annotations

import zipfile
from pathlib import Path
from typing import cast
from xml.sax.saxutils import escape

import pytest

from aethelgard.document_ingest import (
    DocumentIngestError,
    detect_document_type,
    parse_xlsx_document,
    run_document_ingest,
)
from aethelgard.redaction_preflight import has_sensitive_markers, mask_sensitive_text


def _column_letter(index: int) -> str:
    return chr(ord("A") + index)


def _write_shared_string_xlsx(path: Path, rows: list[list[str]]) -> None:
    """Write a minimal shared-string .xlsx (the layout Excel emits by default)."""
    shared: list[str] = []
    lookup: dict[str, int] = {}
    row_fragments: list[str] = []
    for row_number, row in enumerate(rows, start=1):
        cell_fragments: list[str] = []
        for column_index, value in enumerate(row):
            if value not in lookup:
                lookup[value] = len(shared)
                shared.append(value)
            reference = "%s%d" % (_column_letter(column_index), row_number)
            cell_fragments.append('<c r="%s" t="s"><v>%d</v></c>' % (reference, lookup[value]))
        row_fragments.append('<row r="%d">%s</row>' % (row_number, "".join(cell_fragments)))
    sheet_xml = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
        "<sheetData>%s</sheetData></worksheet>" % "".join(row_fragments)
    )
    shared_items = "".join("<si><t>%s</t></si>" % escape(value) for value in shared)
    shared_xml = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<sst xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" '
        'count="%d" uniqueCount="%d">%s</sst>' % (len(shared), len(shared), shared_items)
    )
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("xl/sharedStrings.xml", shared_xml)
        archive.writestr("xl/worksheets/sheet1.xml", sheet_xml)


def _write_empty_xlsx(path: Path) -> None:
    sheet_xml = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
        "<sheetData/></worksheet>"
    )
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("xl/worksheets/sheet1.xml", sheet_xml)


def test_detect_document_type_recognizes_xlsx(tmp_path: Path) -> None:
    assert detect_document_type(tmp_path / "questionnaire.xlsx") == "xlsx"


def test_parse_xlsx_reads_questionnaire_text(tmp_path: Path) -> None:
    path = tmp_path / "questionnaire.xlsx"
    _write_shared_string_xlsx(
        path,
        [
            ["Question", "Answer"],
            ["Is MFA enforced for administrators?", "Yes, MFA is enforced for all admin access."],
            ["Backup restore tested?", "Restore tests are reviewed quarterly."],
        ],
    )
    text = parse_xlsx_document(path)
    assert "MFA is enforced for all admin access." in text
    assert "Restore tests are reviewed quarterly." in text


def test_run_document_ingest_parses_xlsx_and_maps_evidence(tmp_path: Path) -> None:
    input_dir = tmp_path / "docs"
    input_dir.mkdir()
    _write_shared_string_xlsx(
        input_dir / "vendor_questionnaire.xlsx",
        [
            ["Control", "Response"],
            [
                "Access control",
                "Multi-factor authentication (MFA) is enforced for all admin access.",
            ],
        ],
    )
    report = run_document_ingest(input_dir)
    inventory = cast(dict[str, object], report["inventory"])
    documents = cast(list[dict[str, object]], inventory["documents"])
    assert len(documents) == 1
    assert documents[0]["source_type"] == "xlsx"
    assert documents[0]["status"] == "parsed"


def test_empty_xlsx_does_not_crash(tmp_path: Path) -> None:
    path = tmp_path / "empty.xlsx"
    _write_empty_xlsx(path)
    assert parse_xlsx_document(path) == ""

    input_dir = tmp_path / "docs"
    input_dir.mkdir()
    _write_empty_xlsx(input_dir / "empty.xlsx")
    report = run_document_ingest(input_dir)
    inventory = cast(dict[str, object], report["inventory"])
    documents = cast(list[dict[str, object]], inventory["documents"])
    assert documents[0]["source_type"] == "xlsx"
    assert documents[0]["status"] == "parse_error"


def test_corrupted_xlsx_reports_clear_error(tmp_path: Path) -> None:
    path = tmp_path / "corrupt.xlsx"
    path.write_bytes(b"this is not a valid xlsx zip container")
    with pytest.raises(DocumentIngestError) as excinfo:
        parse_xlsx_document(path)
    assert "could not parse xlsx document" in str(excinfo.value)


def test_xlsx_leaked_contact_is_masked_by_data_gate(tmp_path: Path) -> None:
    # NB: the temp dir must not contain forbidden path markers (e.g. "secret"),
    # because _is_forbidden_source_path rejects such sources fail-closed.
    path = tmp_path / "leaky.xlsx"
    leaked_email = "breach.contact@private.example"
    _write_shared_string_xlsx(
        path,
        [
            ["Question", "Answer"],
            ["Primary incident contact", "Escalate to %s immediately." % leaked_email],
        ],
    )
    text = parse_xlsx_document(path)
    assert leaked_email in text  # extraction is faithful ...
    assert has_sensitive_markers(text)  # ... the data-gate sees the leak ...
    assert leaked_email not in mask_sensitive_text(text)  # ... and neutralizes it.
