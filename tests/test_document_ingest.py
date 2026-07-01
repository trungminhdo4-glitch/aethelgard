"""Tests for local document ingest and deterministic evidence mapping."""

from __future__ import annotations

import json
import zipfile
from pathlib import Path
from typing import cast

from aethelgard.document_ingest import (
    DOCUMENT_INVENTORY_NAME,
    EVIDENCE_MAP_NAME,
    detect_document_type,
    run_document_ingest,
)


def _read_json(path: Path) -> dict[str, object]:
    return cast(dict[str, object], json.loads(path.read_text(encoding="utf-8")))


def _write_docx(path: Path, text: str) -> None:
    xml = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
        "<w:body><w:p><w:r><w:t>%s</w:t></w:r></w:p></w:body></w:document>"
        % text
    )
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("word/document.xml", xml)


def test_document_ingest_parses_txt_md_csv_json_and_docx(tmp_path: Path) -> None:
    input_dir = tmp_path / "docs"
    out_dir = tmp_path / "out"
    input_dir.mkdir()
    (input_dir / "access.md").write_text(
        "Access control is documented. MFA is reviewed quarterly by the owner.",
        encoding="utf-8",
    )
    (input_dir / "backup.txt").write_text(
        "Backup restore test records are reviewed monthly by the continuity owner.",
        encoding="utf-8",
    )
    (input_dir / "supplier.csv").write_text(
        "topic,detail\nsupplier security,annual supplier review evidence\n",
        encoding="utf-8",
    )
    (input_dir / "sbom.json").write_text(
        json.dumps({"control": "sbom", "detail": "CycloneDX bill of materials reviewed"}),
        encoding="utf-8",
    )
    _write_docx(input_dir / "incident.docx", "Incident response timeline reviewed by owner.")

    report = run_document_ingest(input_dir, out_dir)

    inventory = cast(dict[str, object], report["inventory"])
    evidence_map = cast(dict[str, object], report["evidence_map"])
    documents = cast(list[dict[str, object]], inventory["documents"])
    evidence = cast(list[dict[str, object]], evidence_map["evidence"])

    assert (out_dir / DOCUMENT_INVENTORY_NAME).is_file()
    assert (out_dir / EVIDENCE_MAP_NAME).is_file()
    assert inventory["document_count"] == 5
    assert all(document["status"] == "parsed" for document in documents)
    assert {document["source_type"] for document in documents} == {
        "csv",
        "docx",
        "json",
        "markdown",
        "text",
    }
    assert any("mfa" in item["mapped_controls"] for item in evidence)
    assert any("restore_test" in item["mapped_controls"] for item in evidence)
    assert any("supplier_management" in item["mapped_controls"] for item in evidence)
    assert any("sbom" in item["mapped_controls"] for item in evidence)


def test_document_ingest_marks_unsupported_and_image_without_crashing(tmp_path: Path) -> None:
    input_dir = tmp_path / "docs"
    input_dir.mkdir()
    (input_dir / "diagram.png").write_bytes(b"\x89PNG\r\n\x1a\n")
    (input_dir / "archive.bin").write_bytes(b"\x00\x01")

    report = run_document_ingest(input_dir)
    inventory = cast(dict[str, object], report["inventory"])
    documents = cast(list[dict[str, object]], inventory["documents"])
    by_name = {str(document["source_path"]): document for document in documents}

    assert by_name["diagram.png"]["status"] == "ocr_required"
    assert by_name["archive.bin"]["status"] == "unsupported"
    assert cast(dict[str, int], inventory["status_counts"])["ocr_required"] == 1
    assert cast(dict[str, int], inventory["status_counts"])["unsupported"] == 1


def test_document_ingest_ids_are_stable_for_same_input(tmp_path: Path) -> None:
    input_dir = tmp_path / "docs"
    input_dir.mkdir()
    (input_dir / "risk.md").write_text(
        "Risk assessment process is documented and reviewed quarterly by the owner.",
        encoding="utf-8",
    )

    first = run_document_ingest(input_dir)
    second = run_document_ingest(input_dir)
    first_evidence = cast(
        list[dict[str, object]],
        cast(dict[str, object], first["evidence_map"])["evidence"],
    )
    second_evidence = cast(
        list[dict[str, object]],
        cast(dict[str, object], second["evidence_map"])["evidence"],
    )

    assert detect_document_type(input_dir / "risk.md") == "markdown"
    assert [item["evidence_id"] for item in first_evidence] == [
        item["evidence_id"] for item in second_evidence
    ]
