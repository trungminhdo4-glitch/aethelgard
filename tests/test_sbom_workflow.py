"""Tests for offline metadata-only SBOM inventory workflows."""

from __future__ import annotations

import json
from pathlib import Path
from typing import cast

import pytest

from aethelgard.cli import C_SCRM_ERROR_EXIT_CODE, main


def _write_json(path: Path, payload: dict[str, object]) -> None:
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _read_json(path: Path) -> dict[str, object]:
    return cast(dict[str, object], json.loads(path.read_text(encoding="utf-8")))


def _write_cyclonedx_fixture(path: Path) -> None:
    _write_json(
        path,
        {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "components": [
                {
                    "bom-ref": "RAW_BOM_REF_SHOULD_NOT_EXPORT",
                    "externalReferences": [
                        {"type": "website", "url": "C:/Users/Example/private"}
                    ],
                    "hashes": [{"alg": "SHA-256", "content": "a" * 64}],
                    "licenses": [{"license": {"id": "MIT"}}],
                    "name": "acme-lib",
                    "properties": [{"name": "debug", "value": "RAW_SNIPPET_SHOULD_NOT_EXPORT"}],
                    "purl": "pkg:pypi/acme-lib@1.2.3",
                    "version": "1.2.3",
                },
                {
                    "name": "gap-lib",
                    "version": "",
                },
                {
                    "name": "gap-lib",
                    "version": "",
                },
            ],
        },
    )


def test_sbom_ingest_extracts_deterministic_metadata_only_inventory(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    sbom_path = tmp_path / "sbom.json"
    first_out = tmp_path / "sbom_inventory_a.json"
    second_out = tmp_path / "sbom_inventory_b.json"
    _write_cyclonedx_fixture(sbom_path)

    first_exit = main(["sbom", "ingest", "--input", str(sbom_path), "--out", str(first_out)])
    second_exit = main(["sbom", "ingest", "--input", str(sbom_path), "--out", str(second_out)])

    first_inventory = _read_json(first_out)
    second_inventory = _read_json(second_out)
    components = cast(list[dict[str, object]], first_inventory["components"])
    inventory_text = first_out.read_text(encoding="utf-8")

    assert first_exit == 0
    assert second_exit == 0
    assert first_inventory == second_inventory
    assert first_inventory["schema_version"] == "1.0"
    assert first_inventory["inventory_type"] == "sbom_inventory"
    assert first_inventory["component_count"] == 3
    assert all("component_id" in component for component in components)
    assert any(component["purl"] == "pkg:pypi/acme-lib@1.2.3" for component in components)
    for unsafe in (
        "RAW_BOM_REF_SHOULD_NOT_EXPORT",
        "RAW_SNIPPET_SHOULD_NOT_EXPORT",
        "externalReferences",
        "properties",
        "C:/Users/Example",
        "certified",
        "audit_passed",
        "NIS2 compliant",
    ):
        assert unsafe not in inventory_text


def test_sbom_findings_reports_local_metadata_gaps(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    sbom_path = tmp_path / "sbom.json"
    findings_out = tmp_path / "sbom_findings.json"
    _write_cyclonedx_fixture(sbom_path)

    exit_code = main(["sbom", "findings", "--input", str(sbom_path), "--out", str(findings_out)])

    report = _read_json(findings_out)
    finding_type_counts = cast(dict[str, int], report["finding_type_counts"])
    findings = cast(list[dict[str, object]], report["findings"])
    per_document = cast(list[dict[str, object]], report["per_document"])
    evidence = cast(list[dict[str, object]], per_document[0]["evidence"])
    output_text = findings_out.read_text(encoding="utf-8")

    assert exit_code == 0
    assert report["report_type"] == "sbom_findings"
    assert finding_type_counts["missing_version"] == 2
    assert finding_type_counts["missing_license"] == 2
    assert finding_type_counts["missing_checksum"] == 2
    assert finding_type_counts["unknown_package_id"] == 2
    assert finding_type_counts["duplicate_component"] == 2
    assert all(str(finding["finding_id"]).startswith("SBOM-F-") for finding in findings)
    assert all(finding["status"] == "needs_review" for finding in findings)
    assert evidence
    assert all(item["review_status"] == "open" for item in evidence)
    assert all(item["category"] == "vulnerability_management" for item in evidence)
    for unsafe in (
        "RAW_BOM_REF_SHOULD_NOT_EXPORT",
        "RAW_SNIPPET_SHOULD_NOT_EXPORT",
        "draft_answer",
        "C:/Users/Example",
        "certified",
        "audit_passed",
        "NIS2 compliant",
    ):
        assert unsafe not in output_text


def test_sbom_spdx_is_rejected_without_output(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    sbom_path = tmp_path / "spdx.json"
    out_path = tmp_path / "sbom_inventory.json"
    _write_json(
        sbom_path,
        {
            "SPDXID": "SPDXRef-DOCUMENT",
            "spdxVersion": "SPDX-2.3",
            "packages": [],
        },
    )

    exit_code = main(["sbom", "ingest", "--input", str(sbom_path), "--out", str(out_path)])

    assert exit_code == C_SCRM_ERROR_EXIT_CODE
    assert not out_path.exists()


def test_sbom_blocks_sensitive_exported_component_fields(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    sbom_path = tmp_path / "sbom.json"
    out_path = tmp_path / "sbom_inventory.json"
    _write_json(
        sbom_path,
        {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "components": [{"name": "C:/Users/Example/.env", "version": "1.0.0"}],
        },
    )

    exit_code = main(["sbom", "ingest", "--input", str(sbom_path), "--out", str(out_path)])

    assert exit_code == C_SCRM_ERROR_EXIT_CODE
    assert not out_path.exists()


def test_sbom_cli_rejects_output_outside_current_project(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    sbom_path = tmp_path / "sbom.json"
    out_path = tmp_path.parent / "sbom_inventory.json"
    _write_cyclonedx_fixture(sbom_path)

    exit_code = main(["sbom", "ingest", "--input", str(sbom_path), "--out", str(out_path)])

    assert exit_code == C_SCRM_ERROR_EXIT_CODE
    assert not out_path.exists()
