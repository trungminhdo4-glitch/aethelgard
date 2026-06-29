"""Tests for offline metadata-only SBOM inventory workflows."""

from __future__ import annotations

import json
from pathlib import Path
from typing import cast

import pytest

from aethelgard.cli import C_SCRM_ERROR_EXIT_CODE, main

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEMO_SBOM = PROJECT_ROOT / "examples" / "sbom" / "cyclonedx_demo.json"


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
    component_ids = [str(component["component_id"]) for component in components]
    assert all(component_id.startswith("SBOM-C-") for component_id in component_ids)
    assert len(component_ids) == len(set(component_ids))
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
    finding_ids = [str(finding["finding_id"]) for finding in findings]
    assert len(finding_ids) == len(set(finding_ids))
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


def test_sbom_demo_fixture_cli_smoke_is_deterministic_and_metadata_only(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    first_inventory_out = tmp_path / "demo-a" / "sbom_inventory.json"
    first_findings_out = tmp_path / "demo-a" / "sbom_findings.json"
    second_inventory_out = tmp_path / "demo-b" / "sbom_inventory.json"
    second_findings_out = tmp_path / "demo-b" / "sbom_findings.json"

    first_inventory_exit = main(
        ["sbom", "ingest", "--input", str(DEMO_SBOM), "--out", str(first_inventory_out)]
    )
    first_findings_exit = main(
        ["sbom", "findings", "--input", str(DEMO_SBOM), "--out", str(first_findings_out)]
    )
    second_inventory_exit = main(
        ["sbom", "ingest", "--input", str(DEMO_SBOM), "--out", str(second_inventory_out)]
    )
    second_findings_exit = main(
        ["sbom", "findings", "--input", str(DEMO_SBOM), "--out", str(second_findings_out)]
    )

    first_inventory = _read_json(first_inventory_out)
    first_findings = _read_json(first_findings_out)
    first_components = cast(list[dict[str, object]], first_inventory["components"])
    first_finding_items = cast(list[dict[str, object]], first_findings["findings"])
    demo_output_text = "%s\n%s" % (
        first_inventory_out.read_text(encoding="utf-8"),
        first_findings_out.read_text(encoding="utf-8"),
    )

    assert first_inventory_exit == 0
    assert first_findings_exit == 0
    assert second_inventory_exit == 0
    assert second_findings_exit == 0
    assert first_inventory == _read_json(second_inventory_out)
    assert first_findings == _read_json(second_findings_out)
    assert first_inventory["source_label"] == "cyclonedx_demo.json"
    assert first_inventory["component_count"] == 3
    assert first_findings["finding_count"] == 5
    assert sorted(str(component["name"]) for component in first_components) == [
        "Demo Component A",
        "Demo Component B",
        "Demo Component C",
    ]
    assert all(str(finding["finding_id"]).startswith("SBOM-F-") for finding in first_finding_items)
    for unsafe in (
        str(DEMO_SBOM.parent),
        "source_path",
        "raw",
        "secret",
        "token",
        "api_key",
        "C:/Users",
        "NIS2 compliant",
        "certified",
    ):
        assert unsafe not in demo_output_text


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


def test_sbom_wrong_bom_format_is_rejected_without_output(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    sbom_path = tmp_path / "not_cyclonedx.json"
    out_path = tmp_path / "sbom_inventory.json"
    _write_json(sbom_path, {"bomFormat": "OtherFormat", "specVersion": "1.5", "components": []})

    exit_code = main(["sbom", "ingest", "--input", str(sbom_path), "--out", str(out_path)])

    assert exit_code == C_SCRM_ERROR_EXIT_CODE
    assert not out_path.exists()


@pytest.mark.parametrize(
    ("payload", "expected_error"),
    [
        (
            {"bomFormat": "CycloneDX", "components": []},
            "specVersion is required",
        ),
        (
            {"bomFormat": "CycloneDX", "specVersion": "9.9", "components": []},
            "unsupported CycloneDX specVersion",
        ),
    ],
)
def test_sbom_invalid_spec_version_is_rejected_without_output(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    payload: dict[str, object],
    expected_error: str,
) -> None:
    monkeypatch.chdir(tmp_path)
    sbom_path = tmp_path / "sbom.json"
    out_path = tmp_path / "sbom_inventory.json"
    _write_json(sbom_path, payload)

    exit_code = main(["sbom", "ingest", "--input", str(sbom_path), "--out", str(out_path)])

    captured = capsys.readouterr()
    assert exit_code == C_SCRM_ERROR_EXIT_CODE
    assert expected_error in captured.err
    assert "Traceback" not in captured.err
    assert not out_path.exists()


def test_sbom_malformed_json_fails_without_traceback_or_output(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.chdir(tmp_path)
    sbom_path = tmp_path / "sbom.json"
    out_path = tmp_path / "sbom_inventory.json"
    sbom_path.write_text("{not-valid-json", encoding="utf-8")

    exit_code = main(["sbom", "ingest", "--input", str(sbom_path), "--out", str(out_path)])

    captured = capsys.readouterr()
    assert exit_code == C_SCRM_ERROR_EXIT_CODE
    assert "invalid SBOM JSON" in captured.err
    assert str(tmp_path) not in captured.err
    assert "Traceback" not in captured.err
    assert not out_path.exists()


def test_sbom_duplicate_bom_ref_is_rejected_without_output(
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
            "components": [
                {"bom-ref": "duplicate-ref", "name": "Demo Component A"},
                {"bom-ref": "duplicate-ref", "name": "Demo Component B"},
            ],
        },
    )

    exit_code = main(["sbom", "ingest", "--input", str(sbom_path), "--out", str(out_path)])

    assert exit_code == C_SCRM_ERROR_EXIT_CODE
    assert not out_path.exists()


def test_sbom_missing_components_is_rejected_without_output(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    sbom_path = tmp_path / "sbom.json"
    out_path = tmp_path / "sbom_inventory.json"
    _write_json(sbom_path, {"bomFormat": "CycloneDX", "specVersion": "1.5"})

    exit_code = main(["sbom", "ingest", "--input", str(sbom_path), "--out", str(out_path)])

    assert exit_code == C_SCRM_ERROR_EXIT_CODE
    assert not out_path.exists()


def test_sbom_empty_components_writes_deterministic_empty_reports(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    sbom_path = tmp_path / "sbom.json"
    inventory_out = tmp_path / "sbom_inventory.json"
    findings_out = tmp_path / "sbom_findings.json"
    _write_json(sbom_path, {"bomFormat": "CycloneDX", "specVersion": "1.5", "components": []})

    inventory_exit = main(
        ["sbom", "ingest", "--input", str(sbom_path), "--out", str(inventory_out)]
    )
    findings_exit = main(
        ["sbom", "findings", "--input", str(sbom_path), "--out", str(findings_out)]
    )

    inventory = _read_json(inventory_out)
    findings = _read_json(findings_out)

    assert inventory_exit == 0
    assert findings_exit == 0
    assert inventory["component_count"] == 0
    assert inventory["components"] == []
    assert findings["finding_count"] == 0
    assert findings["findings"] == []


def test_sbom_component_and_finding_ids_are_stable_when_input_order_changes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    first_path = tmp_path / "sbom_a.json"
    second_path = tmp_path / "sbom_b.json"
    first_inventory_out = tmp_path / "inventory_a.json"
    second_inventory_out = tmp_path / "inventory_b.json"
    first_findings_out = tmp_path / "findings_a.json"
    second_findings_out = tmp_path / "findings_b.json"
    components: list[dict[str, object]] = [
        {"name": "Demo Component B", "version": "2.0.0"},
        {
            "hashes": [{"alg": "SHA-256", "content": "b" * 64}],
            "licenses": [{"license": {"id": "MIT"}}],
            "name": "Demo Component A",
            "purl": "pkg:generic/demo-component-a@1.0.0",
            "version": "1.0.0",
        },
    ]
    _write_json(
        first_path,
        {"bomFormat": "CycloneDX", "specVersion": "1.5", "components": components},
    )
    _write_json(
        second_path,
        {"bomFormat": "CycloneDX", "specVersion": "1.5", "components": list(reversed(components))},
    )

    first_inventory_exit = main(
        ["sbom", "ingest", "--input", str(first_path), "--out", str(first_inventory_out)]
    )
    second_inventory_exit = main(
        ["sbom", "ingest", "--input", str(second_path), "--out", str(second_inventory_out)]
    )
    first_findings_exit = main(
        ["sbom", "findings", "--input", str(first_path), "--out", str(first_findings_out)]
    )
    second_findings_exit = main(
        ["sbom", "findings", "--input", str(second_path), "--out", str(second_findings_out)]
    )

    first_inventory = _read_json(first_inventory_out)
    second_inventory = _read_json(second_inventory_out)
    first_findings = _read_json(first_findings_out)
    second_findings = _read_json(second_findings_out)

    assert first_inventory_exit == 0
    assert second_inventory_exit == 0
    assert first_findings_exit == 0
    assert second_findings_exit == 0
    assert first_inventory["components"] == second_inventory["components"]
    assert first_findings["findings"] == second_findings["findings"]


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
