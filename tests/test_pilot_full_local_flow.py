"""Full synthetic local pilot-flow regression tests."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import cast

import pytest

from aethelgard.cli import DEMO_PILOT_SUMMARY_NAME, main
from aethelgard.questionnaire import QUESTIONNAIRE_JSON_NAME
from aethelgard.review import REVIEWED_REPORT_JSON_NAME
from aethelgard.supplier_risk import SUPPLIER_RISK_JSON_NAME
from aethelgard.trust_bundle import TRUST_BUNDLE_FILES, TRUST_BUNDLE_MANIFEST_NAME

PROJECT_ROOT = Path(__file__).resolve().parents[1]
EXAMPLES_PILOT = PROJECT_ROOT / "examples" / "pilot"


def _read_json(path: Path) -> dict[str, object]:
    return cast(dict[str, object], json.loads(path.read_text(encoding="utf-8")))


def test_demo_pilot_cli_builds_full_metadata_only_flow(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    out_dir = tmp_path / "pilot-output"

    exit_code = main(["demo-pilot", "--examples", str(EXAMPLES_PILOT), "--out", str(out_dir)])

    expected_files = (
        out_dir / "preflight_report.json",
        out_dir / "evidence_report.json",
        out_dir / "review_items.csv",
        out_dir / "reviewed" / REVIEWED_REPORT_JSON_NAME,
        out_dir / "evidence_store.json",
        out_dir / "questionnaire" / QUESTIONNAIRE_JSON_NAME,
        out_dir / "questionnaire-reviewed" / REVIEWED_REPORT_JSON_NAME,
        out_dir / "risk" / SUPPLIER_RISK_JSON_NAME,
        out_dir / "sbom_inventory.json",
        out_dir / "sbom_findings.json",
        out_dir / "supplier_profile_contract.normalized.json",
        out_dir / "trust-bundle" / TRUST_BUNDLE_MANIFEST_NAME,
        out_dir / DEMO_PILOT_SUMMARY_NAME,
    )
    manifest = _read_json(out_dir / "trust-bundle" / TRUST_BUNDLE_MANIFEST_NAME)
    source_hashes = cast(dict[str, str], manifest["source_hashes"])
    bundle_text = "\n".join(
        path.read_text(encoding="utf-8")
        for path in sorted((out_dir / "trust-bundle").iterdir(), key=lambda item: item.name)
        if path.is_file()
    )

    assert exit_code == 0
    assert all(path.is_file() for path in expected_files)
    assert sorted(path.name for path in (out_dir / "trust-bundle").iterdir()) == sorted(
        TRUST_BUNDLE_FILES
    )
    assert manifest["bundle_schema_version"] == "1.0"
    assert manifest["included_sections"] == [
        "evidence_index",
        "questionnaire_summary",
        "supplier_risk_summary",
        "readme",
    ]
    assert sorted(source_hashes) == ["evidence_store", "questionnaire", "supplier_risk"]
    assert all(re.fullmatch(r"[a-f0-9]{64}", value) for value in source_hashes.values())
    for unsafe in (
        "source_citation",
        "draft_answer",
        "RAW_SNIPPET",
        ".env",
        "C:/Users",
        r"C:\Users",
        "/home/",
        "api_key",
        "Bearer",
        "Cookie",
        "NIS2 compliant",
        "audit_passed",
        "certified",
    ):
        assert unsafe not in bundle_text
    assert re.search(r"[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}", bundle_text, re.IGNORECASE) is None


def test_demo_pilot_trust_bundle_rebuild_is_deterministic(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    out_dir = tmp_path / "pilot-output"
    second_bundle = tmp_path / "bundle-rebuild"

    demo_exit = main(["demo-pilot", "--examples", str(EXAMPLES_PILOT), "--out", str(out_dir)])
    rebuild_exit = main(
        [
            "trust-bundle",
            "build",
            "--evidence",
            str(out_dir / "evidence_store.json"),
            "--supplier-risk",
            str(out_dir / "risk" / SUPPLIER_RISK_JSON_NAME),
            "--questionnaire",
            str(out_dir / "questionnaire-reviewed" / REVIEWED_REPORT_JSON_NAME),
            "--out",
            str(second_bundle),
        ]
    )

    first_files = {
        path.name: path.read_text(encoding="utf-8")
        for path in sorted((out_dir / "trust-bundle").iterdir(), key=lambda item: item.name)
    }
    second_files = {
        path.name: path.read_text(encoding="utf-8")
        for path in sorted(second_bundle.iterdir(), key=lambda item: item.name)
    }

    assert demo_exit == 0
    assert rebuild_exit == 0
    assert first_files == second_files


def test_public_data_manifest_documents_offline_synthetic_decision() -> None:
    manifest_path = EXAMPLES_PILOT / "public_data_manifest.json"
    manifest = _read_json(manifest_path)
    sources = cast(list[dict[str, object]], manifest["sources"])
    source = sources[0]
    local_path = PROJECT_ROOT / str(source["local_path"])
    actual_hash = hashlib.sha256(local_path.read_bytes()).hexdigest()
    manifest_text = manifest_path.read_text(encoding="utf-8")

    assert manifest["schema_version"] == "1.0"
    assert "not ingested" in str(manifest["decision"])
    assert source["source_type"] == "synthetic_fixture"
    assert source["contains_pii"] is False
    assert source["sha256"] == actual_hash
    assert "@" not in manifest_text
    assert "C:/Users" not in manifest_text
    assert r"C:\Users" not in manifest_text
