"""Tests for supplier profile cascade contracts."""

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


def _valid_profile() -> dict[str, object]:
    return {
        "supplier_id": "SUP-SYNTH-001",
        "criticality": "high",
        "relationship_type": "managed_service_provider",
        "evidence_refs": ["E-RF-abc123"],
        "questionnaire_refs": ["Q-abc123"],
        "sbom_refs": ["SBOM-C-abc123"],
        "risk_summary_ref": "supplier_risk.json",
    }


def test_supplier_profile_contract_validates_and_normalizes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    input_path = tmp_path / "supplier_profile_contract.json"
    out_path = tmp_path / "supplier_profile_contract.normalized.json"
    _write_json(input_path, _valid_profile())

    exit_code = main(
        ["supplier-profile", "validate", "--input", str(input_path), "--out", str(out_path)]
    )

    profile = _read_json(out_path)
    output_text = out_path.read_text(encoding="utf-8")

    assert exit_code == 0
    assert profile["schema_version"] == "1.0"
    assert profile["supplier_id"] == "SUP-SYNTH-001"
    assert profile["criticality"] == "high"
    assert profile["relationship_type"] == "managed_service_provider"
    assert profile["risk_summary_ref"] == "supplier_risk.json"
    for unsafe in (
        "raw_notes",
        "source_path",
        "C:/Users/Example",
        "debug.log",
        "certified",
        "audit_passed",
        "NIS2 compliant",
    ):
        assert unsafe not in output_text


def test_supplier_profile_contract_invalid_criticality_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    input_path = tmp_path / "supplier_profile_contract.json"
    out_path = tmp_path / "supplier_profile_contract.normalized.json"
    profile = _valid_profile()
    profile["criticality"] = "urgent"
    _write_json(input_path, profile)

    exit_code = main(
        ["supplier-profile", "validate", "--input", str(input_path), "--out", str(out_path)]
    )

    assert exit_code == C_SCRM_ERROR_EXIT_CODE
    assert not out_path.exists()


def test_supplier_profile_contract_invalid_relationship_type_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    input_path = tmp_path / "supplier_profile_contract.json"
    out_path = tmp_path / "supplier_profile_contract.normalized.json"
    profile = _valid_profile()
    profile["relationship_type"] = "live_vendor"
    _write_json(input_path, profile)

    exit_code = main(
        ["supplier-profile", "validate", "--input", str(input_path), "--out", str(out_path)]
    )

    assert exit_code == C_SCRM_ERROR_EXIT_CODE
    assert not out_path.exists()


def test_supplier_profile_contract_missing_supplier_id_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    input_path = tmp_path / "supplier_profile_contract.json"
    out_path = tmp_path / "supplier_profile_contract.normalized.json"
    profile = _valid_profile()
    del profile["supplier_id"]
    _write_json(input_path, profile)

    exit_code = main(
        ["supplier-profile", "validate", "--input", str(input_path), "--out", str(out_path)]
    )

    assert exit_code == C_SCRM_ERROR_EXIT_CODE
    assert not out_path.exists()


def test_supplier_profile_contract_blocks_raw_evidence_references_deterministically(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.chdir(tmp_path)
    first_input_path = tmp_path / "supplier_profile_contract_a.json"
    second_input_path = tmp_path / "supplier_profile_contract_b.json"
    first_out_path = tmp_path / "supplier_profile_contract_a.normalized.json"
    second_out_path = tmp_path / "supplier_profile_contract_b.normalized.json"
    profile = _valid_profile()
    profile["evidence_refs"] = ["RAW_EVIDENCE_SHOULD_NOT_EXPORT"]
    _write_json(first_input_path, profile)
    _write_json(second_input_path, profile)

    first_exit = main(
        [
            "supplier-profile",
            "validate",
            "--input",
            str(first_input_path),
            "--out",
            str(first_out_path),
        ]
    )
    first_stderr = capsys.readouterr().err.replace(str(first_input_path), "<input>")
    second_exit = main(
        [
            "supplier-profile",
            "validate",
            "--input",
            str(second_input_path),
            "--out",
            str(second_out_path),
        ]
    )
    second_stderr = capsys.readouterr().err.replace(str(second_input_path), "<input>")

    assert first_exit == C_SCRM_ERROR_EXIT_CODE
    assert second_exit == C_SCRM_ERROR_EXIT_CODE
    assert first_stderr == second_stderr
    assert "invalid supplier profile contract" in first_stderr
    assert "RAW_EVIDENCE_SHOULD_NOT_EXPORT" not in first_stderr
    assert not first_out_path.exists()
    assert not second_out_path.exists()


def test_supplier_profile_contract_blocks_private_and_raw_fields(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    input_path = tmp_path / "supplier_profile_contract.json"
    out_path = tmp_path / "supplier_profile_contract.normalized.json"
    profile = _valid_profile()
    profile["raw_notes"] = "RAW_SNIPPET_SHOULD_NOT_EXPORT"
    profile["source_path"] = "C:/Users/Example/debug.log"
    _write_json(input_path, profile)

    exit_code = main(
        ["supplier-profile", "validate", "--input", str(input_path), "--out", str(out_path)]
    )

    assert exit_code == C_SCRM_ERROR_EXIT_CODE
    assert not out_path.exists()
