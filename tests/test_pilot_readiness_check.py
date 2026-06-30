"""Tests for the local pilot readiness checker."""

from __future__ import annotations

import json
from pathlib import Path

from scripts.check_pilot_readiness import main


def test_pilot_readiness_check_writes_reports(tmp_path: Path) -> None:
    out_dir = tmp_path / "readiness"

    exit_code = main(["--out", str(out_dir)])

    assert exit_code == 0
    json_path = out_dir / "pilot_readiness.json"
    md_path = out_dir / "pilot_readiness.md"
    assert json_path.is_file()
    assert md_path.is_file()

    payload = json.loads(json_path.read_text(encoding="utf-8"))
    markdown = md_path.read_text(encoding="utf-8")
    assert payload["status"] == "PILOT_DOCKER_STATIC_READY_RUNTIME_UNVERIFIED"
    assert "PILOT_DOCKER_STATIC_READY_RUNTIME_UNVERIFIED" in markdown
    assert all(check["passed"] for check in payload["checks"] if check["required"])
    check_ids = {check["id"] for check in payload["checks"]}
    assert "customer_like_eval" in check_ids
    assert "calibration_report_outputs" in check_ids
    assert "public_url_check_403_tolerant" in check_ids
    assert "real_public_data_validation" in check_ids
    assert "docker_static_delivery" in check_ids
    assert "docker_ml_smoke_script_present" in check_ids
    assert "readme_docker_ml_smoke" in check_ids
    assert "pilot_full_local_flow_test_present" in check_ids


def _write_docker_runtime_proof(out_dir: Path) -> None:
    proof_path = out_dir / "docker_runtime_proof.json"
    proof_path.write_text(
        json.dumps(
            {
                "demo_pilot": "pass",
                "help": "pass",
                "network_none_demo": True,
                "output_mount": "pass",
                "status": "DOCKER_RUNTIME_READY",
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )


def _write_docker_ml_runtime_proof(out_dir: Path) -> None:
    proof_path = out_dir / "docker_ml_runtime_proof.json"
    proof_path.write_text(
        json.dumps(
            {
                "active_review": "pass",
                "classify_docs": "pass",
                "dedupe": "pass",
                "features": "pass",
                "help": "pass",
                "ml_help": "pass",
                "network_none_ml": True,
                "output_mount": "pass",
                "rank_findings": "pass",
                "safety_scan": "pass",
                "search": "pass",
                "status": "DOCKER_ML_RUNTIME_READY",
                "suggest_controls": "pass",
                "train_baselines": "pass",
                "weak_labels": "pass",
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )


def test_pilot_readiness_status_marks_runtime_ml_unverified_without_ml_proof(
    tmp_path: Path,
) -> None:
    out_dir = tmp_path / "readiness"
    out_dir.mkdir()
    _write_docker_runtime_proof(out_dir)

    exit_code = main(["--out", str(out_dir)])

    payload = json.loads((out_dir / "pilot_readiness.json").read_text(encoding="utf-8"))
    assert exit_code == 0
    assert payload["status"] == "PILOT_DOCKER_RUNTIME_READY_ML_UNVERIFIED"


def test_pilot_readiness_status_uses_docker_and_ml_runtime_proofs(tmp_path: Path) -> None:
    out_dir = tmp_path / "readiness"
    out_dir.mkdir()
    _write_docker_runtime_proof(out_dir)
    _write_docker_ml_runtime_proof(out_dir)

    exit_code = main(["--out", str(out_dir)])

    payload = json.loads((out_dir / "pilot_readiness.json").read_text(encoding="utf-8"))
    assert exit_code == 0
    assert payload["status"] == "PILOT_PUBLIC_DATA_READY"
