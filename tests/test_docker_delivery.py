"""Static Docker delivery gate tests."""

from __future__ import annotations

import json
from pathlib import Path

from scripts.check_docker_delivery import build_report, main


def test_docker_delivery_static_gate_passes(tmp_path: Path) -> None:
    out_path = tmp_path / "docker_delivery.json"

    exit_code = main(["--out", str(out_path)])

    payload = json.loads(out_path.read_text(encoding="utf-8"))
    check_ids = {check["id"] for check in payload["checks"]}

    assert exit_code == 0
    assert payload["status"] == "DOCKER_STATIC_READY"
    assert build_report()["status"] == "DOCKER_STATIC_READY"
    assert {
        "dockerfile_non_root",
        "compose_network_none",
        "compose_examples_read_only",
        "compose_reports_writable",
        "dockerignore_required_markers",
        "docker_smoke_writes_runtime_proof",
        "consultant_laptop_smoke_exists",
        "release_package_script_exists",
        "readme_consultant_delivery",
    }.issubset(check_ids)
