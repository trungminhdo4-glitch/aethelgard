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
    assert payload["status"] == "PILOT_OPS_READY"
    assert "PILOT_OPS_READY" in markdown
    assert all(check["passed"] for check in payload["checks"] if check["required"])
    check_ids = {check["id"] for check in payload["checks"]}
    assert "customer_like_eval" in check_ids
    assert "calibration_report_outputs" in check_ids
    assert "public_url_check_403_tolerant" in check_ids
