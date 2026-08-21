"""Tests for calibration and quality report outputs."""

from __future__ import annotations

import json
from pathlib import Path

from aethelgard.triage import (
    CALIBRATION_JSON_NAME,
    CALIBRATION_MD_NAME,
    run_eval,
    run_triage,
)

FIXTURE_DIR = Path(__file__).resolve().parent / "fixtures" / "customer_like_nis2"
LABELS_PATH = FIXTURE_DIR / "golden_labels.json"


def test_eval_writes_calibration_reports(tmp_path: Path) -> None:
    out_dir = tmp_path / "customer-like-eval"

    report = run_eval(FIXTURE_DIR, LABELS_PATH, out_dir)

    assert report["status"] == "PILOT_READY"
    json_path = out_dir / CALIBRATION_JSON_NAME
    md_path = out_dir / CALIBRATION_MD_NAME
    assert json_path.is_file()
    assert md_path.is_file()

    payload = json.loads(json_path.read_text(encoding="utf-8"))
    markdown = md_path.read_text(encoding="utf-8")
    assert payload["metric_note"].startswith("Synthetic calibration indicators only")
    assert "proxy metrics" in payload["metric_note"]
    assert payload["human_review_required"]
    assert "Human Review Required" in markdown


def test_triage_evidence_quality_flags_negative_signals() -> None:
    report = run_triage(FIXTURE_DIR)["report"]
    by_file = {document["file"]: document for document in report["per_document"]}
    marketing_items = by_file["08_management_summary_marketing_noise.md"]["evidence"]
    incident_items = by_file["02_incident_response_partial.md"]["evidence"]

    assert all(item["quality"] == "warning" for item in marketing_items)
    assert any("marketing_only" in item["quality_signals"] for item in marketing_items)
    assert any("missing_timeline" in item["quality_signals"] for item in incident_items)
    assert all(not item["strong"] for item in incident_items)
