"""CLI tests for public synthetic fixture evaluation."""

from __future__ import annotations

import json
from pathlib import Path

from aethelgard.cli import main
from aethelgard.triage import EVAL_JSON_NAME, EVAL_MD_NAME

FIXTURE_DIR = Path(__file__).resolve().parent / "fixtures" / "public_nis2"
LABELS_PATH = FIXTURE_DIR / "golden_labels.json"


def test_eval_cli_writes_reports_and_passes_thresholds(tmp_path: Path) -> None:
    out_dir = tmp_path / "eval"
    exit_code = main(
        [
            "eval",
            "--fixtures",
            str(FIXTURE_DIR),
            "--labels",
            str(LABELS_PATH),
            "--out",
            str(out_dir),
        ]
    )

    assert exit_code == 0
    assert (out_dir / EVAL_JSON_NAME).is_file()
    assert (out_dir / EVAL_MD_NAME).is_file()

    report = json.loads((out_dir / EVAL_JSON_NAME).read_text(encoding="utf-8"))
    markdown = (out_dir / EVAL_MD_NAME).read_text(encoding="utf-8")

    assert report["status"] == "PILOT_READY"
    assert report["documents_total"] == 17
    assert report["parser_failures"] == 0
    assert report["category_hits"]["rate"] >= report["thresholds"]["min_category_hit_rate"]
    assert report["threshold_status"]["marketing_false_positive"] is True
    assert "Pilot readiness" in markdown
