"""Tests for privacy-safe customer-learning feedback exports."""

from __future__ import annotations

import csv
import json
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import cast

import pytest

from aethelgard.cli import ML_ERROR_EXIT_CODE, main


def _write_json(path: Path, payload: Mapping[str, object]) -> None:
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _write_review_csv(path: Path, rows: Sequence[Mapping[str, str]]) -> None:
    fieldnames = ["finding_id", "review_status", "review_note", "reviewer"]
    with path.open("w", encoding="utf-8", newline="") as csv_file:
        writer = csv.DictWriter(csv_file, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow({field: row.get(field, "") for field in fieldnames})


def _read_json(path: Path) -> dict[str, object]:
    return cast(dict[str, object], json.loads(path.read_text(encoding="utf-8")))


def test_learning_export_writes_redacted_owner_gated_contract(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    review_csv = tmp_path / "review.csv"
    predictions = tmp_path / "predictions.json"
    first_out = Path("reports") / "ml" / "learning_export_first.json"
    second_out = Path("reports") / "ml" / "learning_export_second.json"
    _write_review_csv(
        review_csv,
        (
            {"finding_id": "F-B", "review_status": "rejected"},
            {"finding_id": "F-A", "review_status": "accepted"},
        ),
    )
    _write_json(
        predictions,
        {
            "suggestions": [
                {
                    "item_id": "F-A",
                    "suggested_controls": [
                        {
                            "control_id": "NIS2-SCRM-04",
                            "confidence": 0.74,
                            "reason_codes": ["term_match:backup"],
                        }
                    ],
                }
            ],
            "ranked_findings": [
                {
                    "finding_id": "F-B",
                    "suggested_priority": "P2",
                    "confidence": 0.61,
                    "reason_codes": ["missing_restore_test"],
                }
            ],
        },
    )

    assert (
        main(
            [
                "ml",
                "export-learning-feedback",
                "--review-csv",
                str(review_csv),
                "--predictions",
                str(predictions),
                "--out",
                str(first_out),
            ]
        )
        == 0
    )
    assert (
        main(
            [
                "ml",
                "export-learning-feedback",
                "--review-csv",
                str(review_csv),
                "--predictions",
                str(predictions),
                "--out",
                str(second_out),
            ]
        )
        == 0
    )

    payload = _read_json(first_out)
    rendered = first_out.read_text(encoding="utf-8")
    assert first_out.read_text(encoding="utf-8") == second_out.read_text(encoding="utf-8")
    assert payload["contains_raw_text"] is False
    assert payload["contains_file_paths"] is False
    assert payload["contains_customer_identifiers"] is False
    assert payload["requires_owner_approval"] is True
    assert payload["safe_for_vendor_upload"] is False
    assert payload["manual_review_required"] is True
    assert payload["item_count"] == 2
    assert "F-A" not in rendered
    assert "F-B" not in rendered
    assert "backup.md" not in rendered
    assert "control_term_match" in rendered
    assert "NIS2-SCRM-04" in rendered


def test_learning_export_empty_review_csv_does_not_crash(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    review_csv = tmp_path / "review.csv"
    predictions = tmp_path / "predictions.json"
    out_path = Path("reports") / "ml" / "learning_export.json"
    _write_review_csv(review_csv, ())
    _write_json(predictions, {})

    exit_code = main(
        [
            "ml",
            "export-learning-feedback",
            "--review-csv",
            str(review_csv),
            "--predictions",
            str(predictions),
            "--out",
            str(out_path),
        ]
    )

    payload = _read_json(out_path)
    assert exit_code == 0
    assert payload["item_count"] == 0
    assert payload["items"] == []


def test_learning_export_blocks_raw_text_private_paths_and_identifiers(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    review_csv = tmp_path / "review.csv"
    predictions = tmp_path / "predictions.json"
    out_path = Path("reports") / "ml" / "learning_export.json"
    _write_review_csv(review_csv, ({"finding_id": "F-A", "review_status": "accepted"},))
    _write_json(
        predictions,
        {
            "predictions": [
                {
                    "item_id": "F-A",
                    "confidence": 0.52,
                    "source_citation": "RAW_SNIPPET_SHOULD_NOT_EXPORT",
                }
            ]
        },
    )

    exit_code = main(
        [
            "ml",
            "export-learning-feedback",
            "--review-csv",
            str(review_csv),
            "--predictions",
            str(predictions),
            "--out",
            str(out_path),
        ]
    )

    assert exit_code == ML_ERROR_EXIT_CODE
    assert not out_path.exists()


def test_learning_export_enforces_allowlists(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    review_csv = tmp_path / "review.csv"
    predictions = tmp_path / "predictions.json"
    out_path = Path("reports") / "ml" / "learning_export.json"
    _write_review_csv(review_csv, ({"finding_id": "F-A", "review_status": "approved"},))
    _write_json(
        predictions,
        {
            "suggestions": [
                {
                    "item_id": "F-A",
                    "suggested_controls": [
                        {
                            "control_id": "NIS2-UNKNOWN",
                            "confidence": 0.8,
                            "reason_codes": ["unknown_reason"],
                        }
                    ],
                }
            ]
        },
    )

    exit_code = main(
        [
            "ml",
            "export-learning-feedback",
            "--review-csv",
            str(review_csv),
            "--predictions",
            str(predictions),
            "--out",
            str(out_path),
        ]
    )

    assert exit_code == ML_ERROR_EXIT_CODE
    assert not out_path.exists()
