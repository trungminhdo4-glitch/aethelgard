"""End-to-end tests for the integrated pilot product slice."""

from __future__ import annotations

import csv
import json
import re
from pathlib import Path
from typing import cast

from aethelgard.cli import main
from aethelgard.pilot_product import (
    CASE_REVIEW_QUEUE_CSV_NAME,
    COVERAGE_REPORT_HTML_NAME,
    COVERAGE_REPORT_MD_NAME,
    DEFAULT_SQLITE_NAME,
    LOCAL_PRIVATE_DIR_NAME,
    MISSING_EVIDENCE_CSV_NAME,
    PILOT_READINESS_REPORT_NAME,
    QUESTIONNAIRE_DRAFT_CSV_NAME,
    QUESTIONNAIRE_DRAFT_JSON_NAME,
    REVIEW_ITEMS_CSV_NAME,
    SHAREABLE_REDACTED_DIR_NAME,
)

PROJECT_ROOT = Path(__file__).resolve().parents[1]
EXAMPLES_PILOT = PROJECT_ROOT / "examples" / "pilot"


def _read_json(path: Path) -> dict[str, object]:
    return cast(dict[str, object], json.loads(path.read_text(encoding="utf-8")))


def _read_csv(path: Path) -> list[dict[str, str]]:
    with path.open(encoding="utf-8", newline="") as csv_file:
        return list(csv.DictReader(csv_file))


def test_pilot_product_cli_builds_answer_vault_and_review_outputs(
    tmp_path: Path,
    monkeypatch: object,
) -> None:
    from pytest import MonkeyPatch

    typed_monkeypatch = cast(MonkeyPatch, monkeypatch)
    typed_monkeypatch.chdir(tmp_path)
    out_dir = tmp_path / "pilot-product"

    exit_code = main(
        [
            "pilot-product",
            "--workspace",
            str(EXAMPLES_PILOT),
            "--out",
            str(out_dir),
            "--client-id",
            "demo-client",
            "--case-id",
            "case001",
        ]
    )

    local_private = out_dir / LOCAL_PRIVATE_DIR_NAME
    shareable = out_dir / SHAREABLE_REDACTED_DIR_NAME
    readiness = _read_json(shareable / PILOT_READINESS_REPORT_NAME)
    draft = _read_csv(shareable / QUESTIONNAIRE_DRAFT_CSV_NAME)
    queue = _read_csv(shareable / CASE_REVIEW_QUEUE_CSV_NAME)
    missing = _read_csv(shareable / MISSING_EVIDENCE_CSV_NAME)
    shareable_text = "\n".join(
        path.read_text(encoding="utf-8")
        for path in sorted(shareable.iterdir(), key=lambda item: item.name)
        if path.is_file()
    )

    assert exit_code == 0
    assert (local_private / DEFAULT_SQLITE_NAME).is_file()
    assert (local_private / "document_inventory.json").is_file()
    assert (local_private / "evidence_map.json").is_file()
    assert (shareable / "document_summaries.md").is_file()
    assert (shareable / REVIEW_ITEMS_CSV_NAME).is_file()
    assert (shareable / QUESTIONNAIRE_DRAFT_JSON_NAME).is_file()
    assert (shareable / COVERAGE_REPORT_MD_NAME).is_file()
    assert (shareable / COVERAGE_REPORT_HTML_NAME).is_file()
    assert readiness["status"] == "PILOT_PRODUCT_SLICE_READY"
    assert any(row["review_status"] == "reviewed" for row in draft)
    assert any(row["review_status"] == "needs_review" for row in draft)
    assert queue
    assert missing
    for unsafe in (
        "redacted_excerpt",
        "source_citation",
        "candidate_text",
        ".env",
        "C:/Users",
        r"C:\Users",
        "api_key",
        "audit_passed",
        "certified",
        "NIS2 compliant",
    ):
        assert unsafe not in shareable_text
    assert (
        re.search(
            r"[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}",
            shareable_text,
            re.IGNORECASE,
        )
        is None
    )
    lowered_shareable_text = shareable_text.casefold()
    assert "local triage" in lowered_shareable_text
    assert "human review required" in lowered_shareable_text
    assert "no compliance guarantee" in lowered_shareable_text


def test_pilot_product_cli_supports_custom_db_inside_project(
    tmp_path: Path,
    monkeypatch: object,
) -> None:
    from pytest import MonkeyPatch

    typed_monkeypatch = cast(MonkeyPatch, monkeypatch)
    typed_monkeypatch.chdir(tmp_path)
    out_dir = tmp_path / "pilot-product"
    custom_db = tmp_path / "private" / "custom.sqlite"

    exit_code = main(
        [
            "pilot-product",
            "--workspace",
            str(EXAMPLES_PILOT),
            "--out",
            str(out_dir),
            "--db",
            str(custom_db),
        ]
    )

    readiness = _read_json(
        out_dir / SHAREABLE_REDACTED_DIR_NAME / PILOT_READINESS_REPORT_NAME
    )

    assert exit_code == 0
    assert custom_db.is_file()
    assert not (out_dir / LOCAL_PRIVATE_DIR_NAME / DEFAULT_SQLITE_NAME).exists()
    assert readiness["status"] == "PILOT_PRODUCT_SLICE_READY"


def test_workspace_inspect_and_purge_dry_run_use_known_targets(
    tmp_path: Path,
    monkeypatch: object,
    capsys: object,
) -> None:
    from pytest import CaptureFixture, MonkeyPatch

    typed_monkeypatch = cast(MonkeyPatch, monkeypatch)
    typed_capsys = cast(CaptureFixture[str], capsys)
    typed_monkeypatch.chdir(tmp_path)
    out_dir = tmp_path / "pilot-product"
    product_exit = main(
        ["pilot-product", "--workspace", str(EXAMPLES_PILOT), "--out", str(out_dir)]
    )

    inspect_exit = main(["workspace", "inspect", "--workspace", str(out_dir)])
    inspect_output = typed_capsys.readouterr().out
    purge_exit = main(["workspace", "purge", "--workspace", str(out_dir), "--dry-run"])
    purge_output = typed_capsys.readouterr().out

    inspect_report = json.loads(inspect_output)
    purge_report = json.loads(purge_output)

    assert product_exit == 0
    assert inspect_exit == 0
    assert purge_exit == 0
    assert inspect_report["local_private_exists"] is True
    assert inspect_report["shareable_redacted_exists"] is True
    assert purge_report["dry_run"] is True
    assert any(str(target).endswith(LOCAL_PRIVATE_DIR_NAME) for target in purge_report["targets"])
    assert (out_dir / LOCAL_PRIVATE_DIR_NAME).is_dir()
