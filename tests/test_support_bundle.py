"""Tests for redacted pilot support bundles."""

from __future__ import annotations

import json
import zipfile
from pathlib import Path

import pytest

from aethelgard.cli import main
from aethelgard.diagnostics import README_SUPPORT_NAME, build_support_bundle
from aethelgard.errors import AethelgardDiagnosticError, ErrorCode

PROJECT_ROOT = Path(__file__).resolve().parents[1]
EXAMPLES_PILOT = PROJECT_ROOT / "examples" / "pilot"


def test_support_bundle_zip_excludes_private_outputs(
    tmp_path: Path,
    monkeypatch: object,
) -> None:
    from pytest import MonkeyPatch

    typed_monkeypatch = monkeypatch
    assert isinstance(typed_monkeypatch, MonkeyPatch)
    typed_monkeypatch.chdir(tmp_path)
    run_out = tmp_path / "pilot-product"
    bundle_path = tmp_path / "support_bundle.zip"

    product_exit = main(
        [
            "pilot-product",
            "--workspace",
            str(EXAMPLES_PILOT),
            "--out",
            str(run_out),
            "--debug",
        ]
    )
    bundle_exit = main(
        [
            "support-bundle",
            "--workspace",
            str(run_out),
            "--out",
            str(bundle_path),
            "--redacted",
        ]
    )

    assert product_exit == 0
    assert bundle_exit == 0
    assert bundle_path.is_file()
    with zipfile.ZipFile(bundle_path) as bundle:
        names = set(bundle.namelist())
        combined_text = "\n".join(
            bundle.read(name).decode("utf-8") for name in sorted(names)
        )
    assert README_SUPPORT_NAME in names
    assert "doctor_report.json" in names
    assert "run_summary.jsonl" in names
    assert "document_inventory_redacted.json" in names
    assert not any("local_private" in name for name in names)
    assert not any(name.endswith((".sqlite", ".sqlite3", ".db")) for name in names)
    assert "local_private" not in combined_text
    assert ".sqlite" not in combined_text
    expected_notice = (
        "This bundle is redacted and should not contain customer documents. "
        "Human review required."
    )
    assert expected_notice in combined_text


def test_support_bundle_privacy_guard_blocks_forbidden_summary(tmp_path: Path) -> None:
    workspace = tmp_path / "run-output"
    shareable = workspace / "shareable_redacted"
    shareable.mkdir(parents=True)
    (shareable / "run_summary.jsonl").write_text(
        json.dumps(
            {
                "run_id": "demo",
                "timestamp": "2026-07-01T00:00:00+00:00",
                "command": "pilot-product",
                "phase": "test",
                "event": "failed",
                "severity": "error",
                "error_code": "INTERNAL_ERROR",
                "document_id": None,
                "safe_to_share": True,
                "message": "PRIVATE " + "KEY test marker",
            },
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    bundle_path = tmp_path / "support_bundle.zip"

    with pytest.raises(AethelgardDiagnosticError) as exc_info:
        build_support_bundle(workspace, bundle_path, redacted=True)

    assert exc_info.value.error_code == ErrorCode.PRIVACY_GUARD_BLOCKED
    assert not bundle_path.exists()
