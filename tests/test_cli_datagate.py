"""CLI-level tests for the datagate subcommand."""

from __future__ import annotations

import json
from pathlib import Path
from typing import cast

import pytest

from aethelgard.cli import C_SCRM_ERROR_EXIT_CODE, main


def _read_json(path: Path) -> dict[str, object]:
    return cast(dict[str, object], json.loads(path.read_text(encoding="utf-8")))


def test_datagate_validate_metadata_reports_accepted_and_ignored(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    metadata_path = tmp_path / "cm.json"
    metadata_path.write_text(
        json.dumps(
            {
                "company_metadata": {
                    "company_name": "Client GmbH",
                    "security_contact_email": "secops@client.example",
                    "evil_field": "leak@third.example",
                }
            }
        ),
        encoding="utf-8",
    )
    out_path = tmp_path / "report.json"

    exit_code = main(
        [
            "datagate",
            "validate-metadata",
            "--company-metadata",
            str(metadata_path),
            "--out",
            str(out_path),
        ]
    )

    report = _read_json(out_path)
    assert exit_code == 0
    assert report["accepted_count"] == 2
    assert "evil_field" in cast(list[str], report["ignored_fields"])
    accepted = cast(dict[str, str], report["accepted_fields"])
    assert accepted["security_contact_email"] == "secops@client.example"


def test_datagate_guard_preserves_declared_and_masks_incidental(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    metadata_path = tmp_path / "cm.json"
    metadata_path.write_text(
        json.dumps({"security_contact_email": "secops@client.example"}), encoding="utf-8"
    )
    text_path = tmp_path / "answer.txt"
    text_path.write_text(
        "Report to secops@client.example. A user wrote from john.private@gmail.com.",
        encoding="utf-8",
    )
    out_path = tmp_path / "guarded.json"

    exit_code = main(
        [
            "datagate",
            "guard",
            "--text-file",
            str(text_path),
            "--company-metadata",
            str(metadata_path),
            "--out",
            str(out_path),
        ]
    )

    report = _read_json(out_path)
    assert exit_code == 0
    guarded_text = cast(str, report["guarded_text"])
    assert "secops@client.example" in guarded_text
    assert "john.private@gmail.com" not in guarded_text
    assert "[email:redacted]" in guarded_text


def test_datagate_guard_without_metadata_masks_everything(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    text_path = tmp_path / "answer.txt"
    text_path.write_text("Contact secops@client.example please.", encoding="utf-8")
    out_path = tmp_path / "guarded.json"

    exit_code = main(
        ["datagate", "guard", "--text-file", str(text_path), "--out", str(out_path)]
    )

    report = _read_json(out_path)
    assert exit_code == 0
    guarded_text = cast(str, report["guarded_text"])
    assert "secops@client.example" not in guarded_text
    assert "[email:redacted]" in guarded_text


def test_datagate_guard_rejects_non_utf8_text(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.chdir(tmp_path)
    text_path = tmp_path / "answer.bin"
    text_path.write_bytes(b"\xff\xfe\x00binary")
    out_path = tmp_path / "guarded.json"

    exit_code = main(
        ["datagate", "guard", "--text-file", str(text_path), "--out", str(out_path)]
    )

    captured = capsys.readouterr()
    assert exit_code == C_SCRM_ERROR_EXIT_CODE
    assert "datagate guard failed" in captured.err
    assert not out_path.exists()
