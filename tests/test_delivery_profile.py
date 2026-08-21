"""Tests for safe local delivery profile validation."""

from __future__ import annotations

import json
from collections.abc import Mapping
from pathlib import Path
from typing import cast

import pytest

from aethelgard.cli import DELIVERY_PROFILE_ERROR_EXIT_CODE, main


def _write_json(path: Path, payload: Mapping[str, object]) -> None:
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _read_json(path: Path) -> dict[str, object]:
    return cast(dict[str, object], json.loads(path.read_text(encoding="utf-8")))


def _valid_profile() -> dict[str, object]:
    return {
        "display_name": "AethelGard Local Pilot",
        "consultant_name": "Demo Consultant",
        "contact_label": "Use the agreed company channel for follow-up",
        "report_footer": "Local pilot output for human review; no compliance certification.",
        "disclaimer_mode": "pilot",
    }


def test_delivery_profile_validate_writes_safe_normalized_profile(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    input_path = tmp_path / "delivery_profile.json"
    out_path = Path("reports") / "delivery_profile" / "normalized_delivery_profile.json"
    _write_json(input_path, _valid_profile())

    exit_code = main(
        ["delivery-profile", "validate", "--input", str(input_path), "--out", str(out_path)]
    )

    profile = _read_json(out_path)
    rendered = out_path.read_text(encoding="utf-8")
    assert exit_code == 0
    assert profile["schema_version"] == "1.0"
    assert profile["profile_type"] == "delivery_profile"
    assert profile["manual_review_required"] is True
    assert profile["white_label_core_override"] is False
    assert profile["trust_bundle_safety_overrides"] is False
    assert "@" not in rendered
    assert "C:/Users" not in rendered
    assert ".env" not in rendered


def test_delivery_profile_blocks_private_or_secret_like_values(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    input_path = tmp_path / "delivery_profile.json"
    out_path = Path("reports") / "delivery_profile" / "normalized_delivery_profile.json"
    profile = _valid_profile()
    profile["contact_label"] = "Contact owner@example.test"
    _write_json(input_path, profile)

    exit_code = main(
        ["delivery-profile", "validate", "--input", str(input_path), "--out", str(out_path)]
    )

    assert exit_code == DELIVERY_PROFILE_ERROR_EXIT_CODE
    assert not out_path.exists()
