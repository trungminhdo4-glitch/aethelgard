"""Pilot delivery artifact safety checks."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from scripts.check_delivery_artifact import (
    STATUS_BLOCKED,
    STATUS_OK,
    build_report,
    main,
)


def test_check_delivery_artifact_allows_minimal_manifest(tmp_path: Path) -> None:
    artifact = _minimal_artifact(tmp_path)

    exit_code = main(["--path", str(artifact)])

    report_path = artifact / "delivery_check_report.json"
    report = _read_report(report_path)

    assert exit_code == 0
    assert report["status"] == STATUS_OK
    assert (artifact / "delivery_check_report.md").is_file()


@pytest.mark.parametrize(
    ("relative_path", "expected_id"),
    [
        (".git/config", "forbidden_path"),
        ("tests/test_example.py", "forbidden_path"),
        ("reports/output.json", "forbidden_path"),
        ("local_private/evidence.json", "forbidden_path"),
        ("cache/aethelgard.sqlite", "database_file"),
        ("cache/aethelgard.db", "database_file"),
        (".env", "env_file"),
        ("AGENTS.md", "forbidden_file"),
        ("AGENT_LOG.md", "forbidden_file"),
        ("docs/internal_prompt.md", "internal_prompt_or_agent_file"),
        ("samples/customer_like_input.md", "raw_customer_like_file"),
    ],
)
def test_check_delivery_artifact_blocks_forbidden_paths(
    tmp_path: Path,
    relative_path: str,
    expected_id: str,
) -> None:
    artifact = _minimal_artifact(tmp_path)
    _write_file(artifact / relative_path, "placeholder\n")

    report = build_report(artifact)

    assert report["status"] == STATUS_BLOCKED
    assert _has_blocker(report, expected_id)


@pytest.mark.parametrize(
    "content",
    [
        "TOKEN=MASKED\n",
        "PASSWORD=MASKED\n",
        "SECRET=MASKED\n",
        "API_KEY=MASKED\n",
        "-----BEGIN PRIVATE KEY-----\nMASKED\n",
    ],
)
def test_check_delivery_artifact_blocks_secret_markers(tmp_path: Path, content: str) -> None:
    artifact = _minimal_artifact(tmp_path)
    _write_file(artifact / "notes.txt", content)

    report = build_report(artifact)

    assert report["status"] == STATUS_BLOCKED
    assert _has_blocker(report, "secret_marker")


def test_check_delivery_artifact_blocks_source_when_no_source_claim(tmp_path: Path) -> None:
    artifact = _minimal_artifact(tmp_path, no_source_claim=True, source_visible=False)
    _write_file(artifact / "src" / "aethelgard" / "cli.py", "print('masked')\n")

    report = build_report(artifact)

    assert report["status"] == STATUS_BLOCKED
    assert _has_blocker(report, "source_files_with_no_source_claim")


def test_check_delivery_artifact_blocks_no_source_manifest_conflict(tmp_path: Path) -> None:
    artifact = _minimal_artifact(tmp_path, no_source_claim=True, source_visible=True)

    report = build_report(artifact)

    assert report["status"] == STATUS_BLOCKED
    assert _has_blocker(report, "source_claim_conflict")


def test_check_delivery_artifact_blocks_hidden_visible_source(tmp_path: Path) -> None:
    artifact = _minimal_artifact(tmp_path, no_source_claim=False, source_visible=False)
    _write_file(artifact / "src" / "aethelgard" / "cli.py", "print('masked')\n")

    report = build_report(artifact)

    assert report["status"] == STATUS_BLOCKED
    assert _has_blocker(report, "source_visibility_conflict")


def _minimal_artifact(
    tmp_path: Path,
    *,
    no_source_claim: bool = False,
    source_visible: bool = True,
) -> Path:
    artifact = tmp_path / "artifact"
    artifact.mkdir()
    _write_file(artifact / "README_PILOT.md", "Pilot readme\n")
    _write_file(artifact / "PILOT_NOTICE.md", "Pilot notice\n")
    manifest = {
        "build_id": "test-build",
        "build_time": "2026-07-01T00:00:00Z",
        "git_commit": "test",
        "git_branch": "test",
        "package_mode": "dev-runtime",
        "included_components": ["README_PILOT.md", "PILOT_NOTICE.md", "build_manifest.json"],
        "excluded_components": [".git", "tests", "reports"],
        "no_source_claim": no_source_claim,
        "source_visible": source_visible,
        "not_for_customer_delivery": source_visible,
        "pilot_notice": "test notice",
        "expires_at": None,
    }
    _write_file(artifact / "build_manifest.json", json.dumps(manifest, indent=2) + "\n")
    return artifact


def _write_file(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def _read_report(path: Path) -> dict[str, object]:
    loaded: object = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(loaded, dict)
    return {str(key): value for key, value in loaded.items()}


def _has_blocker(report: dict[str, object], blocker_id: str) -> bool:
    blockers = report.get("blockers")
    assert isinstance(blockers, list)
    return any(isinstance(item, dict) and item.get("id") == blocker_id for item in blockers)
