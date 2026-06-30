"""Offline validation tests for committed real public-data fixtures."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import cast

import pytest

from aethelgard.cli import main
from aethelgard.public_data import PUBLIC_DATA_MARKER

PROJECT_ROOT = Path(__file__).resolve().parents[1]
PUBLIC_MANIFEST = PROJECT_ROOT / "examples" / "public" / "public_data_manifest.json"
CISA_KEV_SAMPLE = PROJECT_ROOT / "examples" / "public" / "cisa_kev_sample.json"


def _read_json(path: Path) -> dict[str, object]:
    return cast(dict[str, object], json.loads(path.read_text(encoding="utf-8")))


def test_public_data_validate_cli_writes_metadata_only_report(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    out_path = tmp_path / "public_data_validation.json"

    exit_code = main(
        [
            "public-data",
            "validate",
            "--manifest",
            str(PUBLIC_MANIFEST),
            "--out",
            str(out_path),
        ]
    )

    report = _read_json(out_path)
    sources = cast(list[dict[str, object]], report["sources"])
    source_ids = {str(source["source_id"]) for source in sources}
    report_text = out_path.read_text(encoding="utf-8")

    assert exit_code == 0
    assert report["status"] == "PUBLIC_DATA_READY"
    assert report["public_data_marker"] == PUBLIC_DATA_MARKER
    assert source_ids == {
        "cisa-kev-sample-2026-06-30",
        "cyclonedx-helloworld-mbom-min-2026-06-30",
    }
    for source in sources:
        local_path = PROJECT_ROOT / str(source["local_path"])
        actual_hash = hashlib.sha256(local_path.read_bytes()).hexdigest()
        assert source["sha256"] == actual_hash
        assert str(source["source_url"]).startswith("https://")
        assert source["contains_pii"] is False
        assert source["validation_status"] == "pass"
        assert int(cast(int, source["record_count"])) > 0
    for unsafe in (".env", "api_key", "Bearer", "Cookie", "C:/Users", r"C:\Users", "/home/"):
        assert unsafe not in report_text
    assert re.search(r"[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}", report_text, re.IGNORECASE) is None


def test_cisa_kev_sample_is_minimized_public_non_personal_data() -> None:
    sample = _read_json(CISA_KEV_SAMPLE)
    vulnerabilities = cast(list[dict[str, object]], sample["vulnerabilities"])
    allowed_fields = {
        "cveID",
        "vendorProject",
        "product",
        "dateAdded",
        "dueDate",
        "knownRansomwareCampaignUse",
    }
    sample_text = CISA_KEV_SAMPLE.read_text(encoding="utf-8")

    assert sample["public_data_marker"] == PUBLIC_DATA_MARKER
    assert len(vulnerabilities) == 3
    for item in vulnerabilities:
        assert set(item) == allowed_fields
        assert str(item["cveID"]).startswith("CVE-")
        assert str(item["knownRansomwareCampaignUse"]) in {"Known", "Unknown"}
    assert '"requiredAction"' not in sample_text
    assert "@" not in sample_text
