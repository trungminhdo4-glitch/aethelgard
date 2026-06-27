"""Tests for official public real-document source manifest."""

from __future__ import annotations

import json
import os
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen

import pytest

from aethelgard.public_sources import URL_CHECK_FAIL, URL_CHECK_WARN, classify_public_url_check

MANIFEST_PATH = (
    Path(__file__).resolve().parents[1]
    / "docs"
    / "evaluation"
    / "public-real-docs-manifest.json"
)

EXPECTED_IDS = {
    "eurlex_nis2_directive",
    "enisa_nis2_guidance",
    "bsi_nis2_faq",
    "nist_csf_2",
    "cisa_cpg",
    "owasp_asvs",
}


def test_public_real_docs_manifest_schema_and_sources() -> None:
    manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    sources = manifest["sources"]

    assert {source["id"] for source in sources} == EXPECTED_IDS
    for source in sources:
        assert source["url"].startswith("https://")
        assert source["local_file"] is None
        assert source["commit_file"] is False
        license_note = source["license_note"].lower()
        assert "do not commit" in license_note or "reference link only" in license_note


@pytest.mark.skipif(
    os.getenv("AETHELGARD_RUN_NETWORK_TESTS") != "1",
    reason="real public URL checks are opt-in",
)
def test_public_real_docs_urls_are_reachable_when_enabled() -> None:
    manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    reachable_count = 0
    automation_blocked: set[str] = set()

    for source in manifest["sources"]:
        request = Request(
            source["url"],
            headers={
                "Accept": "text/html,application/pdf,*/*",
                "User-Agent": "Mozilla/5.0 AethelGard-public-source-check/0.1",
            },
        )
        try:
            with urlopen(request, timeout=20) as response:
                status = int(response.status)
                verdict = classify_public_url_check(source["url"], status_code=status)
                assert verdict["status"] != URL_CHECK_FAIL
                if verdict["status"] == URL_CHECK_WARN:
                    automation_blocked.add(source["id"])
                    continue
                assert response.read(1024)
                reachable_count += 1
        except HTTPError as exc:
            verdict = classify_public_url_check(source["url"], status_code=exc.code)
            if verdict["status"] == URL_CHECK_WARN:
                automation_blocked.add(source["id"])
                continue
            raise

    assert reachable_count >= len(manifest["sources"]) - len(automation_blocked)
