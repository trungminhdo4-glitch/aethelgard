"""Tests for the static pilot marketing pack."""

from __future__ import annotations

from pathlib import Path

from scripts.check_marketing_claims import main

PROJECT_ROOT = Path(__file__).resolve().parents[1]
MARKETING_DIR = PROJECT_ROOT / "marketing"


def test_required_marketing_files_exist() -> None:
    required_files = (
        "landing/index.html",
        "landing/styles.css",
        "landing/README.md",
        "demo_video_script.md",
        "outreach/pilot_email_de.md",
        "outreach/linkedin_message_de.md",
        "outreach/followup_email_de.md",
        "outreach/call_agenda_de.md",
        "outreach/pilot_feedback_questions_de.md",
    )

    for relative_path in required_files:
        assert (MARKETING_DIR / relative_path).is_file(), relative_path


def test_marketing_claims_gate_passes_current_pack() -> None:
    assert main(["marketing", "docs/pilot_quickstart.md", "README.md"]) == 0


def test_marketing_claims_gate_blocks_forbidden_claim(tmp_path: Path) -> None:
    bad_file = tmp_path / "bad.md"
    bad_file.write_text("Aethelgard macht NIS2-konform garantiert.", encoding="utf-8")

    assert main([str(bad_file)]) == 1


def test_landing_page_uses_only_local_assets() -> None:
    html = (MARKETING_DIR / "landing" / "index.html").read_text(encoding="utf-8")
    css = (MARKETING_DIR / "landing" / "styles.css").read_text(encoding="utf-8")
    combined = "%s\n%s" % (html, css)

    assert "http://" not in combined
    assert "https://" not in combined
    assert "cdn" not in combined.casefold()
    assert "tracking" not in combined.casefold()
    assert "<script" not in html.casefold()
