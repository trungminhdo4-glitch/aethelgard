"""Safety checks for the Berlin target research pack."""

from __future__ import annotations

import csv
import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
RESEARCH_DIR = REPO_ROOT / "docs" / "research"
TARGET_CSV = RESEARCH_DIR / "berlin-outreach-targets.csv"

REQUIRED_COLUMNS = [
    "priority",
    "company_name",
    "company_type",
    "website",
    "public_contact_channel",
    "region",
    "source_urls",
    "fit_reason",
    "nis2_or_isms_signal",
    "msp_or_kmu_signal",
    "aethelgard_angle",
    "trust_barrier",
    "risk_level",
    "recommended_message_variant",
    "status",
    "notes",
]

ALLOWED_CONTACT_CHANNELS = {
    "",
    "contact form",
    "general inbox",
    "central phone",
    "website contact page",
}

GENERIC_INBOX_PREFIXES = {
    "info",
    "kontakt",
    "contact",
    "sales",
    "vertrieb",
    "hello",
    "mail",
    "office",
}

FORBIDDEN_CLAIMS = (
    "NIS-2 compliant",
    "NIS2 compliant",
    "guarantees compliance",
    "replaces audit",
    "replaces legal review",
    "certifies compliance",
)

EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@([A-Za-z0-9.-]+\.[A-Za-z]{2,})\b")


def read_research_doc(filename: str) -> str:
    return (RESEARCH_DIR / filename).read_text(encoding="utf-8")


def load_targets() -> list[dict[str, str]]:
    with TARGET_CSV.open(encoding="utf-8", newline="") as csv_file:
        return list(csv.DictReader(csv_file))


def test_research_files_exist() -> None:
    for filename in (
        "berlin-target-research-plan.md",
        "berlin-outreach-targets.csv",
        "berlin-target-research.md",
        "target-scoring-model.md",
        "company-specific-outreach-snippets.md",
        "owner-target-review-checklist.md",
    ):
        assert (RESEARCH_DIR / filename).is_file(), filename


def test_target_csv_has_required_columns_and_rows() -> None:
    rows = load_targets()

    assert len(rows) == 15
    assert list(rows[0].keys()) == REQUIRED_COLUMNS
    assert [int(row["priority"]) for row in rows] == list(range(1, 16))


def test_contact_channels_are_company_level_only() -> None:
    for row in load_targets():
        contact_channel = row["public_contact_channel"]
        assert contact_channel in ALLOWED_CONTACT_CHANNELS

        for match in EMAIL_RE.finditer(contact_channel):
            prefix = match.group(0).split("@", maxsplit=1)[0].lower()
            assert prefix in GENERIC_INBOX_PREFIXES


def test_sources_do_not_use_linkedin_or_xing() -> None:
    for row in load_targets():
        sources = row["source_urls"].lower()
        assert "linkedin." not in sources
        assert "xing." not in sources


def test_research_markdown_keeps_claims_narrow() -> None:
    combined = "\n".join(
        read_research_doc(filename)
        for filename in (
            "berlin-target-research.md",
            "company-specific-outreach-snippets.md",
            "target-scoring-model.md",
        )
    )

    for claim in FORBIDDEN_CLAIMS:
        assert claim not in combined
    assert "Es ersetzt keine Rechtsberatung, kein Audit und keine Zertifizierung" in combined
    assert "Human Review bleibt Pflicht" in combined


def test_top_five_snippets_contain_required_disclaimer_and_cta() -> None:
    snippets = read_research_doc("company-specific-outreach-snippets.md")
    disclaimer = "Es ersetzt keine Rechtsberatung, kein Audit und keine Zertifizierung"

    assert len(re.findall(r"^## [^\n]+$", snippets, flags=re.MULTILINE)) == 5
    assert snippets.count(disclaimer) == 5
    assert snippets.count("15-Minuten-Demo mit synthetischen Daten oder redacted Sample Pack") == 5


def test_owner_checklist_exists_and_blocks_sensitive_outreach() -> None:
    checklist = read_research_doc("owner-target-review-checklist.md")

    for required_item in (
        "Kein personenbezogener Kontakt verwendet?",
        "Keine Compliance-/Audit-Garantie?",
        "Keine sensiblen Daten angefragt?",
        "Kein LinkedIn-/Xing-Profil als Quelle oder Kontaktweg verwendet?",
        "Kein Versand automatisiert?",
    ):
        assert required_item in checklist
