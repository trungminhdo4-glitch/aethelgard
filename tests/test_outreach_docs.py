"""Tests for the pilot outreach documentation pack."""

from __future__ import annotations

import csv
from pathlib import Path

DOCS_DIR = Path(__file__).resolve().parent.parent / "docs"

REQUIRED_OUTREACH_FILES = (
    "outreach-readiness.md",
    "icp-scoring.md",
    "target-selection-guide.md",
    "outreach-target-list-template.csv",
    "pilot-email.md",
    "follow-up-sequence.md",
    "objection-handling.md",
    "pilot-call-agenda.md",
    "demo-script.md",
    "pilot-call-notes-template.md",
    "sample-data-request.md",
)

EMAIL_DISCLAIMER = (
    "Aethelgard ist eine lokale Evidence-Triage für Security-/NIS-2-Dokumente. "
    "Es ersetzt keine Rechtsberatung, kein Audit und keine Zertifizierung."
)

TARGET_TEMPLATE_HEADER = [
    "company_name",
    "company_type",
    "website",
    "public_contact_channel",
    "region",
    "why_fit",
    "niche",
    "nis2_relevance_signal",
    "trust_level",
    "outreach_status",
    "last_contact",
    "next_action",
    "notes",
]


def read_doc(name: str) -> str:
    return (DOCS_DIR / name).read_text(encoding="utf-8")


def test_required_outreach_files_exist() -> None:
    for filename in REQUIRED_OUTREACH_FILES:
        assert (DOCS_DIR / filename).is_file(), filename


def test_pilot_email_contains_required_disclaimer_for_each_variant() -> None:
    content = read_doc("pilot-email.md")
    normalized_content = " ".join(content.split())

    for variant in ("Variante A", "Variante B", "Variante C", "Variante D"):
        assert variant in content
    assert normalized_content.count(EMAIL_DISCLAIMER) == 4
    assert "15-minute demo" in content
    assert "3 to 10 redacted, non-sensitive" in content


def test_sample_request_lists_forbidden_contents() -> None:
    content = read_doc("sample-data-request.md")

    for forbidden in (
        "Zugangsdaten",
        "API Keys",
        "personenbezogene Kundendaten",
        "echte Incident-Details mit Betroffenen",
        "interne Schwachstellenlisten mit ausnutzbaren Details",
        "produktive Netzwerkpläne",
        "Logs",
        "Verträge mit personenbezogenen Daten",
    ):
        assert forbidden in content
    assert "3 to 10 documents" in content
    assert "Retention And Deletion" in content


def test_target_list_template_uses_company_level_fields_only() -> None:
    template_path = DOCS_DIR / "outreach-target-list-template.csv"
    with template_path.open(encoding="utf-8", newline="") as csv_file:
        rows = list(csv.DictReader(csv_file))

    assert rows
    assert list(rows[0].keys()) == TARGET_TEMPLATE_HEADER
    assert "contact_name" not in rows[0]
    assert rows[0]["company_name"] == "Example GmbH"
    assert rows[0]["website"] == "https://example.invalid"
    assert rows[0]["public_contact_channel"] == "https://example.invalid/contact"
    assert "@" not in rows[0]["public_contact_channel"]


def test_objection_handling_keeps_claims_narrow() -> None:
    content = read_doc("objection-handling.md")

    assert "No Compliance-Garantie" in content
    assert "No legal advice" in content
    assert "No audit opinion" in content
    assert "No sensitive production data" in content
    assert "only supports first-pass document triage" in content


def test_outreach_readiness_contains_go_no_go_and_forbidden_claims() -> None:
    content = read_doc("outreach-readiness.md")

    assert "## Outreach Go/No-Go" in content
    assert "Claims Allowed" in content
    assert "Claims Forbidden" in content
    assert "guarantees NIS-2 compliance" in content
    assert "replaces audit/legal review" in content
    assert "Owner manually selects 3 to 5" in content
