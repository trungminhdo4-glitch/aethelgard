"""Safety checks for the controlled first-wave outreach artifacts."""

from __future__ import annotations

import csv
import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
RESEARCH_DIR = REPO_ROOT / "docs" / "research"
TRACKER_PATH = RESEARCH_DIR / "outreach-tracker.csv"
DRAFTS_DIR = RESEARCH_DIR / "outreach-drafts"

FIRST_WAVE_COMPANIES = {"NETWORK ASSISTANCE", "030-IT", "procado"}
ALLOWED_GENERIC_EMAIL_PREFIXES = {"info", "kontakt", "contact", "hello", "office", "mail"}
EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@([A-Za-z0-9.-]+\.[A-Za-z]{2,})\b")
FORBIDDEN_POSITIVE_CLAIMS = (
    "garantiert compliant",
    "guarantees compliance",
    "ersetzt ein audit",
    "ersetzt den audit",
    "audit-ersatz",
    "rechtsberatung durch aethelgard",
    "zertifiziert compliance",
    "zertifizierung durch aethelgard",
)


def read_doc(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def load_tracker() -> list[dict[str, str]]:
    with TRACKER_PATH.open(encoding="utf-8", newline="") as csv_file:
        return list(csv.DictReader(csv_file))


def test_first_wave_artifacts_exist() -> None:
    required_files = [
        RESEARCH_DIR / "first-outreach-wave.md",
        RESEARCH_DIR / "first-wave-messages.md",
        TRACKER_PATH,
        RESEARCH_DIR / "outreach-response-playbook.md",
        RESEARCH_DIR / "demo-runbook-first-call.md",
        RESEARCH_DIR / "first-call-qualification.md",
        RESEARCH_DIR / "second-wave-review.md",
        RESEARCH_DIR / "outreach-retrospective.md",
        DRAFTS_DIR / "NETWORK_ASSISTANCE.md",
        DRAFTS_DIR / "030_IT.md",
        DRAFTS_DIR / "procado.md",
    ]

    for path in required_files:
        assert path.is_file(), str(path)


def test_tracker_limits_first_wave_to_three_draft_ready_companies() -> None:
    rows = load_tracker()

    assert len(rows) == 3
    assert {row["company_name"] for row in rows} == FIRST_WAVE_COMPANIES
    assert {row["status"] for row in rows} == {"draft_ready"}
    assert all(row["manual_send_date"] == "" for row in rows)


def test_tracker_uses_company_level_contact_paths_only() -> None:
    for row in load_tracker():
        contact_blob = "%s %s" % (row["contact_path"], row["contact_detail"])
        assert "linkedin" not in contact_blob.lower()
        assert "xing" not in contact_blob.lower()
        assert "person" not in contact_blob.lower()

        for match in EMAIL_RE.finditer(contact_blob):
            prefix = match.group(0).split("@", maxsplit=1)[0].lower()
            assert prefix in ALLOWED_GENERIC_EMAIL_PREFIXES


def test_first_wave_messages_keep_claims_and_first_contact_scope_safe() -> None:
    messages = read_doc(RESEARCH_DIR / "first-wave-messages.md")
    lower = messages.lower()

    for claim in FORBIDDEN_POSITIVE_CLAIMS:
        assert claim not in lower
    assert messages.count("15-Minuten-Demo mit synthetischen Beispieldaten") == 3
    assert messages.count("nicht Rechtsberatung, Audit oder Compliance-Garantie") == 3
    assert "Anhang" not in messages
    assert "Kundendokument" not in messages
    assert "LinkedIn" not in messages
    assert "Xing" not in messages


def test_each_draft_documents_exact_blocker_and_owner_placeholder() -> None:
    for filename in ("NETWORK_ASSISTANCE.md", "030_IT.md", "procado.md"):
        draft = read_doc(DRAFTS_DIR / filename)

        assert "Status: `draft_ready`" in draft
        assert "[OWNER_NAME]" in draft
        assert draft.count("Blocker:") == 1
        assert "Kein freigegebenes Absenderkonto/kein OWNER_NAME" in draft
        assert "Subject: Kurze Demo-Idee" in draft


def test_response_playbook_contains_required_response_types() -> None:
    playbook = read_doc(RESEARCH_DIR / "outreach-response-playbook.md")

    for response_type in (
        "interessiert",
        "will Demo",
        "fragt nach Datenschutz",
        "fragt nach Rechtsberatung/Audit",
        "fragt nach Kosten",
        "keine Relevanz",
        "falscher Ansprechpartner",
        "keine Antwort",
    ):
        assert response_type in playbook


def test_second_wave_is_review_only() -> None:
    review = read_doc(RESEARCH_DIR / "second-wave-review.md")

    assert "Do not contact these companies without a fresh owner gate" in review
    for company in (
        "DProtected / DataProtected",
        "de-bit Computer-Service",
        "M&H IT-Security",
        "aptaro",
        "CASKAN IT-Security",
        "NKMG Berlin",
        "Cyberport IT-Services Berlin",
        "microCAT Berlin",
    ):
        assert company in review
