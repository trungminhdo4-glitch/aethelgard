"""Tests for source-backed NIS2 Article 21 control coverage."""

from __future__ import annotations

from pathlib import Path

from aethelgard.nis2_controls import (
    COVERAGE_MISSING,
    COVERAGE_REVIEW,
    COVERAGE_STRONG,
    NIS2_ARTICLE_21_SOURCE_URL,
    NIS2_CONTROL_REFERENCES,
    build_control_coverage,
)
from aethelgard.triage import run_triage


def test_control_reference_matrix_has_article_21_topics() -> None:
    article_refs = [reference.article_reference for reference in NIS2_CONTROL_REFERENCES]

    assert len(NIS2_CONTROL_REFERENCES) == 10
    assert article_refs == [
        "Article 21(2)(a)",
        "Article 21(2)(b)",
        "Article 21(2)(c)",
        "Article 21(2)(d)",
        "Article 21(2)(e)",
        "Article 21(2)(f)",
        "Article 21(2)(g)",
        "Article 21(2)(h)",
        "Article 21(2)(i)",
        "Article 21(2)(j)",
    ]
    assert all(
        reference.source_url == NIS2_ARTICLE_21_SOURCE_URL
        for reference in NIS2_CONTROL_REFERENCES
    )
    assert all(reference.evidence_categories for reference in NIS2_CONTROL_REFERENCES)


def test_build_control_coverage_uses_metadata_only() -> None:
    documents = [
        {
            "file": "risk.md",
            "categories": {"risk_management": 2, "supplier_security": 1},
            "strong_categories": ["risk_management"],
        },
        {
            "file": "supplier.md",
            "categories": {"supplier_security": 1},
            "strong_categories": [],
        },
    ]

    coverage = build_control_coverage(documents)
    controls = {str(control["control_id"]): control for control in coverage["controls"]}

    assert controls["nis2_art_21_2_a"]["status"] == COVERAGE_STRONG
    assert controls["nis2_art_21_2_d"]["status"] == COVERAGE_REVIEW
    assert controls["nis2_art_21_2_h"]["status"] == COVERAGE_MISSING
    assert "source_citation" not in str(coverage)
    assert "document content" not in str(coverage).lower()


def test_triage_detects_added_article_21_keyword_categories(tmp_path: Path) -> None:
    document = tmp_path / "article21_additional_topics.md"
    document.write_text(
        "\n".join(
            [
                "The control effectiveness review is documented, implemented, tested, "
                "approved, monitored, and owned by the security owner.",
                "The cybersecurity training procedure includes security awareness review, "
                "documented attendance, implemented phishing training, and owner approval.",
                "The encryption policy defines cryptography and key management controls; "
                "it is documented, implemented, tested, approved, and regularly reviewed.",
                "The asset inventory procedure keeps an asset register and device inventory; "
                "the owner reviews the documented export monthly.",
                "Secure communications require strong authentication and emergency "
                "communication procedures that are documented, implemented, and tested.",
            ]
        ),
        encoding="utf-8",
    )

    report = run_triage(tmp_path)["report"]
    categories = report["categories"]
    controls = {
        control["control_id"]: control
        for control in report["control_coverage"]["controls"]
    }

    assert categories["control_effectiveness"] > 0
    assert categories["cyber_hygiene_training"] > 0
    assert categories["cryptography_encryption"] > 0
    assert categories["asset_management"] > 0
    assert categories["secure_auth_communications"] > 0
    assert controls["nis2_art_21_2_f"]["status"] == COVERAGE_STRONG
    assert controls["nis2_art_21_2_g"]["status"] == COVERAGE_STRONG
    assert controls["nis2_art_21_2_h"]["status"] == COVERAGE_STRONG
    assert controls["nis2_art_21_2_j"]["status"] == COVERAGE_STRONG
