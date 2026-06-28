"""Source-backed NIS2 control coverage helpers.

The controls in this module are a local reporting aid. They map extracted
evidence categories to the minimum topic areas listed in Directive (EU)
2022/2555 Article 21(2), without making legal, audit, or certification claims.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import asdict, dataclass
from typing import Final

NIS2_ARTICLE_21_SOURCE_URL: Final[str] = (
    "https://eur-lex.europa.eu/legal-content/EN/TXT/HTML/?uri=CELEX%3A32022L2555"
)
NIS2_ARTICLE_21_REFERENCE_BASIS: Final[str] = (
    "Directive (EU) 2022/2555 Article 21(2) minimum cybersecurity "
    "risk-management measure topics"
)
CONTROL_COVERAGE_NOTE: Final[str] = (
    "Automated local coverage only. A strong status means the report found at least one "
    "strong evidence category linked to this topic; it is not legal advice, not an audit "
    "opinion, and not a NIS-2 compliance decision."
)

COVERAGE_STRONG: Final[str] = "strong_evidence"
COVERAGE_REVIEW: Final[str] = "needs_review"
COVERAGE_MISSING: Final[str] = "no_evidence"


@dataclass(frozen=True, slots=True)
class NIS2ControlReference:
    """Stable Article 21(2) reporting reference for local coverage output."""

    control_id: str
    article_reference: str
    title: str
    plain_language_summary: str
    evidence_categories: tuple[str, ...]
    source_url: str = NIS2_ARTICLE_21_SOURCE_URL


NIS2_CONTROL_REFERENCES: Final[tuple[NIS2ControlReference, ...]] = (
    NIS2ControlReference(
        control_id="nis2_art_21_2_a",
        article_reference="Article 21(2)(a)",
        title="Risk analysis and information system security policies",
        plain_language_summary=(
            "Risk analysis, risk ownership, and information-security policy evidence."
        ),
        evidence_categories=("risk_management",),
    ),
    NIS2ControlReference(
        control_id="nis2_art_21_2_b",
        article_reference="Article 21(2)(b)",
        title="Incident handling",
        plain_language_summary=(
            "Incident-response handling, escalation, and reporting-timeline evidence."
        ),
        evidence_categories=("incident_reporting",),
    ),
    NIS2ControlReference(
        control_id="nis2_art_21_2_c",
        article_reference="Article 21(2)(c)",
        title="Business continuity, backup, disaster recovery, and crisis management",
        plain_language_summary=(
            "Continuity, backup/restore, disaster-recovery, and crisis-management evidence."
        ),
        evidence_categories=("business_continuity",),
    ),
    NIS2ControlReference(
        control_id="nis2_art_21_2_d",
        article_reference="Article 21(2)(d)",
        title="Supply chain security",
        plain_language_summary=(
            "Supplier, service-provider, onboarding, contract, and review evidence."
        ),
        evidence_categories=("supplier_security",),
    ),
    NIS2ControlReference(
        control_id="nis2_art_21_2_e",
        article_reference="Article 21(2)(e)",
        title="Secure acquisition, development, maintenance, and vulnerability handling",
        plain_language_summary=(
            "Patch, vulnerability, secure-development, maintenance, and disclosure evidence."
        ),
        evidence_categories=("vulnerability_management", "secure_development"),
    ),
    NIS2ControlReference(
        control_id="nis2_art_21_2_f",
        article_reference="Article 21(2)(f)",
        title="Effectiveness assessment of cybersecurity measures",
        plain_language_summary=(
            "Control testing, control-effectiveness review, and security-metric evidence."
        ),
        evidence_categories=("control_effectiveness",),
    ),
    NIS2ControlReference(
        control_id="nis2_art_21_2_g",
        article_reference="Article 21(2)(g)",
        title="Cyber hygiene and cybersecurity training",
        plain_language_summary=(
            "Cyber-hygiene, awareness, phishing exercise, and training evidence."
        ),
        evidence_categories=("cyber_hygiene_training",),
    ),
    NIS2ControlReference(
        control_id="nis2_art_21_2_h",
        article_reference="Article 21(2)(h)",
        title="Cryptography and encryption",
        plain_language_summary="Cryptography, encryption, and key-management policy evidence.",
        evidence_categories=("cryptography_encryption",),
    ),
    NIS2ControlReference(
        control_id="nis2_art_21_2_i",
        article_reference="Article 21(2)(i)",
        title="Human resources security, access control, and asset management",
        plain_language_summary=(
            "Access control, privileged access, HR security, and asset-inventory evidence."
        ),
        evidence_categories=("access_control", "asset_management"),
    ),
    NIS2ControlReference(
        control_id="nis2_art_21_2_j",
        article_reference="Article 21(2)(j)",
        title="Multi-factor authentication and secured communications",
        plain_language_summary=(
            "Strong authentication, continuous authentication, and secured communications evidence."
        ),
        evidence_categories=("secure_auth_communications", "access_control"),
    ),
)


def build_control_coverage(documents: Sequence[Mapping[str, object]]) -> dict[str, object]:
    """Build metadata-only Article 21(2) coverage from triage document summaries."""
    category_counts = _sum_category_counts(documents)
    strong_category_files = _collect_strong_category_files(documents)
    controls = [
        _build_control_item(ref, category_counts, strong_category_files)
        for ref in NIS2_CONTROL_REFERENCES
    ]
    status_counts = Counter(str(control["status"]) for control in controls)

    return {
        "reference_basis": NIS2_ARTICLE_21_REFERENCE_BASIS,
        "source_url": NIS2_ARTICLE_21_SOURCE_URL,
        "coverage_note": CONTROL_COVERAGE_NOTE,
        "controls_total": len(controls),
        "status_counts": {
            COVERAGE_STRONG: status_counts.get(COVERAGE_STRONG, 0),
            COVERAGE_REVIEW: status_counts.get(COVERAGE_REVIEW, 0),
            COVERAGE_MISSING: status_counts.get(COVERAGE_MISSING, 0),
        },
        "controls": controls,
    }


def _build_control_item(
    reference: NIS2ControlReference,
    category_counts: Mapping[str, int],
    strong_category_files: Mapping[str, set[str]],
) -> dict[str, object]:
    linked_categories = reference.evidence_categories
    detected_categories = tuple(
        category for category in linked_categories if category_counts.get(category, 0) > 0
    )
    strong_categories = tuple(
        category for category in linked_categories if strong_category_files.get(category)
    )
    status = _status_for_categories(detected_categories, strong_categories)

    return {
        **asdict(reference),
        "status": status,
        "detected_categories": detected_categories,
        "strong_categories": strong_categories,
        "evidence_count": sum(category_counts.get(category, 0) for category in linked_categories),
        "strong_document_count": len(
            {
                file_name
                for category in strong_categories
                for file_name in strong_category_files.get(category, set())
            }
        ),
    }


def _sum_category_counts(documents: Sequence[Mapping[str, object]]) -> dict[str, int]:
    totals: dict[str, int] = {}
    for document in documents:
        categories = document.get("categories", {})
        if not isinstance(categories, Mapping):
            continue
        for category, count in categories.items():
            category_name = str(category)
            totals[category_name] = totals.get(category_name, 0) + _as_non_negative_int(count)
    return totals


def _collect_strong_category_files(
    documents: Sequence[Mapping[str, object]],
) -> dict[str, set[str]]:
    files_by_category: dict[str, set[str]] = {}
    for document in documents:
        file_name = str(document.get("file", ""))
        strong_categories = document.get("strong_categories", ())
        if isinstance(strong_categories, str) or not isinstance(strong_categories, Sequence):
            continue
        for category in strong_categories:
            category_name = str(category)
            files_by_category.setdefault(category_name, set()).add(file_name)
    return files_by_category


def _status_for_categories(
    detected_categories: Sequence[str],
    strong_categories: Sequence[str],
) -> str:
    if strong_categories:
        return COVERAGE_STRONG
    if detected_categories:
        return COVERAGE_REVIEW
    return COVERAGE_MISSING


def _as_non_negative_int(value: object) -> int:
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return max(0, value)
    if isinstance(value, str) and value.isdecimal():
        return int(value)
    return 0
