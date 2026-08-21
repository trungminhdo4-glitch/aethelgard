"""Unit tests for the additive ``evidence_basis`` label on supplier-risk reports.

The label mirrors the fragility labeling in the sibling HOS discovery module: it distinguishes a
score carried by several independent signal families from one that rests solely on the self-declared
criticality. It is purely additive — it must not change ``risk_score`` or ``risk_level``.
"""
from __future__ import annotations

from aethelgard.supplier_risk import (
    EVIDENCE_BASIS_CORROBORATED,
    EVIDENCE_BASIS_CRITICALITY_ONLY,
    EVIDENCE_BASIS_PARTIAL,
    SupplierProfile,
    build_supplier_risk_report,
    render_supplier_risk_markdown,
)


def _profile(criticality: str = "critical") -> SupplierProfile:
    return SupplierProfile.model_validate(
        {"supplier_id": "S1", "name": "Acme", "criticality": criticality}
    )


def _questionnaire(needs_evidence: int = 0, draft_review: int = 0) -> dict[str, object]:
    items = (
        [{"answer_status": "needs_evidence"}] * needs_evidence
        + [{"answer_status": "draft_review_required"}] * draft_review
    )
    return {"items": items}


def _findings(open_count: int = 0) -> dict[str, object]:
    evidence = [{"review_status": "open", "quality": "warning"}] * open_count
    return {"per_document": [{"evidence": evidence}]}


def test_criticality_only_when_no_other_signal() -> None:
    report = build_supplier_risk_report(_profile("critical"), _questionnaire())
    assert report["evidence_basis"] == EVIDENCE_BASIS_CRITICALITY_ONLY
    # The 'medium' label rests solely on the self-declared criticality (base 75) — the exact case
    # the label exists to flag (no assessed questionnaire evidence, no findings).
    assert report["risk_level"] == "medium"


def test_partial_evidence_with_single_signal() -> None:
    report = build_supplier_risk_report(_profile("medium"), _questionnaire(needs_evidence=2))
    assert report["evidence_basis"] == EVIDENCE_BASIS_PARTIAL


def test_corroborated_with_two_signals() -> None:
    report = build_supplier_risk_report(
        _profile("medium"), _questionnaire(needs_evidence=1), _findings(open_count=2)
    )
    assert report["evidence_basis"] == EVIDENCE_BASIS_CORROBORATED


def test_evidence_basis_is_additive_and_does_not_change_score() -> None:
    report = build_supplier_risk_report(_profile("critical"), _questionnaire())
    # Purely additive: risk_score stays the plain sum of components (label is metadata only).
    components = report["score_components"]
    assert isinstance(components, dict)
    assert report["risk_score"] == sum(components.values())


def test_markdown_renders_evidence_basis() -> None:
    report = build_supplier_risk_report(_profile("critical"), _questionnaire())
    md = render_supplier_risk_markdown(report)
    assert "Evidence basis" in md
    assert EVIDENCE_BASIS_CRITICALITY_ONLY in md
