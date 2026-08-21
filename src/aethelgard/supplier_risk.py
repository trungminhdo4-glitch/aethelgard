"""Deterministic supplier-risk scoring from C-SCRM questionnaire outputs."""

from __future__ import annotations

import json
import re
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Final, Literal, cast

from pydantic import BaseModel, ConfigDict, Field

from aethelgard import __version__
from aethelgard.redaction_preflight import has_sensitive_markers, mask_sensitive_text

SUPPLIER_RISK_JSON_NAME: Final[str] = "supplier_risk.json"
SUPPLIER_RISK_MD_NAME: Final[str] = "supplier_risk.md"
MAX_SUPPLIER_ID_CHARS: Final[int] = 80
MAX_SUPPLIER_NAME_CHARS: Final[int] = 160
MAX_SERVICES: Final[int] = 20
MAX_SERVICE_CHARS: Final[int] = 120
EVIDENCE_GAP_WEIGHT: Final[int] = 8
EVIDENCE_GAP_CAP: Final[int] = 24
OPEN_FINDING_WEIGHT: Final[int] = 3
OPEN_FINDING_CAP: Final[int] = 15
QUESTION_REVIEW_WEIGHT: Final[int] = 3
QUESTION_REVIEW_CAP: Final[int] = 12
MAX_RISK_SCORE: Final[int] = 100
HIGH_RISK_THRESHOLD: Final[int] = 80
MEDIUM_RISK_THRESHOLD: Final[int] = 60
LOW_RISK_THRESHOLD: Final[int] = 35

# Evidence-basis label (purely additive; does NOT change risk_score/risk_level). Mirrors the
# fragility labeling in the sibling HOS discovery module: a score driven only by the self-declared
# criticality base is far thinner than one corroborated by assessed questionnaire items + findings.
EVIDENCE_BASIS_CORROBORATED: Final[str] = "corroborated"
EVIDENCE_BASIS_PARTIAL: Final[str] = "partial_evidence"
EVIDENCE_BASIS_CRITICALITY_ONLY: Final[str] = "criticality_only"
MIN_CORROBORATION_SIGNALS: Final[int] = 2

Criticality = Literal["low", "medium", "high", "critical"]

CRITICALITY_BASE_SCORE: Final[dict[str, int]] = {
    "low": 20,
    "medium": 40,
    "high": 60,
    "critical": 75,
}


class SupplierRiskError(ValueError):
    """Raised when supplier-risk input cannot be processed."""


class SupplierProfile(BaseModel):
    """Supplier metadata used for local deterministic risk scoring."""

    model_config = ConfigDict(
        frozen=True,
        extra="forbid",
        str_strip_whitespace=True,
    )

    supplier_id: str = Field(min_length=1, max_length=MAX_SUPPLIER_ID_CHARS)
    name: str = Field(min_length=1, max_length=MAX_SUPPLIER_NAME_CHARS)
    criticality: Criticality
    services: tuple[str, ...] = Field(default=(), max_length=MAX_SERVICES)


def run_supplier_risk(
    profile_path: Path | str,
    questionnaire_report_path: Path | str,
    out_dir: Path | str | None = None,
    *,
    findings_report_path: Path | str | None = None,
) -> dict[str, object]:
    """Score supplier risk from profile criticality, gaps, findings, and questionnaire status."""
    profile = _load_supplier_profile(Path(profile_path))
    questionnaire_report = _read_json(Path(questionnaire_report_path), "questionnaire report")
    findings_report = (
        _read_json(Path(findings_report_path), "findings report")
        if findings_report_path is not None
        else None
    )
    score_report = build_supplier_risk_report(profile, questionnaire_report, findings_report)
    if out_dir is not None:
        output_path = Path(out_dir)
        output_path.mkdir(parents=True, exist_ok=True)
        _write_json(output_path / SUPPLIER_RISK_JSON_NAME, score_report)
        _write_text(
            output_path / SUPPLIER_RISK_MD_NAME,
            render_supplier_risk_markdown(score_report),
        )
    return score_report


def build_supplier_risk_report(
    profile: SupplierProfile,
    questionnaire_report: Mapping[str, object],
    findings_report: Mapping[str, object] | None = None,
) -> dict[str, object]:
    """Build a deterministic metadata-only supplier-risk report."""
    items = cast(Sequence[Mapping[str, object]], questionnaire_report.get("items", ()))
    status_counts = _questionnaire_status_counts(items)
    open_findings = _count_open_findings(findings_report) if findings_report is not None else 0
    score_components = _score_components(profile.criticality, status_counts, open_findings)
    risk_score = min(MAX_RISK_SCORE, sum(score_components.values()))
    return {
        "run_id": _build_run_id("supplier-risk"),
        "timestamp": datetime.now(UTC).isoformat(),
        "supplier": {
            "supplier_id": _safe_output_text(profile.supplier_id),
            "name": _safe_output_text(profile.name),
            "criticality": profile.criticality,
            "services": tuple(_safe_output_text(service) for service in profile.services),
        },
        "risk_score": risk_score,
        "risk_level": _risk_level(risk_score),
        "evidence_basis": _evidence_basis(score_components),
        "score_components": score_components,
        "questionnaire_status_counts": status_counts,
        "open_findings": open_findings,
        "evidence_gap_count": status_counts["needs_evidence"],
        "tool_version": __version__,
        "disclaimer": (
            "Deterministic local prioritization only. This is not legal advice, not an audit, "
            "not a certification, and not a compliance decision."
        ),
    }


def render_supplier_risk_markdown(report: Mapping[str, object]) -> str:
    """Render a concise supplier-risk report without raw evidence contents."""
    supplier = cast(Mapping[str, object], report["supplier"])
    status_counts = cast(Mapping[str, int], report["questionnaire_status_counts"])
    components = cast(Mapping[str, int], report["score_components"])
    risk_score = int(cast(int, report["risk_score"]))
    open_findings = int(cast(int, report["open_findings"]))
    lines = [
        "# AethelGard Supplier Risk",
        "",
        "## Scope / Disclaimer",
        str(report["disclaimer"]),
        "",
        "## Supplier",
        "- Supplier ID: `%s`" % _escape_markdown(str(supplier["supplier_id"])),
        "- Name: `%s`" % _escape_markdown(str(supplier["name"])),
        "- Criticality: `%s`" % supplier["criticality"],
        "",
        "## Score",
        "- Risk score: `%d`" % risk_score,
        "- Risk level: `%s`" % report["risk_level"],
        "- Evidence basis: `%s`" % report.get("evidence_basis", EVIDENCE_BASIS_CRITICALITY_ONLY),
        "",
        "## Components",
    ]
    for key, value in components.items():
        lines.append("- %s: %d" % (_escape_markdown(key), value))
    lines.extend(
        [
            "",
            "## Questionnaire Signals",
            "- Needs evidence: %d" % status_counts["needs_evidence"],
            "- Draft review required: %d" % status_counts["draft_review_required"],
            "- Draft ready: %d" % status_counts["draft_ready"],
            "- Open findings: %d" % open_findings,
        ]
    )
    return "\n".join(lines) + "\n"


def _load_supplier_profile(path: Path) -> SupplierProfile:
    payload = _read_json(path, "supplier profile")
    try:
        return SupplierProfile.model_validate(payload)
    except ValueError as exc:
        raise SupplierRiskError("invalid supplier profile: %s" % path) from exc


def _questionnaire_status_counts(items: Sequence[Mapping[str, object]]) -> dict[str, int]:
    counts = {"needs_evidence": 0, "draft_review_required": 0, "draft_ready": 0}
    for item in items:
        status = str(item.get("answer_status", "needs_evidence"))
        if status not in counts:
            status = "needs_evidence"
        counts[status] += 1
    return counts


def _count_open_findings(report: Mapping[str, object] | None) -> int:
    if report is None:
        return 0
    count = 0
    documents = cast(Sequence[Mapping[str, object]], report.get("per_document", ()))
    for document in documents:
        findings = cast(Sequence[Mapping[str, object]], document.get("evidence", ()))
        for finding in findings:
            review_status = str(finding.get("review_status", "open") or "open")
            quality = str(finding.get("quality", ""))
            if review_status in {"open", "needs_evidence"} or quality == "warning":
                count += 1
    return count


def _score_components(
    criticality: str,
    status_counts: Mapping[str, int],
    open_findings: int,
) -> dict[str, int]:
    return {
        "criticality": CRITICALITY_BASE_SCORE[criticality],
        "evidence_gaps": min(
            EVIDENCE_GAP_CAP,
            status_counts["needs_evidence"] * EVIDENCE_GAP_WEIGHT,
        ),
        "open_findings": min(OPEN_FINDING_CAP, open_findings * OPEN_FINDING_WEIGHT),
        "questionnaire_review": min(
            QUESTION_REVIEW_CAP,
            status_counts["draft_review_required"] * QUESTION_REVIEW_WEIGHT,
        ),
    }


def _risk_level(score: int) -> str:
    if score >= HIGH_RISK_THRESHOLD:
        return "high"
    if score >= MEDIUM_RISK_THRESHOLD:
        return "medium"
    if score >= LOW_RISK_THRESHOLD:
        return "low"
    return "watch"


def _evidence_basis(score_components: Mapping[str, int]) -> str:
    """Classify how broadly the score is evidenced (purely additive; risk_score is unchanged).

    ``criticality`` is always present (self-declared base). Count the *other* non-zero components
    (evidence gaps, open findings, questionnaire review) as independent signal families: >=2 =>
    corroborated, exactly 1 => partial_evidence, none => criticality_only (the score rests solely on
    the self-declared criticality — a 'medium'/'high' label without any assessed evidence).
    """
    corroborating = sum(
        1
        for name, value in score_components.items()
        if name != "criticality" and value > 0
    )
    if corroborating >= MIN_CORROBORATION_SIGNALS:
        return EVIDENCE_BASIS_CORROBORATED
    if corroborating == 1:
        return EVIDENCE_BASIS_PARTIAL
    return EVIDENCE_BASIS_CRITICALITY_ONLY


def _read_json(path: Path, label: str) -> Mapping[str, object]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise SupplierRiskError("could not read %s: %s" % (label, path)) from exc
    except json.JSONDecodeError as exc:
        raise SupplierRiskError("invalid %s JSON: %s" % (label, path)) from exc
    if not isinstance(payload, Mapping):
        raise SupplierRiskError("%s must contain a JSON object" % label)
    return cast(Mapping[str, object], payload)


def _safe_output_text(value: str) -> str:
    return mask_sensitive_text(value) if has_sensitive_markers(value) else value


def _escape_markdown(value: str) -> str:
    return re.sub(r"([`*_\[\]<>|])", r"\\\1", value)


def _build_run_id(prefix: str) -> str:
    return "%s-%s" % (prefix, datetime.now(UTC).strftime("%Y%m%dT%H%M%S%fZ"))


def _write_json(path: Path, payload: Mapping[str, object]) -> None:
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _write_text(path: Path, text: str) -> None:
    path.write_text(text, encoding="utf-8")
