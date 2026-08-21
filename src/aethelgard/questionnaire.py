"""Questionnaire import, control mapping, and evidence-backed draft answers."""

from __future__ import annotations

import csv
import hashlib
import json
import re
from collections import Counter
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Final, Literal, cast

from aethelgard import __version__
from aethelgard.control_catalog import (
    ControlCatalogBundle,
    ControlDefinition,
    load_control_catalog_bundle,
)
from aethelgard.evidence_store import (
    EvidenceRecord,
    EvidenceStoreDocument,
    load_evidence_store,
    safe_claims,
)
from aethelgard.redaction_preflight import has_sensitive_markers, mask_sensitive_text
from aethelgard.review import REVIEW_CSV_COLUMNS, REVIEW_CSV_NAME, safe_review_csv_cell
from aethelgard.triage import DISCLAIMER

QUESTIONNAIRE_JSON_NAME: Final[str] = "questionnaire_answers.json"
QUESTIONNAIRE_MD_NAME: Final[str] = "questionnaire_answers.md"
QUESTION_ID_PREFIX: Final[str] = "question_"
QUESTION_FINDING_PREFIX: Final[str] = "Q-"
QUESTION_FINDING_HASH_CHARS: Final[int] = 10
MAX_QUESTIONS: Final[int] = 300
MAX_QUESTION_CHARS: Final[int] = 600
MAX_QUESTION_ID_CHARS: Final[int] = 80
MAX_MAPPED_CONTROLS: Final[int] = 3
MAX_DRAFT_CLAIMS: Final[int] = 3
MAX_MARKDOWN_CELL_CHARS: Final[int] = 240

QuestionStatus = Literal["needs_evidence", "draft_review_required", "draft_ready"]


class QuestionnaireError(ValueError):
    """Raised when a questionnaire import or answer draft cannot be built."""


class QuestionnaireQuestion:
    """A normalized CSV questionnaire row."""

    __slots__ = ("question_id", "question", "row_number")

    def __init__(self, question_id: str, question: str, row_number: int) -> None:
        self.question_id = question_id
        self.question = question
        self.row_number = row_number


def run_questionnaire(
    questions_csv: Path | str,
    evidence_store_path: Path | str,
    out_dir: Path | str | None = None,
    *,
    catalog_dir: Path | str | None = None,
) -> dict[str, object]:
    """Build questionnaire answers from existing evidence only."""
    catalog_bundle = (
        load_control_catalog_bundle(catalog_dir) if catalog_dir else load_control_catalog_bundle()
    )
    evidence_store = load_evidence_store(evidence_store_path, catalog_bundle=catalog_bundle)
    questions_path = Path(questions_csv)
    questions = read_questionnaire_csv(questions_path)
    items = [
        _build_questionnaire_item(question, catalog_bundle, evidence_store)
        for question in questions
    ]
    status_counts = Counter(str(item["answer_status"]) for item in items)
    report: dict[str, object] = {
        "run_id": _build_run_id("questionnaire"),
        "timestamp": datetime.now(UTC).isoformat(),
        "questionnaire_path": questions_path.name,
        "catalog_ids": catalog_bundle.catalog_ids,
        "question_count": len(questions),
        "status_counts": {
            "needs_evidence": status_counts.get("needs_evidence", 0),
            "draft_review_required": status_counts.get("draft_review_required", 0),
            "draft_ready": status_counts.get("draft_ready", 0),
        },
        "items": items,
        "per_document": [
            {
                "file": questions_path.name,
                "evidence_count": len(items),
                "evidence": [_review_compatible_item(item) for item in items],
            }
        ],
        "tool_version": __version__,
        "disclaimer": DISCLAIMER,
    }
    if out_dir is not None:
        output_path = Path(out_dir)
        output_path.mkdir(parents=True, exist_ok=True)
        _write_json(output_path / QUESTIONNAIRE_JSON_NAME, report)
        _write_text(output_path / QUESTIONNAIRE_MD_NAME, render_questionnaire_markdown(report))
        _write_review_csv(output_path / REVIEW_CSV_NAME, report)
    return report


def read_questionnaire_csv(path: Path | str) -> list[QuestionnaireQuestion]:
    """Import security questions from a CSV file."""
    questions: list[QuestionnaireQuestion] = []
    seen_question_ids: set[str] = set()
    with Path(path).open(encoding="utf-8", newline="") as csv_file:
        reader = csv.DictReader(csv_file)
        fieldnames = reader.fieldnames or []
        if "question" not in fieldnames:
            raise QuestionnaireError("questionnaire CSV is missing question column")
        for row_number, row in enumerate(reader, start=2):
            if len(questions) >= MAX_QUESTIONS:
                raise QuestionnaireError("questionnaire exceeds maximum row count")
            raw_question = str(row.get("question", "")).strip()
            if not raw_question:
                raise QuestionnaireError("questionnaire row %d is missing question" % row_number)
            if len(raw_question) > MAX_QUESTION_CHARS:
                raise QuestionnaireError(
                    "questionnaire row %d exceeds question length limit" % row_number
                )
            raw_id = str(row.get("question_id") or row.get("id") or "").strip()
            question_id = raw_id if raw_id else "%s%03d" % (QUESTION_ID_PREFIX, len(questions) + 1)
            if len(question_id) > MAX_QUESTION_ID_CHARS:
                raise QuestionnaireError(
                    "questionnaire row %d exceeds question_id length limit" % row_number
                )
            safe_question_id = _safe_output_text(question_id)
            if safe_question_id in seen_question_ids:
                raise QuestionnaireError(
                    "questionnaire row %d duplicates question_id %s"
                    % (row_number, safe_question_id)
                )
            seen_question_ids.add(safe_question_id)
            questions.append(
                QuestionnaireQuestion(
                    question_id=safe_question_id,
                    question=_safe_output_text(raw_question),
                    row_number=row_number,
                )
            )
    return questions


def map_question_to_controls(
    question: str,
    catalog_bundle: ControlCatalogBundle,
) -> tuple[str, ...]:
    """Map one question to likely controls using deterministic keyword hits."""
    normalized = _normalize_for_match(question)
    scored: list[tuple[int, str]] = []
    for control in catalog_bundle.controls_by_id.values():
        score = _score_control_match(normalized, control)
        if score > 0:
            scored.append((score, control.control_id))
    scored.sort(key=lambda item: (-item[0], item[1]))
    return tuple(control_id for _score, control_id in scored[:MAX_MAPPED_CONTROLS])


def render_questionnaire_markdown(report: Mapping[str, object]) -> str:
    """Render a review-friendly questionnaire answer report."""
    status_counts = cast(Mapping[str, int], report["status_counts"])
    items = cast(Sequence[Mapping[str, object]], report["items"])
    question_count = int(cast(int, report["question_count"]))
    lines = [
        "# AethelGard Questionnaire Evidence Drafts",
        "",
        "## Scope / Disclaimer",
        str(report["disclaimer"]),
        "",
        "## Status",
        "- Questions: %d" % question_count,
        "- Needs evidence: %d" % status_counts["needs_evidence"],
        "- Draft review required: %d" % status_counts["draft_review_required"],
        "- Draft ready: %d" % status_counts["draft_ready"],
        "",
        "## Review Items",
        "| Finding ID | Status | Controls | Evidence Refs | Question |",
        "|---|---|---|---|---|",
    ]
    for item in items:
        evidence_refs = cast(Sequence[str], item["evidence_refs"])
        controls = cast(Sequence[str], item["mapped_controls"])
        lines.append(
            "| `%s` | `%s` | `%s` | `%s` | %s |"
            % (
                _escape_markdown(str(item["finding_id"])),
                _escape_markdown(str(item["answer_status"])),
                _escape_markdown(", ".join(controls) or "-"),
                _escape_markdown(", ".join(evidence_refs) or "-"),
                _escape_markdown(_truncate(str(item["question"]), MAX_MARKDOWN_CELL_CHARS)),
            )
        )
    lines.extend(
        [
            "",
            "## Boundary",
            "- Draft answers are generated only from evidence-store metadata and "
            "evidence references.",
            "- Items without evidence are blocked as `needs_evidence`.",
            "- Human review is required before customer handover.",
        ]
    )
    return "\n".join(lines) + "\n"


def _build_questionnaire_item(
    question: QuestionnaireQuestion,
    catalog_bundle: ControlCatalogBundle,
    evidence_store: EvidenceStoreDocument,
) -> dict[str, object]:
    mapped_controls = map_question_to_controls(question.question, catalog_bundle)
    evidence = _matching_evidence(evidence_store.evidence, mapped_controls)
    evidence_refs = tuple(record.evidence_id for record in evidence)
    status = _answer_status(evidence)
    draft_answer = _build_draft_answer(evidence) if evidence_refs else ""
    if draft_answer and not evidence_refs:
        raise QuestionnaireError("draft answer was built without evidence_refs")
    finding_id = _build_finding_id(question.question_id, question.question, mapped_controls)
    return {
        "finding_id": finding_id,
        "question_id": question.question_id,
        "question": question.question,
        "mapped_controls": mapped_controls,
        "required_evidence": _required_evidence_for_controls(mapped_controls, catalog_bundle),
        "answer_status": status,
        "draft_answer": draft_answer,
        "evidence_refs": evidence_refs,
        "review_required": status != "draft_ready",
        "source_reference": "%s#%s" % ("questionnaire", question.question_id),
        "recommended_manual_check": _manual_check(status),
    }


def _matching_evidence(
    evidence: Sequence[EvidenceRecord],
    mapped_controls: Sequence[str],
) -> tuple[EvidenceRecord, ...]:
    if not mapped_controls:
        return ()
    wanted = set(mapped_controls)
    return tuple(
        record
        for record in evidence
        if record.validity != "expired" and wanted.intersection(record.mapped_controls)
    )


def _answer_status(evidence: Sequence[EvidenceRecord]) -> QuestionStatus:
    if not evidence:
        return "needs_evidence"
    if any(record.review_required or record.validity != "current" for record in evidence):
        return "draft_review_required"
    return "draft_ready"


def _build_draft_answer(evidence: Sequence[EvidenceRecord]) -> str:
    refs = ", ".join(record.evidence_id for record in evidence)
    claims: list[str] = []
    for record in evidence:
        claims.extend(safe_claims(record))
        if len(claims) >= MAX_DRAFT_CLAIMS:
            break
    claim_text = "; ".join(claims[:MAX_DRAFT_CLAIMS])
    if claim_text:
        return (
            "Evidence refs %s support this draft: %s. Human review required."
            % (refs, claim_text)
        )
    return (
        "Evidence refs %s are available for the mapped controls, but no reusable claim text "
        "is stored. Human review required." % refs
    )


def _score_control_match(normalized_question: str, control: ControlDefinition) -> int:
    score = 0
    for keyword in control.keywords:
        if _normalize_for_match(keyword) in normalized_question:
            score += 3
    for evidence_name in control.required_evidence:
        evidence_phrase = _normalize_for_match(evidence_name.replace("_", " "))
        if evidence_phrase in normalized_question:
            score += 2
    title_words = tuple(
        word for word in _normalize_for_match(control.title).split() if len(word) > 3
    )
    score += sum(1 for word in title_words if word in normalized_question)
    return score


def _required_evidence_for_controls(
    mapped_controls: Sequence[str],
    catalog_bundle: ControlCatalogBundle,
) -> tuple[str, ...]:
    required: list[str] = []
    controls = catalog_bundle.controls_by_id
    for control_id in mapped_controls:
        control = controls.get(control_id)
        if control is not None:
            required.extend(control.required_evidence)
    return tuple(sorted(set(required)))


def _review_compatible_item(item: Mapping[str, object]) -> dict[str, object]:
    status = str(item["answer_status"])
    mapped_controls = cast(Sequence[str], item["mapped_controls"])
    evidence_refs = cast(Sequence[str], item["evidence_refs"])
    return {
        "finding_id": item["finding_id"],
        "category": mapped_controls[0] if mapped_controls else "questionnaire_unmapped",
        "quality": "medium" if evidence_refs else "warning",
        "quality_signals": (status,),
        "concrete_features": ("evidence_refs",) if evidence_refs else (),
        "strong": False,
        "source_citation": _truncate(str(item["question"]), MAX_MARKDOWN_CELL_CHARS),
        "source_reference": item["source_reference"],
        "recommended_manual_check": item["recommended_manual_check"],
        "answer_status": status,
        "draft_answer": item["draft_answer"],
        "evidence_refs": evidence_refs,
    }


def _write_review_csv(path: Path, report: Mapping[str, object]) -> None:
    items = cast(Sequence[Mapping[str, object]], report["items"])
    with path.open("w", encoding="utf-8", newline="") as csv_file:
        writer = csv.DictWriter(csv_file, fieldnames=list(REVIEW_CSV_COLUMNS), lineterminator="\n")
        writer.writeheader()
        for item in items:
            mapped_controls = cast(Sequence[str], item["mapped_controls"])
            evidence_refs = cast(Sequence[str], item["evidence_refs"])
            row = {
                "finding_id": str(item["finding_id"]),
                "category": mapped_controls[0] if mapped_controls else "questionnaire_unmapped",
                "control_area": ", ".join(mapped_controls) or "unmapped",
                "document": str(report["questionnaire_path"]),
                "evidence_level": "medium" if evidence_refs else "warning",
                "status": str(item["answer_status"]),
                "finding": _truncate(str(item["question"]), MAX_MARKDOWN_CELL_CHARS),
                "recommended_manual_check": str(item["recommended_manual_check"]),
                "source_reference": str(item["source_reference"]),
                "review_status": "",
                "review_note": "",
                "reviewer": "",
                "reviewed_at": "",
            }
            writer.writerow({key: safe_review_csv_cell(value) for key, value in row.items()})


def _manual_check(status: str) -> str:
    if status == "needs_evidence":
        return "Collect or map evidence before drafting an answer."
    if status == "draft_review_required":
        return "Verify evidence freshness, review flag, and answer wording before use."
    return "Confirm reviewer approval before customer handover."


def _build_finding_id(
    question_id: str,
    question: str,
    mapped_controls: Sequence[str],
) -> str:
    basis = "\n".join((question_id, _normalize_for_match(question), "\n".join(mapped_controls)))
    digest = hashlib.sha256(basis.encode("utf-8")).hexdigest()[:QUESTION_FINDING_HASH_CHARS]
    return "%s%s" % (QUESTION_FINDING_PREFIX, digest)


def _safe_output_text(value: str) -> str:
    return mask_sensitive_text(value) if has_sensitive_markers(value) else value


def _normalize_for_match(value: str) -> str:
    return " ".join(value.casefold().replace("-", " ").replace("_", " ").split())


def _truncate(value: str, max_chars: int) -> str:
    if len(value) <= max_chars:
        return value
    return value[: max_chars - 3].rstrip() + "..."


def _escape_markdown(value: str) -> str:
    return re.sub(r"([`*_\[\]<>|])", r"\\\1", value)


def _build_run_id(prefix: str) -> str:
    return "%s-%s" % (prefix, datetime.now(UTC).strftime("%Y%m%dT%H%M%S%fZ"))


def _write_json(path: Path, payload: Mapping[str, object]) -> None:
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _write_text(path: Path, text: str) -> None:
    path.write_text(text, encoding="utf-8")
