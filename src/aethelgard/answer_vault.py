"""SQLite-backed reusable answer vault for local questionnaire drafting."""

from __future__ import annotations

import csv
import hashlib
import json
import contextlib
import sqlite3
from collections import Counter
from collections.abc import Iterator, Mapping, Sequence
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Final, Literal, cast

from aethelgard import __version__
from aethelgard.document_ingest import CONTROL_ALIASES, TOPIC_CLUSTERS, detect_topics_for_text
from aethelgard.pii_classification import CompanyMetadata, guard_shareable_text
from aethelgard.questionnaire import (
    MAX_QUESTION_CHARS,
    QuestionnaireQuestion,
    read_questionnaire_csv,
)
from aethelgard.redaction_preflight import has_sensitive_markers, mask_sensitive_text
from aethelgard.review import safe_review_csv_cell
from aethelgard.triage import DISCLAIMER

ANSWER_VAULT_SCHEMA_VERSION: Final[str] = "1"
ANSWER_LIBRARY_EXPORT_NAME: Final[str] = "answer_library.json"
QUESTIONNAIRE_DRAFT_CSV_NAME: Final[str] = "questionnaire_draft.csv"
CASE_REVIEW_QUEUE_CSV_NAME: Final[str] = "case_review_queue.csv"
MISSING_EVIDENCE_CSV_NAME: Final[str] = "missing_evidence.csv"

MAX_CLIENT_ID_CHARS: Final[int] = 80
MAX_CASE_ID_CHARS: Final[int] = 80
MAX_ANSWER_CHARS: Final[int] = 1_200
MAX_REVIEWER_CHARS: Final[int] = 120
MAX_REASON_CHARS: Final[int] = 400
MAX_EVIDENCE_REFS: Final[int] = 12
ANSWER_ID_HASH_CHARS: Final[int] = 14
DRAFT_ID_HASH_CHARS: Final[int] = 14
VERSION_ID_HASH_CHARS: Final[int] = 16
AUDIT_ID_HASH_CHARS: Final[int] = 16
REVIEWED_ANSWER_STATUSES: Final[frozenset[str]] = frozenset(
    {"accepted", "reviewed", "resolved"}
)
FINAL_DRAFT_STATUSES: Final[frozenset[str]] = frozenset({"reviewed"})
EVIDENCE_DRAFT_CONFIDENCE: Final[float] = 0.64

ReviewStatus = Literal["draft", "needs_review", "reviewed", "rejected", "stale", "missing_evidence"]

QUESTION_DRAFT_COLUMNS: Final[tuple[str, ...]] = (
    "question_id",
    "original_question",
    "normalized_question",
    "matched_cluster",
    "draft_answer",
    "evidence_refs",
    "confidence",
    "review_status",
    "reason",
    "missing_evidence",
    "source_answer_id",
    "source_case_id",
)
CASE_REVIEW_COLUMNS: Final[tuple[str, ...]] = (
    "case_id",
    "question_id",
    "original_question",
    "normalized_question",
    "proposed_cluster",
    "proposed_answer",
    "evidence_refs",
    "reason_for_review",
    "missing_evidence",
    "reviewer_decision",
    "reviewer_note",
    "final_answer",
)
MISSING_EVIDENCE_COLUMNS: Final[tuple[str, ...]] = (
    "cluster",
    "status",
    "question_ids",
    "required_evidence",
    "reason",
)

CANONICAL_QUESTION_BANK: Final[tuple[dict[str, str], ...]] = (
    {
        "cluster": "access_control",
        "question": "How are access rights assigned, reviewed, and removed?",
    },
    {"cluster": "mfa", "question": "Where is multi-factor authentication required?"},
    {
        "cluster": "identity_lifecycle",
        "question": "How are joiner, mover, and leaver identity changes handled?",
    },
    {
        "cluster": "privileged_access",
        "question": "How are privileged accounts controlled and reviewed?",
    },
    {"cluster": "backup", "question": "How are backups created and protected?"},
    {"cluster": "restore_test", "question": "How are restore tests performed and recorded?"},
    {
        "cluster": "incident_response",
        "question": "How are security incidents escalated and handled?",
    },
    {
        "cluster": "business_continuity",
        "question": "How are business continuity plans maintained and tested?",
    },
    {
        "cluster": "patch_management",
        "question": "How are security patches tracked and deployed?",
    },
    {
        "cluster": "vulnerability_management",
        "question": "How are vulnerabilities identified and remediated?",
    },
    {
        "cluster": "logging_monitoring",
        "question": "How are logs monitored and reviewed?",
    },
    {"cluster": "asset_inventory", "question": "How is the asset inventory maintained?"},
    {
        "cluster": "supplier_management",
        "question": "How are supplier security requirements reviewed?",
    },
    {
        "cluster": "data_protection",
        "question": "How are data protection responsibilities handled?",
    },
    {"cluster": "encryption", "question": "How is encryption used and managed?"},
    {
        "cluster": "awareness_training",
        "question": "How is security awareness training delivered?",
    },
    {"cluster": "risk_management", "question": "How are security risks assessed and tracked?"},
    {
        "cluster": "policy_governance",
        "question": "How are security policies owned and reviewed?",
    },
    {"cluster": "sbom", "question": "How is software supply-chain metadata tracked?"},
    {
        "cluster": "secure_development",
        "question": "How are secure development practices applied?",
    },
    {
        "cluster": "change_management",
        "question": "How are security-relevant changes approved and rolled back?",
    },
)


class AnswerVaultError(ValueError):
    """Raised when the local answer vault cannot be updated safely."""


def init_answer_vault(db_path: Path | str, *, client_id: str | None = None) -> dict[str, object]:
    """Create or migrate the SQLite answer vault schema idempotently."""
    path = Path(db_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with _connect(path) as connection:
        _apply_schema(connection)
        if client_id is not None:
            _upsert_client(connection, _safe_id(client_id, MAX_CLIENT_ID_CHARS, "client_id"))
        _seed_controls_and_questions(connection)
        _append_audit_log(connection, "init", {"client_id": client_id or ""})
    return {
        "status": "ready",
        "schema_version": ANSWER_VAULT_SCHEMA_VERSION,
        "db_path": str(path),
        "client_id": client_id or "",
    }


def store_ingest_result(
    db_path: Path | str,
    *,
    client_id: str,
    ingest_report: Mapping[str, object],
) -> dict[str, object]:
    """Store document, chunk, and evidence metadata in the local answer vault."""
    safe_client_id = _safe_id(client_id, MAX_CLIENT_ID_CHARS, "client_id")
    init_answer_vault(db_path, client_id=safe_client_id)
    inventory = cast(Mapping[str, object], ingest_report["inventory"])
    evidence_map = cast(Mapping[str, object], ingest_report["evidence_map"])
    documents = cast(Sequence[Mapping[str, object]], inventory["documents"])
    chunks = cast(Sequence[Mapping[str, object]], ingest_report["chunks"])
    evidence = cast(Sequence[Mapping[str, object]], evidence_map["evidence"])
    with _connect(Path(db_path)) as connection:
        for document in documents:
            connection.execute(
                """
                INSERT OR REPLACE INTO documents (
                    document_id, client_id, source_path, source_type, status,
                    sha256, evidence_count, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    str(document["document_id"]),
                    safe_client_id,
                    str(document["source_path"]),
                    str(document["source_type"]),
                    str(document["status"]),
                    str(document.get("sha256", "")),
                    _to_int(document.get("evidence_count", 0)),
                    _utc_now(),
                ),
            )
        for chunk in chunks:
            connection.execute(
                """
                INSERT OR REPLACE INTO document_chunks (
                    chunk_id, document_id, snippet_hash, detected_topics, confidence
                ) VALUES (?, ?, ?, ?, ?)
                """,
                (
                    str(chunk["chunk_id"]),
                    str(chunk["document_id"]),
                    str(chunk["snippet_hash"]),
                    "[]",
                    0.0,
                ),
            )
        for item in evidence:
            connection.execute(
                """
                INSERT OR REPLACE INTO evidence_items (
                    evidence_id, client_id, document_id, source_path, source_type,
                    chunk_id, snippet_hash, mapped_controls, confidence, reason,
                    review_status, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    str(item["evidence_id"]),
                    safe_client_id,
                    str(item["document_id"]),
                    str(item["source_path"]),
                    str(item["source_type"]),
                    str(item["chunk_id"]),
                    str(item["snippet_hash"]),
                    json.dumps(list(cast(Sequence[str], item["mapped_controls"]))),
                    _to_float(item["confidence"]),
                    str(item["reason"]),
                    "needs_review",
                    _utc_now(),
                ),
            )
        _append_audit_log(
            connection,
            "store_ingest",
            {"documents": len(documents), "evidence": len(evidence)},
        )
    return {"documents": len(documents), "chunks": len(chunks), "evidence": len(evidence)}


def import_answer_library_json(
    db_path: Path | str,
    answers_path: Path | str,
    *,
    client_id: str,
    company_metadata: CompanyMetadata | None = None,
) -> dict[str, object]:
    """Import a local reviewed baseline answer JSON document."""
    safe_client_id = _safe_id(client_id, MAX_CLIENT_ID_CHARS, "client_id")
    init_answer_vault(db_path, client_id=safe_client_id)
    payload = _read_json(Path(answers_path))
    raw_answers = payload.get("answers", [])
    if not isinstance(raw_answers, Sequence) or isinstance(raw_answers, (str, bytes, bytearray)):
        raise AnswerVaultError("answer library JSON must contain an answers array")
    imported = 0
    with _connect(Path(db_path)) as connection:
        for raw_answer in raw_answers:
            if not isinstance(raw_answer, Mapping):
                raise AnswerVaultError("answer library item must be an object")
            _upsert_answer(
                connection, safe_client_id, raw_answer, company_metadata=company_metadata
            )
            imported += 1
        _append_audit_log(connection, "import_answer_library", {"answers": imported})
    return {"imported": imported, "client_id": safe_client_id}


def import_reviewed_report_answers(
    db_path: Path | str,
    reviewed_report_path: Path | str,
    *,
    client_id: str,
    source_case_id: str = "",
    company_metadata: CompanyMetadata | None = None,
) -> dict[str, object]:
    """Import accepted/reviewed questionnaire findings into the answer vault."""
    safe_client_id = _safe_id(client_id, MAX_CLIENT_ID_CHARS, "client_id")
    safe_case_id = (
        _safe_id(source_case_id, MAX_CASE_ID_CHARS, "source_case_id")
        if source_case_id
        else ""
    )
    init_answer_vault(db_path, client_id=safe_client_id)
    report = _read_json(Path(reviewed_report_path))
    imported = 0
    skipped = 0
    with _connect(Path(db_path)) as connection:
        for item in _iter_reviewed_report_items(report):
            review_status = str(item.get("review_status", "open")).strip().lower()
            if review_status not in REVIEWED_ANSWER_STATUSES:
                skipped += 1
                continue
            draft_answer = str(item.get("draft_answer", "")).strip()
            evidence_refs = _normalize_string_sequence(item.get("evidence_refs", ()))
            if not draft_answer or not evidence_refs:
                skipped += 1
                continue
            controls = _normalize_string_sequence(
                item.get("mapped_controls") or item.get("control_area") or item.get("category")
            )
            cluster = _best_cluster_from_values(controls, str(item.get("question", "")))
            answer = {
                "question_cluster": cluster,
                "canonical_question": str(
                    item.get("question") or item.get("source_citation") or cluster
                ),
                "answer_de": draft_answer,
                "answer_en": "",
                "evidence_refs": evidence_refs,
                "review_status": "reviewed",
                "reviewer": item.get("reviewer", ""),
                "reviewed_at": item.get("reviewed_at", ""),
                "valid_until": item.get("valid_until", ""),
                "confidence": item.get("confidence", item.get("confidence_score", 0.8)),
                "source_case_id": safe_case_id,
            }
            _upsert_answer(connection, safe_client_id, answer, company_metadata=company_metadata)
            imported += 1
        _append_audit_log(
            connection,
            "import_reviewed_report",
            {"imported": imported, "skipped": skipped},
        )
    return {"imported": imported, "skipped": skipped, "client_id": safe_client_id}


def export_answer_library(
    db_path: Path | str,
    out_path: Path | str,
    *,
    client_id: str | None = None,
) -> dict[str, object]:
    """Export answer-library rows as metadata-only JSON."""
    answers = list_answer_library(db_path, client_id=client_id)
    payload: dict[str, object] = {
        "schema_version": ANSWER_VAULT_SCHEMA_VERSION,
        "tool_version": __version__,
        "client_id": client_id or "",
        "answer_count": len(answers),
        "answers": answers,
        "disclaimer": DISCLAIMER,
    }
    target = Path(out_path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return payload


def list_answer_library(
    db_path: Path | str,
    *,
    client_id: str | None = None,
) -> list[dict[str, object]]:
    """List current answer-library entries."""
    query = "SELECT * FROM answer_library"
    params: tuple[str, ...] = ()
    if client_id is not None:
        query += " WHERE client_id = ?"
        params = (_safe_id(client_id, MAX_CLIENT_ID_CHARS, "client_id"),)
    query += " ORDER BY question_cluster, canonical_question, answer_id"
    with _connect(Path(db_path)) as connection:
        rows = connection.execute(query, params).fetchall()
    return [_answer_row_to_dict(row) for row in rows]


def build_questionnaire_draft(
    db_path: Path | str,
    questions_csv: Path | str,
    evidence_map: Mapping[str, object],
    out_dir: Path | str | None = None,
    *,
    client_id: str,
    case_id: str,
) -> dict[str, object]:
    """Draft questionnaire answers from reviewed vault answers and local evidence."""
    safe_client_id = _safe_id(client_id, MAX_CLIENT_ID_CHARS, "client_id")
    safe_case_id = _safe_id(case_id, MAX_CASE_ID_CHARS, "case_id")
    init_answer_vault(db_path, client_id=safe_client_id)
    questions = read_questionnaire_csv(questions_csv)
    evidence_items = cast(Sequence[Mapping[str, object]], evidence_map.get("evidence", ()))
    draft_rows: list[dict[str, object]] = []
    review_rows: list[dict[str, object]] = []
    missing_rows: list[dict[str, object]] = []

    with _connect(Path(db_path)) as connection:
        _upsert_case(connection, safe_client_id, safe_case_id, Path(questions_csv).name)
        for question in questions:
            draft = _draft_one_question(
                connection,
                safe_client_id,
                safe_case_id,
                question,
                evidence_items,
            )
            draft_rows.append(draft)
            _store_question_and_draft(connection, safe_case_id, question, draft)
            if str(draft["review_status"]) not in FINAL_DRAFT_STATUSES:
                review_item = _review_row_from_draft(safe_case_id, question, draft)
                review_rows.append(review_item)
                _store_review_item(connection, review_item)

        missing_rows = _build_missing_rows(questions, draft_rows, evidence_items)
        _append_audit_log(
            connection,
            "questionnaire_draft",
            {"case_id": safe_case_id, "questions": len(questions)},
        )

    status_counts = Counter(str(row["review_status"]) for row in draft_rows)
    report: dict[str, object] = {
        "schema_version": "1.0",
        "tool_version": __version__,
        "client_id": safe_client_id,
        "case_id": safe_case_id,
        "question_count": len(questions),
        "status_counts": dict(sorted(status_counts.items())),
        "draft_answers": draft_rows,
        "review_queue": review_rows,
        "missing_evidence": missing_rows,
        "disclaimer": DISCLAIMER,
    }
    if out_dir is not None:
        write_questionnaire_draft_outputs(report, Path(out_dir))
    return report


def write_questionnaire_draft_outputs(report: Mapping[str, object], out_dir: Path) -> None:
    """Write draft, review-queue, and missing-evidence CSV files."""
    out_dir.mkdir(parents=True, exist_ok=True)
    _write_csv(
        out_dir / QUESTIONNAIRE_DRAFT_CSV_NAME,
        QUESTION_DRAFT_COLUMNS,
        cast(Sequence[Mapping[str, object]], report["draft_answers"]),
    )
    _write_csv(
        out_dir / CASE_REVIEW_QUEUE_CSV_NAME,
        CASE_REVIEW_COLUMNS,
        cast(Sequence[Mapping[str, object]], report["review_queue"]),
    )
    _write_csv(
        out_dir / MISSING_EVIDENCE_CSV_NAME,
        MISSING_EVIDENCE_COLUMNS,
        cast(Sequence[Mapping[str, object]], report["missing_evidence"]),
    )


def _draft_one_question(
    connection: sqlite3.Connection,
    client_id: str,
    case_id: str,
    question: QuestionnaireQuestion,
    evidence_items: Sequence[Mapping[str, object]],
) -> dict[str, object]:
    clusters = _clusters_for_question(question.question)
    cluster = clusters[0] if clusters else "policy_governance"
    normalized_question = _normalize_question(question.question)
    answer = _find_reusable_answer(connection, client_id, cluster)
    if answer is not None:
        answer_refs = _json_list(str(answer["evidence_refs"]))
        valid_until = str(answer["valid_until"] or "")
        if _is_stale(valid_until):
            return _draft_row(
                question,
                normalized_question,
                cluster,
                str(answer["answer_de"]),
                answer_refs,
                float(answer["confidence"] or 0.0),
                "stale",
                "reusable_answer_stale",
                "fresh_review_required",
                str(answer["answer_id"]),
                str(answer["source_case_id"] or ""),
            )
        if not answer_refs:
            return _draft_row(
                question,
                normalized_question,
                cluster,
                "",
                (),
                0.0,
                "missing_evidence",
                "reviewed_answer_without_evidence_refs",
                "evidence_refs_required",
                str(answer["answer_id"]),
                str(answer["source_case_id"] or ""),
            )
        return _draft_row(
            question,
            normalized_question,
            cluster,
            str(answer["answer_de"]),
            answer_refs,
            _to_float(answer["confidence"] or 0.0),
            "reviewed",
            "reused_reviewed_answer_from_answer_vault",
            "",
            str(answer["answer_id"]),
            str(answer["source_case_id"] or case_id),
        )

    matching_evidence = _matching_evidence(evidence_items, clusters)
    if matching_evidence:
        best_confidence = max(_to_float(item.get("confidence", 0.0)) for item in matching_evidence)
        evidence_refs = tuple(str(item["evidence_id"]) for item in matching_evidence)
        if best_confidence >= EVIDENCE_DRAFT_CONFIDENCE:
            draft_answer = (
                "Evidence refs %s indicate local evidence for %s. Human review required."
                % (", ".join(evidence_refs[:MAX_EVIDENCE_REFS]), cluster)
            )
            return _draft_row(
                question,
                normalized_question,
                cluster,
                draft_answer,
                evidence_refs,
                best_confidence,
                "needs_review",
                "draft_from_local_evidence",
                "",
                "",
                case_id,
            )
        return _draft_row(
            question,
            normalized_question,
            cluster,
            "",
            evidence_refs,
            best_confidence,
            "needs_review",
            "low_confidence_evidence",
            "human_review_required",
            "",
            case_id,
        )

    return _draft_row(
        question,
        normalized_question,
        cluster,
        "",
        (),
        0.0,
        "missing_evidence",
        "no_matching_answer_or_evidence",
        "collect_evidence_or_answer_manually",
        "",
        "",
    )


def _draft_row(
    question: QuestionnaireQuestion,
    normalized_question: str,
    cluster: str,
    draft_answer: str,
    evidence_refs: Sequence[str],
    confidence: float,
    review_status: ReviewStatus,
    reason: str,
    missing_evidence: str,
    source_answer_id: str,
    source_case_id: str,
) -> dict[str, object]:
    safe_answer = _safe_text(draft_answer, MAX_ANSWER_CHARS)
    if review_status == "reviewed" and (not safe_answer or not evidence_refs):
        raise AnswerVaultError("reviewed draft answers require answer text and evidence refs")
    return {
        "question_id": question.question_id,
        "original_question": question.question,
        "normalized_question": normalized_question,
        "matched_cluster": cluster,
        "draft_answer": safe_answer,
        "evidence_refs": tuple(evidence_refs[:MAX_EVIDENCE_REFS]),
        "confidence": round(confidence, 4),
        "review_status": review_status,
        "reason": _safe_text(reason, MAX_REASON_CHARS),
        "missing_evidence": _safe_text(missing_evidence, MAX_REASON_CHARS),
        "source_answer_id": source_answer_id,
        "source_case_id": source_case_id,
    }


def _review_row_from_draft(
    case_id: str,
    question: QuestionnaireQuestion,
    draft: Mapping[str, object],
) -> dict[str, object]:
    reason = _reason_for_review(draft)
    return {
        "case_id": case_id,
        "question_id": question.question_id,
        "original_question": question.question,
        "normalized_question": draft["normalized_question"],
        "proposed_cluster": draft["matched_cluster"],
        "proposed_answer": draft["draft_answer"],
        "evidence_refs": draft["evidence_refs"],
        "reason_for_review": reason,
        "missing_evidence": draft["missing_evidence"],
        "reviewer_decision": "",
        "reviewer_note": "",
        "final_answer": "",
    }


def _reason_for_review(draft: Mapping[str, object]) -> str:
    status = str(draft["review_status"])
    reason = str(draft["reason"])
    if status == "missing_evidence":
        return "no_evidence"
    if status == "stale":
        return "stale_evidence"
    if reason == "low_confidence_evidence":
        return "low_confidence"
    return "needs_human_input"


def _build_missing_rows(
    questions: Sequence[QuestionnaireQuestion],
    drafts: Sequence[Mapping[str, object]],
    evidence_items: Sequence[Mapping[str, object]],
) -> list[dict[str, object]]:
    evidence_topics = {
        topic
        for item in evidence_items
        for topic in cast(Sequence[str], item.get("mapped_controls", ()))
    }
    questions_by_cluster: dict[str, list[str]] = {cluster: [] for cluster in TOPIC_CLUSTERS}
    for question in questions:
        clusters = _clusters_for_question(question.question) or ("policy_governance",)
        for cluster in clusters:
            questions_by_cluster.setdefault(cluster, []).append(question.question_id)
    draft_status_by_cluster = {
        str(draft["matched_cluster"]): str(draft["review_status"]) for draft in drafts
    }
    rows: list[dict[str, object]] = []
    for cluster in TOPIC_CLUSTERS:
        question_ids = tuple(sorted(set(questions_by_cluster.get(cluster, []))))
        if cluster in draft_status_by_cluster and draft_status_by_cluster[cluster] == "reviewed":
            continue
        if cluster in evidence_topics:
            status = "partial"
            reason = "local evidence exists but human review or answer approval is still needed"
        else:
            status = "missing"
            reason = "no local evidence candidate mapped to this cluster"
        if question_ids or status == "missing":
            rows.append(
                {
                    "cluster": cluster,
                    "status": status,
                    "question_ids": question_ids,
                    "required_evidence": _required_evidence_label(cluster),
                    "reason": reason,
                }
            )
    return rows


def _upsert_answer(
    connection: sqlite3.Connection,
    client_id: str,
    answer: Mapping[str, object],
    *,
    company_metadata: CompanyMetadata | None = None,
) -> None:
    cluster = _valid_cluster(str(answer.get("question_cluster", "")))
    canonical_question = _safe_text(
        str(answer.get("canonical_question", _canonical_question(cluster))),
        MAX_QUESTION_CHARS,
    )
    answer_de = _safe_answer_text(str(answer.get("answer_de", "")), company_metadata)
    if not answer_de:
        raise AnswerVaultError("answer_de is required for answer_library import")
    answer_en = _safe_answer_text(str(answer.get("answer_en", "")), company_metadata)
    evidence_refs = _normalize_string_sequence(answer.get("evidence_refs", ()))
    review_status = str(answer.get("review_status", "reviewed")).strip().lower()
    if review_status not in {"reviewed", "draft", "needs_review", "rejected", "stale"}:
        raise AnswerVaultError("unsupported answer review_status: %s" % review_status)
    reviewer = _safe_text(str(answer.get("reviewer", "")), MAX_REVIEWER_CHARS)
    reviewed_at = _safe_temporal_text(str(answer.get("reviewed_at", "")))
    valid_until = _safe_temporal_text(str(answer.get("valid_until", "")))
    confidence = _to_float(answer.get("confidence", 0.0))
    source_case_id = _safe_text(str(answer.get("source_case_id", "")), MAX_CASE_ID_CHARS)
    answer_id = _answer_id(client_id, cluster, canonical_question)
    now = _utc_now()
    existing = connection.execute(
        "SELECT * FROM answer_library WHERE answer_id = ?",
        (answer_id,),
    ).fetchone()
    if existing is not None:
        _insert_answer_version(connection, existing)
    connection.execute(
        """
        INSERT OR REPLACE INTO answer_library (
            answer_id, client_id, question_cluster, canonical_question,
            answer_de, answer_en, evidence_refs, review_status, reviewer,
            reviewed_at, valid_until, confidence, source_case_id, created_at,
            updated_at, superseded_by
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, COALESCE(?, ?), ?, ?)
        """,
        (
            answer_id,
            client_id,
            cluster,
            canonical_question,
            answer_de,
            answer_en,
            json.dumps(list(evidence_refs), sort_keys=True),
            review_status,
            reviewer,
            reviewed_at,
            valid_until,
            confidence,
            source_case_id,
            existing["created_at"] if existing is not None else now,
            now,
            now,
            "",
        ),
    )


def _insert_answer_version(connection: sqlite3.Connection, row: sqlite3.Row) -> None:
    version_number = int(
        connection.execute(
            "SELECT COUNT(*) FROM answer_versions WHERE answer_id = ?",
            (row["answer_id"],),
        ).fetchone()[0]
    ) + 1
    version_id = _stable_id(
        "AV",
        (str(row["answer_id"]), str(version_number), str(row["updated_at"])),
        VERSION_ID_HASH_CHARS,
    )
    connection.execute(
        """
        INSERT OR IGNORE INTO answer_versions (
            version_id, answer_id, version_number, answer_de, evidence_refs,
            review_status, reviewer, reviewed_at, valid_until, confidence, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            version_id,
            row["answer_id"],
            version_number,
            row["answer_de"],
            row["evidence_refs"],
            row["review_status"],
            row["reviewer"],
            row["reviewed_at"],
            row["valid_until"],
            row["confidence"],
            _utc_now(),
        ),
    )


def _store_question_and_draft(
    connection: sqlite3.Connection,
    case_id: str,
    question: QuestionnaireQuestion,
    draft: Mapping[str, object],
) -> None:
    case_question_id = _stable_id("CQ", (case_id, question.question_id), DRAFT_ID_HASH_CHARS)
    connection.execute(
        """
        INSERT OR REPLACE INTO case_questions (
            case_question_id, case_id, question_id, original_question,
            normalized_question, proposed_cluster, review_status, reason_for_review
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            case_question_id,
            case_id,
            question.question_id,
            question.question,
            str(draft["normalized_question"]),
            str(draft["matched_cluster"]),
            str(draft["review_status"]),
            _reason_for_review(draft),
        ),
    )
    draft_id = _stable_id("DA", (case_id, question.question_id), DRAFT_ID_HASH_CHARS)
    connection.execute(
        """
        INSERT OR REPLACE INTO draft_answers (
            draft_id, case_id, question_id, matched_cluster, draft_answer,
            evidence_refs, confidence, review_status, reason, source_answer_id,
            source_case_id, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            draft_id,
            case_id,
            question.question_id,
            str(draft["matched_cluster"]),
            str(draft["draft_answer"]),
            json.dumps(list(cast(Sequence[str], draft["evidence_refs"]))),
            _to_float(draft["confidence"]),
            str(draft["review_status"]),
            str(draft["reason"]),
            str(draft["source_answer_id"]),
            str(draft["source_case_id"]),
            _utc_now(),
        ),
    )


def _store_review_item(connection: sqlite3.Connection, review_item: Mapping[str, object]) -> None:
    review_item_id = _stable_id(
        "RI",
        (str(review_item["case_id"]), str(review_item["question_id"])),
        DRAFT_ID_HASH_CHARS,
    )
    connection.execute(
        """
        INSERT OR REPLACE INTO review_items (
            review_item_id, case_id, question_id, reason_for_review,
            missing_evidence, reviewer_decision, reviewer_note, final_answer, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            review_item_id,
            str(review_item["case_id"]),
            str(review_item["question_id"]),
            str(review_item["reason_for_review"]),
            str(review_item["missing_evidence"]),
            str(review_item["reviewer_decision"]),
            str(review_item["reviewer_note"]),
            str(review_item["final_answer"]),
            _utc_now(),
        ),
    )


def _matching_evidence(
    evidence_items: Sequence[Mapping[str, object]],
    clusters: Sequence[str],
) -> tuple[Mapping[str, object], ...]:
    wanted = set(clusters)
    matches = [
        item
        for item in evidence_items
        if wanted.intersection(cast(Sequence[str], item.get("mapped_controls", ())))
    ]
    matches.sort(
        key=lambda item: (-_to_float(item.get("confidence", 0.0)), str(item["evidence_id"]))
    )
    return tuple(matches[:MAX_EVIDENCE_REFS])


def _find_reusable_answer(
    connection: sqlite3.Connection,
    client_id: str,
    cluster: str,
) -> sqlite3.Row | None:
    row = connection.execute(
        """
        SELECT * FROM answer_library
        WHERE client_id = ? AND question_cluster = ? AND review_status = 'reviewed'
        ORDER BY confidence DESC, updated_at DESC, answer_id ASC
        LIMIT 1
        """,
        (client_id, cluster),
    ).fetchone()
    return cast(sqlite3.Row | None, row)


def _iter_reviewed_report_items(report: Mapping[str, object]) -> list[Mapping[str, object]]:
    items: list[Mapping[str, object]] = []
    for document in cast(Sequence[Mapping[str, object]], report.get("per_document", [])):
        for item in cast(Sequence[Mapping[str, object]], document.get("evidence", [])):
            items.append(item)
    return items


def _apply_schema(connection: sqlite3.Connection) -> None:
    connection.executescript(
        """
        CREATE TABLE IF NOT EXISTS schema_version (
            version TEXT PRIMARY KEY,
            applied_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS clients (
            client_id TEXT PRIMARY KEY,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS documents (
            document_id TEXT PRIMARY KEY,
            client_id TEXT NOT NULL,
            source_path TEXT NOT NULL,
            source_type TEXT NOT NULL,
            status TEXT NOT NULL,
            sha256 TEXT NOT NULL,
            evidence_count INTEGER NOT NULL,
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS document_chunks (
            chunk_id TEXT PRIMARY KEY,
            document_id TEXT NOT NULL,
            snippet_hash TEXT NOT NULL,
            detected_topics TEXT NOT NULL,
            confidence REAL NOT NULL
        );
        CREATE TABLE IF NOT EXISTS evidence_items (
            evidence_id TEXT PRIMARY KEY,
            client_id TEXT NOT NULL,
            document_id TEXT NOT NULL,
            source_path TEXT NOT NULL,
            source_type TEXT NOT NULL,
            chunk_id TEXT NOT NULL,
            snippet_hash TEXT NOT NULL,
            mapped_controls TEXT NOT NULL,
            confidence REAL NOT NULL,
            reason TEXT NOT NULL,
            review_status TEXT NOT NULL,
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS controls (
            control_id TEXT PRIMARY KEY,
            title TEXT NOT NULL,
            aliases_json TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS questions (
            question_id TEXT PRIMARY KEY,
            question_cluster TEXT NOT NULL,
            canonical_question TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS answer_library (
            answer_id TEXT PRIMARY KEY,
            client_id TEXT NOT NULL,
            question_cluster TEXT NOT NULL,
            canonical_question TEXT NOT NULL,
            answer_de TEXT NOT NULL,
            answer_en TEXT NOT NULL,
            evidence_refs TEXT NOT NULL,
            review_status TEXT NOT NULL,
            reviewer TEXT NOT NULL,
            reviewed_at TEXT NOT NULL,
            valid_until TEXT NOT NULL,
            confidence REAL NOT NULL,
            source_case_id TEXT NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            superseded_by TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS answer_versions (
            version_id TEXT PRIMARY KEY,
            answer_id TEXT NOT NULL,
            version_number INTEGER NOT NULL,
            answer_de TEXT NOT NULL,
            evidence_refs TEXT NOT NULL,
            review_status TEXT NOT NULL,
            reviewer TEXT NOT NULL,
            reviewed_at TEXT NOT NULL,
            valid_until TEXT NOT NULL,
            confidence REAL NOT NULL,
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS cases (
            case_id TEXT PRIMARY KEY,
            client_id TEXT NOT NULL,
            created_at TEXT NOT NULL,
            source_questionnaire TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS case_questions (
            case_question_id TEXT PRIMARY KEY,
            case_id TEXT NOT NULL,
            question_id TEXT NOT NULL,
            original_question TEXT NOT NULL,
            normalized_question TEXT NOT NULL,
            proposed_cluster TEXT NOT NULL,
            review_status TEXT NOT NULL,
            reason_for_review TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS draft_answers (
            draft_id TEXT PRIMARY KEY,
            case_id TEXT NOT NULL,
            question_id TEXT NOT NULL,
            matched_cluster TEXT NOT NULL,
            draft_answer TEXT NOT NULL,
            evidence_refs TEXT NOT NULL,
            confidence REAL NOT NULL,
            review_status TEXT NOT NULL,
            reason TEXT NOT NULL,
            source_answer_id TEXT NOT NULL,
            source_case_id TEXT NOT NULL,
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS review_items (
            review_item_id TEXT PRIMARY KEY,
            case_id TEXT NOT NULL,
            question_id TEXT NOT NULL,
            reason_for_review TEXT NOT NULL,
            missing_evidence TEXT NOT NULL,
            reviewer_decision TEXT NOT NULL,
            reviewer_note TEXT NOT NULL,
            final_answer TEXT NOT NULL,
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS audit_log (
            audit_id TEXT PRIMARY KEY,
            event_type TEXT NOT NULL,
            event_payload TEXT NOT NULL,
            created_at TEXT NOT NULL
        );
        """
    )
    existing_versions = [
        str(row[0]) for row in connection.execute("SELECT version FROM schema_version").fetchall()
    ]
    if existing_versions and ANSWER_VAULT_SCHEMA_VERSION not in existing_versions:
        raise AnswerVaultError("unsupported answer vault schema version")
    connection.execute(
        "INSERT OR IGNORE INTO schema_version (version, applied_at) VALUES (?, ?)",
        (ANSWER_VAULT_SCHEMA_VERSION, _utc_now()),
    )


@contextlib.contextmanager
def _connect(path: Path) -> Iterator[sqlite3.Connection]:
    connection = sqlite3.connect(path)
    connection.row_factory = sqlite3.Row
    try:
        yield connection
    except Exception:
        connection.rollback()
        raise
    else:
        connection.commit()
    finally:
        connection.close()


def _upsert_client(connection: sqlite3.Connection, client_id: str) -> None:
    now = _utc_now()
    connection.execute(
        """
        INSERT INTO clients (client_id, created_at, updated_at)
        VALUES (?, ?, ?)
        ON CONFLICT(client_id) DO UPDATE SET updated_at = excluded.updated_at
        """,
        (client_id, now, now),
    )


def _upsert_case(
    connection: sqlite3.Connection,
    client_id: str,
    case_id: str,
    source_questionnaire: str,
) -> None:
    connection.execute(
        """
        INSERT OR REPLACE INTO cases (case_id, client_id, created_at, source_questionnaire)
        VALUES (?, ?, ?, ?)
        """,
        (case_id, client_id, _utc_now(), source_questionnaire),
    )


def _seed_controls_and_questions(connection: sqlite3.Connection) -> None:
    for cluster, aliases in CONTROL_ALIASES.items():
        connection.execute(
            """
            INSERT OR REPLACE INTO controls (control_id, title, aliases_json)
            VALUES (?, ?, ?)
            """,
            (cluster, cluster.replace("_", " ").title(), json.dumps(list(aliases))),
        )
    for item in CANONICAL_QUESTION_BANK:
        cluster = item["cluster"]
        question_id = _stable_id("QB", (cluster, item["question"]), DRAFT_ID_HASH_CHARS)
        connection.execute(
            """
            INSERT OR REPLACE INTO questions (
                question_id, question_cluster, canonical_question
            ) VALUES (?, ?, ?)
            """,
            (question_id, cluster, item["question"]),
        )


def _append_audit_log(
    connection: sqlite3.Connection,
    event_type: str,
    payload: Mapping[str, object],
) -> None:
    created_at = _utc_now()
    audit_id = _stable_id(
        "AL",
        (event_type, json.dumps(payload, sort_keys=True), created_at),
        AUDIT_ID_HASH_CHARS,
    )
    connection.execute(
        "INSERT OR IGNORE INTO audit_log (audit_id, event_type, event_payload, created_at)"
        " VALUES (?, ?, ?, ?)",
        (audit_id, event_type, json.dumps(payload, sort_keys=True), created_at),
    )


def _clusters_for_question(question: str) -> tuple[str, ...]:
    matches = detect_topics_for_text(question)
    if matches:
        return tuple(sorted(matches, key=lambda cluster: (-len(matches[cluster]), cluster)))
    lowered = question.casefold()
    if "policy" in lowered or "richtlinie" in lowered:
        return ("policy_governance",)
    return ()


def _best_cluster_from_values(values: Sequence[str], fallback_text: str) -> str:
    for value in values:
        normalized = value.strip().lower()
        if normalized in TOPIC_CLUSTERS:
            return normalized
    clusters = _clusters_for_question("%s %s" % (" ".join(values), fallback_text))
    return clusters[0] if clusters else "policy_governance"


def _valid_cluster(value: str) -> str:
    normalized = value.strip().lower()
    if normalized not in TOPIC_CLUSTERS:
        raise AnswerVaultError("unknown question_cluster: %s" % value)
    return normalized


def _canonical_question(cluster: str) -> str:
    for item in CANONICAL_QUESTION_BANK:
        if item["cluster"] == cluster:
            return item["question"]
    return cluster.replace("_", " ")


def _required_evidence_label(cluster: str) -> str:
    return "%s policy/process evidence, owner/review metadata, and reviewer approval" % (
        cluster.replace("_", " ")
    )


def _answer_id(client_id: str, cluster: str, canonical_question: str) -> str:
    return _stable_id("ANS", (client_id, cluster, canonical_question), ANSWER_ID_HASH_CHARS)


def _stable_id(prefix: str, parts: Sequence[str], hash_chars: int) -> str:
    basis = "\n".join(_normalize_question(part) for part in parts)
    digest = hashlib.sha256(basis.encode("utf-8")).hexdigest()[:hash_chars]
    return "%s-%s" % (prefix, digest)


def _normalize_question(value: str) -> str:
    return " ".join(value.casefold().replace("-", " ").replace("_", " ").split())


def _normalize_string_sequence(value: object) -> tuple[str, ...]:
    result: tuple[str, ...]
    if value is None:
        result = ()
    elif isinstance(value, str):
        stripped = value.strip()
        if not stripped:
            result = ()
        elif stripped.startswith("["):
            try:
                decoded = json.loads(stripped)
            except json.JSONDecodeError:
                result = (stripped,)
            else:
                result = _normalize_string_sequence(decoded)
        else:
            result = (stripped,)
    elif isinstance(value, Sequence) and not isinstance(value, (bytes, bytearray)):
        result = tuple(str(item).strip() for item in value if str(item).strip())
    else:
        normalized = str(value).strip()
        result = (normalized,) if normalized else ()
    return result


def _safe_id(value: str, max_chars: int, field_name: str) -> str:
    normalized = value.strip()
    if not normalized:
        raise AnswerVaultError("%s is required" % field_name)
    if len(normalized) > max_chars:
        raise AnswerVaultError("%s exceeds length limit" % field_name)
    if any(character in normalized for character in ("\\", "/", "..")):
        raise AnswerVaultError("%s contains unsafe path-like characters" % field_name)
    return normalized


def _safe_text(value: str, max_chars: int) -> str:
    single_line = " ".join(value.split())
    bounded = single_line[:max_chars]
    return mask_sensitive_text(bounded) if has_sensitive_markers(bounded) else bounded


def _safe_answer_text(value: str, company_metadata: CompanyMetadata | None) -> str:
    """Sanitize an answer body, preserving declared Class-1 company metadata.

    Class-2 markers (incidental third-party PII) are masked as before. With no declared company
    metadata this is byte-for-byte identical to ``_safe_text`` at ``MAX_ANSWER_CHARS``.
    """
    single_line = " ".join(value.split())
    bounded = single_line[:MAX_ANSWER_CHARS]
    if company_metadata is None:
        return mask_sensitive_text(bounded) if has_sensitive_markers(bounded) else bounded
    return guard_shareable_text(bounded, company_metadata).text


def _safe_temporal_text(value: str) -> str:
    single_line = " ".join(value.split())[:MAX_REVIEWER_CHARS]
    if not single_line:
        return ""
    try:
        date.fromisoformat(single_line[:10])
    except ValueError:
        return _safe_text(single_line, MAX_REVIEWER_CHARS)
    return single_line


def _is_stale(valid_until: str) -> bool:
    if not valid_until:
        return False
    try:
        return date.fromisoformat(valid_until[:10]) < date.today()
    except ValueError:
        return True


def _json_list(value: str) -> tuple[str, ...]:
    return _normalize_string_sequence(value)


def _answer_row_to_dict(row: sqlite3.Row) -> dict[str, object]:
    return {
        "answer_id": row["answer_id"],
        "client_id": row["client_id"],
        "question_cluster": row["question_cluster"],
        "canonical_question": row["canonical_question"],
        "answer_de": row["answer_de"],
        "answer_en": row["answer_en"],
        "evidence_refs": _json_list(str(row["evidence_refs"])),
        "review_status": row["review_status"],
        "reviewer": row["reviewer"],
        "reviewed_at": row["reviewed_at"],
        "valid_until": row["valid_until"],
        "confidence": row["confidence"],
        "source_case_id": row["source_case_id"],
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
        "superseded_by": row["superseded_by"],
    }


def _write_csv(
    path: Path,
    columns: Sequence[str],
    rows: Sequence[Mapping[str, object]],
) -> None:
    with path.open("w", encoding="utf-8", newline="") as csv_file:
        writer = csv.DictWriter(csv_file, fieldnames=list(columns), lineterminator="\n")
        writer.writeheader()
        for row in rows:
            writer.writerow(
                {
                    column: safe_review_csv_cell(_csv_cell(row.get(column, "")))
                    for column in columns
                }
            )


def _csv_cell(value: object) -> str:
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return ";".join(str(item) for item in value)
    return str(value)


def _read_json(path: Path) -> dict[str, object]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise AnswerVaultError("could not read JSON: %s" % path) from exc
    except json.JSONDecodeError as exc:
        raise AnswerVaultError("invalid JSON: %s" % path) from exc
    if not isinstance(payload, Mapping):
        raise AnswerVaultError("JSON document must be an object: %s" % path)
    return cast(dict[str, object], payload)


def _to_int(value: object) -> int:
    if isinstance(value, int):
        return value
    if isinstance(value, float | str):
        return int(value)
    raise AnswerVaultError("expected numeric value")


def _to_float(value: object) -> float:
    if isinstance(value, int | float):
        return float(value)
    if isinstance(value, str):
        return float(value)
    raise AnswerVaultError("expected numeric value")


def _utc_now() -> str:
    return datetime.now(UTC).isoformat()


__all__ = [
    "ANSWER_LIBRARY_EXPORT_NAME",
    "ANSWER_VAULT_SCHEMA_VERSION",
    "CASE_REVIEW_QUEUE_CSV_NAME",
    "MISSING_EVIDENCE_CSV_NAME",
    "QUESTIONNAIRE_DRAFT_CSV_NAME",
    "AnswerVaultError",
    "build_questionnaire_draft",
    "export_answer_library",
    "import_answer_library_json",
    "import_reviewed_report_answers",
    "init_answer_vault",
    "list_answer_library",
    "store_ingest_result",
    "write_questionnaire_draft_outputs",
]
