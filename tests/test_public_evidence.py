"""Tests for the deterministic, tenant-bound public-evidence workflow."""

from __future__ import annotations

import csv
import hashlib
import json
import shutil
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import cast

import pytest
from pydantic import ValidationError

from aethelgard.cli import main
from aethelgard.public_evidence import (
    ANALYSIS_REPORT_NAME,
    AUDIT_LEDGER_NAME,
    BENCHMARK_REPORT_NAME,
    REVIEWED_REPORT_NAME,
    ExecutionContext,
    PublicEvidenceError,
    append_audit_event,
    apply_public_evidence_review,
    export_public_evidence_trust_bundle,
    run_public_evidence_benchmark,
    validate_source_locator,
)

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DATASET = PROJECT_ROOT / "benchmarks" / "public-evidence-v1"
TENANT_ID = "public-lab"
RUNNER_ID = "local-operator"
REVIEWER_ID = "qualified-reviewer"
AUDITOR_ID = "release-auditor"


def _context(role: str, actor_id: str, *, tenant_id: str = TENANT_ID) -> ExecutionContext:
    return ExecutionContext.model_validate(
        {
            "tenant_id": tenant_id,
            "actor_id": actor_id,
            "role": role,
            "offline": True,
            "deterministic": True,
        }
    )


def _read_json(path: Path) -> dict[str, object]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(payload, dict)
    return cast(dict[str, object], payload)


def _write_json(path: Path, payload: Mapping[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _canonical_hash(payload: Mapping[str, object]) -> str:
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _run(tmp_path: Path, *, name: str = "run") -> tuple[Path, dict[str, object]]:
    output = tmp_path / name
    report = run_public_evidence_benchmark(
        DATASET,
        output,
        _context("operator", RUNNER_ID),
    )
    return output, report


def _analysis(output: Path) -> dict[str, object]:
    return _read_json(output / ANALYSIS_REPORT_NAME)


def _findings(analysis: Mapping[str, object]) -> list[dict[str, object]]:
    findings = cast(Sequence[Mapping[str, object]], analysis["findings"])
    return [dict(finding) for finding in findings]


def _complete_review_payload(
    analysis: Mapping[str, object],
    *,
    tenant_id: str = TENANT_ID,
    default_status: str = "rejected",
) -> dict[str, object]:
    findings = _findings(analysis)
    decisions = [
        {
            "finding_id": str(finding["finding_id"]),
            "status": "accepted" if index == 0 else default_status,
            "comment": "Source and boundary checked by a human reviewer.",
        }
        for index, finding in enumerate(findings)
    ]
    return {
        "schema_version": "1.0",
        "tenant_id": tenant_id,
        "run_id": str(analysis["run_id"]),
        "reviewer_id": REVIEWER_ID,
        "reviewer_role": "reviewer",
        "reviewed_at": "2026-07-14T12:00:00+00:00",
        "human_review_confirmed": True,
        "decisions": decisions,
    }


def _apply_complete_review(tmp_path: Path, output: Path) -> tuple[Path, dict[str, object]]:
    analysis = _analysis(output)
    decisions_path = tmp_path / "review-decisions.json"
    _write_json(decisions_path, _complete_review_payload(analysis))
    review_output = tmp_path / "reviewed"
    reviewed = apply_public_evidence_review(
        output / ANALYSIS_REPORT_NAME,
        decisions_path,
        review_output,
        output / AUDIT_LEDGER_NAME,
        _context("reviewer", REVIEWER_ID),
    )
    return review_output, reviewed


def _update_source_register(dataset: Path, source_id: str, **updates: str) -> None:
    register = dataset / "licenses" / "source_register.csv"
    with register.open(encoding="utf-8", newline="") as input_file:
        reader = csv.DictReader(input_file)
        fieldnames = list(reader.fieldnames or ())
        rows = [dict(row) for row in reader]
    for row in rows:
        if row.get("source_id") == source_id:
            row.update(updates)
    with register.open("w", encoding="utf-8", newline="") as output_file:
        writer = csv.DictWriter(output_file, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def test_committed_public_evidence_benchmark_passes_with_traceable_findings(
    tmp_path: Path,
) -> None:
    output, benchmark = _run(tmp_path)
    analysis = _analysis(output)
    metrics = cast(Mapping[str, object], benchmark["metrics"])
    findings = _findings(analysis)

    assert benchmark["passed"] is True
    assert benchmark["source_count"] == 10
    assert benchmark["case_count"] == 20
    assert metrics["false_positive_evidence"] == 0
    assert metrics["missed_evidence"] == 0
    assert metrics["findings_without_source_reference"] == 0
    assert metrics["forbidden_compliance_claims"] == 0
    assert analysis["requires_human_review"] is True
    assert findings
    assert {str(item["confidence_category"]) for item in findings} == {"high", "medium", "low"}
    assert all("confidence" not in item for item in findings)
    assert all(item["review_status"] == "pending" for item in findings)
    assert all(item["normalized_quote"] for item in findings)
    assert all(item["quote_sha256"] for item in findings)
    assert all(
        int(cast(int, item["char_end"])) > int(cast(int, item["char_start"])) for item in findings
    )
    assert (output / BENCHMARK_REPORT_NAME).is_file()


def test_validate_source_locator_accepts_verified_pdf_page_and_exact_span() -> None:
    text = "Documented restore test completed successfully."
    quote = "restore test completed"
    start = text.index(quote)
    finding: dict[str, object] = {
        "normalized_quote": quote,
        "char_start": start,
        "char_end": start + len(quote),
        "quote_sha256": hashlib.sha256(quote.encode("utf-8")).hexdigest(),
        "page": 3,
        "table_position": None,
    }

    validate_source_locator(finding, text, "pdf", actual_page=3)


@pytest.mark.parametrize(
    ("updates", "error"),
    [
        ({"char_end": 999}, "invalid normalized span"),
        ({"normalized_quote": "invented quote"}, "does not match"),
        ({"page": 7}, "unverified page"),
    ],
)
def test_validate_source_locator_blocks_missing_or_invented_references(
    updates: Mapping[str, object],
    error: str,
) -> None:
    text = "Documented restore test completed successfully."
    quote = "restore test completed"
    start = text.index(quote)
    finding: dict[str, object] = {
        "normalized_quote": quote,
        "char_start": start,
        "char_end": start + len(quote),
        "quote_sha256": hashlib.sha256(quote.encode("utf-8")).hexdigest(),
        "page": None,
        "table_position": None,
    }
    finding.update(updates)

    with pytest.raises(PublicEvidenceError, match=error):
        validate_source_locator(finding, text, "text")


def test_identical_inputs_produce_identical_normalized_outputs(tmp_path: Path) -> None:
    first_output, first = _run(tmp_path, name="first")
    second_output, second = _run(tmp_path, name="second")

    assert first["content_sha256"] == second["content_sha256"]
    assert _analysis(first_output)["content_sha256"] == _analysis(second_output)["content_sha256"]
    assert _analysis(first_output) == _analysis(second_output)


def test_changed_fixture_is_blocked_by_manifest_hash(tmp_path: Path) -> None:
    dataset = tmp_path / "dataset"
    shutil.copytree(DATASET, dataset)
    fixture = dataset / "generated-lab-evidence" / "backup_report.txt"
    fixture.write_text(fixture.read_text(encoding="utf-8") + "\nchanged\n", encoding="utf-8")

    with pytest.raises(PublicEvidenceError, match="source hash mismatch"):
        run_public_evidence_benchmark(
            dataset,
            tmp_path / "out",
            _context("operator", RUNNER_ID),
        )


def test_missing_local_source_is_blocked_without_network_fallback(tmp_path: Path) -> None:
    dataset = tmp_path / "dataset"
    shutil.copytree(DATASET, dataset)
    (dataset / "generated-lab-evidence" / "backup_report.txt").unlink()

    with pytest.raises(PublicEvidenceError, match="network retrieval is blocked"):
        run_public_evidence_benchmark(
            dataset,
            tmp_path / "out",
            _context("operator", RUNNER_ID),
        )


def test_unclear_license_is_blocked_even_when_register_matches(tmp_path: Path) -> None:
    dataset = tmp_path / "dataset"
    shutil.copytree(DATASET, dataset)
    manifest_path = dataset / "manifest.json"
    manifest = _read_json(manifest_path)
    sources = cast(list[dict[str, object]], manifest["sources"])
    source_id = str(sources[0]["source_id"])
    sources[0]["license_status"] = "unclear"
    _write_json(manifest_path, manifest)
    _update_source_register(dataset, source_id, license_status="unclear")

    with pytest.raises(PublicEvidenceError, match="unapproved license"):
        run_public_evidence_benchmark(
            dataset,
            tmp_path / "out",
            _context("operator", RUNNER_ID),
        )


def test_declared_file_type_mismatch_is_blocked(tmp_path: Path) -> None:
    dataset = tmp_path / "dataset"
    shutil.copytree(DATASET, dataset)
    manifest_path = dataset / "manifest.json"
    manifest = _read_json(manifest_path)
    sources = cast(list[dict[str, object]], manifest["sources"])
    source_id = str(sources[0]["source_id"])
    sources[0]["file_type"] = "json"
    _write_json(manifest_path, manifest)
    _update_source_register(dataset, source_id, file_type="json")

    with pytest.raises(PublicEvidenceError, match="file_type"):
        run_public_evidence_benchmark(
            dataset,
            tmp_path / "out",
            _context("operator", RUNNER_ID),
        )


def test_offline_and_deterministic_flags_are_mandatory() -> None:
    with pytest.raises(ValidationError):
        ExecutionContext.model_validate(
            {
                "tenant_id": TENANT_ID,
                "actor_id": RUNNER_ID,
                "role": "operator",
                "offline": False,
                "deterministic": True,
            }
        )


@pytest.mark.parametrize(
    "mutation",
    ["human_confirmation", "pending_status", "missing_finding"],
)
def test_invalid_or_incomplete_review_is_blocked(tmp_path: Path, mutation: str) -> None:
    output, _ = _run(tmp_path)
    analysis = _analysis(output)
    payload = _complete_review_payload(analysis)
    decisions = cast(list[dict[str, object]], payload["decisions"])
    if mutation == "human_confirmation":
        payload["human_review_confirmed"] = False
    elif mutation == "pending_status":
        decisions[0]["status"] = "pending"
    else:
        decisions.pop()
    decisions_path = tmp_path / (mutation + ".json")
    _write_json(decisions_path, payload)

    with pytest.raises((PublicEvidenceError, ValidationError, ValueError)):
        apply_public_evidence_review(
            output / ANALYSIS_REPORT_NAME,
            decisions_path,
            tmp_path / ("review-" + mutation),
            output / AUDIT_LEDGER_NAME,
            _context("reviewer", REVIEWER_ID),
        )


def test_tampered_analysis_hash_is_blocked_before_review(tmp_path: Path) -> None:
    output, _ = _run(tmp_path)
    analysis_path = output / ANALYSIS_REPORT_NAME
    analysis = _read_json(analysis_path)
    decisions_path = tmp_path / "review-decisions.json"
    _write_json(decisions_path, _complete_review_payload(analysis))
    analysis["disclaimer"] = "tampered"
    _write_json(analysis_path, analysis)

    with pytest.raises(PublicEvidenceError, match="content hash verification failed"):
        apply_public_evidence_review(
            analysis_path,
            decisions_path,
            tmp_path / "reviewed",
            output / AUDIT_LEDGER_NAME,
            _context("reviewer", REVIEWER_ID),
        )


def test_operator_cannot_review_own_analysis(tmp_path: Path) -> None:
    output, _ = _run(tmp_path)
    analysis = _analysis(output)
    payload = _complete_review_payload(analysis)
    payload["reviewer_id"] = RUNNER_ID
    decisions_path = tmp_path / "same-actor-review.json"
    _write_json(decisions_path, payload)

    with pytest.raises(PublicEvidenceError, match="must be distinct"):
        apply_public_evidence_review(
            output / ANALYSIS_REPORT_NAME,
            decisions_path,
            tmp_path / "reviewed",
            output / AUDIT_LEDGER_NAME,
            _context("reviewer", RUNNER_ID),
        )


def test_export_of_unreviewed_analysis_is_blocked(tmp_path: Path) -> None:
    output, _ = _run(tmp_path)

    with pytest.raises(PublicEvidenceError, match="reviewed report"):
        export_public_evidence_trust_bundle(
            output / ANALYSIS_REPORT_NAME,
            tmp_path / "bundle",
            output / AUDIT_LEDGER_NAME,
            _context("auditor", AUDITOR_ID),
        )


def test_cross_tenant_review_is_blocked(tmp_path: Path) -> None:
    output, _ = _run(tmp_path)
    analysis = _analysis(output)
    decisions = _complete_review_payload(analysis, tenant_id="other-tenant")
    decisions_path = tmp_path / "cross-tenant-review.json"
    _write_json(decisions_path, decisions)

    with pytest.raises(PublicEvidenceError, match="cross-tenant"):
        apply_public_evidence_review(
            output / ANALYSIS_REPORT_NAME,
            decisions_path,
            tmp_path / "reviewed",
            output / AUDIT_LEDGER_NAME,
            _context("reviewer", REVIEWER_ID, tenant_id="other-tenant"),
        )


def test_cross_tenant_export_is_blocked(tmp_path: Path) -> None:
    output, _ = _run(tmp_path)
    review_output, _ = _apply_complete_review(tmp_path, output)

    with pytest.raises(PublicEvidenceError, match="tenant"):
        export_public_evidence_trust_bundle(
            review_output / REVIEWED_REPORT_NAME,
            tmp_path / "bundle",
            output / AUDIT_LEDGER_NAME,
            _context("auditor", AUDITOR_ID, tenant_id="other-tenant"),
        )


def test_audit_ledger_covers_critical_steps_and_is_tenant_run_bound(tmp_path: Path) -> None:
    output, _ = _run(tmp_path)
    analysis = _analysis(output)
    lines = (output / AUDIT_LEDGER_NAME).read_text(encoding="utf-8").splitlines()
    events = [cast(dict[str, object], json.loads(line)) for line in lines]
    event_types = {str(event["event_type"]) for event in events}

    assert {
        "analysis_started",
        "configuration_frozen",
        "input_registered",
        "parser_completed",
        "finding_created",
        "analysis_completed",
    } <= event_types
    assert {str(event["tenant_id"]) for event in events} == {TENANT_ID}
    assert {str(event["run_id"]) for event in events} == {str(analysis["run_id"])}
    assert [int(cast(int, event["sequence"])) for event in events] == list(
        range(1, len(events) + 1)
    )
    assert events[0]["previous_hash"] == "0" * 64
    assert all(
        events[index]["previous_hash"] == events[index - 1]["event_hash"]
        for index in range(1, len(events))
    )


def test_audit_tampering_is_detected_before_append(tmp_path: Path) -> None:
    output, _ = _run(tmp_path)
    analysis = _analysis(output)
    ledger = output / AUDIT_LEDGER_NAME
    lines = ledger.read_text(encoding="utf-8").splitlines()
    tampered = cast(dict[str, object], json.loads(lines[0]))
    tampered["actor_id"] = "tampered-actor"
    lines[0] = json.dumps(tampered, sort_keys=True, separators=(",", ":"))
    ledger.write_text("\n".join(lines) + "\n", encoding="utf-8")

    with pytest.raises(PublicEvidenceError, match="hash verification failed"):
        append_audit_event(
            ledger,
            _context("operator", RUNNER_ID),
            str(analysis["run_id"]),
            "blocked_action",
            {"reason": "test"},
        )


def test_audit_cannot_start_with_a_blocked_action(tmp_path: Path) -> None:
    with pytest.raises(PublicEvidenceError, match="requires an analysis start"):
        append_audit_event(
            tmp_path / "audit.jsonl",
            _context("operator", RUNNER_ID),
            "PEV-test-run",
            "blocked_action",
            {"reason": "no lifecycle"},
        )

    assert not (tmp_path / "audit.jsonl").exists()


def test_foreign_tenant_cannot_append_to_existing_audit(tmp_path: Path) -> None:
    output, _ = _run(tmp_path)
    analysis = _analysis(output)

    with pytest.raises(PublicEvidenceError, match="cross-tenant audit append"):
        append_audit_event(
            output / AUDIT_LEDGER_NAME,
            _context("auditor", AUDITOR_ID, tenant_id="other-tenant"),
            str(analysis["run_id"]),
            "blocked_action",
            {"reason": "foreign append"},
        )


def test_analysis_review_export_flow_exports_only_accepted_findings(tmp_path: Path) -> None:
    output, _ = _run(tmp_path)
    review_output, reviewed = _apply_complete_review(tmp_path, output)
    bundle_output = tmp_path / "bundle"
    manifest = export_public_evidence_trust_bundle(
        review_output / REVIEWED_REPORT_NAME,
        bundle_output,
        output / AUDIT_LEDGER_NAME,
        _context("auditor", AUDITOR_ID),
    )
    approved = _read_json(bundle_output / "approved_report.json")
    evidence_index = _read_json(bundle_output / "evidence_index.json")
    accepted = cast(Sequence[Mapping[str, object]], approved["accepted_findings"])
    reviewed_findings = cast(Sequence[Mapping[str, object]], reviewed["findings"])

    assert manifest["accepted_count"] == 1
    assert manifest["rejected_or_needs_evidence_omitted"] == len(reviewed_findings) - 1
    assert len(accepted) == 1
    assert all(item["review_status"] == "accepted" for item in accepted)
    assert "normalized_quote" not in accepted[0]
    assert "review_comment" not in accepted[0]
    assert "file_name" not in accepted[0]
    assert evidence_index["evidence_count"] == 1
    assert (
        "normalized_quote" not in cast(Sequence[Mapping[str, object]], evidence_index["items"])[0]
    )
    assert (bundle_output / "README.md").is_file()
    authorization = _read_json(bundle_output / "EXPORT_AUTHORIZATION.json")
    assert authorization["bundle_sha256"] == manifest["content_sha256"]
    event_types = {
        str(json.loads(line)["event_type"])
        for line in (output / AUDIT_LEDGER_NAME).read_text(encoding="utf-8").splitlines()
    }
    assert {"export_authorized", "export_created"} <= event_types


def test_fabricated_reviewed_report_is_rejected_by_audit_binding(tmp_path: Path) -> None:
    output, _ = _run(tmp_path)
    review_output, _ = _apply_complete_review(tmp_path, output)
    reviewed_path = review_output / REVIEWED_REPORT_NAME
    reviewed = _read_json(reviewed_path)
    findings = cast(list[dict[str, object]], reviewed["findings"])
    findings[-1]["review_status"] = "accepted"
    unhashed = dict(reviewed)
    unhashed.pop("content_sha256")
    reviewed["content_sha256"] = _canonical_hash(unhashed)
    _write_json(reviewed_path, reviewed)

    with pytest.raises(PublicEvidenceError, match="review audit"):
        export_public_evidence_trust_bundle(
            reviewed_path,
            tmp_path / "bundle",
            output / AUDIT_LEDGER_NAME,
            _context("auditor", AUDITOR_ID),
        )


def test_cli_benchmark_run_smoke(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("aethelgard.cli._resolve_output_path", lambda path, *_args: Path(path))
    output = tmp_path / "cli-run"

    exit_code = main(
        [
            "benchmark",
            "run",
            "--dataset",
            str(DATASET),
            "--out",
            str(output),
            "--tenant-id",
            TENANT_ID,
            "--actor-id",
            RUNNER_ID,
            "--role",
            "operator",
            "--offline",
            "--deterministic",
        ]
    )

    assert exit_code == 0
    assert (output / ANALYSIS_REPORT_NAME).is_file()
