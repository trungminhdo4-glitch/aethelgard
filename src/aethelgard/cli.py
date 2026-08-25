"""Command line interface for AethelGard local evidence triage."""

from __future__ import annotations

import argparse
import csv
import json
import sys
import traceback
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import Any, Final, cast

from aethelgard import review as review_module
from aethelgard.answer_vault import (
    ANSWER_LIBRARY_EXPORT_NAME,
    AnswerVaultError,
    export_answer_library,
    import_answer_library_json,
    import_reviewed_report_answers,
    init_answer_vault,
    list_answer_library,
)
from aethelgard.audit import append_audit_entry, build_audit_entry
from aethelgard.control_catalog import (
    ControlCatalogError,
    build_catalog_validation_report,
    load_control_catalog_bundle,
)
from aethelgard.delivery_profile import DeliveryProfileError, validate_delivery_profile
from aethelgard.diagnostics import (
    DiagnosticLogWriter,
    build_support_bundle,
    diagnostic_error_from_exception,
    run_doctor,
)
from aethelgard.document_ingest import DocumentIngestError, run_document_ingest
from aethelgard.errors import (
    EXIT_C_SCRM_ERROR,
    EXIT_DELIVERY_PROFILE_ERROR,
    EXIT_ML_ERROR,
    EXIT_PILOT_PRODUCT_ERROR,
    EXIT_PREFLIGHT_BLOCKED,
    EXIT_REVIEW_APPLY_ERROR,
    AethelgardDiagnosticError,
    ErrorCode,
    exit_code_for_error,
)
from aethelgard.evidence_bridge import (
    EvidenceBridgeError,
    bridge_reviewed_report_to_evidence_store,
)
from aethelgard.evidence_store import EvidenceStoreError
from aethelgard.ml_baselines.active_learning import (
    ActiveLearningError,
    build_active_review_queue,
)
from aethelgard.ml_baselines.bm25 import BM25Error, search_bm25
from aethelgard.ml_baselines.control_mapper import ControlMapperError, suggest_controls
from aethelgard.ml_baselines.doc_classifier import (
    DocClassifierError,
    classify_documents,
    train_doc_type_baseline,
)
from aethelgard.ml_baselines.features import FeatureExtractionError, write_features_jsonl
from aethelgard.ml_baselines.learning_export import (
    LearningExportError,
    export_learning_feedback,
)
from aethelgard.ml_baselines.model_registry import write_json as write_ml_json
from aethelgard.ml_baselines.severity import SeverityError, rank_findings
from aethelgard.ml_baselines.simhash import SimHashError, detect_near_duplicates
from aethelgard.ml_baselines.weak_labels import write_weak_labels_jsonl
from aethelgard.pii_classification import (
    PiiClassificationError,
    guard_shareable_text,
    load_company_metadata,
)
from aethelgard.pilot_product import (
    DEFAULT_CASE_ID,
    DEFAULT_CLIENT_ID,
    PilotProductError,
    inspect_workspace,
    purge_workspace,
    run_pilot_product_slice,
)
from aethelgard.public_data import PublicDataError, validate_public_data_manifest
from aethelgard.public_evidence import (
    ExecutionContext,
    PublicEvidenceError,
    apply_public_evidence_review,
    export_public_evidence_trust_bundle,
    run_public_evidence_benchmark,
)
from aethelgard.questionnaire import QUESTIONNAIRE_JSON_NAME, QuestionnaireError, run_questionnaire
from aethelgard.redaction_preflight import (
    build_skipped_preflight_report,
    run_redaction_preflight,
    write_preflight_reports,
)
from aethelgard.review import REVIEWED_REPORT_JSON_NAME, ReviewApplyError, apply_review_csv
from aethelgard.sbom import (
    SbomError,
    build_sbom_findings_report,
    build_sbom_inventory,
)
from aethelgard.supplier_profile import (
    SupplierProfileContractError,
    validate_supplier_profile_contract,
)
from aethelgard.supplier_risk import SUPPLIER_RISK_JSON_NAME, SupplierRiskError, run_supplier_risk
from aethelgard.triage import REPORT_JSON_NAME, run_eval, run_triage
from aethelgard.trust_bundle import TrustBundleError, build_trust_bundle_preview

_PROJECT_ROOT: Final[Path] = Path(__file__).resolve().parents[2]

REVIEW_CSV_NAME: Final[str] = review_module.REVIEW_CSV_NAME
REVIEW_CSV_COLUMNS: Final[tuple[str, ...]] = review_module.REVIEW_CSV_COLUMNS
PREFLIGHT_BLOCK_EXIT_CODE: Final[int] = EXIT_PREFLIGHT_BLOCKED
REVIEW_APPLY_ERROR_EXIT_CODE: Final[int] = EXIT_REVIEW_APPLY_ERROR
C_SCRM_ERROR_EXIT_CODE: Final[int] = EXIT_C_SCRM_ERROR
ML_ERROR_EXIT_CODE: Final[int] = EXIT_ML_ERROR
DELIVERY_PROFILE_ERROR_EXIT_CODE: Final[int] = EXIT_DELIVERY_PROFILE_ERROR
PILOT_PRODUCT_ERROR_EXIT_CODE: Final[int] = EXIT_PILOT_PRODUCT_ERROR
DATAGATE_MAX_TEXT_BYTES: Final[int] = 1_000_000
MAX_BENCHMARK_ID_CHARS: Final[int] = 64
DEMO_PILOT_SUMMARY_NAME: Final[str] = "demo_pilot_summary.json"
DEMO_REVIEWED_AT: Final[str] = "2026-06-30T00:00:00+00:00"
DEMO_ACCEPTABLE_CATEGORIES: Final[frozenset[str]] = frozenset(
    {
        "access_control",
        "business_continuity",
        "incident_reporting",
        "secure_development",
        "supplier_security",
        "vulnerability_management",
    }
)


def _bounded_benchmark_id(value: str) -> str:
    normalized = value.strip()
    if not 3 <= len(normalized) <= MAX_BENCHMARK_ID_CHARS:
        raise argparse.ArgumentTypeError("identifier must contain 3 to 64 characters")
    return normalized


def _add_benchmark_context_arguments(
    parser: argparse.ArgumentParser,
    *,
    role_choices: tuple[str, ...],
) -> None:
    parser.add_argument("--tenant-id", required=True, type=_bounded_benchmark_id)
    parser.add_argument("--actor-id", required=True, type=_bounded_benchmark_id)
    parser.add_argument("--role", required=True, choices=role_choices)
    parser.add_argument("--offline", required=True, action="store_true")
    parser.add_argument("--deterministic", required=True, action="store_true")


def build_parser() -> argparse.ArgumentParser:
    """Build the top-level CLI parser."""
    parser = argparse.ArgumentParser(
        prog="python -m aethelgard.cli",
        description="Local NIS-2 evidence triage for synthetic or owner-approved documents.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    triage_parser = subparsers.add_parser("triage", help="Create evidence JSON/Markdown reports.")
    triage_parser.add_argument("--input", required=True, type=Path, help="Input file or directory.")
    triage_parser.add_argument("--out", required=True, type=Path, help="Output directory.")
    triage_parser.add_argument(
        "--audit",
        action="store_true",
        help="Append run metadata to reports/audit/aethelgard_runs.jsonl.",
    )

    eval_parser = subparsers.add_parser("eval", help="Evaluate fixtures against golden labels.")
    eval_parser.add_argument("--fixtures", required=True, type=Path, help="Fixture directory.")
    eval_parser.add_argument("--labels", required=True, type=Path, help="Golden labels JSON file.")
    eval_parser.add_argument("--out", required=True, type=Path, help="Output directory.")
    eval_parser.add_argument(
        "--audit",
        action="store_true",
        help="Append run metadata to reports/audit/aethelgard_runs.jsonl.",
    )

    pilot_parser = subparsers.add_parser(
        "pilot-run",
        help="Run preflight, triage, and review CSV export for demo/pilot preparation.",
    )
    pilot_parser.add_argument("--input", required=True, type=Path, help="Input file or directory.")
    pilot_parser.add_argument("--out", required=True, type=Path, help="Output directory.")
    pilot_parser.add_argument(
        "--audit",
        action="store_true",
        help="Append run metadata to reports/audit/aethelgard_runs.jsonl.",
    )
    pilot_parser.add_argument(
        "--fail-on-sensitive",
        action="store_true",
        help="Block medium sensitive findings such as e-mail addresses and phone numbers.",
    )
    pilot_parser.add_argument(
        "--no-preflight",
        action="store_true",
        help="Skip redaction preflight and write an explicit skipped preflight report.",
    )

    demo_pilot_parser = subparsers.add_parser(
        "demo-pilot",
        help="Run the full local synthetic pilot flow and build a trust bundle.",
    )
    demo_pilot_parser.add_argument(
        "--examples",
        type=Path,
        default=None,
        help="Pilot example directory. Defaults to examples/pilot.",
    )
    demo_pilot_parser.add_argument(
        "--out",
        type=Path,
        default=Path("reports") / "pilot-demo-local",
        help="Output directory for the full local pilot flow.",
    )

    document_ingest_parser = subparsers.add_parser(
        "document-ingest",
        help="Inventory local documents and build deterministic evidence-map metadata.",
    )
    document_ingest_parser.add_argument(
        "--input",
        required=True,
        type=Path,
        help="Input file or directory.",
    )
    document_ingest_parser.add_argument("--out", required=True, type=Path, help="Output directory.")
    document_ingest_parser.add_argument(
        "--no-local-excerpts",
        action="store_true",
        help="Omit redacted local excerpts from the private evidence map.",
    )
    document_ingest_parser.add_argument(
        "--debug",
        action="store_true",
        help="Write local-private debug JSONL and redacted run summary JSONL.",
    )

    pilot_product_parser = subparsers.add_parser(
        "pilot-product",
        help="Run the integrated local documents -> evidence -> answer-vault -> draft flow.",
    )
    pilot_product_parser.add_argument(
        "--workspace",
        required=True,
        type=Path,
        help="Pilot workspace with documents/ and questionnaire_demo.csv.",
    )
    pilot_product_parser.add_argument("--out", required=True, type=Path, help="Output directory.")
    pilot_product_parser.add_argument(
        "--client-id",
        default=DEFAULT_CLIENT_ID,
        help="Local client identifier stored in the SQLite answer vault.",
    )
    pilot_product_parser.add_argument(
        "--case-id",
        default=DEFAULT_CASE_ID,
        help="Questionnaire case identifier.",
    )
    pilot_product_parser.add_argument(
        "--docs",
        type=Path,
        default=None,
        help="Optional document directory override.",
    )
    pilot_product_parser.add_argument(
        "--questions",
        type=Path,
        default=None,
        help="Optional questionnaire CSV override.",
    )
    pilot_product_parser.add_argument(
        "--db",
        type=Path,
        default=None,
        help="Optional SQLite DB path. Defaults to local_private/aethelgard.sqlite.",
    )
    pilot_product_parser.add_argument(
        "--debug",
        action="store_true",
        help="Write additional local-private diagnostics while keeping shareable logs redacted.",
    )

    doctor_parser = subparsers.add_parser(
        "doctor",
        help="Run passive local diagnostics without reading raw customer document content.",
    )
    doctor_parser.add_argument(
        "--workspace",
        required=True,
        type=Path,
        help="Pilot workspace to inspect metadata-only.",
    )
    doctor_parser.add_argument("--out", required=True, type=Path, help="Output directory.")

    support_bundle_parser = subparsers.add_parser(
        "support-bundle",
        help="Create a redacted local support bundle for pilot troubleshooting.",
    )
    support_bundle_parser.add_argument(
        "--workspace",
        required=True,
        type=Path,
        help="Pilot workspace or generated pilot-product output directory.",
    )
    support_bundle_parser.add_argument("--out", required=True, type=Path, help="Output ZIP path.")
    support_bundle_parser.add_argument(
        "--redacted",
        action="store_true",
        default=True,
        help="Create only the redacted support bundle. This is the default.",
    )
    support_bundle_parser.add_argument(
        "--include-private",
        action="store_true",
        help="Blocked: private support bundles are intentionally not implemented.",
    )

    review_parser = subparsers.add_parser(
        "review-apply",
        help="Apply human review CSV data to an evidence report.",
    )
    review_parser.add_argument("--report", required=True, type=Path, help="Evidence report JSON.")
    review_parser.add_argument("--review-csv", required=True, type=Path, help="Review CSV file.")
    review_parser.add_argument("--out", required=True, type=Path, help="Output directory.")
    review_parser.add_argument(
        "--strict",
        action="store_true",
        help="Fail on unknown review statuses or unknown finding IDs.",
    )

    catalog_parser = subparsers.add_parser(
        "validate-controls",
        help="Validate local C-SCRM control catalogs and cross-framework mappings.",
    )
    catalog_parser.add_argument(
        "--catalog-dir",
        type=Path,
        default=None,
        help="Control catalog directory. Defaults to bundled catalogs.",
    )

    questionnaire_parser = subparsers.add_parser(
        "questionnaire",
        help="Map security-question CSV rows to controls and draft answers from evidence.",
    )
    questionnaire_parser.add_argument("--questions", required=True, type=Path, help="Question CSV.")
    questionnaire_parser.add_argument(
        "--evidence-store",
        required=True,
        type=Path,
        help="Metadata-only evidence store JSON.",
    )
    questionnaire_parser.add_argument("--out", required=True, type=Path, help="Output directory.")
    questionnaire_parser.add_argument(
        "--catalog-dir",
        type=Path,
        default=None,
        help="Control catalog directory. Defaults to bundled catalogs.",
    )

    answer_vault_parser = subparsers.add_parser(
        "answer-vault",
        help="Manage the local SQLite client profile / answer vault.",
    )
    answer_vault_subparsers = answer_vault_parser.add_subparsers(
        dest="answer_vault_command",
        required=True,
    )
    answer_vault_init_parser = answer_vault_subparsers.add_parser(
        "init",
        help="Initialize an idempotent SQLite answer vault.",
    )
    answer_vault_init_parser.add_argument("--db", required=True, type=Path, help="SQLite DB path.")
    answer_vault_init_parser.add_argument("--client-id", required=True, help="Client identifier.")

    answer_vault_import_reviewed_parser = answer_vault_subparsers.add_parser(
        "import-reviewed",
        help="Import reviewed questionnaire answers from reviewed_report.json.",
    )
    answer_vault_import_reviewed_parser.add_argument(
        "--db",
        required=True,
        type=Path,
        help="SQLite DB path.",
    )
    answer_vault_import_reviewed_parser.add_argument(
        "--reviewed-report",
        required=True,
        type=Path,
        help="reviewed_report.json from review-apply.",
    )
    answer_vault_import_reviewed_parser.add_argument(
        "--client-id",
        required=True,
        help="Client identifier.",
    )
    answer_vault_import_reviewed_parser.add_argument(
        "--case-id",
        default="",
        help="Optional source case identifier.",
    )

    answer_vault_import_library_parser = answer_vault_subparsers.add_parser(
        "import-library",
        help="Import a local reviewed answer_library JSON fixture.",
    )
    answer_vault_import_library_parser.add_argument(
        "--db",
        required=True,
        type=Path,
        help="SQLite DB path.",
    )
    answer_vault_import_library_parser.add_argument(
        "--answers",
        required=True,
        type=Path,
        help="Answer library JSON.",
    )
    answer_vault_import_library_parser.add_argument(
        "--client-id",
        required=True,
        help="Client identifier.",
    )

    answer_vault_export_parser = answer_vault_subparsers.add_parser(
        "export",
        help="Export the current answer library as JSON.",
    )
    answer_vault_export_parser.add_argument(
        "--db",
        required=True,
        type=Path,
        help="SQLite DB path.",
    )
    answer_vault_export_parser.add_argument(
        "--out",
        required=False,
        type=Path,
        default=Path("reports") / ANSWER_LIBRARY_EXPORT_NAME,
        help="Output JSON path.",
    )
    answer_vault_export_parser.add_argument(
        "--client-id",
        default=None,
        help="Optional client filter.",
    )

    answer_vault_list_parser = answer_vault_subparsers.add_parser(
        "list",
        help="Print answer library entries as JSON.",
    )
    answer_vault_list_parser.add_argument("--db", required=True, type=Path, help="SQLite DB path.")
    answer_vault_list_parser.add_argument(
        "--client-id",
        default=None,
        help="Optional client filter.",
    )

    supplier_parser = subparsers.add_parser(
        "supplier-risk",
        help="Score supplier risk from profile, questionnaire status, and open findings.",
    )
    supplier_parser.add_argument(
        "--profile",
        required=True,
        type=Path,
        help="Supplier profile JSON.",
    )
    supplier_parser.add_argument(
        "--questionnaire-report",
        required=True,
        type=Path,
        help="questionnaire_answers.json from the questionnaire command.",
    )
    supplier_parser.add_argument(
        "--findings-report",
        type=Path,
        default=None,
        help="Optional evidence or reviewed report JSON for open finding counts.",
    )
    supplier_parser.add_argument("--out", required=True, type=Path, help="Output directory.")

    evidence_parser = subparsers.add_parser(
        "evidence",
        help="Build metadata-only evidence stores from reviewed local artifacts.",
    )
    evidence_subparsers = evidence_parser.add_subparsers(
        dest="evidence_command",
        required=True,
    )
    reviewed_parser = evidence_subparsers.add_parser(
        "from-reviewed-report",
        help="Convert accepted reviewed findings into an evidence store JSON file.",
    )
    reviewed_parser.add_argument(
        "--input",
        required=True,
        type=Path,
        help="reviewed_report.json from review-apply.",
    )
    reviewed_parser.add_argument(
        "--out",
        required=True,
        type=Path,
        help="Output evidence store JSON file.",
    )
    reviewed_parser.add_argument(
        "--catalog-dir",
        type=Path,
        default=None,
        help="Control catalog directory. Defaults to bundled catalogs.",
    )

    trust_bundle_parser = subparsers.add_parser(
        "trust-bundle",
        help="Build metadata-only customer/auditor preview bundles.",
    )
    trust_bundle_subparsers = trust_bundle_parser.add_subparsers(
        dest="trust_bundle_command",
        required=True,
    )
    trust_bundle_build_parser = trust_bundle_subparsers.add_parser(
        "build",
        help="Build a deterministic metadata-only trust bundle preview.",
    )
    trust_bundle_build_parser.add_argument(
        "--evidence",
        required=True,
        type=Path,
        help="Metadata-only evidence store JSON.",
    )
    trust_bundle_build_parser.add_argument(
        "--supplier-risk",
        required=True,
        type=Path,
        help="supplier_risk.json from supplier-risk.",
    )
    trust_bundle_build_parser.add_argument(
        "--questionnaire",
        required=True,
        type=Path,
        help="questionnaire or reviewed questionnaire JSON.",
    )
    trust_bundle_build_parser.add_argument(
        "--out",
        required=True,
        type=Path,
        help="Output trust bundle preview directory.",
    )

    sbom_parser = subparsers.add_parser(
        "sbom",
        help="Build offline metadata-only SBOM inventory and gap findings.",
    )
    sbom_subparsers = sbom_parser.add_subparsers(
        dest="sbom_command",
        required=True,
    )
    sbom_ingest_parser = sbom_subparsers.add_parser(
        "ingest",
        help="Extract a deterministic CycloneDX component inventory.",
    )
    sbom_ingest_parser.add_argument("--input", required=True, type=Path, help="SBOM JSON file.")
    sbom_ingest_parser.add_argument(
        "--out",
        required=True,
        type=Path,
        help="Output SBOM inventory JSON file.",
    )
    sbom_findings_parser = sbom_subparsers.add_parser(
        "findings",
        help="Create local SBOM metadata-gap findings.",
    )
    sbom_findings_parser.add_argument("--input", required=True, type=Path, help="SBOM JSON file.")
    sbom_findings_parser.add_argument(
        "--out",
        required=True,
        type=Path,
        help="Output SBOM findings JSON file.",
    )

    public_data_parser = subparsers.add_parser(
        "public-data",
        help="Validate committed public reference fixtures without network access.",
    )
    public_data_subparsers = public_data_parser.add_subparsers(
        dest="public_data_command",
        required=True,
    )
    public_data_validate_parser = public_data_subparsers.add_parser(
        "validate",
        help="Validate public-data fixture metadata and hashes.",
    )
    public_data_validate_parser.add_argument(
        "--manifest",
        required=True,
        type=Path,
        help="Public-data manifest JSON file.",
    )
    public_data_validate_parser.add_argument(
        "--out",
        required=True,
        type=Path,
        help="Output public-data validation JSON file.",
    )

    benchmark_parser = subparsers.add_parser(
        "benchmark",
        help="Run, review, or export the offline public evidence benchmark.",
    )
    benchmark_subparsers = benchmark_parser.add_subparsers(
        dest="benchmark_command",
        required=True,
    )
    benchmark_run_parser = benchmark_subparsers.add_parser(
        "run",
        help="Create source-backed candidates and provisional benchmark metrics.",
    )
    benchmark_run_parser.add_argument("--dataset", required=True, type=Path)
    benchmark_run_parser.add_argument("--out", required=True, type=Path)
    _add_benchmark_context_arguments(benchmark_run_parser, role_choices=("operator", "admin"))

    benchmark_review_parser = benchmark_subparsers.add_parser(
        "review",
        help="Apply complete tenant-bound human review decisions.",
    )
    benchmark_review_parser.add_argument("--report", required=True, type=Path)
    benchmark_review_parser.add_argument("--decisions", required=True, type=Path)
    benchmark_review_parser.add_argument("--audit-ledger", required=True, type=Path)
    benchmark_review_parser.add_argument("--out", required=True, type=Path)
    _add_benchmark_context_arguments(
        benchmark_review_parser,
        role_choices=("reviewer", "admin"),
    )

    benchmark_export_parser = benchmark_subparsers.add_parser(
        "export",
        help="Export accepted findings as a controlled trust-bundle preview.",
    )
    benchmark_export_parser.add_argument("--reviewed-report", required=True, type=Path)
    benchmark_export_parser.add_argument("--audit-ledger", required=True, type=Path)
    benchmark_export_parser.add_argument("--out", required=True, type=Path)
    _add_benchmark_context_arguments(
        benchmark_export_parser,
        role_choices=("auditor", "admin"),
    )

    datagate_parser = subparsers.add_parser(
        "datagate",
        help="Classify declared company metadata vs third-party PII and guard shareable text.",
    )
    datagate_subparsers = datagate_parser.add_subparsers(
        dest="datagate_command",
        required=True,
    )
    datagate_validate_parser = datagate_subparsers.add_parser(
        "validate-metadata",
        help="Validate declared Class-1 company metadata and report ignored fields.",
    )
    datagate_validate_parser.add_argument(
        "--company-metadata",
        required=True,
        type=Path,
        help="Company metadata JSON file with declared Class-1 fields.",
    )
    datagate_validate_parser.add_argument(
        "--out",
        required=True,
        type=Path,
        help="Output company-metadata validation JSON file.",
    )
    datagate_guard_parser = datagate_subparsers.add_parser(
        "guard",
        help="Mask third-party PII in a text file while preserving declared company metadata.",
    )
    datagate_guard_parser.add_argument(
        "--text-file",
        required=True,
        type=Path,
        help="UTF-8 text file to guard before sharing.",
    )
    datagate_guard_parser.add_argument(
        "--company-metadata",
        type=Path,
        default=None,
        help="Optional company metadata JSON whose declared Class-1 values are preserved.",
    )
    datagate_guard_parser.add_argument(
        "--out",
        required=True,
        type=Path,
        help="Output guarded-text report JSON file.",
    )

    supplier_profile_parser = subparsers.add_parser(
        "supplier-profile",
        help="Validate metadata-only supplier cascade profile contracts.",
    )
    supplier_profile_subparsers = supplier_profile_parser.add_subparsers(
        dest="supplier_profile_command",
        required=True,
    )
    supplier_profile_validate_parser = supplier_profile_subparsers.add_parser(
        "validate",
        help="Validate and normalize a supplier profile contract JSON file.",
    )
    supplier_profile_validate_parser.add_argument(
        "--input",
        required=True,
        type=Path,
        help="Supplier profile contract JSON file.",
    )
    supplier_profile_validate_parser.add_argument(
        "--out",
        required=True,
        type=Path,
        help="Output normalized supplier profile contract JSON file.",
    )

    delivery_profile_parser = subparsers.add_parser(
        "delivery-profile",
        help="Validate metadata-only delivery/white-label profile files.",
    )
    delivery_profile_subparsers = delivery_profile_parser.add_subparsers(
        dest="delivery_profile_command",
        required=True,
    )
    delivery_profile_validate_parser = delivery_profile_subparsers.add_parser(
        "validate",
        help="Validate and normalize a local delivery profile JSON file.",
    )
    delivery_profile_validate_parser.add_argument(
        "--input",
        required=True,
        type=Path,
        help="Delivery profile JSON file.",
    )
    delivery_profile_validate_parser.add_argument(
        "--out",
        required=True,
        type=Path,
        help="Output normalized delivery profile JSON file.",
    )

    workspace_parser = subparsers.add_parser(
        "workspace",
        help="Inspect or purge local generated pilot workspaces.",
    )
    workspace_subparsers = workspace_parser.add_subparsers(dest="workspace_command", required=True)
    workspace_inspect_parser = workspace_subparsers.add_parser(
        "inspect",
        help="Inspect generated product-slice workspace metadata.",
    )
    workspace_inspect_parser.add_argument(
        "--workspace",
        required=True,
        type=Path,
        help="Generated workspace/output directory.",
    )
    workspace_purge_parser = workspace_subparsers.add_parser(
        "purge",
        help="Delete known generated product-slice outputs when explicitly confirmed.",
    )
    workspace_purge_parser.add_argument(
        "--workspace",
        required=True,
        type=Path,
        help="Generated workspace/output directory.",
    )
    workspace_purge_parser.add_argument(
        "--dry-run",
        action="store_true",
        help="List purge targets without deleting them.",
    )
    workspace_purge_parser.add_argument(
        "--confirm",
        action="store_true",
        help="Actually delete known generated outputs in the workspace.",
    )

    ml_parser = subparsers.add_parser(
        "ml",
        help="Run local experimental low-compute ML baselines.",
    )
    ml_subparsers = ml_parser.add_subparsers(dest="ml_command", required=True)
    ml_features_parser = ml_subparsers.add_parser(
        "features",
        help="Extract metadata-only feature records as JSONL.",
    )
    ml_features_parser.add_argument("--input", required=True, type=Path, help="Input file or dir.")
    ml_features_parser.add_argument(
        "--out",
        type=Path,
        default=Path("reports") / "ml" / "features.jsonl",
        help="Output feature JSONL path.",
    )

    ml_search_parser = ml_subparsers.add_parser(
        "search",
        help="Search local documents or feature records with BM25.",
    )
    ml_search_parser.add_argument(
        "--index",
        required=True,
        type=Path,
        help="Input corpus or JSONL.",
    )
    ml_search_parser.add_argument("--query", required=True, help="Search query.")
    ml_search_parser.add_argument(
        "--top-k",
        type=int,
        default=10,
        help="Maximum number of results.",
    )
    ml_search_parser.add_argument(
        "--out",
        type=Path,
        default=Path("reports") / "ml" / "search_results.json",
        help="Output search JSON path.",
    )

    ml_dedupe_parser = ml_subparsers.add_parser(
        "dedupe",
        help="Detect possible duplicate or versioned items with SimHash.",
    )
    ml_dedupe_parser.add_argument("--input", required=True, type=Path, help="Input corpus.")
    ml_dedupe_parser.add_argument(
        "--threshold",
        type=float,
        default=0.9,
        help="Minimum SimHash similarity.",
    )
    ml_dedupe_parser.add_argument(
        "--out",
        type=Path,
        default=Path("reports") / "ml" / "duplicates.json",
        help="Output duplicate JSON path.",
    )

    ml_weak_labels_parser = ml_subparsers.add_parser(
        "weak-labels",
        help="Create weak supervision label suggestions as JSONL.",
    )
    ml_weak_labels_parser.add_argument("--input", required=True, type=Path, help="Input corpus.")
    ml_weak_labels_parser.add_argument(
        "--out",
        type=Path,
        default=Path("reports") / "ml" / "weak_labels.jsonl",
        help="Output weak-label JSONL path.",
    )

    ml_train_parser = ml_subparsers.add_parser(
        "train-baselines",
        help="Train a tiny fallback baseline model.",
    )
    ml_train_parser.add_argument(
        "--task",
        required=True,
        choices=("doc-type",),
        help="Baseline task to train.",
    )
    ml_train_parser.add_argument("--input", required=True, type=Path, help="Training fixture.")
    ml_train_parser.add_argument(
        "--out",
        type=Path,
        default=Path("reports") / "ml" / "models" / "doc_type_model.json",
        help="Output model JSON path.",
    )

    ml_classify_docs_parser = ml_subparsers.add_parser(
        "classify-docs",
        help="Classify documents with a trained fallback model.",
    )
    ml_classify_docs_parser.add_argument("--model", required=True, type=Path, help="Model JSON.")
    ml_classify_docs_parser.add_argument("--input", required=True, type=Path, help="Input corpus.")
    ml_classify_docs_parser.add_argument(
        "--out",
        type=Path,
        default=Path("reports") / "ml" / "doc_predictions.json",
        help="Output prediction JSON path.",
    )

    ml_suggest_controls_parser = ml_subparsers.add_parser(
        "suggest-controls",
        help="Suggest C-SCRM controls for local items.",
    )
    ml_suggest_controls_parser.add_argument(
        "--input",
        required=True,
        type=Path,
        help="Input corpus.",
    )
    ml_suggest_controls_parser.add_argument(
        "--min-confidence",
        type=float,
        default=0.55,
        help="Minimum suggestion confidence.",
    )
    ml_suggest_controls_parser.add_argument(
        "--out",
        type=Path,
        default=Path("reports") / "ml" / "control_suggestions.json",
        help="Output suggestion JSON path.",
    )

    ml_rank_parser = ml_subparsers.add_parser(
        "rank-findings",
        help="Suggest finding/evidence priority for human review.",
    )
    ml_rank_parser.add_argument(
        "--input",
        required=True,
        type=Path,
        help="Input corpus or features.",
    )
    ml_rank_parser.add_argument(
        "--out",
        type=Path,
        default=Path("reports") / "ml" / "ranked_findings.json",
        help="Output ranking JSON path.",
    )

    ml_active_parser = ml_subparsers.add_parser(
        "active-review",
        help="Build a human-review queue from ML baseline outputs.",
    )
    ml_active_parser.add_argument("--predictions", type=Path, default=None, help="Prediction JSON.")
    ml_active_parser.add_argument(
        "--weak-labels",
        type=Path,
        default=None,
        help="Weak-label JSONL.",
    )
    ml_active_parser.add_argument("--duplicates", type=Path, default=None, help="Duplicate JSON.")
    ml_active_parser.add_argument("--severity", type=Path, default=None, help="Severity JSON.")
    ml_active_parser.add_argument(
        "--review-csv",
        type=Path,
        default=None,
        help="Optional review CSV.",
    )
    ml_active_parser.add_argument(
        "--out",
        type=Path,
        default=Path("reports") / "ml" / "active_review_queue.json",
        help="Output review queue JSON path.",
    )

    ml_export_parser = ml_subparsers.add_parser(
        "export-learning-feedback",
        help="Export redacted review-feedback signals for owner-approved learning.",
    )
    ml_export_parser.add_argument(
        "--review-csv",
        required=True,
        type=Path,
        help="Reviewed CSV with finding_id/item_id and allowlisted review_status.",
    )
    ml_export_parser.add_argument(
        "--predictions",
        required=True,
        type=Path,
        help="Metadata-only ML output JSON to join with review decisions.",
    )
    ml_export_parser.add_argument(
        "--out",
        type=Path,
        default=Path("reports") / "ml" / "learning_export.json",
        help="Output redacted learning-feedback JSON path.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    """Run the AethelGard CLI."""
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "triage":
        result = run_triage(args.input, args.out)
        if args.audit:
            _append_triage_audit(args.input, args.out, result)
        exit_code = int(result["summary"]["exit_code"])
    elif args.command == "eval":
        report = run_eval(args.fixtures, args.labels, args.out)
        if args.audit:
            _append_eval_audit(args.fixtures, args.out, report)
        exit_code = 0 if report["status"] == "PILOT_READY" else 2
    elif args.command == "pilot-run":
        exit_code = _run_pilot(args)
    elif args.command == "demo-pilot":
        exit_code = _run_demo_pilot(args)
    elif args.command == "document-ingest":
        exit_code = _run_document_ingest(args)
    elif args.command == "pilot-product":
        exit_code = _run_pilot_product(args)
    elif args.command == "review-apply":
        exit_code = _run_review_apply(args)
    elif args.command == "validate-controls":
        exit_code = _run_validate_controls(args)
    elif args.command in {
        "questionnaire",
        "answer-vault",
        "supplier-risk",
        "evidence",
        "trust-bundle",
        "sbom",
        "public-data",
        "benchmark",
        "datagate",
        "supplier-profile",
        "delivery-profile",
        "doctor",
        "support-bundle",
        "workspace",
        "ml",
    }:
        exit_code = _run_local_workflow(args)
    else:
        parser.error("unknown command: %s" % args.command)
        exit_code = 1
    return exit_code


def _run_local_workflow(args: argparse.Namespace) -> int:
    handlers: Mapping[str, Callable[[argparse.Namespace], int]] = {
        "questionnaire": _run_questionnaire,
        "answer-vault": _run_answer_vault,
        "supplier-risk": _run_supplier_risk,
        "evidence": _run_evidence,
        "trust-bundle": _run_trust_bundle,
        "sbom": _run_sbom,
        "public-data": _run_public_data,
        "benchmark": _run_benchmark,
        "datagate": _run_datagate,
        "supplier-profile": _run_supplier_profile,
        "delivery-profile": _run_delivery_profile,
        "doctor": _run_doctor,
        "support-bundle": _run_support_bundle,
        "workspace": _run_workspace,
        "ml": _run_ml,
    }
    handler = handlers.get(str(args.command))
    if handler is not None:
        return handler(args)
    raise ReviewApplyError("unknown local workflow command: %s" % args.command)


def _run_pilot(args: argparse.Namespace) -> int:
    input_path = cast(Path, args.input)
    output_path = cast(Path, args.out)
    output_path.mkdir(parents=True, exist_ok=True)

    if bool(args.no_preflight):
        preflight_report = build_skipped_preflight_report()
    else:
        preflight_report = run_redaction_preflight(
            input_path,
            fail_on_sensitive=bool(args.fail_on_sensitive),
        )
    write_preflight_reports(output_path, preflight_report)

    if preflight_report["status"] == "block":
        return PREFLIGHT_BLOCK_EXIT_CODE

    result = run_triage(input_path, output_path)
    report = cast(dict[str, Any], result["report"])
    _write_review_items_csv(output_path / REVIEW_CSV_NAME, report)
    if args.audit:
        _append_triage_audit(input_path, output_path, result)
    return int(result["summary"]["exit_code"])


def _run_demo_pilot(args: argparse.Namespace) -> int:
    try:
        examples_dir = _resolve_examples_dir(cast(Path | None, args.examples))
        output_path = _resolve_output_path(cast(Path, args.out))
        _run_demo_pilot_flow(examples_dir, output_path)
    except (
        ControlCatalogError,
        EvidenceBridgeError,
        EvidenceStoreError,
        QuestionnaireError,
        ReviewApplyError,
        SbomError,
        SupplierProfileContractError,
        SupplierRiskError,
        TrustBundleError,
    ) as exc:
        print("demo-pilot failed: %s" % exc, file=sys.stderr)
        return C_SCRM_ERROR_EXIT_CODE
    return 0


def _run_demo_pilot_flow(examples_dir: Path, output_path: Path) -> None:
    documents_dir = examples_dir / "documents"
    questionnaire_csv = examples_dir / "questionnaire_demo.csv"
    supplier_profile = examples_dir / "supplier_profile_demo.json"
    supplier_profile_contract = examples_dir / "supplier_profile_contract_demo.json"
    sbom_path = examples_dir / "sbom" / "cyclonedx_demo.json"
    _require_demo_inputs(
        documents_dir,
        questionnaire_csv,
        supplier_profile,
        supplier_profile_contract,
        sbom_path,
    )
    output_path.mkdir(parents=True, exist_ok=True)

    preflight_report = run_redaction_preflight(documents_dir)
    write_preflight_reports(output_path, preflight_report)
    if preflight_report["status"] == "block":
        raise ReviewApplyError("demo-pilot preflight blocked synthetic inputs")

    pilot_result = run_triage(documents_dir, output_path)
    pilot_report = cast(dict[str, Any], pilot_result["report"])
    _write_review_items_csv(output_path / REVIEW_CSV_NAME, pilot_report)
    _fill_demo_review_csv(output_path / REVIEW_CSV_NAME)

    reviewed_dir = output_path / "reviewed"
    apply_review_csv(
        output_path / REPORT_JSON_NAME,
        output_path / REVIEW_CSV_NAME,
        reviewed_dir,
        strict=True,
    )

    evidence_store_path = output_path / "evidence_store.json"
    bridge_reviewed_report_to_evidence_store(
        reviewed_dir / REVIEWED_REPORT_JSON_NAME,
        evidence_store_path,
    )

    questionnaire_dir = output_path / "questionnaire"
    run_questionnaire(questionnaire_csv, evidence_store_path, questionnaire_dir)
    _fill_demo_questionnaire_review_csv(questionnaire_dir / REVIEW_CSV_NAME)

    reviewed_questionnaire_dir = output_path / "questionnaire-reviewed"
    apply_review_csv(
        questionnaire_dir / QUESTIONNAIRE_JSON_NAME,
        questionnaire_dir / REVIEW_CSV_NAME,
        reviewed_questionnaire_dir,
        strict=True,
    )

    risk_dir = output_path / "risk"
    run_supplier_risk(
        supplier_profile,
        reviewed_questionnaire_dir / REVIEWED_REPORT_JSON_NAME,
        risk_dir,
        findings_report_path=reviewed_dir / REVIEWED_REPORT_JSON_NAME,
    )
    build_sbom_inventory(sbom_path, output_path / "sbom_inventory.json")
    build_sbom_findings_report(sbom_path, output_path / "sbom_findings.json")
    validate_supplier_profile_contract(
        supplier_profile_contract,
        output_path / "supplier_profile_contract.normalized.json",
    )
    trust_bundle_dir = output_path / "trust-bundle"
    build_trust_bundle_preview(
        evidence_store_path,
        risk_dir / SUPPLIER_RISK_JSON_NAME,
        reviewed_questionnaire_dir / REVIEWED_REPORT_JSON_NAME,
        trust_bundle_dir,
    )
    _write_demo_summary(output_path, trust_bundle_dir)


def _resolve_examples_dir(path: Path | None) -> Path:
    if path is not None:
        return Path(path)
    cwd_examples = Path("examples") / "pilot"
    if cwd_examples.is_dir():
        return cwd_examples
    return Path(__file__).resolve().parents[2] / "examples" / "pilot"


def _require_demo_inputs(*paths: Path) -> None:
    missing = [path for path in paths if not path.exists()]
    if missing:
        raise ReviewApplyError(
            "demo-pilot inputs are missing: %s" % ", ".join(path.as_posix() for path in missing)
        )


def _fill_demo_review_csv(path: Path) -> None:
    headers, rows = _read_review_csv_rows(path)
    approved_count = 0
    for row in rows:
        category = row.get("category", "")
        if category in DEMO_ACCEPTABLE_CATEGORIES and approved_count == 0:
            row["review_status"] = "accepted"
            approved_count += 1
        elif category in DEMO_ACCEPTABLE_CATEGORIES and approved_count == 1:
            row["review_status"] = "reviewed"
            approved_count += 1
        elif row.get("evidence_level") == "warning":
            row["review_status"] = "needs_evidence"
        else:
            row["review_status"] = "open"
        row["review_note"] = "Synthetic demo review decision."
        row["reviewer"] = "Security Reviewer"
        row["reviewed_at"] = DEMO_REVIEWED_AT
    if approved_count == 0:
        raise ReviewApplyError("demo-pilot could not mark any synthetic finding as accepted")
    _write_review_csv_rows(path, headers, rows)


def _fill_demo_questionnaire_review_csv(path: Path) -> None:
    headers, rows = _read_review_csv_rows(path)
    accepted = False
    for row in rows:
        if row.get("status") == "needs_evidence":
            row["review_status"] = "needs_evidence"
        elif not accepted:
            row["review_status"] = "accepted"
            accepted = True
        else:
            row["review_status"] = "reviewed"
        row["review_note"] = "Synthetic questionnaire review decision."
        row["reviewer"] = "Security Reviewer"
        row["reviewed_at"] = DEMO_REVIEWED_AT
    _write_review_csv_rows(path, headers, rows)


def _read_review_csv_rows(path: Path) -> tuple[list[str], list[dict[str, str]]]:
    with path.open(encoding="utf-8", newline="") as csv_file:
        reader = csv.DictReader(csv_file)
        fieldnames = reader.fieldnames or []
        return list(fieldnames), list(reader)


def _write_review_csv_rows(
    path: Path,
    headers: Sequence[str],
    rows: Sequence[Mapping[str, str]],
) -> None:
    with path.open("w", encoding="utf-8", newline="") as csv_file:
        writer = csv.DictWriter(csv_file, fieldnames=list(headers), lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)


def _write_demo_summary(output_path: Path, trust_bundle_dir: Path) -> None:
    summary = {
        "flow": "demo-pilot",
        "inputs": {
            "type": "synthetic_examples",
            "customer_data": False,
            "network_required": False,
        },
        "outputs": {
            "pilot_report": REPORT_JSON_NAME,
            "reviewed_report": "reviewed/%s" % REVIEWED_REPORT_JSON_NAME,
            "evidence_store": "evidence_store.json",
            "questionnaire": "questionnaire/%s" % QUESTIONNAIRE_JSON_NAME,
            "reviewed_questionnaire": "questionnaire-reviewed/%s" % REVIEWED_REPORT_JSON_NAME,
            "supplier_risk": "risk/%s" % SUPPLIER_RISK_JSON_NAME,
            "sbom_inventory": "sbom_inventory.json",
            "sbom_findings": "sbom_findings.json",
            "supplier_profile_contract": "supplier_profile_contract.normalized.json",
            "trust_bundle": trust_bundle_dir.name,
        },
    }
    _write_json(output_path / DEMO_PILOT_SUMMARY_NAME, summary)


def _write_json(path: Path, payload: Mapping[str, object]) -> None:
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _run_document_ingest(args: argparse.Namespace) -> int:
    logger: DiagnosticLogWriter | None = None
    try:
        output_path = _resolve_output_path(cast(Path, args.out))
        if bool(args.debug):
            logger = DiagnosticLogWriter(output_path, command="document-ingest", debug=True)
            logger.write_event(
                phase="document_ingest",
                event="started",
                message="Document ingest started.",
            )
        run_document_ingest(
            cast(Path, args.input),
            output_path,
            include_local_excerpts=not bool(args.no_local_excerpts),
        )
        if logger is not None:
            logger.write_event(
                phase="document_ingest",
                event="completed",
                message="Document ingest completed.",
            )
    except (DocumentIngestError, ReviewApplyError) as exc:
        if logger is not None:
            logger.write_error(
                diagnostic_error_from_exception(exc, phase="document_ingest"),
                stacktrace=traceback.format_exc(),
            )
        print("document-ingest failed: %s" % exc, file=sys.stderr)
        return PILOT_PRODUCT_ERROR_EXIT_CODE
    return 0


def _run_pilot_product(args: argparse.Namespace) -> int:
    logger: DiagnosticLogWriter | None = None
    try:
        output_path = _resolve_output_path(cast(Path, args.out))
        logger = DiagnosticLogWriter(
            output_path,
            command="pilot-product",
            debug=bool(args.debug),
        )
        logger.write_event(
            phase="pilot_product",
            event="started",
            message="Pilot product run started.",
        )
        db_path = cast(Path | None, args.db)
        resolved_db_path = _resolve_output_path(db_path, "--db") if db_path is not None else None
        result = run_pilot_product_slice(
            cast(Path, args.workspace),
            output_path,
            client_id=str(args.client_id),
            case_id=str(args.case_id),
            docs_path=cast(Path | None, args.docs),
            questionnaire_path=cast(Path | None, args.questions),
            db_path=resolved_db_path,
        )
        _write_json(output_path / "pilot_product_summary.json", result)
        logger.write_event(
            phase="pilot_product",
            event="completed",
            message="Pilot product run completed.",
        )
    except (
        AnswerVaultError,
        DocumentIngestError,
        PilotProductError,
        QuestionnaireError,
        ReviewApplyError,
    ) as exc:
        diagnostic_error = diagnostic_error_from_exception(exc, phase="pilot_product")
        if logger is not None:
            logger.write_error(diagnostic_error, stacktrace=traceback.format_exc())
        print("pilot-product failed: %s" % exc, file=sys.stderr)
        print(
            "Run failed. Create a redacted support bundle with: "
            "python -m aethelgard.cli support-bundle --workspace <run-output> "
            "--out reports/support_bundle.zip --redacted",
            file=sys.stderr,
        )
        return PILOT_PRODUCT_ERROR_EXIT_CODE
    return 0


def _run_doctor(args: argparse.Namespace) -> int:
    try:
        output_path = _resolve_output_path(cast(Path, args.out))
        report = run_doctor(cast(Path, args.workspace), output_path)
    except AethelgardDiagnosticError as exc:
        print("doctor failed: %s" % exc.safe_message, file=sys.stderr)
        return exit_code_for_error(exc.error_code)
    status = str(report["status"])
    print("Doctor status: %s" % status)
    return 0 if status != "FAIL" else exit_code_for_error(ErrorCode.READINESS_FAILED)


def _run_support_bundle(args: argparse.Namespace) -> int:
    try:
        if bool(args.include_private):
            raise AethelgardDiagnosticError(
                error_code=ErrorCode.PRIVACY_GUARD_BLOCKED,
                severity="critical",
                phase="support_bundle",
                safe_message="Private support bundles are not implemented.",
                technical_detail="--include-private was requested",
                remediation_hint=(
                    "Run again with redacted outputs only or inspect local_private manually."
                ),
                safe_to_share=True,
            )
        output_path = _resolve_output_path(cast(Path, args.out))
        result = build_support_bundle(
            cast(Path, args.workspace),
            output_path,
            redacted=bool(args.redacted),
        )
    except AethelgardDiagnosticError as exc:
        print("support-bundle failed: %s" % exc.safe_message, file=sys.stderr)
        print("remediation: %s" % exc.remediation_hint, file=sys.stderr)
        return exit_code_for_error(exc.error_code)
    print("Support bundle: %s" % result["bundle"])
    return 0


def _run_review_apply(args: argparse.Namespace) -> int:
    try:
        output_path = _resolve_output_path(cast(Path, args.out))
        apply_review_csv(
            cast(Path, args.report),
            cast(Path, args.review_csv),
            output_path,
            strict=bool(args.strict),
        )
    except ReviewApplyError as exc:
        print("review-apply failed: %s" % exc, file=sys.stderr)
        return REVIEW_APPLY_ERROR_EXIT_CODE
    return 0


def _run_validate_controls(args: argparse.Namespace) -> int:
    try:
        catalog_dir = cast(Path | None, args.catalog_dir)
        bundle = (
            load_control_catalog_bundle(catalog_dir)
            if catalog_dir
            else load_control_catalog_bundle()
        )
        print(build_catalog_validation_report(bundle))
    except ControlCatalogError as exc:
        print("validate-controls failed: %s" % exc, file=sys.stderr)
        return C_SCRM_ERROR_EXIT_CODE
    return 0


def _run_questionnaire(args: argparse.Namespace) -> int:
    try:
        output_path = _resolve_output_path(cast(Path, args.out))
        catalog_dir = cast(Path | None, args.catalog_dir)
        run_questionnaire(
            cast(Path, args.questions),
            cast(Path, args.evidence_store),
            output_path,
            catalog_dir=catalog_dir,
        )
    except (ControlCatalogError, EvidenceStoreError, QuestionnaireError, ReviewApplyError) as exc:
        print("questionnaire failed: %s" % exc, file=sys.stderr)
        return C_SCRM_ERROR_EXIT_CODE
    return 0


def _run_answer_vault(args: argparse.Namespace) -> int:
    try:
        command = str(args.answer_vault_command)
        db_path = _resolve_output_path(cast(Path, args.db), "--db")
        if command == "init":
            init_answer_vault(db_path, client_id=str(args.client_id))
        elif command == "import-reviewed":
            import_reviewed_report_answers(
                db_path,
                cast(Path, args.reviewed_report),
                client_id=str(args.client_id),
                source_case_id=str(args.case_id),
            )
        elif command == "import-library":
            import_answer_library_json(
                db_path,
                cast(Path, args.answers),
                client_id=str(args.client_id),
            )
        elif command == "export":
            output_path = _resolve_output_path(cast(Path, args.out))
            export_answer_library(
                db_path,
                output_path,
                client_id=cast(str | None, args.client_id),
            )
        elif command == "list":
            answers = list_answer_library(
                db_path,
                client_id=cast(str | None, args.client_id),
            )
            print(json.dumps({"answers": answers}, indent=2, sort_keys=True))
        else:
            raise AnswerVaultError("unknown answer-vault command: %s" % command)
    except (AnswerVaultError, ReviewApplyError) as exc:
        print("answer-vault failed: %s" % exc, file=sys.stderr)
        return PILOT_PRODUCT_ERROR_EXIT_CODE
    return 0


def _run_supplier_risk(args: argparse.Namespace) -> int:
    try:
        output_path = _resolve_output_path(cast(Path, args.out))
        run_supplier_risk(
            cast(Path, args.profile),
            cast(Path, args.questionnaire_report),
            output_path,
            findings_report_path=cast(Path | None, args.findings_report),
        )
    except (SupplierRiskError, ReviewApplyError) as exc:
        print("supplier-risk failed: %s" % exc, file=sys.stderr)
        return C_SCRM_ERROR_EXIT_CODE
    return 0


def _run_evidence(args: argparse.Namespace) -> int:
    if args.evidence_command == "from-reviewed-report":
        return _run_evidence_from_reviewed_report(args)
    raise EvidenceBridgeError("unknown evidence command: %s" % args.evidence_command)


def _run_evidence_from_reviewed_report(args: argparse.Namespace) -> int:
    try:
        output_path = _resolve_output_path(cast(Path, args.out))
        bridge_reviewed_report_to_evidence_store(
            cast(Path, args.input),
            output_path,
            catalog_dir=cast(Path | None, args.catalog_dir),
        )
    except (ControlCatalogError, EvidenceBridgeError, EvidenceStoreError, ReviewApplyError) as exc:
        print("evidence from-reviewed-report failed: %s" % exc, file=sys.stderr)
        return C_SCRM_ERROR_EXIT_CODE
    return 0


def _run_trust_bundle(args: argparse.Namespace) -> int:
    if args.trust_bundle_command == "build":
        return _run_trust_bundle_build(args)
    raise TrustBundleError("unknown trust-bundle command: %s" % args.trust_bundle_command)


def _run_trust_bundle_build(args: argparse.Namespace) -> int:
    try:
        output_path = _resolve_output_path(cast(Path, args.out))
        build_trust_bundle_preview(
            cast(Path, args.evidence),
            cast(Path, args.supplier_risk),
            cast(Path, args.questionnaire),
            output_path,
        )
    except (EvidenceStoreError, ReviewApplyError, TrustBundleError) as exc:
        print("trust-bundle build failed: %s" % exc, file=sys.stderr)
        return C_SCRM_ERROR_EXIT_CODE
    return 0


def _run_sbom(args: argparse.Namespace) -> int:
    try:
        output_path = _resolve_output_path(cast(Path, args.out))
        if args.sbom_command == "ingest":
            build_sbom_inventory(cast(Path, args.input), output_path)
        elif args.sbom_command == "findings":
            build_sbom_findings_report(cast(Path, args.input), output_path)
        else:
            raise SbomError("unknown sbom command: %s" % args.sbom_command)
    except (ReviewApplyError, SbomError) as exc:
        print("sbom %s failed: %s" % (args.sbom_command, exc), file=sys.stderr)
        return C_SCRM_ERROR_EXIT_CODE
    return 0


def _run_public_data(args: argparse.Namespace) -> int:
    try:
        output_path = _resolve_output_path(cast(Path, args.out))
        if args.public_data_command == "validate":
            validate_public_data_manifest(cast(Path, args.manifest), output_path)
        else:
            raise PublicDataError("unknown public-data command: %s" % args.public_data_command)
    except (ReviewApplyError, PublicDataError) as exc:
        print(
            "public-data %s failed: %s" % (args.public_data_command, exc),
            file=sys.stderr,
        )
        return C_SCRM_ERROR_EXIT_CODE
    return 0


def _run_benchmark(args: argparse.Namespace) -> int:
    try:
        context = ExecutionContext.model_validate(
            {
                "tenant_id": args.tenant_id,
                "actor_id": args.actor_id,
                "role": args.role,
                "offline": args.offline,
                "deterministic": args.deterministic,
            }
        )
        output_path = _resolve_output_path(cast(Path, args.out))
        if args.benchmark_command == "run":
            dataset_path = _resolve_benchmark_dataset_path(cast(Path, args.dataset))
            run_public_evidence_benchmark(dataset_path, output_path, context)
        elif args.benchmark_command == "review":
            audit_path = _resolve_output_path(cast(Path, args.audit_ledger), "--audit-ledger")
            apply_public_evidence_review(
                _resolve_output_path(cast(Path, args.report), "--report"),
                _resolve_output_path(cast(Path, args.decisions), "--decisions"),
                output_path,
                audit_path,
                context,
            )
        elif args.benchmark_command == "export":
            audit_path = _resolve_output_path(cast(Path, args.audit_ledger), "--audit-ledger")
            export_public_evidence_trust_bundle(
                _resolve_output_path(
                    cast(Path, args.reviewed_report),
                    "--reviewed-report",
                ),
                output_path,
                audit_path,
                context,
            )
        else:
            raise PublicEvidenceError("unknown benchmark command: %s" % args.benchmark_command)
    except (PublicEvidenceError, ReviewApplyError, ValueError) as exc:
        print("benchmark %s failed: %s" % (args.benchmark_command, exc), file=sys.stderr)
        return C_SCRM_ERROR_EXIT_CODE
    return 0


def _run_datagate(args: argparse.Namespace) -> int:
    try:
        output_path = _resolve_output_path(cast(Path, args.out))
        if args.datagate_command == "validate-metadata":
            metadata = load_company_metadata(cast(Path, args.company_metadata))
            report: dict[str, object] = {
                "report_type": "company_metadata_validation",
                "accepted_count": len(metadata.fields),
                "accepted_fields": dict(metadata.fields),
                "ignored_fields": list(metadata.ignored_fields),
            }
        elif args.datagate_command == "guard":
            metadata_arg = cast(Path | None, args.company_metadata)
            guard_metadata = (
                load_company_metadata(metadata_arg) if metadata_arg is not None else None
            )
            guarded = guard_shareable_text(
                _read_datagate_text(cast(Path, args.text_file)), guard_metadata
            )
            report = {
                "report_type": "guarded_text",
                "had_sensitive": guarded.had_sensitive,
                "preserved": list(guarded.preserved),
                "masked_types": list(guarded.masked_types),
                "guarded_text": guarded.text,
            }
        else:
            raise PiiClassificationError("unknown datagate command: %s" % args.datagate_command)
        output_path.write_text(
            json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
    except PiiClassificationError as exc:
        print("datagate %s failed: %s" % (args.datagate_command, exc), file=sys.stderr)
        return C_SCRM_ERROR_EXIT_CODE
    return 0


def _read_datagate_text(path: Path) -> str:
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise PiiClassificationError("could not read text file: %s" % path.name) from exc
    if len(raw) > DATAGATE_MAX_TEXT_BYTES:
        raise PiiClassificationError("text file exceeds the datagate size limit")
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise PiiClassificationError("text file must be UTF-8 text") from exc


def _run_supplier_profile(args: argparse.Namespace) -> int:
    try:
        output_path = _resolve_output_path(cast(Path, args.out))
        if args.supplier_profile_command == "validate":
            validate_supplier_profile_contract(cast(Path, args.input), output_path)
        else:
            raise SupplierProfileContractError(
                "unknown supplier-profile command: %s" % args.supplier_profile_command
            )
    except (ReviewApplyError, SupplierProfileContractError) as exc:
        print(
            "supplier-profile %s failed: %s" % (args.supplier_profile_command, exc),
            file=sys.stderr,
        )
        return C_SCRM_ERROR_EXIT_CODE
    return 0


def _run_delivery_profile(args: argparse.Namespace) -> int:
    try:
        output_path = _resolve_output_path(cast(Path, args.out))
        if args.delivery_profile_command == "validate":
            validate_delivery_profile(cast(Path, args.input), output_path)
        else:
            raise DeliveryProfileError(
                "unknown delivery-profile command: %s" % args.delivery_profile_command
            )
    except (ReviewApplyError, DeliveryProfileError) as exc:
        print(
            "delivery-profile %s failed: %s" % (args.delivery_profile_command, exc),
            file=sys.stderr,
        )
        return DELIVERY_PROFILE_ERROR_EXIT_CODE
    return 0


def _run_workspace(args: argparse.Namespace) -> int:
    try:
        command = str(args.workspace_command)
        if command == "inspect":
            report = inspect_workspace(cast(Path, args.workspace))
        elif command == "purge":
            dry_run = bool(args.dry_run) or not bool(args.confirm)
            report = purge_workspace(
                cast(Path, args.workspace),
                dry_run=dry_run,
                confirm=bool(args.confirm),
            )
        else:
            raise PilotProductError("unknown workspace command: %s" % command)
        print(json.dumps(report, indent=2, sort_keys=True))
    except PilotProductError as exc:
        print("workspace %s failed: %s" % (args.workspace_command, exc), file=sys.stderr)
        return PILOT_PRODUCT_ERROR_EXIT_CODE
    return 0


def _run_ml(args: argparse.Namespace) -> int:
    handlers: Mapping[str, Callable[[argparse.Namespace], int]] = {
        "features": _run_ml_features,
        "search": _run_ml_search,
        "dedupe": _run_ml_dedupe,
        "weak-labels": _run_ml_weak_labels,
        "train-baselines": _run_ml_train_baselines,
        "classify-docs": _run_ml_classify_docs,
        "suggest-controls": _run_ml_suggest_controls,
        "rank-findings": _run_ml_rank_findings,
        "active-review": _run_ml_active_review,
        "export-learning-feedback": _run_ml_export_learning_feedback,
    }
    try:
        command = str(args.ml_command)
        handler = handlers.get(command)
        if handler is None:
            raise ActiveLearningError("unknown ml command: %s" % command)
        handler(args)
    except (
        ActiveLearningError,
        BM25Error,
        ControlMapperError,
        DocClassifierError,
        FeatureExtractionError,
        LearningExportError,
        ReviewApplyError,
        SeverityError,
        SimHashError,
        ValueError,
    ) as exc:
        print("ml %s failed: %s" % (args.ml_command, exc), file=sys.stderr)
        return ML_ERROR_EXIT_CODE
    return 0


def _run_ml_features(args: argparse.Namespace) -> int:
    output_path = _resolve_output_path(cast(Path, args.out))
    write_features_jsonl(cast(Path, args.input), output_path)
    return 0


def _run_ml_search(args: argparse.Namespace) -> int:
    output_path = _resolve_output_path(cast(Path, args.out))
    report = search_bm25(
        cast(Path, args.index),
        str(args.query),
        top_k=int(args.top_k),
    )
    write_ml_json(output_path, report)
    return 0


def _run_ml_dedupe(args: argparse.Namespace) -> int:
    output_path = _resolve_output_path(cast(Path, args.out))
    report = detect_near_duplicates(
        cast(Path, args.input),
        threshold=float(args.threshold),
    )
    write_ml_json(output_path, report)
    return 0


def _run_ml_weak_labels(args: argparse.Namespace) -> int:
    output_path = _resolve_output_path(cast(Path, args.out))
    write_weak_labels_jsonl(cast(Path, args.input), output_path)
    return 0


def _run_ml_train_baselines(args: argparse.Namespace) -> int:
    output_path = _resolve_output_path(cast(Path, args.out))
    if str(args.task) == "doc-type":
        train_doc_type_baseline(cast(Path, args.input), output_path)
        return 0
    raise DocClassifierError("unsupported ML task: %s" % args.task)


def _run_ml_classify_docs(args: argparse.Namespace) -> int:
    output_path = _resolve_output_path(cast(Path, args.out))
    report = classify_documents(cast(Path, args.model), cast(Path, args.input))
    write_ml_json(output_path, report)
    return 0


def _run_ml_suggest_controls(args: argparse.Namespace) -> int:
    output_path = _resolve_output_path(cast(Path, args.out))
    report = suggest_controls(
        cast(Path, args.input),
        min_confidence=float(args.min_confidence),
    )
    write_ml_json(output_path, report)
    return 0


def _run_ml_rank_findings(args: argparse.Namespace) -> int:
    output_path = _resolve_output_path(cast(Path, args.out))
    report = rank_findings(cast(Path, args.input))
    write_ml_json(output_path, report)
    return 0


def _run_ml_active_review(args: argparse.Namespace) -> int:
    output_path = _resolve_output_path(cast(Path, args.out))
    if not _has_active_review_input(args):
        raise ActiveLearningError("active-review requires at least one input")
    report = build_active_review_queue(
        predictions_path=cast(Path | None, args.predictions),
        weak_labels_path=cast(Path | None, args.weak_labels),
        duplicates_path=cast(Path | None, args.duplicates),
        severity_path=cast(Path | None, args.severity),
        review_csv_path=cast(Path | None, args.review_csv),
    )
    write_ml_json(output_path, report)
    return 0


def _run_ml_export_learning_feedback(args: argparse.Namespace) -> int:
    output_path = _resolve_output_path(cast(Path, args.out))
    export_learning_feedback(
        review_csv_path=cast(Path, args.review_csv),
        predictions_path=cast(Path, args.predictions),
        out_path=output_path,
    )
    return 0


def _has_active_review_input(args: argparse.Namespace) -> bool:
    return any(
        value is not None
        for value in (
            args.predictions,
            args.weak_labels,
            args.duplicates,
            args.severity,
            args.review_csv,
        )
    )


def _resolve_output_path(path: Path, label: str = "--out") -> Path:
    resolved = Path(path).resolve()
    safe_base = Path.cwd().resolve()
    try:
        resolved.relative_to(safe_base)
    except ValueError as exc:
        raise ReviewApplyError("%s must stay inside the current project folder" % label) from exc
    return resolved


def _resolve_benchmark_dataset_path(path: Path) -> Path:
    resolved = Path(path).resolve()
    approved_base = (_PROJECT_ROOT / "benchmarks").resolve()
    try:
        resolved.relative_to(approved_base)
    except ValueError as exc:
        raise ReviewApplyError("--dataset must stay inside the project benchmarks folder") from exc
    if not resolved.is_dir():
        raise ReviewApplyError("--dataset must identify a local benchmark directory")
    return resolved


def _append_triage_audit(
    input_path: Path,
    output_path: Path,
    result: dict[str, Any],
) -> None:
    report = cast(dict[str, Any], result["report"])
    entry = build_audit_entry(
        command="triage",
        input_path=input_path,
        output_path=output_path,
        document_count=int(report["document_count"]),
        parsed_count=int(report["parsed_count"]),
        failed_count=int(report["failed_count"]),
        evidence_count=int(report["evidence_count"]),
        run_id=str(report["run_id"]),
        evaluation_status=None,
        tool_version=str(report["tool_version"]),
        warnings=[str(warning) for warning in report["warnings"]],
        errors=[cast(dict[str, str], error) for error in report["errors"]],
    )
    append_audit_entry(entry)


def _append_eval_audit(
    fixtures_path: Path,
    output_path: Path,
    report: dict[str, Any],
) -> None:
    entry = build_audit_entry(
        command="eval",
        input_path=fixtures_path,
        output_path=output_path,
        document_count=int(report["document_count"]),
        parsed_count=int(report["parsed_count"]),
        failed_count=int(report["failed_count"]),
        evidence_count=int(report["evidence_count"]),
        run_id=str(report["run_id"]),
        evaluation_status=str(report["status"]),
        tool_version=str(report["tool_version"]),
        warnings=[],
        errors=[],
    )
    append_audit_entry(entry)


def _write_review_items_csv(path: Path, report: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as csv_file:
        writer = csv.DictWriter(csv_file, fieldnames=list(REVIEW_CSV_COLUMNS), lineterminator="\n")
        writer.writeheader()
        for row in _build_review_rows(report):
            writer.writerow(row)


def _build_review_rows(report: Mapping[str, Any]) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    documents = cast(Sequence[Mapping[str, Any]], report["per_document"])
    for document in documents:
        document_name = str(document["file"])
        evidence_items = cast(Sequence[Mapping[str, Any]], document["evidence"])
        for item_index, item in enumerate(evidence_items, start=1):
            category = str(item["category"])
            quality = str(item["quality"])
            signals = [str(signal) for signal in cast(Sequence[object], item["quality_signals"])]
            row = {
                "finding_id": str(item["finding_id"]),
                "category": category,
                "control_area": _humanize_category(category),
                "document": document_name,
                "evidence_level": quality,
                "status": _review_status(quality),
                "finding": str(item["source_citation"]),
                "recommended_manual_check": str(
                    item.get(
                        "recommended_manual_check",
                        _manual_check_for_item(quality, signals),
                    )
                ),
                "source_reference": str(
                    item.get("source_reference", "%s#evidence-%d" % (document_name, item_index))
                ),
                "review_status": "",
                "review_note": "",
                "reviewer": "",
                "reviewed_at": "",
            }
            rows.append(_safe_review_csv_row(row))
    return rows


def _safe_review_csv_row(row: Mapping[str, str]) -> dict[str, str]:
    return {key: review_module.safe_review_csv_cell(value) for key, value in row.items()}


def _humanize_category(category: str) -> str:
    return category.replace("_", " ")


def _review_status(quality: str) -> str:
    if quality == "strong":
        return "candidate_evidence"
    if quality == "warning":
        return "warning_review"
    return "manual_review"


def _manual_check_for_item(quality: str, signals: Sequence[str]) -> str:
    if signals:
        return "Review quality signals: %s." % ", ".join(signals[:4])
    if quality == "strong":
        return "Confirm implemented control, owner, review cadence, and evidence freshness."
    return "Confirm whether this is real control evidence or only weak wording."


if __name__ == "__main__":
    raise SystemExit(main())
