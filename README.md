# AethelGard

AethelGard MVP1 is a local-first Python package for Security/NIS-2 evidence triage.
It finds configured evidence keywords in text/PDF documents, extracts bounded citations,
classifies them with deterministic heuristics, and writes JSON/Markdown reports.

It is not a compliance certification tool, not legal advice, not a SaaS platform, and not
a final NIS-2 compliance decision. The narrow product claim is: AethelGard supports fast
human pre-review of security documentation through local evidence triage.

## Current Capabilities

- Local text parsing with bounded file and text-size limits.
- Optional PDF page streaming through `pypdf`.
- Lazy chunk extraction with generator-based APIs.
- Deterministic heuristic classification with no external model calls.
- Source-backed NIS-2 Article 21(2) control coverage matrix in triage reports.
- Public synthetic NIS-2 fixture corpus with golden labels.
- Demo CLI for JSON/Markdown evidence reports.
- Pilot-run CLI with masked preflight reports and human-review CSV export.
- Review-apply CLI for reviewed JSON/Markdown reports and review summaries.
- Metadata-only evidence store, questionnaire, supplier-risk, and trust-bundle preview flow.
- Offline CycloneDX SBOM inventory and metadata-gap findings with no CVE/API/network lookup.
- Supplier profile contract validator for local cascade references.
- Evaluation CLI with pilot-readiness thresholds.
- Calibration reports with proxy quality indicators for synthetic fixture packs.
- Optional metadata-only audit ledger for CLI runs.
- Paid-pilot ops readiness checker.
- Static fixture safety check for secrets, PII, domains, IPs, and phone-like values.

## Install

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -e ".[all]"
```

## Validate

```powershell
$env:PYTEST_DISABLE_PLUGIN_AUTOLOAD = "1"
$env:PYTHONPATH = "D:\projects\aethelgard\src"
python -m compileall -q src tests scripts
python -m pytest -q
python scripts/check_public_fixtures.py
python scripts/check_pilot_readiness.py --out reports/readiness
```

## Demo Command

```powershell
python -m aethelgard.cli triage --input tests/fixtures/public_nis2 --out reports/demo --audit
```

Outputs:

- `reports/demo/evidence_report.json`
- `reports/demo/evidence_report.md`
- `reports/demo/run_summary.json`
- `reports/audit/aethelgard_runs.jsonl` when `--audit` is enabled

Current synthetic demo summary:

- documents discovered: 17
- documents parsed: 17
- parser failures: 0
- evidence items: generated from positive, gap, and adversarial fixtures
- Article 21(2) control topics: 10 mapped reporting topics
- exit code: 0

## Pilot Run Command

```powershell
python -m aethelgard.cli pilot-run --input tests/fixtures/customer_like_nis2 --out reports/pilot-demo --audit
```

Outputs:

- `reports/pilot-demo/preflight_report.json`
- `reports/pilot-demo/preflight_report.md`
- `reports/pilot-demo/evidence_report.json`
- `reports/pilot-demo/evidence_report.md`
- `reports/pilot-demo/run_summary.json`
- `reports/pilot-demo/review_items.csv`

Use `--fail-on-sensitive` to block medium sensitive markers such as e-mail addresses
and phone numbers. Use `--no-preflight` only for explicitly safe synthetic/demo runs.

## Review Apply Command

```powershell
python -m aethelgard.cli review-apply --report reports/pilot-demo/evidence_report.json --review-csv reports/pilot-demo/review_items.csv --out reports/pilot-reviewed
```

Outputs:

- `reports/pilot-reviewed/reviewed_report.json`
- `reports/pilot-reviewed/reviewed_report.md`
- `reports/pilot-reviewed/review_summary.json`

Use `--strict` to fail on unknown review statuses or unknown finding IDs. Blank
`review_status` values are treated as `open`.

## Local C-SCRM Flow

```powershell
python -m aethelgard.cli evidence from-reviewed-report --input reports/pilot-reviewed/reviewed_report.json --out reports/cscrm/evidence_store.json
python -m aethelgard.cli questionnaire --questions tests/fixtures/scrm/questionnaire_e2e.csv --evidence-store reports/cscrm/evidence_store.json --out reports/cscrm/questionnaire
python -m aethelgard.cli supplier-risk --profile tests/fixtures/scrm/supplier_profile.json --questionnaire-report reports/cscrm/questionnaire/questionnaire_answers.json --out reports/cscrm/risk
python -m aethelgard.cli trust-bundle build --evidence reports/cscrm/evidence_store.json --supplier-risk reports/cscrm/risk/supplier_risk.json --questionnaire reports/cscrm/questionnaire/questionnaire_answers.json --out reports/cscrm/trust-bundle
```

Trust bundles are metadata-only previews. They include source hashes, section names,
conservative status values, evidence indexes, questionnaire summaries, supplier-risk
summaries, and a disclaimer. They do not export raw snippets, citations, draft answers,
logs, cookies, private local paths, or compliance confirmations.

## Offline SBOM Commands

```powershell
python -m aethelgard.cli sbom ingest --input sbom.json --out reports/cscrm/sbom_inventory.json
python -m aethelgard.cli sbom findings --input sbom.json --out reports/cscrm/sbom_findings.json
```

The SBOM MVP supports CycloneDX JSON `components` only. SPDX JSON is rejected with a
clear unsupported-format error. Findings are local metadata gaps only: missing version,
missing license, missing checksum/hash, unknown package identifier, and duplicate
component.

## Offline SBOM Demo

This demo is fully offline and uses only the synthetic CycloneDX fixture in
`examples/sbom/cyclonedx_demo.json`. It does not use customer data, live CVE feeds,
network APIs, legal advice, audit attestation, or compliance confirmation.

```powershell
python -m aethelgard.cli sbom ingest --input examples/sbom/cyclonedx_demo.json --out reports/sbom-demo/sbom_inventory.json
python -m aethelgard.cli sbom findings --input examples/sbom/cyclonedx_demo.json --out reports/sbom-demo/sbom_findings.json
```

Expected outputs:

- `reports/sbom-demo/sbom_inventory.json`
- `reports/sbom-demo/sbom_findings.json`

## Supplier Profile Contract

```powershell
python -m aethelgard.cli supplier-profile validate --input supplier_profile_contract.json --out reports/cscrm/supplier_profile_contract.json
```

The contract links supplier metadata to evidence, questionnaire, SBOM, and risk-summary
references. Raw notes, private paths, secret-like markers, and unsupported fields are
blocked.

## Evaluation Command

```powershell
python -m aethelgard.cli eval --fixtures tests/fixtures/public_nis2 --labels tests/fixtures/public_nis2/golden_labels.json --out reports/eval --audit
```

Outputs:

- `reports/eval/eval_report.json`
- `reports/eval/eval_report.md`
- `reports/eval/calibration_report.json`
- `reports/eval/calibration_report.md`

Current synthetic evaluation result:

- status: `PILOT_READY`
- documents passed: 17/17
- parser failures: 0
- category hit rate: 1.0
- false positives: 0
- false negatives: 0

Customer-like synthetic pilot eval:

```powershell
python -m aethelgard.cli eval --fixtures tests/fixtures/customer_like_nis2 --labels tests/fixtures/customer_like_nis2/golden_labels.json --out reports/customer-like-eval --audit
```

This second pack is invented customer-like data with mixed quality, intentional gaps,
marketing noise, and calibration warnings.

Exit codes:

- `0`: command succeeded; evaluation also meets thresholds for `eval`.
- `1`: technical failure.
- `2`: evaluation completed but did not meet pilot-readiness thresholds.
- `3`: pilot-run preflight blocked sensitive input before triage.

## Readiness Command

```powershell
python scripts/check_pilot_readiness.py --out reports/readiness
```

Outputs:

- `reports/readiness/pilot_readiness.json`
- `reports/readiness/pilot_readiness.md`

Status values:

- `PILOT_OPS_READY`: local pilot operations pack is present and local readiness gates pass.
- `PILOT_READY_PAID_CONTROLLED`: ready only for a small controlled pilot with
  non-sensitive documents and human review.
- `NOT_READY`: a required local gate is missing.

## Minimal Python Usage

```python
from aethelgard.mvp1 import LocalDocumentParser

parser = LocalDocumentParser(
    keywords=("risk assessment", "incident response", "audit"),
    requirement_map={"risk assessment": "risk_management"},
)

for evidence in parser.parse_text("Our risk assessment process is documented and audited."):
    print(evidence.requirement_id, evidence.confidence_score, evidence.is_compliant)
```

## Security Boundaries

- Do not use real customer data in the public fixture corpus.
- Do not include secrets, `.env` files, logs, cookies, tokens, private databases, or raw
  production data.
- Do not commit third-party PDFs unless licensing and redistribution are explicitly clear.
- Reports are written to `reports/`, which is ignored by Git.
- `--audit` stores metadata only: command, paths, counts, status, version, warnings, and
  errors. It does not store document text or extracted citations.

## Pilot Status

AethelGard is now `PILOT_READY` for an internal/friendly synthetic pilot and
`PILOT_OPS_READY` for preparing outreach to 3-5 MSP/security consultancies, provided
the first real pilot still uses non-sensitive documents, human review, local processing,
and explicit deletion/retention handling.
