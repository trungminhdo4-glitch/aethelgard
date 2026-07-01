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
- Integrated pilot-product CLI for document ingest, SQLite answer vault reuse,
  questionnaire draft, review queue, missing-evidence report, and HTML preview.
- Metadata-only evidence store, questionnaire, supplier-risk, and trust-bundle preview flow.
- Offline CycloneDX SBOM inventory and metadata-gap findings with no CVE/API/network lookup.
- Offline public-data validation for a minimized CISA KEV sample and a minimized
  CycloneDX public fixture.
- Supplier profile contract validator for local cascade references.
- Full synthetic `demo-pilot` CLI flow for local consultant/laptop validation.
- Experimental low-compute ML baselines for metadata-only feature extraction, BM25
  search, SimHash duplicate review, weak labels, fallback document classification,
  control suggestions, severity ranking, and active-review queues.
- Privacy-safe learning-feedback export for owner-reviewed, redacted ML signals.
- Metadata-only delivery-profile validator for local consultant/white-label handoff.
- Dockerfile and Compose profile for local offline CLI delivery.
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
$env:PYTHONPATH = (Resolve-Path .\src).Path
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

Review metadata is sanitized before it reaches reviewed JSON or Markdown outputs:
`reviewer` and `review_note` mask e-mail, token, `.env`, and private-path markers;
spreadsheet formula prefixes are escaped; and `reviewed_at` must be empty or ISO-8601.

## Pilot Demo: What the Customer Gets

The full synthetic local demo runs:

```powershell
python -m aethelgard.cli demo-pilot --examples examples/pilot --out reports/pilot-demo-local
```

Outputs:

- `reports/pilot-demo-local/preflight_report.json` and `.md`
- `reports/pilot-demo-local/evidence_report.json` and `.md`
- `reports/pilot-demo-local/review_items.csv`
- `reports/pilot-demo-local/reviewed/reviewed_report.json` and `.md`
- `reports/pilot-demo-local/evidence_store.json`
- `reports/pilot-demo-local/questionnaire/questionnaire_answers.json` and `.md`
- `reports/pilot-demo-local/questionnaire-reviewed/reviewed_report.json`
- `reports/pilot-demo-local/risk/supplier_risk.json` and `.md`
- `reports/pilot-demo-local/sbom_inventory.json`
- `reports/pilot-demo-local/sbom_findings.json`
- `reports/pilot-demo-local/supplier_profile_contract.normalized.json`
- `reports/pilot-demo-local/trust-bundle/manifest.json`
- `reports/pilot-demo-local/trust-bundle/evidence_index.json`
- `reports/pilot-demo-local/trust-bundle/questionnaire_summary.json`
- `reports/pilot-demo-local/trust-bundle/supplier_risk_summary.json`

The demo answers: which synthetic documents produced candidate evidence, which findings
were reviewed, which controls have metadata-only evidence, which questionnaire items
still need evidence, which SBOM metadata gaps exist, and what goes into the final trust
bundle preview. It does not certify compliance, replace legal review, make audit claims,
or process customer data. Inputs in `examples/pilot` are synthetic. Real public
reference fixtures are validated separately under `examples/public`.

## Pilot Product Slice

This is the first product-shaped local workflow:

```powershell
python -m aethelgard.cli pilot-product --workspace examples/pilot --out reports/pilot-product-demo --client-id demo-client --case-id case001
```

Outputs are split deliberately:

- `reports/pilot-product-demo/local_private/document_inventory.json`
- `reports/pilot-product-demo/local_private/evidence_map.json`
- `reports/pilot-product-demo/local_private/aethelgard.sqlite`
- `reports/pilot-product-demo/shareable_redacted/document_summaries.md`
- `reports/pilot-product-demo/shareable_redacted/questionnaire_draft.csv`
- `reports/pilot-product-demo/shareable_redacted/case_review_queue.csv`
- `reports/pilot-product-demo/shareable_redacted/review_items.csv`
- `reports/pilot-product-demo/shareable_redacted/missing_evidence.csv`
- `reports/pilot-product-demo/shareable_redacted/coverage_report.md`
- `reports/pilot-product-demo/shareable_redacted/coverage_report.html`
- `reports/pilot-product-demo/shareable_redacted/pilot_readiness_report.json`

The command inventories supported and unsupported files, marks images as
`ocr_required`, imports reviewed reusable answers into the local SQLite answer vault,
reuses only reviewed answer-vault entries as reviewed drafts, and routes uncertain or
missing answers to human review. Shareable outputs avoid raw snippets and private paths.

Useful lower-level commands:

```powershell
python -m aethelgard.cli document-ingest --input examples/pilot/documents --out reports/document-ingest-demo
python -m aethelgard.cli answer-vault init --db reports/pilot-product-demo/local_private/aethelgard.sqlite --client-id demo-client
python -m aethelgard.cli answer-vault export --db reports/pilot-product-demo/local_private/aethelgard.sqlite --out reports/pilot-product-demo/local_private/answer_library.json
python -m aethelgard.cli workspace inspect --workspace reports/pilot-product-demo
python -m aethelgard.cli workspace purge --workspace reports/pilot-product-demo --dry-run
```

## Local C-SCRM Flow

```powershell
python -m aethelgard.cli evidence from-reviewed-report --input reports/pilot-reviewed/reviewed_report.json --out reports/cscrm/evidence_store.json
python -m aethelgard.cli questionnaire --questions tests/fixtures/scrm/questionnaire_e2e.csv --evidence-store reports/cscrm/evidence_store.json --out reports/cscrm/questionnaire
python -m aethelgard.cli review-apply --report reports/cscrm/questionnaire/questionnaire_answers.json --review-csv reports/cscrm/questionnaire/review_items.csv --out reports/cscrm/questionnaire-reviewed --strict
python -m aethelgard.cli supplier-risk --profile tests/fixtures/scrm/supplier_profile.json --questionnaire-report reports/cscrm/questionnaire-reviewed/reviewed_report.json --out reports/cscrm/risk
python -m aethelgard.cli trust-bundle build --evidence reports/cscrm/evidence_store.json --supplier-risk reports/cscrm/risk/supplier_risk.json --questionnaire reports/cscrm/questionnaire-reviewed/reviewed_report.json --out reports/cscrm/trust-bundle
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

## Public Data Validation

AethelGard includes a tiny offline public-data pack for pilot validation:

- `examples/public/cisa_kev_sample.json`: 3 minimized CISA KEV records.
- `examples/public/cyclonedx_helloworld_mbom.min.json`: minimized CycloneDX public
  example derived from the official bom-examples repository.
- `examples/public/public_data_manifest.json`: source URL, publisher, retrieval date,
  SHA256, upstream SHA256 where relevant, license note, and `contains_pii: false`.

The default tests do not download these sources. They validate the committed local
fixtures by schema, hash, source metadata, and `public-data-marker`.

```powershell
python -m aethelgard.cli public-data validate --manifest examples/public/public_data_manifest.json --out reports/public-data/public_data_validation.json
python -m aethelgard.cli sbom ingest --input examples/public/cyclonedx_helloworld_mbom.min.json --out reports/public-data/sbom_inventory.json
python -m aethelgard.cli sbom findings --input examples/public/cyclonedx_helloworld_mbom.min.json --out reports/public-data/sbom_findings.json
```

This is a public reference-source validation path only. It is not a live KEV feed, not
a vulnerability assessment, not legal advice, not an audit, and not a compliance
decision.

## Experimental Low-Compute ML Baselines

The `ml` CLI group adds a local, deterministic assistance layer. It is experimental,
metadata-only, and review-first. It does not use LLMs, embeddings, fine-tuning, cloud
APIs, SaaS processing, customer data in the repo, or automatic compliance decisions.
All labels, priorities, search hits, duplicates, and control mappings are suggestions
that require human review.

```powershell
python -m aethelgard.cli ml features --input examples/pilot/documents --out reports/ml/features.jsonl
python -m aethelgard.cli ml search --index examples/pilot/documents --query "backup restore test" --out reports/ml/search_results.json
python -m aethelgard.cli ml dedupe --input examples/pilot/documents --out reports/ml/duplicates.json
python -m aethelgard.cli ml weak-labels --input examples/pilot/documents --out reports/ml/weak_labels.jsonl
python -m aethelgard.cli ml train-baselines --task doc-type --input training_fixture.json --out reports/ml/models/doc_type_model.json
python -m aethelgard.cli ml classify-docs --model reports/ml/models/doc_type_model.json --input examples/pilot/documents --out reports/ml/doc_predictions.json
python -m aethelgard.cli ml suggest-controls --input examples/pilot/documents --out reports/ml/control_suggestions.json
python -m aethelgard.cli ml rank-findings --input reports/ml/features.jsonl --out reports/ml/ranked_findings.json
python -m aethelgard.cli ml active-review --predictions reports/ml/doc_predictions.json --weak-labels reports/ml/weak_labels.jsonl --duplicates reports/ml/duplicates.json --severity reports/ml/ranked_findings.json --out reports/ml/active_review_queue.json
python -m aethelgard.cli ml export-learning-feedback --review-csv reports/pilot-demo/review_items.csv --predictions reports/ml/control_suggestions.json --out reports/ml/learning_export.json
```

Outputs avoid raw snippets and private absolute paths. Feature rows contain stable IDs,
relative source references, SHA-256 text hashes, compact booleans, and word counts.
Search and mapping outputs expose only scores, IDs, relative refs, and reason codes.
Model outputs include explicit registry metadata: model name/type/version, feature
schema, training-data reference, generated timestamp, git commit when available, and
`experimental: true`.

Learning-feedback exports are local files only. They do not send data, train weights,
or include raw snippets, file names, private paths, e-mail addresses, IPs, hostnames,
tokens, free-text review notes, or customer identifiers. The export contains only
hashes, allowlisted control IDs, allowlisted reason codes, confidence buckets, and
allowlisted review decisions. It always sets `requires_owner_approval: true`,
`manual_review_required: true`, and `safe_for_vendor_upload: false` by default.

Implemented P0/P1 slice:

- P0: feature extraction, BM25 search, SimHash dedupe, weak labels, fallback document
  classification, rule-based multi-label control suggestions, and active-review queue.
- P1: rule-based severity/evidence-quality ranking from structured features.
- P2: future sklearn-backed `ComplementNB`, `SGDClassifier`/`OneVsRestClassifier`, and
  calibrated severity models once owner-approved dependencies and review-feedback
  training fixtures exist.

## Supplier Profile Contract

```powershell
python -m aethelgard.cli supplier-profile validate --input supplier_profile_contract.json --out reports/cscrm/supplier_profile_contract.json
```

The contract links supplier metadata to evidence, questionnaire, SBOM, and risk-summary
references. Raw notes, private paths, secret-like markers, and unsupported fields are
blocked.

For a runnable synthetic contract example:

```powershell
python -m aethelgard.cli supplier-profile validate --input examples/pilot/supplier_profile_contract_demo.json --out reports/cscrm/supplier_profile_contract.normalized.json
```

## Delivery Profile

```powershell
python -m aethelgard.cli delivery-profile validate --input examples/delivery_profile/demo_consultant_profile.json --out reports/delivery-profile/demo_consultant_profile.normalized.json
```

Delivery profiles are a minimal local handoff contract for consultant labels and report
footer text. They do not override review, trust-bundle, SBOM, or compliance-safety
rules. The validator blocks e-mail addresses, phone-like values, IPs, private absolute
paths, secret-like markers, unsupported fields, and real contact details in examples.

## Consultant Laptop Delivery

No VM is required. The primary delivery path is Docker Desktop or Docker Engine on the
consultant laptop. A VM remains optional infrastructure if a consultant already uses
one, but AethelGard is delivered as source plus a Docker/container image or image
tarball, not as a VM appliance.

Prerequisite: Docker Desktop or Docker Engine.

```powershell
docker build -t aethelgard:local .
docker run --rm aethelgard:local --help
docker compose run --rm aethelgard --help
docker compose run --rm aethelgard demo-pilot --examples examples/pilot --out reports/docker-demo
docker run --rm --network none -v ${PWD}/examples:/workspace/examples:ro -v ${PWD}/reports:/workspace/reports:rw aethelgard:local public-data validate --manifest examples/public/public_data_manifest.json --out reports/public-data/public_data_validation.json
```

Inputs are mounted from `./examples` as read-only data. Outputs are written under
`./reports`, which is ignored by Git. The Compose service uses `network_mode: "none"`
for the default local demo path and runs as a non-root user. Do not place secrets,
customer data, `.env` files, databases, or private logs in the Docker build context.

To process owner-approved local files, mount them read-only from outside the repository
and write outputs to `./reports`. Do not copy customer samples into the repo or Docker
build context.

Delivery and maintenance models:

- Local source build: the consultant builds `aethelgard:local` from this repository.
- Versioned Docker image or tarball: the owner can distribute a reviewed container
  image artifact tagged with the commit SHA.
- Maintenance updates: new checks, templates, public-fixture manifests, security
  updates, and bug fixes can be delivered as a new source or image release.

Runtime Docker proof is opt-in:

```powershell
.\scripts\docker_smoke.ps1
.\scripts\consultant_laptop_smoke.ps1
```

Docker ML smoke is the post-ML delivery proof. It builds `aethelgard:ml-smoke`, runs
`--help` and `ml --help`, then executes `ml features`, `ml search`, `ml dedupe`,
`ml weak-labels`, `ml train-baselines`, `ml classify-docs`, `ml suggest-controls`,
`ml rank-findings`, and `ml active-review` under `--network none`. Outputs go to
`reports/docker-ml-smoke` and are scanned for `.env`, token/cookie/authorization
markers, private paths, and raw snippet markers.

```powershell
.\scripts\docker_ml_smoke.ps1
```

Native Python fallback, if Docker is not allowed:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -e ".[all]"
$env:PYTEST_DISABLE_PLUGIN_AUTOLOAD = "1"
$env:PYTHONPATH = (Resolve-Path .\src).Path
python -m aethelgard.cli demo-pilot --examples examples/pilot --out reports/native-demo
python -m aethelgard.cli public-data validate --manifest examples/public/public_data_manifest.json --out reports/native-public-data/public_data_validation.json
```

Release handoff can be prepared with:

```powershell
.\scripts\build_release_package.ps1 -SkipDockerBuild
.\scripts\build_release_package.ps1 -SaveDockerImage
```

The release script creates a source ZIP, a commit-SHA Docker image tag, optional Docker
image tar, and `SHA256SUMS.txt`. It excludes `reports/`, `.git`, `.env*`, virtual
environments, databases, logs, `dist/`, and research/outreach raw material.

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

- `PILOT_PUBLIC_DATA_READY`: Docker runtime proof exists, static delivery gates pass,
  and real public fixtures validate offline.
- `PILOT_DOCKER_RUNTIME_READY`: Docker runtime proof exists and static Docker delivery
  plus Docker ML runtime proof exist and static Docker delivery gates pass, but
  public-data readiness is not complete.
- `PILOT_DOCKER_RUNTIME_READY_ML_UNVERIFIED`: Docker runtime proof exists, but the
  post-ML Docker smoke proof has not been written yet.
- `PILOT_DOCKER_STATIC_READY_RUNTIME_UNVERIFIED`: local pilot gates and static Docker
  delivery gates pass; Docker runtime smoke has not been run by this checker.
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

## Pilot Outreach Readiness

A pilot customer receives a local evidence triage run, a human-review CSV, reviewed
metadata reports, questionnaire/risk summaries, SBOM metadata-gap findings, and a
metadata-only trust bundle preview.

AethelGard needs 3 to 10 redacted, non-sensitive documents, an optional CycloneDX SBOM,
supplier profile metadata, and an owner-approved retention/deletion decision. Public
fixtures may be used for a no-customer-data demo.

Outputs stay local under `reports/` on the owner or consultant machine. The default
Docker demo uses `--network none`, read-only examples, and a writable reports mount.

Limits remain explicit: no legal advice, no certification, no audit opinion, no
automatic NIS-2 conformity, no SaaS, no private customer data by default, no secrets,
and no live external API calls in the normal pilot path.

## Pilot Status

AethelGard is now ready for a first consultant pilot rehearsal with synthetic examples
and committed public reference fixtures. A first real customer-document pilot still
requires owner-approved redaction, non-sensitive inputs, human review, local processing,
and explicit deletion/retention handling.
