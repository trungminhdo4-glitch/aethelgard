# Public Evidence Validation: Consultant-Pilot Handoff

Date: 2026-07-14  
Readiness: **EXPERT_REVIEW_READY**

This is an internal, reproducible engineering validation. It is not a qualified
NIS-2/ISO 27001 opinion, legal advice, an audit result, a penetration test, or a
certification.

## Verified starting point

- Repository: `D:\projects\aethelgard`
- Branch: `codex/nis2-control-coverage`
- Starting HEAD: `f1286d5f9372c124ad70f229e2524d5dc821ba55`
- Starting worktree: clean
- Baseline: existing full pytest, Ruff, and mypy gates were executed successfully
  before implementation; the opt-in network test remained skipped.
- No environment file, secret, customer document, database, application log, or PII
  source was opened. No network, Docker, paid API, exchange, or external AI workflow
  was invoked.

## Requirement status before and after

| Requirement | Before | After this run |
|---|---|---|
| Exact source-backed findings | Partial anchors in older flows | Exact normalized quote/span/hash plus document/source identity; page only when reliable |
| Categorical confidence | Mixed/numeric legacy paths | Public mode uses only high/medium/low/insufficient with deterministic criteria |
| No autonomous compliance claim | Partial disclaimers | Core-generated statements are bounded and forbidden claims are benchmarked |
| Complete public-mode audit | Not present | Tenant/run-bound hash chain for analysis, parsing, findings, review, authorization, export, and blocks |
| Human review gate | Existing workflows but export bypass risk | Exact-schema and hash-bound complete review; distinct reviewer; accepted-only export allowlist |
| Reproducibility | Existing deterministic components | Frozen versions/config/input hashes; two-run normalized hash comparison |
| Tenant/role separation | No multi-tenant platform | Mandatory audit context, cross-tenant fail-closed tests, distinct actors; still no authentication |
| Offline data-flow control | Local-first but no dedicated mode | Mandatory offline/deterministic context and no network fallback/client in this mode |
| Supply-chain transparency | CycloneDX input feature only | Pilot lock snapshot, CycloneDX SBOM, dependency-license inventory, release-hash process |

## Benchmark v1

The committed dataset has ten project-created lab sources and twenty provisional
reference cases across TXT, Markdown, CSV, and JSON/CycloneDX. It includes positive,
partial, ambiguous, stale, irrelevant, and explicit no-evidence cases. Two cases are
deliberately ambiguous and more than two require insufficient/no finding behavior.

All source entries are `project_created`, locally storable, redistributable, and
registered with SHA-256. No third-party public document or ISO text is vendored. The
expected cases remain `provisional_internal_reference` until independent expert review.

Observed deterministic run result:

- 10 sources, 20 cases, 11 evidence candidates;
- benchmark `passed=true` against the provisional internal reference;
- control precision and recall: 11/11 on this lab set;
- positive-case source and locator accuracy: 11/11;
- zero false-positive pairs, missed pairs, unsupported findings, forbidden claims, or
  findings without source references;
- page accuracy: `not_measured` because there are no provisionally reviewed page refs;
- review-gate and cross-tenant violation metrics: `not_measured` in the dataset report;
  they are covered by adversarial tests rather than represented as invented zeros.

This small, keyword-aligned lab set cannot establish real-world accuracy.

## Implemented security properties

- strict manifest/source-register parity, file-type match, license/storage flags,
  source/aggregate byte caps, finding/case/source caps, SHA-256 checks, and symlink
  rejection;
- exact report field allowlists and content-hash verification;
- mandatory analysis, review, export lifecycle transitions with stage-appropriate
  roles and distinct actor labels;
- audit-bound review decisions and reviewed-report hash;
- staged export with an audit authorization proof before atomic publication;
- controlled export excludes filename, normalized quote, review comment, unknown
  fields, rejected findings, and needs-evidence findings;
- explicit disclaimers and no numeric confidence.

## Validation record

Executed locally without network or Docker:

- targeted public-evidence tests: 26 passed;
- full project suite: 439 passed, 1 opt-in network test skipped, 17 subtests passed
  (440 tests collected);
- Ruff: all checks passed;
- mypy strict: success across 99 source files;
- public-fixture safety: 30 files passed;
- `pip check`: no broken requirements;
- CycloneDX SBOM and benchmark JSON parsed successfully;
- two independent CLI benchmark output directories produced identical normalized
  analysis and benchmark hashes;
- final diff whitespace and release-manifest hashes checked successfully.

The durable benchmark proof is
`benchmarks/public-evidence-v1/results/reproducibility.json`. Its analysis hash is
`23a673accf8603a3bf43e78d3d9218b8448b3f92a0bb1f3ca29d1d6abd8f4d52` and its
benchmark hash is
`34186e8a90bbca2770d0824285accd81e3fcb8df5ec7d6355ceb88147329f189`.
The source snapshot inventory is `security/release-hash-manifest.json`; it deliberately
does not hash itself.

## Remaining technical work the agent could do

1. Preserve reliable PDF page numbers and CSV/XLSX table-cell coordinates through the
   production parser path.
2. Aggregate repeated source/control evidence instead of rejecting duplicate pairs.
3. Add longer/noisier/multilingual/adversarial fixtures and independently labelled
   public URL-only cases after license approval.
4. Add owner-controlled OS/service authentication, authorization policy, and separate
   tenant storage roots.
5. Integrate an approved offline vulnerability scanner and signed release provenance.

## Owner gates

Priority 0: appoint an independent NIS-2/ISO 27001 reviewer; approve budget; review all
twenty provisional cases; decide source model and public benchmark release. Priority 1:
legal review of licensing, liability, disclaimer, pilot terms, NDA/DPA, company identity,
imprint, and required norm access. Priority 1: commission independent code/security
review and decide code signing/release process. Priority 2: select design partners and
approve any anonymized or real-data use. Push, release, publication, purchase, contract,
and customer contact remain owner actions.

## Work requiring external professionals

- binding license, privacy, liability, and contract advice;
- independent security review and penetration test;
- qualified NIS-2/ISO 27001 validation;
- any official seal, certification, or audit opinion.

Internal tests cannot credibly confirm these services.

## Budget proposal: maximum EUR 1,000

| Priority | Item | Range | Purpose / benefit | Preparation and owner gate | Lower-cost alternative |
|---|---|---:|---|---|---|
| 1 | NIS-2/ISO expert review | EUR 350-420 | Review 20 cases, allowed/forbidden claims, and gaps | Send dataset, rubric, limitations; owner selects and contracts reviewer | One 90-minute scoped workshop plus written redlines |
| 2 | IT-law review | EUR 150-200 | Disclaimer, pilot terms, license/privacy/liability triage | Owner provides business model and intended participants | Fixed-scope clinic or founder legal consultation |
| 3 | Norm/official guidance access | EUR 100-160 | Legitimate access to required reference material | Owner decides exact standards before purchase | Use free official guidance until exact norm need is confirmed |
| 4 | Independent security review | EUR 100-140 | Focused review of CLI path, artifact integrity, and offline boundary | Provide commit/diff, threat model, test commands | Peer review by an experienced application-security engineer |
| 5 | Reserve | EUR 80 | Cover tax, extra review time, or one follow-up | Owner releases only against a concrete quote | Keep unspent |

Maximum planned spend: **EUR 1,000**. No purchase, registration, or contract was made.

## Readiness rationale

`EXPERT_REVIEW_READY` is supported by a deterministic offline benchmark, traceable
source references, strict review/export integrity, negative security tests, and durable
trust documentation. `ANONYMIZED_PILOT_READY` and `REAL_DATA_PILOT_READY` are not
supported because authentication, stronger tenant isolation, external expert/legal/
security validation, broader real-world evidence, and owner approvals are missing.
