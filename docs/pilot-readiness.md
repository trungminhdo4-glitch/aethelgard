# AethelGard Pilot Readiness

## Status

Internal/friendly pilot status: PILOT READY for the public synthetic evaluation package.

Paid pilot status: ALMOST READY. The technical demo path is now reproducible, but customer
data handling, onboarding, pricing validation, and human review workflow still need a
real pilot agreement.

## Verified Strengths

- Local-only processing path for text and optional PDF input.
- No external model or paid API call in the MVP1 code path.
- JSON and Markdown reports from `python -m aethelgard.cli triage`.
- Evaluation metrics from `python -m aethelgard.cli eval`.
- 12 safe synthetic fixture documents and machine-readable golden labels.
- Fixture safety gate: `python scripts/check_public_fixtures.py`.
- Current synthetic evaluation: 12/12 documents passed, 0 parser failures, 1.0 category hit rate.
- Bounded file size, bounded text length, lazy iterators, and immutable output schema.

## Current Readiness Matrix

| Area | Status | Evidence | Remaining Risk | Next Step |
|---|---|---|---|---|
| Product clarity | READY | README and product positioning keep claim to evidence triage. | Overclaiming in sales calls. | Reuse onepager wording. |
| Demo | READY | `triage` CLI writes JSON/Markdown reports. | Demo is synthetic, not customer-validated. | Run with one owner-approved non-sensitive sample set. |
| Onboarding | PARTIAL | README commands exist. | Fresh-venv result still must be recorded per machine. | Keep `.venv-fresh` smoke test in release checklist. |
| Security | PARTIAL | Fixture safety gate passes. | General staged-file secret scan still manual. | Run fixture check and staged scan before every commit. |
| Datenschutz | PARTIAL | Data-handling boundaries documented. | No signed DPA or retention terms for external customers. | Draft pilot data-handling agreement. |
| Logging | READY | `run_summary.json` and reports capture run metadata. | No append-only run ledger yet. | Add JSONL run history only if pilot needs it. |
| Installation | PARTIAL | `.[all]` includes dev tools and pypdf. | Fresh-venv gate pending in current run until executed. | Execute and record result. |
| Tests | READY | 167 tests pass including CLI/eval/schema/fixtures. | No real customer fixture tests. | Keep only synthetic fixtures in repo. |
| Documentation | READY | README, eval docs, source manifest, labeling guide, onepager. | Needs customer-specific handout after discovery. | Adapt onepager after first pilot conversation. |
| Pricing | PARTIAL | Pilot price ranges documented. | Unvalidated willingness to pay. | Test with 3 discovery calls. |
| Sales material | READY | `docs/pilot-onepager.md`. | Not designed as public marketing page. | Convert to PDF/email only when needed. |

## P0 Before First Paid Pilot

1. Execute and record fresh-venv install and demo/eval commands.
2. Decide customer data-handling terms and retention/deletion policy.
3. Run one owner-approved non-sensitive sample pack through the CLI.
4. Add a human review checklist for false positives/false negatives.
5. Keep the claim limited to evidence triage, not compliance certification.
