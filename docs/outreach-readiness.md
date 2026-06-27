# Aethelgard Outreach Readiness

## Current Status

Aethelgard is technically ready for owner-reviewed outreach preparation, not for automatic
contacting. The first outreach wave must stay manual and limited to 3 to 5 target
companies selected from public company-level signals only.

Verified local baseline:

| Area | Status |
| --- | --- |
| Branch | `main` |
| Baseline HEAD | `97bb5a7 feat: prepare paid pilot operations` |
| Git remote | none configured |
| Preflight tests | `184 passed, 1 skipped, 17 subtests passed` |
| Pilot readiness | `PILOT_OPS_READY` |
| Push performed | no |

Fresh outreach demo run on `tests/fixtures/customer_like_nis2`:

| Metric | Result |
| --- | ---: |
| Documents | 8 |
| Parsed documents | 8 |
| Parser failures | 0 |
| Evidence count | 57 |
| Calibration warnings | 31 |
| Eval status | `PILOT_READY` |
| Readiness status | `PILOT_OPS_READY` |

The warnings are expected for mixed-quality customer-like fixtures and must be used to
explain why human review remains mandatory.

## Ready Assets

- `docs/pilot-onepager.md`: concise pilot offer and data boundaries.
- `docs/pilot-email.md`: four cautious outreach variants by target type.
- `docs/follow-up-sequence.md`: polite 3/7/14 working-day follow-up cadence.
- `docs/icp-scoring.md`: target-customer scoring and first ICP recommendation.
- `docs/target-selection-guide.md`: manual target selection criteria.
- `docs/outreach-target-list-template.csv`: company-level tracking template.
- `docs/sample-data-request.md`: redacted non-sensitive sample-pack request.
- `docs/data-handling.md`: accepted and excluded data categories.
- `docs/legal-review-checklist.md`: legal/privacy review gate.
- `docs/objection-handling.md`: short answers to common pilot objections.
- `docs/pilot-call-agenda.md`: 30-minute pilot call structure.
- `docs/demo-script.md`: 15-minute synthetic-data demo flow.
- `docs/pilot-call-notes-template.md`: structured CRM-style call notes.

## Missing Assets

- Owner-selected list of 3 to 5 company-level targets.
- Qualified legal/privacy review before any paid pilot paperwork is used.
- Customer-approved redacted sample pack for any real pilot.
- Owner decision on whether the first wave is friendly, unpaid, or paid controlled.

## Claims Allowed

- local evidence triage
- supports human review
- structured evidence/gap report
- no external API calls in pilot flow
- redacted non-sensitive samples only
- not legal advice

## Claims Forbidden

- guarantees NIS-2 compliance
- replaces audit/legal review
- certifies security
- automatically makes company compliant
- handles sensitive production data by default

## Target ICP

Best first ICP: MSP / IT-Systemhaus with SME customers.

Why:

- recurring customer document-review pain
- clear fit for a local first-pass evidence triage
- can test with redacted non-sensitive samples from typical customer documentation
- likely to understand human-review boundaries

Initial priority order:

1. MSP / IT-Systemhaus with SME customers
2. Small security or compliance consultancy
3. Data protection / ISMS consultancy

Direct NIS-2-affected SMEs and software agencies are lower priority for the first wave
because the trust barrier, education effort, or pilot fit is weaker.

## Outreach Go/No-Go

GO only when all criteria are true:

- owner manually selected 3 to 5 company-level targets
- only public company contact channels are used
- no private contacts, personal emails, scraped leads, or LinkedIn automation are used
- message uses one of the approved cautious variants
- CTA is a 15-minute demo, not a compliance promise
- sample request asks only for 3 to 10 redacted non-sensitive documents
- recipient is told that Aethelgard is not legal advice, not an audit, and not a
  certification

NO-GO if any criterion is true:

- the target expects a NIS-2 guarantee, legal advice, audit opinion, or certification
- the target wants to send sensitive production data, secrets, logs, incident packs, or
  customer personal data
- the target requires SaaS, multi-tenant hosting, or live integrations for MVP1
- only a recruiting or personal contact channel is available
- the owner has not reviewed the target list and selected the exact first wave

## Next Action

Owner manually selects 3 to 5 company-level MSP/security targets using
`docs/target-selection-guide.md` and records them in
`docs/outreach-target-list-template.csv` before sending any message.
