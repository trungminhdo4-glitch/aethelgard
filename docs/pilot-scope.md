# AethelGard Controlled Pilot Scope

## In Scope

- Local processing of 3 to 10 approved non-sensitive documents.
- Text, Markdown, and PDF input supported by the MVP1 parser.
- Evidence and gap triage for human review.
- JSON and Markdown report handover.
- Optional audit ledger with metadata only.
- False-positive and false-negative review against agreed expectations.

## Out of Scope

- Legal advice.
- Audit opinion, certification, or NIS-2 compliance guarantee.
- SaaS, multi-tenant hosting, cloud upload, or external API processing.
- Secrets, credentials, private logs, production exports, databases, or incident evidence.
- Live integrations with customer systems.
- SBOM, CI/CD, GitHub/GitLab, ticketing, or vulnerability-scanner integrations.

## Assumptions

- Customer provides a small redacted sample pack.
- Customer has authority to share the sample pack.
- A human reviewer evaluates every finding before handover.
- The pilot tests review-time reduction, not legal compliance.

## Required Inputs

- 3 to 10 non-sensitive files in `.txt`, `.md`, or `.pdf` format.
- Short description of what each document is supposed to prove.
- Optional expected categories for review discussion.
- Agreed retention/deletion date.

## Deliverables

- `evidence_report.json`
- `evidence_report.md`
- `run_summary.json`
- Optional `reports/audit/aethelgard_runs.jsonl`
- Reviewer notes against `docs/human-review-checklist.md`

## Done Criteria

- All approved input documents processed or parser failures explained.
- Report disclaimer preserved.
- Human review completed.
- False positives and false negatives discussed.
- Deletion or retention status confirmed.

## Stop Conditions

- Sample pack contains secrets, credentials, raw logs, or avoidable personal data.
- Customer asks for a compliance certification or legal conclusion.
- Customer requires external API processing or SaaS hosting.
- Parser failures prevent meaningful review.
- Scope expands beyond the controlled pilot without owner approval.
