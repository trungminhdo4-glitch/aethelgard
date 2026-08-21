# Aethelgard Paid Pilot Readiness

## Current Status

- Friendly/internal pilot: READY and hardened for synthetic/local evaluation.
- Paid pilot: READY only for a small, controlled, non-sensitive document pilot.

## Paid Pilot Gates

1. Non-sensitive sample policy: sample data request exists and forbids secrets, raw logs,
   productive credentials, and avoidable personal data.
2. Data handling and retention: local processing, report storage, retention, and deletion
   process are documented.
3. Human review workflow: every report must be reviewed before customer handover.
4. Audit/run traceability: optional JSONL ledger is available via `--audit`.
5. Evaluation baseline: synthetic public fixture evaluation remains the default gate.
6. Report handover: Markdown report includes scope, disclaimer, gaps, review items, and
   technical run metadata.
7. Explicit non-legal disclaimer: reports and docs reject legal advice, audit opinion,
   certification, or NIS-2 compliance guarantee.
8. Owner approval before external data: customer samples require explicit approval and
   should be non-sensitive.
9. No external API calls: MVP1 CLI path is local-only.
10. Deletion confirmation: reusable confirmation template exists.

## Go / No-Go Criteria

| Gate | READY | PARTIAL | BLOCKED |
|---|---|---|---|
| Sample scope | 3-10 non-sensitive docs approved | Customer still redacting docs | Customer wants secrets, logs, or production exports |
| Local processing | CLI runs locally with reports under ignored `reports/` | Operator has not run current validation | External API/cloud upload required |
| Evaluation | Synthetic eval passes | Customer-specific labels not yet defined | Parser crashes or baseline eval fails |
| Human review | Checklist completed before handover | Reviewer still resolving gaps | Customer asks for automated compliance conclusion |
| Audit | `--audit` enabled when traceability is needed | Ledger disabled by choice | Customer requires a formal audit trail beyond MVP scope |
| Deletion | Deletion date and folders agreed | Retention still being discussed | Customer requires long-term storage or SaaS hosting |

## Current Classification

READY for a controlled paid pilot only when all of the following are true:

- The customer provides non-sensitive sample documents.
- The operator runs the fixture safety check and synthetic eval before customer handover.
- A human reviewer completes `docs/human-review-checklist.md`.
- The handover uses the report disclaimer without changing it into a compliance claim.
- Input samples and reports are deleted or retained only under the agreed pilot terms.

The product remains BLOCKED for SaaS, multi-tenant processing, legal advice, audit
opinion, certification, live customer systems, secrets, and production incident data.
