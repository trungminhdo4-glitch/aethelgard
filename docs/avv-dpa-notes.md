# AVV / DPA Notes for Later Legal Review

This is a note collection for a qualified legal/privacy advisor, not a contract and not legal
advice.

## Pilot Facts to Confirm

- Processing mode: local CLI, no SaaS upload in MVP1.
- Data scope: owner-approved non-sensitive policy/process documents only.
- Exclusions: secrets, credentials, production logs, raw incident data, and avoidable personal data.
- Outputs: JSON/Markdown reports under ignored `reports/`.
- Audit ledger: metadata-only JSONL when `--audit` is enabled.
- Retention: agreed per pilot, then deletion confirmation.

## Questions for Advisor

- Whether an AVV/DPA is required for the exact pilot setup.
- Whether AethelGard is controller, processor, or another role for each pilot scenario.
- Which liability and disclaimer wording is acceptable.
- Which customer data categories are allowed or must be excluded.
- Whether any subcontractor/subprocessor language is needed for local-only operation.
