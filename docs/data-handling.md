# AethelGard Data Handling Boundaries

## Accepted Data

- Synthetic documents created for this repository.
- Public documents or public URLs used only as reference sources.
- Customer-approved non-sensitive sample documents for a controlled pilot.
- Security policies, supplier questionnaires, incident-process templates, access-control
  policies, continuity plans, vulnerability-management descriptions, and similar files
  after the customer has removed sensitive details.

## Data Not Accepted

- Secrets, API keys, wallet keys, access tokens, cookies, `.env` files, private keys, or
  production credentials.
- Private databases, raw logs, monitoring exports, support dumps, incident evidence
  packs, forensic images, or production telemetry.
- Personal data where avoidable, including named employees, private phone numbers,
  personal email addresses, HR notes, or customer/end-user records.
- Productive access details such as VPN profiles, admin URLs, passwords, seed phrases,
  recovery codes, or internal network maps.
- Incident details naming real affected persons, patients, customers, or suppliers.
- Third-party PDFs or long copied source texts unless redistribution is explicitly clear.

## Processing Model

- AethelGard MVP1 runs locally.
- The CLI does not call external APIs, LLM providers, cloud services, or model endpoints.
- Reports are written to the operator-selected output directory, normally under
  `reports/`, which is ignored by Git.
- Audit ledger entries, when enabled with `--audit`, store run metadata only and do not
  store source document text or extracted citations.

## Pilot Retention

- Default pilot retention: keep input samples and reports only until the pilot review is
  complete, then delete them after written owner/customer confirmation.
- Recommended maximum retention for a controlled paid pilot: 14 calendar days unless a
  shorter period is agreed.
- Reports may be regenerated from the same approved sample pack if the customer asks for
  a repeat run during the retention window.

## Deletion Process

1. Confirm the exact input folder and output folder used for the run.
2. Confirm that the customer has received the agreed JSON/Markdown report files.
3. Delete local input samples and generated reports from the pilot working folder.
4. Keep only non-sensitive operational metadata if the customer agreed to an audit ledger.
5. Send the deletion confirmation template in `docs/deletion-confirmation-template.md`.

## Human Review And Claim Boundary

- Every report requires human review before customer handover.
- AethelGard output is evidence triage, not legal advice.
- AethelGard output is not an audit opinion, certification, or NIS-2 compliance guarantee.
- Reviewers must reject evidence that is marketing-only, template-only, outdated,
  missing an owner/review date, or contradicted by a gap statement.
