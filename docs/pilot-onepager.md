# AethelGard Evidence Triage Pilot

## Product Name

AethelGard Evidence Triage Pilot

## Target Customer

Small MSPs, security consultancies, IT compliance advisors, and NIS-2-affected SMEs that
need a faster first pass over security and supplier documentation.

## Problem

Teams spend expensive expert time opening policies, questionnaires, and procedures just
to find whether useful evidence exists and where obvious gaps remain.

## What AethelGard Does

- Runs locally on approved non-sensitive documents.
- Extracts bounded evidence snippets.
- Groups findings by categories such as risk management, incident reporting, supplier
  security, continuity, access control, and vulnerability management.
- Flags likely gaps and false-positive risks for human review.
- Produces JSON and Markdown handover reports.

## What AethelGard Does Not Do

- No legal advice.
- No audit opinion.
- No certification or NIS-2 compliance guarantee.
- No SaaS or multi-tenant processing in MVP1.
- No external API calls or cloud model upload.
- No processing of secrets, credentials, raw logs, or production incident data.

## 7-Day Pilot

- Validate install and synthetic evaluation.
- Process one non-sensitive sample pack.
- Deliver evidence/gap report.
- Review false positives and obvious gaps with the customer.

## 14-Day Pilot

- Add a small customer-specific keyword/category map.
- Run a second review iteration.
- Produce handover notes and manual next checks.
- Confirm deletion or agreed retention.

## Needed Data

- 3 to 10 non-sensitive files.
- Suitable formats: `.txt`, `.md`, `.pdf`.
- Preferred documents: risk, incident, supplier, access-control, continuity, and
  vulnerability-management policies or questionnaires.

## Data Protection Boundaries

- Customer removes secrets, credentials, personal data where avoidable, production URLs,
  raw logs, private databases, and incident details naming real affected parties.
- Processing is local.
- Reports go to an ignored local `reports/` folder.
- Deletion confirmation is available after handover.

## Success Criteria

- All approved sample files are processed or failures are explained.
- Human reviewer can trace each accepted item to a bounded snippet.
- False positives and false negatives are visible.
- Customer can judge whether the workflow saves manual review time.

## Price Options

- Friendly Pilot: 0 EUR for reference feedback.
- Starter Pilot: 500-1,500 EUR.
- Standard Pilot: 2,500-5,000 EUR.

## Handover Result

The customer receives a JSON/Markdown evidence triage report, run summary, optional
audit-ledger metadata, human-review notes, and a short list of recommended manual checks.
