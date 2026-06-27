# Pilot Sample Data Request

Hi [Name],

for the AethelGard Evidence Triage Pilot, please send a small non-sensitive sample pack
of 3 to 10 documents. The goal is to test whether AethelGard can reduce manual review
time by finding possible Security/NIS-2 evidence and obvious gaps for human review.

Good sample documents:

- security policy or information-security policy
- risk-management or risk-assessment process
- incident-response or reporting procedure
- business-continuity or backup/restore policy
- supplier-security or vendor-review questionnaire
- access-control or privileged-access policy
- vulnerability or patch-management process

Accepted formats: `.txt`, `.md`, and `.pdf`.

## Allowed Document Types

- security policy or information-security policy
- risk-management or risk-assessment process
- incident-response or reporting procedure
- business-continuity or backup/restore policy
- supplier-security or vendor-review questionnaire
- access-control or privileged-access policy
- vulnerability or patch-management process
- redacted security questionnaire excerpts

## Forbidden Contents

Please remove these before sending and do not include the file if removal is not safe:

- Zugangsdaten
- API Keys
- personenbezogene Kundendaten
- echte Incident-Details mit Betroffenen
- interne Schwachstellenlisten mit ausnutzbaren Details
- produktive Netzwerkpläne
- Logs
- Verträge mit personenbezogenen Daten
- passwords, tokens, `.env` files, private keys, wallet keys, and credentials
- production URLs, internal IP ranges, VPN profiles, database exports, or admin portals
- confidential commercial terms that are not needed for this pilot

## Redaction Guidance

- Replace names, email addresses, ticket numbers, customer names, and suppliers with
  neutral placeholders such as `[REDACTED_CUSTOMER]`.
- Remove secrets completely; do not mask only the middle characters.
- Remove exploit details, internal hostnames, IP ranges, and production URLs.
- Keep enough generic context to understand the document type and control intent.
- If a document cannot be redacted without losing its meaning, do not include it.

## Suitable Example

A redacted supplier-security questionnaire that mentions review owner, review cadence,
access-control expectations, incident-notification timeline, and evidence links without
real customer names or secrets.

## Unsuitable Example

An incident export containing named affected people, raw log lines, internal IP ranges,
production hostnames, and exploit details.

## File Count And Formats

- Send 3 to 10 documents.
- Preferred formats: `.txt`, `.md`, `.pdf`.
- Do not send archives, databases, spreadsheets, screenshots, email inbox exports, or raw
  log bundles for MVP1.

What AethelGard will do:

- process the documents locally
- extract bounded evidence snippets
- group findings by review category
- flag likely gaps and false-positive risks
- produce JSON and Markdown reports for human review

What AethelGard will not do:

- provide legal advice
- certify NIS-2 compliance
- replace an audit or a qualified reviewer
- upload documents to external APIs or model providers

## Retention And Deletion

Retention is agreed before the run. The default pilot expectation is to keep approved
input samples and generated reports only until the review is complete, then delete them
after written confirmation. A deletion confirmation template is available in
`docs/deletion-confirmation-template.md`.

## What You Get Back

- JSON and Markdown evidence/gap report
- short run summary with processed/failed document counts
- warnings that require human review
- recommended manual checks
- deletion or retention confirmation according to the agreed pilot handling

Please send only documents you are comfortable using for this limited pilot.
