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

Please remove before sending:

- passwords, API keys, tokens, `.env` files, private keys, and credentials
- personal data where avoidable
- real incident details naming affected people, customers, or suppliers
- production URLs, internal IP ranges, network diagrams, raw logs, and database exports
- confidential commercial terms that are not needed for this pilot

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

Please send only documents you are comfortable using for this limited pilot.
