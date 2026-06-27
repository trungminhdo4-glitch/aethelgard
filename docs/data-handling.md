# AethelGard Data Handling Boundaries

## Allowed For Public Evaluation

- Synthetic documents written for this repository.
- Public reference URLs used only as source-manifest links.
- Example domains such as `example.invalid`.
- Documentation-only IP ranges such as `192.0.2.0/24`.

## Not Allowed In Repository Fixtures

- Customer documents.
- Secrets, API keys, tokens, cookies, `.env` files, private keys, or credentials.
- Private databases, raw logs, support exports, or production telemetry.
- Real personal data, phone numbers, emails outside `example.com` / `example.invalid`.
- Third-party PDFs or copied long source text unless redistribution is explicitly cleared.

## Pilot Data Rule

External pilot data must be owner-approved and non-sensitive by default. If a customer wants
real documents processed, agree on scope, retention, deletion, and human review
responsibilities before ingestion.

## Processing Model

The MVP1 CLI runs locally and does not call external APIs. Reports are written to a local
output directory chosen by the operator. `reports/` is ignored by Git.
