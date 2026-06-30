# Pilot Outreach Readiness

## What A Pilot Customer Gets

- Local `demo-pilot` or owner-approved `pilot-run` execution.
- Evidence report, human-review CSV, reviewed report, and metadata-only evidence store.
- Questionnaire summary, supplier-risk summary, SBOM metadata-gap report, and trust
  bundle preview.
- Public-data validation report for the minimized CISA KEV and CycloneDX fixtures when
  no customer data is used.

## Inputs Needed

- 3 to 10 redacted, non-sensitive security documents.
- Optional CycloneDX SBOM if the supplier wants software-component metadata checked.
- Supplier profile metadata without personal contacts, secrets, logs, or private paths.
- Owner-approved retention and deletion decision before any real customer document is
  accepted.

## Outputs

- JSON and Markdown reports under `reports/`.
- Review CSVs for human decisions.
- Metadata-only trust-bundle preview.
- No raw customer snippets in trust-bundle outputs.

## Local Data Boundary

- Processing stays on the owner or consultant laptop.
- Docker delivery uses read-only input mounts and writable `reports/` output mounts.
- Default demo commands do not require network access.
- Public fixtures are small, committed, hashed, and offline-testable.

## Non-Promises

- No legal advice.
- No audit opinion.
- No certification.
- No automatic NIS-2 conformity.
- No SaaS or managed hosting in MVP1.
- No live external API, CVE-feed, or model call in the normal pilot path.
