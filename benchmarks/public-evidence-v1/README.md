# Public Evidence Benchmark v1

This offline benchmark contains ten small, project-created lab records and twenty
provisional reference cases. No third-party document, ISO standard text, customer data,
personal data, credential, database, or live log is included.

The files cover TXT, Markdown, CSV, and JSON/CycloneDX parsing. Cases include positive,
partial, ambiguous, stale, irrelevant, and explicit no-evidence examples. The reference
labels are `provisional_internal_reference`; they are an internal engineering fixture,
not a qualified NIS-2/ISO opinion or independently validated gold standard.

Run from the repository root:

```powershell
python -m aethelgard.cli benchmark run `
  --dataset benchmarks/public-evidence-v1 `
  --offline --deterministic `
  --tenant-id public-lab `
  --actor-id local-operator `
  --role operator `
  --out reports/public-evidence-v1
```

The run creates deterministic analysis and benchmark reports, a pending review template,
and a hash-chained metadata-only audit ledger. Review and export are separate CLI phases;
export fails closed until every finding has an explicit human-confirmed decision.

This is an owner-controlled, single-user CLI workflow. Tenant IDs, actor IDs, and roles
are mandatory audit assertions supplied by the trusted local operator; they are not
authentication, authorization, or OS-enforced multi-user tenant isolation. Distinct
operator/reviewer/auditor values prevent accidental workflow reuse, but an independent
human process and a controlled workstation are still required.

## External review handoff

An independent reviewer should inspect `expected/cases.json`, replace the provisional
review identity/status and timestamp, optionally add a second review, and record any
changed rationale. Owner approval is required before publishing this dataset.

## Licensing boundary

All vendored artifacts were created for this repository and are registered in
`licenses/source_register.csv`. Public sources with unclear reuse rights must remain
URL-and-metadata-only and are blocked from local benchmark ingestion until owner/legal review.
