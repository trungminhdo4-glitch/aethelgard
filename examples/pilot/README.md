# AethelGard Local Pilot Demo Pack

This pack contains synthetic, non-customer demo inputs for the full local pilot flow.

Files:

- `documents/`: invented security-policy snippets for local triage.
- `questionnaire_demo.csv`: synthetic supplier-security questions.
- `supplier_profile_demo.json`: synthetic supplier-risk profile.
- `supplier_profile_contract_demo.json`: metadata-only supplier contract example.
- `sbom/cyclonedx_demo.json`: synthetic CycloneDX SBOM for offline metadata-gap checks.
- `public_data_manifest.json`: records that no third-party public data was ingested.

The demo pack is for offline CLI validation only. It is not a compliance certification,
not an audit, and not legal advice.

## Pilot Product Demo

Use this command to rebuild the redacted demo outputs for screenshots, a short product
video, or a local walkthrough:

```powershell
python -m aethelgard.cli pilot-product --workspace examples/pilot --out reports/pilot-product-demo --client-id demo-client --case-id case001
```

Expected shareable outputs:

- `reports/pilot-product-demo/shareable_redacted/coverage_report.html`
- `reports/pilot-product-demo/shareable_redacted/questionnaire_draft.csv`
- `reports/pilot-product-demo/shareable_redacted/case_review_queue.csv`
- `reports/pilot-product-demo/shareable_redacted/missing_evidence.csv`
- `reports/pilot-product-demo/shareable_redacted/pilot_readiness_report.json`

The demo shows three synthetic documents analyzed, evidence candidates found,
questionnaire drafts generated, open review items routed into the review queue, and
missing evidence made visible. Generated `reports/` outputs, SQLite files, and
`local_private` contents stay uncommitted.
