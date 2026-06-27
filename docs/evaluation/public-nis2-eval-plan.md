# Public Synthetic NIS2 Evaluation Plan

## Purpose

This evaluation package demonstrates that AethelGard can run a local evidence-triage
workflow without customer data. It uses only synthetic documents written for this project
and public reference frameworks as category inspiration.

## Scope

- Input: synthetic Markdown fixtures in `tests/fixtures/public_nis2/`.
- Processing: `python -m aethelgard.cli triage`.
- Evaluation: `python -m aethelgard.cli eval`.
- Outputs: JSON and Markdown reports under a caller-provided `reports/` path.
- Claim boundary: evidence triage for human pre-review only.

## Categories

- `risk_management`
- `incident_reporting`
- `business_continuity`
- `supplier_security`
- `access_control`
- `vulnerability_management`

## Pilot Readiness Thresholds

- 0 parser crashes.
- 100% fixture documents processed.
- Category hit rate >= 80%.
- 0 strong evidence from `misleading_security_marketing.md`.
- Gap fixtures produce no strong evidence or produce clear warnings.

## Commands

```powershell
python -m aethelgard.cli triage --input tests/fixtures/public_nis2 --out reports/demo
python -m aethelgard.cli eval --fixtures tests/fixtures/public_nis2 --labels tests/fixtures/public_nis2/golden_labels.json --out reports/eval
python scripts/check_public_fixtures.py
```

## Non-Goals

- No legal advice.
- No certification claim.
- No real customer data.
- No external API calls.
- No downloaded or committed third-party PDFs.
