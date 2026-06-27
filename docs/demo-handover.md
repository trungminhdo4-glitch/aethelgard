# Demo Handover

## Demo Commands

```powershell
python -m aethelgard.cli triage --input tests/fixtures/customer_like_nis2 --out reports/demo-customer-like --audit
python -m aethelgard.cli eval --fixtures tests/fixtures/customer_like_nis2 --labels tests/fixtures/customer_like_nis2/golden_labels.json --out reports/eval-customer-like --audit
```

## Outputs

- `reports/demo-customer-like/evidence_report.md`
- `reports/demo-customer-like/evidence_report.json`
- `reports/eval-customer-like/eval_report.md`
- `reports/eval-customer-like/eval_report.json`
- `reports/eval-customer-like/calibration_report.md`
- `reports/eval-customer-like/calibration_report.json`
- `reports/audit/aethelgard_runs.jsonl`

## How to Read the Report

- Start with parsed documents, parser failures, and evidence count.
- Show strong categories only as triage candidates.
- Use warnings to explain why human review is mandatory.
- Use calibration indicators to discuss false-positive and false-negative risks.

## What to Show a Pilot Partner

- The synthetic customer-like sample pack structure.
- A Markdown evidence report with bounded snippets.
- The calibration report and warning list.
- The human-review checklist and data-handling boundaries.

## What Not to Claim

- Do not claim NIS-2 compliance.
- Do not claim legal advice.
- Do not claim audit opinion or certification.
- Do not claim the heuristic replaces consultant review.
