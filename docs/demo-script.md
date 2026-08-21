# Fifteen Minute Demo Script

## Demo Flow

1. Problem: first-pass evidence review is slow and repetitive.
2. Boundary: AethelGard is local evidence triage, not legal advice, not an audit, and not
   certification.
3. Sample pack: show `tests/fixtures/customer_like_nis2/` as synthetic, non-customer
   data.
4. CLI run: execute `triage` against the sample pack.
5. Report: show Markdown/JSON outputs, bounded snippets, warnings, and gaps.
6. Human review: show `docs/human-review-checklist.md`.
7. Data handling: show allowed inputs, exclusions, retention, and deletion flow.
8. Pilot scope: show `docs/pilot-scope.md`.
9. CTA: ask for a redacted, non-sensitive sample pack for a small controlled pilot.

## Commands

```powershell
$env:PYTHONPATH = (Resolve-Path .\src).Path
python -m aethelgard.cli triage --input tests/fixtures/customer_like_nis2 --out reports/outreach-demo --audit
python -m aethelgard.cli eval --fixtures tests/fixtures/customer_like_nis2 --labels tests/fixtures/customer_like_nis2/golden_labels.json --out reports/outreach-eval --audit
```

## What To Say

- "This is a preparation aid for human review."
- "Warnings are useful because they show where a reviewer should be careful."
- "The pilot succeeds if the first sorting step becomes faster and clearer."

## What Not To Say

- "This makes you NIS-2 compliant."
- "This replaces a reviewer."
- "This is audit-ready."
- "Send us production logs or incident files."
