# AethelGard

AethelGard MVP1 is a local-first Python package for Security/NIS-2 evidence triage.
It finds configured evidence keywords in text/PDF documents, extracts bounded citations,
classifies them with deterministic heuristics, and writes JSON/Markdown reports.

It is not a compliance certification tool, not legal advice, not a SaaS platform, and not
a final NIS-2 compliance decision. The narrow product claim is: AethelGard supports fast
human pre-review of security documentation through local evidence triage.

## Current Capabilities

- Local text parsing with bounded file and text-size limits.
- Optional PDF page streaming through `pypdf`.
- Lazy chunk extraction with generator-based APIs.
- Deterministic heuristic classification with no external model calls.
- Public synthetic NIS-2 fixture corpus with golden labels.
- Demo CLI for JSON/Markdown evidence reports.
- Evaluation CLI with pilot-readiness thresholds.
- Static fixture safety check for secrets, PII, domains, IPs, and phone-like values.

## Install

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -e ".[all]"
```

## Validate

```powershell
$env:PYTEST_DISABLE_PLUGIN_AUTOLOAD = "1"
$env:PYTHONPATH = "D:\projects\aethelgard\src"
python -m compileall -q src tests scripts
python -m pytest -q
python scripts/check_public_fixtures.py
```

## Demo Command

```powershell
python -m aethelgard.cli triage --input tests/fixtures/public_nis2 --out reports/demo
```

Outputs:

- `reports/demo/evidence_report.json`
- `reports/demo/evidence_report.md`
- `reports/demo/run_summary.json`

Current synthetic demo summary:

- documents discovered: 12
- documents parsed: 12
- parser failures: 0
- evidence items: 56
- exit code: 0

## Evaluation Command

```powershell
python -m aethelgard.cli eval --fixtures tests/fixtures/public_nis2 --labels tests/fixtures/public_nis2/golden_labels.json --out reports/eval
```

Outputs:

- `reports/eval/eval_report.json`
- `reports/eval/eval_report.md`

Current synthetic evaluation result:

- status: `PILOT_READY`
- documents passed: 12/12
- parser failures: 0
- category hit rate: 1.0
- false positives: 0
- false negatives: 0

Exit codes:

- `0`: command succeeded; evaluation also meets thresholds for `eval`.
- `1`: technical failure.
- `2`: evaluation completed but did not meet pilot-readiness thresholds.

## Minimal Python Usage

```python
from aethelgard.mvp1 import LocalDocumentParser

parser = LocalDocumentParser(
    keywords=("risk assessment", "incident response", "audit"),
    requirement_map={"risk assessment": "risk_management"},
)

for evidence in parser.parse_text("Our risk assessment process is documented and audited."):
    print(evidence.requirement_id, evidence.confidence_score, evidence.is_compliant)
```

## Security Boundaries

- Do not use real customer data in the public fixture corpus.
- Do not include secrets, `.env` files, logs, cookies, tokens, private databases, or raw
  production data.
- Do not commit third-party PDFs unless licensing and redistribution are explicitly clear.
- Reports are written to `reports/`, which is ignored by Git.

## Pilot Status

AethelGard is now `PILOT_READY` for an internal/friendly synthetic pilot. It is still
`ALMOST_READY` for a paid pilot because real customer onboarding, data-handling terms,
and human review workflow still need validation.
