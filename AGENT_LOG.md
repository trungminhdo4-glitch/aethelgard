### 2026-06-27 02:53 - Pilot-readiness hardening
| Feld | Wert |
|---|---|
| Agent | Codex |
| Task | AethelGard Kontext-Audit, kleine Parser-/Test-Gate-Fixes, README und Pilot-Dokumentation |
| Commit | - |
| Ergebnis | OK: `compileall`, `pytest` (157 passed), TOML-Parse und Smoke-Test gruen; Ruff/Mypy nicht installiert; keine Secrets, APIs, Services oder Commits |

### 2026-06-27 23:05 - Public NIS2 evaluation demo
| Feld | Wert |
|---|---|
| Agent | Codex |
| Task | Demo-/Eval-CLI, synthetische NIS2-Fixtures, Golden Labels, Report-Schema, Fixture-Safety-Gate |
| Commit | - |
| Ergebnis | OK: `compileall`, `pytest` (167 passed), `triage`, `eval`, `check_public_fixtures.py`, Fresh-Venv, `ruff` und `mypy` gruen; Git-Commit noch ausstehend |

### 2026-06-28 00:40 - Paid-pilot hardening
| Feld | Wert |
|---|---|
| Agent | Codex |
| Task | Audit-Ledger, Paid-Pilot-Datenpaket, Human-Review, Real-Docs-Manifest, adversarial Fixtures, Report-Handover und Readiness-Gate |
| Commit | - |
| Ergebnis | OK: `compileall`, `pytest` (176 passed, 1 skipped opt-in network, 17 subtests), `check_public_fixtures.py` (18 files), opt-in public URL check, `ruff`, `mypy`, `triage --audit`, `eval --audit` und `check_pilot_readiness.py` gruen; kein Push, keine fremden Dokumente oder Secrets |
