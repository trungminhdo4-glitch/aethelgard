### 2026-07-06 - Pilot-Readiness-Audit + Input-Gate haertet forbidden binaries (Opus 4.8)
| Feld | Wert |
|---|---|
| Agent | Claude Code (Opus 4.8, effort xhigh) |
| Task | Owner-Auftrag: MVP fuer den ersten kontrollierten Pilotkunden absichern (Pilot Safety Pack: pilot_data_gate / trust_bundle_leak_check / claim_disclaimer_gate + Docker/Fresh-Smoke + Runbook). **Ehrlicher Audit ZUERST (Owner-Regel „nicht doppelt bauen"): das MVP ist bereits weitgehend pilot-ready.** Vorhanden + getestet: `redaction_preflight.py` (Input-Secret-/PII-Scan, block-on-high, JSON+MD), `trust_bundle.py` (metadata-only per Konstruktion, Disclaimer, source-outside-output-Guard), `pilot_product.py` (`local_private`/`shareable_redacted`-Trennung, `PRIVATE_PATH_MARKERS`, `OVERCLAIM_MARKERS`, `no_compliance_overclaim`-Check, `purge_workspace`), `support_bundle` (Redaction-Guard), Docker (Dockerfile non-root + compose + `.dockerignore` + `docker_smoke.ps1` + `docker_ml_smoke.ps1` + Runtime-Proof-Verifikation), `check_pilot_readiness.py` (mehrstufiges Gate) + Runbooks (`pilot_support.md`, `demo-script.md`, README-Quickstart). `check_pilot_readiness.py` meldet **PILOT_PUBLIC_DATA_READY** (Top-Tier, 0 failing checks). → **KEINE parallelen Gate-Module gebaut** (waere Duplikat + mypy-strict-Risiko). |
| Commit | dieser Commit. GEAENDERT: `src/aethelgard/redaction_preflight.py` (+forbidden-binary-Klasse), `tests/test_redaction_preflight.py` (+4 Tests). **KEIN Push (Owner-Gate).** |
| Ergebnis | OK — ruff gruen, **mypy strict gruen (39 Dateien)**, Suite **381 passed / 1 opt-in-Skip** (+4; vorher 377), `check_pilot_readiness.py` = **PILOT_PUBLIC_DATA_READY** (unveraendert Top-Tier). **EIN echter, vom Brief benannter Gap geschlossen**: der Brief verlangt, dass „Datenbanken, grosse Binaerdateien, ungepruefte ZIPs/Archive, private keys" als Pilot-Input **blockiert** werden — `redaction_preflight` behandelte `.sqlite`/`.zip`/`.pfx`/`.key` (nicht „secret"-benannt) aber nur als `unsupported`/**low/WARN**, und `run_pilot_product_slice` blockt nur bei `status=="block"` → ein Kunde, der versehentlich eine `customer.sqlite`/`backup.zip`/`server.pfx` in den Input-Ordner legt, waere **durchgelaufen**. Neu: `FORBIDDEN_INPUT_SUFFIXES` (Datenbanken/Archive/Schluessel-/Zertifikatsmaterial) + Nicht-Text-Datei > `MAX_INPUT_FILE_BYTES` (25 MB) → Finding-Typ `forbidden_binary`/high → `status=block` → fail-closed (PilotProductError). Kleine gewoehnliche Nicht-Text-Dateien (Logo/Screenshot) bleiben `unsupported`/low/WARN (unveraendert). Erweitert das **vorhandene** Gate, kein Parallelsystem (Owner-Regel eingehalten). **Bewusst NICHT gemacht**: naive deutsche Claim-Phrasen in `OVERCLAIM_MARKERS` (Substring-Check → False-Positives gegen negierte Disclaimer wie „keine garantierte Compliance"; der vorhandene DISCLAIMER + `no_compliance_overclaim` deckt die Tool-eigenen Outputs bereits ab). **Advisor `unavailable`** (Fable-Classifier-Bug bei Security-Kontext) → Opus-Selbstreview. **Verboten eingehalten**: kein Push/Merge/Rebase/Force, kein `git add .`, keine Secrets/`.env`, keine echten Kundendaten, kein Live-Netzwerk, kein Docker-Rebuild in diesem Job (Runtime-Proof lag bereits vor). OFFEN (Owner, unveraendert): `main`-Fast-Forward hinter `codex/nis2-control-coverage`; kein Remote → Push-Ziel anlegen; TODO_CONTACT ×5 (Legal-Review vor Deploy); Bundle-Backup nach Commit. |

### 2026-07-05 - supplier_risk evidence_basis + timeout-Magic-Number (Cross-Repo-Konsistenz, Opus 4.8)
| Feld | Wert |
|---|---|
| Agent | Claude Code (Opus 4.8) |
| Task | Cross-Repo-Scan-Findings (HOS<->MVP, adversarial verifiziert im Workflow `wooluad0x`), MVP-Seite umgesetzt. **(1) NEU additives Feld `evidence_basis`** in `supplier_risk.build_supplier_risk_report` (+ Markdown-Zeile „Evidence basis"): der `risk_level` (high/medium/low/watch) trug bisher KEIN Evidenzbreite-Signal — ein Supplier mit `criticality="critical"` + leerem Fragebogen bekam Score 75 = „medium" mit derselben Autoritaet wie ein voll belegter Score, und `evidence_gap_count=0` verwechselte „alles beantwortet" mit „nichts bewertet". Neues Label `corroborated`/`partial_evidence`/`criticality_only` (rein additiv, aendert `risk_score`/`risk_level` NICHT — Determinismus-Test bleibt gruen) — spiegelt die Fragilitaets-Labels des Schwester-Moduls HOS `discovery.fragility_of`. **(2) Magic Number** `timeout=10` in `check_pilot_readiness._reports_are_not_staged` → benannte Konstante `GIT_STATUS_TIMEOUT_SECONDS` (war der einzige Subprocess im MVP-Repo ohne benannten Timeout; diagnostics/model_registry nutzen `GIT_COMMAND_TIMEOUT_SECONDS`). **(3) Doku**: stale absolute „18 Commits"-Zahl im 2026-07-04-Eintrag durch `git rev-list`-Verweis ersetzt (real jetzt 19 — die Zahl driftet mit jedem Branch-Commit). |
| Commit | dieser Commit |
| Ergebnis | OK — ruff gruen, mypy strict gruen, Suite **377 passed / 1 opt-in-Skip** (+5 `test_supplier_risk_evidence_basis.py`; vorher 372). Bundle-Backup nach dem Commit empfohlen (Repo hat KEIN Remote). OFFEN (Owner, unveraendert): `main`-Fast-Forward hinter `codex/nis2-control-coverage`; kein Remote → Push-Ziel anlegen; TODO_CONTACT ×5 (Legal-Review vor Deploy). |

### 2026-07-04 - Exit-Code-Konsolidierung + document-ingest CLI-Tests (Fable 5)
| Feld | Wert |
|---|---|
| Agent | Claude Code (Fable 5) |
| Task | Orchestrator-Session: Multi-Agent-Leverage-Scan ueber HOS+Aethelgard, bestaetigte Findings umgesetzt. (1) Exit-Codes 3-7 lebten nur in `cli.py`, Code 8 doppelt definiert (`errors.py:12` + `cli.py:104` ohne Import = stilles Drift-Risiko) — konsolidiert: `EXIT_PREFLIGHT_BLOCKED/REVIEW_APPLY_ERROR/C_SCRM_ERROR/ML_ERROR/DELIVERY_PROFILE_ERROR` neu in `errors.py`, `cli.py` importiert und re-exportiert die bisherigen Alias-Namen (10 Testdateien importieren sie — bleiben stabil). (2) `document-ingest` war der einzige CLI-Subcommand ohne jeden `main()`-Test — `tests/test_cli_document_ingest.py` neu (5 Tests: Happy-Path, fehlender Input Exit 8, `--out`-Sandbox, `--no-local-excerpts`, `--debug`-JSONL). (3) Magic Number `timeout=5` in `diagnostics._git_commit` durch `GIT_COMMAND_TIMEOUT_SECONDS` ersetzt (analog `model_registry.py:16`; Helper bewusst NICHT geteilt — short- vs. voll-Hash + andere Fallbacks). (4) Git-Bundle-Backup erstellt: `D:\backups\agent-git-bundles\aethelgard_20260704_113503_d4aa3f2.bundle` (Repo hat KEIN Remote — einzige externe Sicherung). |
| Commit | siehe git log (dieser Commit) |
| Ergebnis | OK — ruff gruen, mypy strict gruen (39 Dateien), Suite 372/373 (1 opt-in Skip, vorher 367). OFFEN (Owner): (a) `main` liegt hinter `codex/nis2-control-coverage` (exakte Zahl IMMER via `git rev-list --count main..codex/nis2-control-coverage`; Fast-Forward waere `git checkout main && git merge --ff-only codex/nis2-control-coverage` — reversibel, aber Merge-Entscheid liegt beim Owner); (b) kein Remote → Push-Ziel anlegen; (c) TODO_CONTACT in 5 Auslieferungsdateien (Legal-Review vor Deploy). |

### 2026-07-02 - Landingpage Design-Optimierung (A11y + Dark-Mode + Hero-Grid) (Fable 5)
| Feld | Wert |
|---|---|
| Agent | Claude Code (Fable 5) |
| Task | Owner: Aethelgard-Landingpage ansehen, passenden Design-Ansatz waehlen und die ChatGPT-Version optimieren — ohne das Marketing-Claim-Gate zu brechen. |
| Commit | - (uncommittet — Owner-Gate). GEAENDERT: `marketing/landing/index.html`, `marketing/landing/styles.css`. |
| Ergebnis | OK — `scripts/check_marketing_claims.py` weiter **grün** (keine externen URLs/Emails eingefuehrt → gate-safe; System-Fonts, keine Google-Fonts). Design-Skill-Entscheid: direkte Experten-CSS/HTML-Optimierung statt Mockup-/Widget-Skill, weil der Deliverable die DEPLOYBARE Datei ist (ein Widget-Skill erzeugt nur eine Wegwerf-Vorschau). Umgesetzt: **(A11y)** Skip-Link, `:focus-visible`-Ringe, `prefers-reduced-motion`, `color-scheme`-Meta, verbesserter `--muted`-Kontrast. **(Dark-Mode)** volle `prefers-color-scheme: dark`-Palette via reiner Token-Ueberschreibung (Surface/On-Forest/Accent-Band/Topbar-Tokens statt hartkodiertem Weiss). **(Robustheit)** Hero von absolut-ueberlappend (Text-ueber-Karte-Lesbarkeitsrisiko) auf 2-Spalten-Grid (Copy links/Visual rechts, stackt <900px). **(Politur)** Button-/Card-Hover-Transitions, Topbar-Backdrop-Blur, Share-Meta (og/twitter, text-only = gate-safe), Radius-Token-Skala. Strukturell validiert: CSS-Braces 80/80 balanciert, HTML-Tags matchen, `--surface`/Skip-Link/Dark-Media vorhanden. TODO_CONTACT-Platzhalter bewusst belassen (Owner ersetzt vor Deploy). Kein Commit/Push. |

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

Post-commit correction: previous run committed as e17da1c feat: harden paid pilot readiness.

### 2026-06-28 01:52 - Pilot outreach preparation
| Feld | Wert |
|---|---|
| Agent | Codex |
| Task | Outreach-Paket mit Readiness-Doku, ICP-Scoring, Target-Template, E-Mail-Varianten, Follow-ups, Objection Handling, Call-Pack und Dokument-Gate |
| Commit | - |
| Ergebnis | OK: `compileall`, `pytest` (190 passed, 1 skipped opt-in network, 17 subtests), `check_public_fixtures.py`, `check_pilot_readiness.py`, `ruff`, `mypy`, Customer-like Demo/Eval und Outreach-Dokumenttest gruen; kein Push, keine echten Leads, keine privaten Kontakte, keine Secrets |

### 2026-06-28 03:20 - Berlin target research
| Feld | Wert |
|---|---|
| Agent | Codex |
| Task | Berlin/Brandenburg Outreach-Zielliste mit oeffentlichen Firmenquellen, Top-5-Priorisierung, Snippets, Owner-Checkliste und Dokument-Safety-Test |
| Commit | - |
| Ergebnis | OK: `compileall`, `pytest` (197 passed, 1 skipped opt-in network, 17 subtests), `check_public_fixtures.py`, `check_pilot_readiness.py`, `ruff`, `mypy`, Berlin-Research-Dokumenttest und `git diff --check` gruen; kein Push, keine personenbezogenen Leads, keine privaten Kontakte, keine LinkedIn-/Xing-Scrapes |

### 2026-06-28 04:05 - NIS2 control coverage
| Feld | Wert |
|---|---|
| Agent | Codex |
| Task | NIS2 Artikel-21(2)-Coverage-Matrix, erweiterte Evidence-Kategorien, Report-Schema, Tests und Doku |
| Commit | - |
| Ergebnis | OK: `compileall`, `pytest` (200 passed, 1 skipped opt-in network, 17 subtests), `check_public_fixtures.py`, `check_pilot_readiness.py`, `ruff`, `mypy` und `git diff --check` gruen; kein Outreach-Versand, kein Push, keine personenbezogenen Leads, keine Secrets |

### 2026-06-28 05:10 - Controlled first outreach wave
| Feld | Wert |
|---|---|
| Agent | Codex |
| Task | First-Wave-Firmenverifikation, sendefertige Drafts, Outreach-Tracker, Response-/Demo-/Qualification-Runbooks und Safety-Tests |
| Commit | - |
| Ergebnis | DRAFT_READY_BLOCKED_BY_SENDER: Preflight gruen, drei Firmen auf Firmenebene verifiziert, kein Versand ohne freigegebenes Absenderkonto/OWNER_NAME; keine privaten Kontakte, keine LinkedIn-/Xing-Recherche, keine Anhaenge, keine Secrets |

### 2026-06-28 22:48 - Safe pilot-run flow
| Feld | Wert |
|---|---|
| Agent | Codex |
| Task | Redaction-Preflight, `pilot-run` CLI, Review-CSV, Demo-Bundle und Tests |
| Commit | - |
| Ergebnis | OK: `compileall`, `pytest` (219 passed, 1 skipped), `ruff`, `mypy`, Fixture-Safety, Pilot-Readiness und `pilot-run` Demo gruen; kein Outreach, keine externen APIs, keine echten Kundendaten, keine Secrets |

### 2026-06-28 23:20 - Reviewed findings workflow
| Feld | Wert |
|---|---|
| Agent | Codex |
| Task | Stabile Finding-IDs, `review-apply` CLI, reviewed JSON/Markdown/Summary und Review-Workflow-Tests |
| Commit | - |
| Ergebnis | OK: `compileall`, `pytest` (225 passed, 1 skipped, 17 subtests), `ruff`, `mypy`, Fixture-Safety, Pilot-Readiness, `pilot-run`, `review-apply` und `git diff --check` gruen; kein Outreach, keine externen APIs, keine echten Kundendaten, keine Secrets |

### 2026-06-29 02:11 - Technical C-SCRM MVP
| Feld | Wert |
|---|---|
| Agent | Codex |
| Task | Control-Kataloge, Evidence Store, Questionnaire-Drafts mit Review-CSV und deterministischer Supplier-Risk-Score |
| Commit | - |
| Ergebnis | OK: `py_compile`, `pytest` (233 passed, 1 skipped, 17 subtests), `ruff`, `mypy src`, Fixture-Safety und Pilot-Readiness gruen; kein Live-Netzwerk, keine echten Kundendaten, keine Secrets, kein Push |

### 2026-06-29 03:05 - Reviewed evidence bridge
| Feld | Wert |
|---|---|
| Agent | Codex |
| Task | Review von `7fe5673`, C-SCRM-Hardening, Sub-Agent-Regel und Bridge von reviewed Findings in Evidence Store |
| Commit | - |
| Ergebnis | OK: `py_compile`, `pytest` (254 passed, 1 skipped, 17 subtests), `ruff`, `mypy src`, Fixture-Safety, Pilot-Readiness und CLI-Smoke gruen; kein Live-Netzwerk, keine echten Kundendaten, keine Secrets, kein Push |

### 2026-06-29 12:31 - Trust bundle preview workflow
| Feld | Wert |
|---|---|
| Agent | Codex |
| Task | Review von `bd706ec`, E2E-C-SCRM-Workflow, `reviewed`-Status-Kompatibilitaet und metadata-only Trust-Bundle-Preview |
| Commit | - |
| Ergebnis | OK: `py_compile`, `pytest` (261 passed, 1 skipped, 17 subtests), `ruff`, `mypy src`, Fixture-Safety, Pilot-Readiness und `git diff --check` gruen; 2 Read-Only-Sub-Agenten genutzt; kein Live-Netzwerk, keine echten Kundendaten, keine Secrets, kein Push |

### 2026-06-29 18:24 - SBOM and supplier profile contracts
| Feld | Wert |
|---|---|
| Agent | Codex |
| Task | Review von `275eba4`, Trust-Bundle-/Review-Contract-Hardening, CLI-E2E-Smoke, offline SBOM-Inventar und Supplier-Profile-Contract |
| Commit | - |
| Ergebnis | OK: `py_compile`, `pytest` (273 passed, 1 skipped, 17 subtests), `ruff`, `mypy src`, Fixture-Safety, Pilot-Readiness, `git diff --check` und Secret-Wertscan gruen; 2 Read-Only-Sub-Agenten genutzt; kein Live-Netzwerk, keine echten Kundendaten, keine Secrets, kein Push |

### 2026-06-29 20:05 - Offline SBOM demo hardening
| Feld | Wert |
|---|---|
| Agent | Codex |
| Task | Synthetische CycloneDX-Demo-Fixture, SBOM-Negativtests, Supplier-Profile-/Trust-Bundle-Regressionen und README-Demo-Flow |
| Commit | - |
| Ergebnis | OK: `py_compile`, `pytest` (285 passed, 1 skipped, 17 subtests), `ruff`, `mypy src`, Fixture-Safety inkl. Demo-Fixture, Pilot-Readiness, `git diff --check`, `git diff --cached --check` und Secret-Wertscan gruen; 3 Read-Only-Sub-Agenten genutzt; kein Live-Netzwerk, keine echten Kundendaten, keine Secrets |

### 2026-06-30 00:32 - Pilot readiness and Docker local delivery
| Feld | Wert |
|---|---|
| Agent | Codex |
| Task | Review-Metadaten-Sanitization, voller synthetischer `demo-pilot`-Flow, manifest-only Public-Data-Entscheidung, Dockerfile/Compose und statische Delivery-Gates |
| Commit | - |
| Ergebnis | OK: Start-HEAD `1865320ca45835f34b1612004be46eade295884d`; echte Gaps: `reviewer`/`reviewed_at` unsanitized, raw invalid `review_status` in Warnings, kein einzelner Full-Pilot-Flow, keine Docker-Artefakte; umgesetzt mit Tests, `pytest` (297 passed, 1 skipped, 17 subtests), `py_compile`, targeted `ruff`, `mypy src`, `demo-pilot`, Docker-Static-Gate und Pilot-Readiness `PILOT_DOCKER_STATIC_READY_RUNTIME_UNVERIFIED`; Public Data: keine Drittquelle ingested, lokale synthetische SBOM mit SHA256 manifestiert; keine Secrets/PII/.env gelesen oder beruehrt; Docker Runtime-Smoke separat via `scripts/docker_smoke.ps1` |

### 2026-06-30 17:00 - Low-compute ML baselines
| Feld | Wert |
|---|---|
| Agent | Codex |
| Task | Experimentaler lokaler ML-Assistenz-Layer fuer Features, BM25, SimHash, Weak Labels, fallback Doc-Type-Klassifikation, Control-Suggestions, Severity Ranking und Active-Review-Queue |
| Commit | - |
| Ergebnis | OK: Start-HEAD `42e227818059a8e8657169a6305bf34c6aa4cad0`; pure-Python ohne neue Dependencies, sklearn fallbackfaehig und auf diesem System nicht installiert; `pytest` (319 passed, 1 skipped, 17 subtests), `compileall`, `ruff check .`, `mypy src`, Fixture-Safety, Pilot-Readiness `PILOT_PUBLIC_DATA_READY`, `git diff --check` gruen; Beispieloutputs unter `reports/ml/`; keine raw Snippets, privaten Pfade, Secrets, Kundendaten, LLMs, Cloud, Docker-Runtime oder Netzwerk |

### 2026-06-30 18:45 - ML delivery readiness hardening
| Feld | Wert |
|---|---|
| Agent | Codex |
| Task | Docker-ML-Smoke, Release-/Readiness-Gates nach ML-Slice, Consultant-Laptop-Hardening, Delivery-Profil und privacy-safe Learning-Export |
| Commit | - |
| Ergebnis | OK: Start-HEAD `bf86c70fe00dd8b225d13276e347901b75c8e7a6`; umgesetzt ohne neue Dependencies mit `docker_ml_smoke.ps1`, `delivery-profile validate`, redigiertem `ml export-learning-feedback`, deterministischem ML-Metadata-Timestamp und token-freiem fallback Doc-Type-Model-Output; `pytest` (326 passed, 1 skipped, 17 subtests), `compileall`, `ruff`, `mypy src`, Fixture-Safety, Docker-Static-Gate, `docker_smoke`, `docker_ml_smoke`, `consultant_laptop_smoke` und Pilot-Readiness `PILOT_PUBLIC_DATA_READY` gruen; keine echten Kundendaten, Secrets, `.env`, LLMs, Cloud, Push, Merge oder Rebase |

### 2026-07-01 20:12 - Pilot product slice and answer vault
| Feld | Wert |
|---|---|
| Agent | Codex |
| Task | Integrierter lokaler Product-Slice Dokumente -> Evidence -> SQLite Answer Vault -> Questionnaire Draft -> Human Review Queue -> Missing Evidence/HTML Preview |
| Commit | - |
| Ergebnis | OK: Start-HEAD `c92cc79b2fcd34592ce7b7dc6c86cea1fe41adce`; umgesetzt ohne neue Dependencies mit `document-ingest`, `answer-vault`, `pilot-product`, `workspace inspect/purge`, synthetischem Answer-Library-Sample, Readiness-Gates und Tests; `py_compile`, fokussierte Tests (12 passed), `pytest` (335 passed, 1 skipped, 17 subtests), `ruff check .`, `mypy src`, Fixture-Safety und Pilot-Readiness `PILOT_PUBLIC_DATA_READY` gruen; Produkt-Smoke `PILOT_PRODUCT_SLICE_READY`; Docker-Runtime nicht ausgefuehrt (Owner-Gate); keine echten Kundendaten, Secrets, `.env`, LLMs, Cloud, Push, Merge oder Rebase |

### 2026-07-01 21:20 - Pilot product slice stabilization
| Feld | Wert |
|---|---|
| Agent | Codex |
| Task | Diff-Review, minimale Stabilisierung und Commit-Readiness fuer den vorhandenen Product-Slice |
| Commit | - |
| Ergebnis | OK: Start-HEAD `c92cc79b2fcd34592ce7b7dc6c86cea1fe41adce`; fixte projektgebundene `answer-vault --db`-Pfade, Custom-DB-Readiness und explizite HTML-Disclaimer (`local triage`, `human review required`, `no compliance guarantee`); `py_compile`, fokussierte Product-Slice-Tests (11 passed), `pytest -q` (337 passed, 1 skipped), `ruff check .`, `mypy src`, Fixture-Safety, Pilot-Readiness und Product-Smoke `PILOT_PRODUCT_SLICE_READY` gruen; Output-Validierung bestaetigt CSV/JSON/SQLite, stabile Evidence-IDs und keine Shareable-Leakage-Marker; kein Docker, Push, Merge, Rebase, `.env`, Secrets, echte Kundendaten, LLMs, Cloud oder Netzwerk |

### 2026-07-01 22:35 - Pilot demo marketing pack
| Feld | Wert |
|---|---|
| Agent | Codex |
| Task | Statische Landingpage, Demo-Video-Script, Outreach-Pack, Pilot-Quickstart und Marketing-Claim-Gate fuer den redacted Pilot-Demo-Flow |
| Commit | - |
| Ergebnis | OK: Start-HEAD `20fe2fd72233b723cedfd74dc29b06cbfe4089b3`; umgesetzt ohne neue Dependencies, SaaS, externe APIs, Docker-Runtime, echte Kundendaten, Secrets oder private Outputs; `pytest -q` (341 passed, 1 skipped, 17 subtests), `ruff check .`, `mypy src`, Fixture-Safety, Marketing-Claim-Gate, Docker-Static-Gate, Pilot-Readiness `PILOT_PUBLIC_DATA_READY` und redacted Product-Smoke `PILOT_PRODUCT_SLICE_READY` gruen; direkter `python -m aethelgard.cli ...` Systemlauf scheiterte wegen nicht installiertem Package und wurde mit `.venv-fresh` erfolgreich wiederholt |

### 2026-07-01 23:45 - Local diagnostics support bundle
| Feld | Wert |
|---|---|
| Agent | Codex |
| Task | Lokale Diagnose-/Support-Schicht fuer Pilotkunden: Doctor, redacted Support Bundle, Debug-JSONL, Error-Taxonomie, Privacy Guard und Support-Doku |
| Commit | - |
| Ergebnis | OK: Start-HEAD `ea6c8cce7873c9f246957a91234bd696b936965a`; umgesetzt ohne neue Dependencies, Telemetrie, Cloud-Monitoring, externe Error-Tracker, Docker-Runtime, echte Kundendaten, Secrets oder private Bundle-Inhalte; `py_compile`, fokussierte Tests (12 passed), `pytest -q` (347 passed, 1 skipped, 17 subtests), `ruff check .`, `mypy src`, Fixture-Safety, Marketing-Claim-Gate, Docker-Static-Gate, Pilot-Readiness `PILOT_PUBLIC_DATA_READY`, `pilot-product --debug`, `doctor` und `support-bundle --redacted` gruen; kein Push, Merge oder Rebase |
