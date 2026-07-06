# AGENTS.md — AethelGard MVP1

> AethelGard ist eine B2B-Plattform fuer Lieferkettensicherheit (NIS-2 Compliance).
> **MVP1** ist der erste lauffaehige Inkrement: lokale Extraktion von
> Compliance-Evidenzen aus Text-Dokumenten.

## Pflichtregeln (single source of truth)

- Globale Regeln: `D:\conventions.md`
- Workspace-Index: `D:\AGENTS.md`
- Bei Unklarheiten: `D:\conventions.md` VOR jeder Aenderung lesen.

## Rolle dieser Datei

Projektlokale AGENTS.md fuer AethelGard MVP1. Definiert:
- Startbefehl und Tests
- Modulgrenzen und Layer-Aufteilung
- Bekannte Gotchas und Constraints
- Performance-Ziele (16 GB RAM Workstation)

## Quick-Start

```powershell
# Venv anlegen (einmalig)
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -e ".[all]"   # inkl. pypdf + dev tools

# Oder nur Dev-Tools (pypdf bleibt optional)
pip install -e ".[dev]"

# Tests
$env:PYTEST_DISABLE_PLUGIN_AUTOLOAD = "1"
$env:PYTHONPATH = "D:\projects\aethelgard\src"
python -m pytest tests/ -v
```

**Voraussetzungen**: Python 3.11+, pydantic >=2.5, pytest >=7.4.
Auf diesem Workspace laeuft Python 3.12.6 mit pydantic 2.13.4 — kompatibel.

**Optional**: `pypdf == 6.14.2` (fuer PDF-Support). Install via
`pip install pypdf==6.14.2` oder `pip install aethelgard[pdf]`.

## Architektur

```
src/aethelgard/
  __init__.py              # Package-Marker, __version__
  nis2_controls.py         # NIS2 Artikel-21(2)-Coverage-Referenzen + Report-Matrix
  control_catalog.py       # C-SCRM Control-Catalog-Loader + Cross-Map-Validator
  evidence_store.py        # Metadata-only Evidence Store, SHA-256, Secret-Path-Guards
  evidence_bridge.py       # Reviewed Findings -> Evidence Store Bridge
  questionnaire.py         # CSV-Frageimport, Frage->Controls, Evidence-basierte Drafts
  document_ingest.py       # Multi-Format Document Inventory, DOCX/CSV/JSON, OCR-needed Status
  answer_vault.py          # Lokaler SQLite Client Profile / Answer Vault + Draft-Reuse
  pilot_product.py         # Integrierter Pilot Product Slice + Shareable/Private Output-Split
  supplier_risk.py         # Deterministischer Supplier-Risk-Score + JSON/MD-Report (+ evidence_basis: corroborated/partial_evidence/criticality_only, rein additiv)
  trust_bundle.py          # Metadata-only Trust-Bundle-Preview-Export
  sbom.py                  # Offline CycloneDX-SBOM-Inventar + Metadata-Gap-Findings
  supplier_profile.py      # Supplier-Cascade-Profilvertrag + Validator
  delivery_profile.py      # Lokales Delivery-/White-Label-Profil, metadata-only, keine PII
  errors.py                # Stabile lokale Error-Taxonomie + Exit-Code-Mapping
  diagnostics.py           # Doctor, JSONL-Debug-Logs, redacted Support-Bundle, Privacy Guard
  ml_baselines/            # Low-Compute-ML-Baselines, lokal, deterministisch, review-only
    __init__.py
    features.py            # Metadata-only Feature JSONL, Text-Hash statt Snippets
    bm25.py                # BM25-Suche ohne Embeddings, Output nur IDs/Scores/Reasons
    simhash.py             # SimHash-Nahe-Dubletten, Review-Paare ohne Rohtext
    doc_classifier.py      # Fallback Dokumenttyp-Klassifikation ohne harte sklearn-Dependency
    control_mapper.py      # Regelbasierte Multi-Label-Control-Vorschlaege, nie auto-fulfilled
    severity.py            # Prioritaets-/Evidence-Quality-Vorschlaege aus Features
    active_learning.py     # Unsicherheits-/Konflikt-Review-Queue
    weak_labels.py         # Schwache Labels aus transparenten Keyword-Regeln
    model_registry.py      # Modell-/Feature-Metadaten fuer ML-Ausgaben
    learning_export.py     # Redigierter Review-/Learning-Signal-Export, owner-gated
  mvp1/
    __init__.py            # Public API Re-Exports (Schemas + Parser + PDF + Classifier)
    schemas.py             # pydantic v2 Schemas (ComplianceEvidence)
    document_parser.py     # Parser (OOP + Functional), Text + PDF-Dispatch, parse_and_classify
    pdf_handler.py         # PDF Page-Streaming (optional pypdf)
    classifier.py          # Klassifikations-Engine (deterministische Heuristik)
  audit.py                 # Append-only JSONL Run-Ledger (Metadaten, keine Inhalte)
  cli.py                   # CLI: triage + eval + pilot-run + demo-pilot + review-apply + C-SCRM + trust-bundle + SBOM
  public_sources.py        # Pure URL-Check-Klassifikation fuer offizielle Quellen
  redaction_preflight.py   # Lokaler Sensitive-Content-Preflight mit Maskierung; forbidden_binary (DB/Archiv/Key/>25MB) = block
  review.py                # Human-Review-Import, reviewed reports, review summary
  triage.py                # Report-, Quality-, Calibration- und Evaluations-Engine
data/control_catalogs/
  nis2_supply_chain_controls.json # lokaler NIS2 C-SCRM-Control-Katalog
  din_spec_27076_light.json       # leichter DIN-SPEC-27076-Katalog
  cross_framework_map.json        # lokale Cross-Framework-Referenzen
README.md                  # Nutzer-Quickstart und Produktkern
docs/
  data-handling.md         # Daten-/Privacy-Grenzen fuer Fixtures und Pilot
  sample-data-request.md   # Kundentext fuer nicht-sensitive Pilot-Samples
  deletion-confirmation-template.md # Loeschbestaetigung fuer Pilotdaten
  human-review-checklist.md # Pflicht-Review vor Kundenhandover
  report-schema.md         # JSON-Report-Felder und Semantik
  risk-register.md         # Pilot-Ops-Risikoregister mit Fix/Alternative
  legal-review-checklist.md # Legal/Privacy Review-Gates, keine Rechtsberatung
  backup-restore.md        # Lokale Git-Bundle-Backup/Restore-Anleitung
  demo-handover.md         # Demo-Outputs und Kundenhandover-Grenzen
  demo-script.md           # 15-Minuten Demo-Ablauf
  pilot-call-agenda.md     # 30-Minuten Pilot-Call-Struktur
  paid-pilot-readiness.md  # Go/No-Go-Gates fuer kontrollierten Paid Pilot
  product-positioning.md   # Verifizierte Produktpositionierung / Pilot-ICP
  pilot-readiness.md       # Pilot-Readiness-Gaps und P0-Schritte
  pilot-onepager.md        # Kundennaher Pilot-Zuschnitt
  pilot-email.md           # Outreach-Varianten fuer MSP/KMU
  follow-up-sequence.md    # Vorsichtige 3/7/14-Werktage Follow-up-Sequenz
  icp-scoring.md           # Zielkunden-Scoring fuer erste Outreach-Welle
  objection-handling.md    # Kurze Pilot-Einwandbehandlung ohne Hype
  outreach-readiness.md    # Outreach-Gates, Claims und Demo-Run-Zusammenfassung
  outreach-target-list-template.csv # Company-level CRM-/Tracking-Template
  pilot-scope.md           # In/Out of Scope, Inputs, Done/Stop Criteria
  target-selection-guide.md # Manuelle Zielauswahl ohne private Lead-Daten
  pilot-call-notes-template.md # Call-Notes und Go/No-Go-Erfassung
  pilot_delivery_security.md # Delivery-Optionen, Source-Sichtbarkeit und Pilot-1-Empfehlung
  pilot_license_notice.md  # Technische Pilot-Notice, keine Rechtsberatung
  evaluation/              # Public/Synthetic Eval-Plan, Quellenmanifest, Labeling
  research/                 # Berlin-Recherche, First-Wave-Drafts, Tracker, Response-/Demo-Runbooks
scripts/
  check_public_fixtures.py # statischer Fixture Safety Gate
  check_pilot_readiness.py # kontrollierter Paid-Pilot Gate-Report
  check_docker_delivery.py # statischer Docker-Delivery-Gate
  check_marketing_claims.py # statischer Marketing-Claim-/Kontakt-Safety-Gate
  build_pilot_artifact.py  # begrenztes Pilot-Artefakt unter dist/, kein Repo-Root-Copy
  check_delivery_artifact.py # Scanner fuer Delivery-Artefakt-Safety und Source-Claims
  docker_ml_smoke.ps1      # opt-in Docker-Runtime-Smoke fuer ML-CLI unter --network none
examples/pilot/            # synthetischer lokaler End-to-End-Pilot-Pack
examples/delivery_profile/ # synthetisches Berater-/Delivery-Profil ohne echte Kontaktdaten
marketing/                 # statische Landingpage, Demo-Video-Script, Outreach-Pack
Dockerfile                 # lokale CLI-Auslieferung, non-root, keine Reports/Caches im Image
compose.yaml               # Offline-Demo-Service mit examples read-only und reports writable
tests/fixtures/public_nis2/ # 17 synthetische Fixtures + golden_labels.json
tests/fixtures/customer_like_nis2/ # 8 customer-like synthetische Fixtures + Labels
tests/test_evidence_bridge.py # Reviewed Findings -> Evidence Store Bridge
tests/mvp1/
  test_document_parser.py  # 69 Unit-Tests, vollstaendig gemockt
  test_pdf_handler.py      # 40 Unit-Tests, pypdf gemockt
  test_classifier.py       # 48 Unit-Tests, Heuristik + Pipeline-Integration
```

### Modulgrenzen

| Modul | Verantwortung | Darf NICHT |
|---|---|---|
| `schemas.py` | Datenvertraege (pydantic v2) | IO, Parsing, Business-Logik |
| `document_parser.py` | Text-Extraktion, Chunking, PDF-Dispatch | Netzwerk, NLP-Frameworks, schwere Dependencies |
| `pdf_handler.py` | PDF Page-Streaming, Custom PDF-Exceptions | pypdf-Internals leaken, vollstaendige PDF-Inhalte laden |
| `classifier.py` | Deterministische Heuristik, Compliance-Mapping | Mutationen, IO, externe Modelle (Stufe 1 rein Python, Stufe 2 ONNX-prep) |
| `control_catalog.py` | Lokale Control-Kataloge und Cross-Map-Validierung | Rechts-/Audit-Claims, externe Quellen zur Laufzeit |
| `evidence_store.py` | Metadata-only Evidence Records, Hashes, Control-Refs | Rohdaten/Secrets in Reports ausgeben |
| `evidence_bridge.py` | Reviewte Findings als Evidence-Metadaten exportieren | Rohzitate, private Pfade, nicht-akzeptierte Findings uebernehmen |
| `questionnaire.py` | CSV-Fragen, heuristisches Control-Mapping, Evidence-Drafts | Antworten ohne Evidence erzeugen |
| `document_ingest.py` | Lokale Dokument-Inventarisierung, Text/MD/CSV/JSON/DOCX/PDF-Parsing, OCR-needed/unsupported Status, stabile Evidence-IDs | OCR halluzinieren, Secrets lesen, Unsupported-Dateien crashen lassen |
| `answer_vault.py` | SQLite Answer Vault, idempotentes Schema, reviewed Answer-Reuse, Case Review Queue | Antworten ohne Review/Evidence finalisieren, globale versteckte DB nutzen, destruktive Migration |
| `pilot_product.py` | Produkt-Slice Dokumente -> Evidence -> Answer Vault -> Questionnaire Draft -> Review/Gaps/HTML | SaaS/UI-Plattform bauen, rohe Snippets in shareable Outputs exportieren, Compliance-Garantie behaupten |
| `supplier_risk.py` | Deterministischer Supplier-Risk-Score | Finanz-/Compliance-Beratung, Live-Daten |
| `trust_bundle.py` | Deterministischer metadata-only Bundle-Preview | Rohzitate, Draft-Antworten, private Pfade, Compliance-Claims exportieren |
| `sbom.py` | Offline CycloneDX-Komponenten-Inventar und lokale Metadata-Gap-Findings | CVE/API/Netzwerk-Abfragen, rohe SBOM-Felder, SPDX-Halbsupport |
| `supplier_profile.py` | Supplier-Cascade-Contract mit Referenzen zu Evidence/Questionnaire/SBOM/Risk | Raw Notes, private Pfade, unbekannte Felder, Compliance-Claims |
| `delivery_profile.py` | Lokales Consultant-/Delivery-Profil normalisieren | Echte Kontakte/PII, Secrets, private Pfade, Safety-Overrides |
| `ml_baselines/*` | Lokale Low-Compute-Such-/Label-/Dedupe-/Priorisierungs-Vorschlaege | LLMs, Embeddings, Cloud, Kundendaten im Repo, Auto-Compliance, Review-Status ueberschreiben |
| `ml_baselines/learning_export.py` | Redigierte Review-/Learning-Signale als lokale Datei | Raw Text, Dateinamen/Pfade, Freitext-Notizen, Upload, Training, nicht-allowlistete Labels |

### Sub-Agent-Regel

- Standard: Hauptagent arbeitet selbst und bleibt fuer Integration, Git und Validierung verantwortlich.
- Sub-Agenten sind erlaubt, wenn sie den Hauptagenten messbar entlasten oder unabhaengige Pruefung liefern.
- Sub-Agenten nur fuer klar abgegrenzte Read-Only-Aufgaben wie Testluecken suchen, Code-Review,
  Mapping-Konsistenz oder Security-Fixture-Scan.
- Maximal 2 Sub-Agenten pro Run, ausser der Nutzer erlaubt explizit mehr.
- Keine Sub-Agenten fuer Git-Write-Aktionen, Commits, Pushes, Secrets, private Rohdaten, Cookies,
  Datenbanken, Logs oder Live-Netzwerk.
- Jeder Sub-Agent bekommt Scope, verbotene Bereiche und Output-Limit.
- Wenn Sub-Agenten nicht verfuegbar sind oder haengen, uebernimmt der Hauptagent die Rolle selbst und
  dokumentiert kurz.
- Sub-Agenten duerfen keine Owner-Gates ueberschreiben.

### Public-/Demo-Data-Regel

- Beispiel- und Public-Data-Fixtures duerfen keine PII, privaten Pfade, Secrets,
  Cookies, Datenbanken, Logs oder echte Kundendaten enthalten.
- Oeffentliche Drittdateien werden nicht blind committet. Falls sie genutzt werden,
  braucht jede Fixture Quelle, Abrufdatum, Lizenz-/Terms-Hinweis soweit auffindbar
  und SHA256; Tests muessen offline laufen.
- `examples/pilot/public_data_manifest.json` dokumentiert bewusst, wenn keine
  Drittquelle ingested wurde.
- Docker-Kontext muss `.env*`, `.git`, `reports/`, venvs, Caches, Logs, DBs und
  Research-/Outreach-Rohmaterial ausschliessen.

### Public API

```python
from aethelgard.mvp1 import (
    # Schema
    ComplianceEvidence,        # pydantic v2
    # Parser
    LocalDocumentParser,       # OOP-Wrapper
    functional_chunk_extractor, # Pure functional pipeline
    # PDF
    stream_pdf_pages,          # Generator: lazy page-by-page
    extract_pdf_text,          # Convenience: joined text
    is_pypdf_available,        # Feature-Detection
    # Classifier
    compute_heuristic_score,   # Pure: base + boosts - penalties, clamped
    evaluate_chunk,            # Mappt chunk -> ComplianceEvidence
    # Constants
    DEFAULT_CHUNK_RADIUS,      # 200
    DEFAULT_MIN_CONFIDENCE,    # 0.5
    MAX_PDF_PAGES,             # 10_000
    PDF_EXTENSION,             # ".pdf"
    DEFAULT_PAGE_SEPARATOR,    # "\n\n"
    BASE_SCORE,                # 0.5
    BOOST_DELTA,               # 0.05
    BOOST_CAP,                 # 0.2
    PENALTY_DELTA,             # 0.1
    PENALTY_CAP,               # 0.3
    SCORE_MIN, SCORE_MAX,      # 0.0, 1.0
    COMPLIANCE_THRESHOLD,      # 0.7
    BOOST_TERMS, PENALTY_TERMS, CRITICAL_PENALTY_TERMS,  # frozenset
    # Exceptions
    DocumentParserError,       # Base
    EmptyDocumentError,
    EncodingError,
    FileSizeLimitExceededError,
    ClassifierError,           # Schritt 3
    PdfParseError,             # PDF-Base
    EncryptedPdfError,
    CorruptPdfError,
    PdfDependencyMissingError,
)
```

## Konventionen (projektlokal)

### Typsicherheit
- **Strict-Mode**: mypy `strict = true` ist in `pyproject.toml` aktiv
- **Kein `any`**: Typen muessen explizit sein
- Pydantic v2 `ConfigDict` nutzen (nicht mehr `class Config`)

### Fehlerbehandlung
- Eigene Exception-Hierarchie unter `DocumentParserError`
- Spezifische Exceptions (nicht generic `Exception`)
- Encoding-Fehler werden mit Fallback `errors="replace"` behandelt,
  bei komplettem Versagen wird `EncodingError` geworfen

### Performance-Constraints (16 GB RAM Workstation)
- **MAX_FILE_SIZE_BYTES = 50 MB**: Schutz vor OOM
- **MAX_TEXT_LENGTH = 1_000_000 Zeichen**: DoS-Schutz fuer einzelne Calls
- **MAX_PDF_PAGES = 10_000**: Schutz vor Endlos-Loops in kaputten PDFs
- **Generatoren statt Listen**: Iteratoren ueber Chunks, lazy evaluation
- **Kein Full-Document-Load**: nur Chunk-Window wird im Speicher gehalten
- **PDF Page-Streaming**: RAM-Footprint = O(max_page_size), nicht O(pdf_total_size)

### Logging
- Modul-Logger: `_LOGGER = logging.getLogger(__name__)`
- Style: `_LOGGER.info("text %s", var)` — **kein f-String** (siehe `conventions.md`)
- Log-Level: INFO fuer Pipeline-Start, WARNING fuer Encoding-Fallback

### Confidence-Scoring (Heuristik)
- **Alte (Schritt 1/2) Heuristik** in `document_parser.compute_confidence`:
  - Basis: 0.5 (Treffer an sich)
  - Keyword-Dichte: +0.05 pro zusaetzlichem Vorkommen, max +0.2
  - Positiver Kontext: +0.05 pro Boost-Term, max +0.2
  - Negativer Kontext: -0.1 pro Penalty-Term, max -0.3
  - Cap: [0.0, 1.0]
- **Neue (Schritt 3) Heuristik** in `classifier.compute_heuristic_score`:
  - Basis: `BASE_SCORE` (0.5)
  - Boost-Terme: +`BOOST_DELTA` (0.05) pro Hit, cap `BOOST_CAP` (0.2)
  - Penalty-Terme: -`PENALTY_DELTA` (0.1) pro Hit, cap `PENALTY_CAP` (0.3)
  - Clamp: [SCORE_MIN, SCORE_MAX] = [0.0, 1.0]
  - `is_compliant` = `score >= COMPLIANCE_THRESHOLD` (0.7) AND kein `CRITICAL_PENALTY_TERM` im Chunk

## Tests

- **381 Tests** (Stand 2026-07-06; readiness = PILOT_PUBLIC_DATA_READY), vollstaendig deterministisch (1 opt-in Netzwerk-Test standardmaessig skipped) — exakter Stand via `PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 pytest -q`
- Externe IO (Dateisystem, pypdf) zu 100 % gemockt via `unittest.mock`
- AAA-Pattern (Arrange, Act, Assert)
- Test-Klassen (document_parser): `TestComplianceEvidenceSchema`,
  `TestNormalizeText`, `TestLocateKeywordPositions`, `TestExtractChunk`,
  `TestComputeConfidence`, `TestFunctionalChunkExtractor`,
  `TestLocalDocumentParserInit`, `TestLocalDocumentParserParseText`,
  `TestLocalDocumentParserParseFile`, `TestGeneratorBehavior`
- Test-Klassen (pdf_handler): `TestIsPypdfAvailable`,
  `TestStreamPdfPagesFileValidation`, `TestStreamPdfPagesSuccessful`,
  `TestStreamPdfPagesErrors`, `TestPypdfMissing`, `TestClassifyPypdfError`,
  `TestExtractPdfText`, `TestLocalDocumentParserPDFDispatch`,
  `TestStreamPdfPagesWithRealTmpFile`
- Test-Klassen (classifier): `TestClassifierError`,
  `TestComputeHeuristicScore` (20 Tests: Basis, Boosts, Penalties, Caps,
  Clamps, Edge-Cases, Substring-Match, Case-Insensitivity, Realistic-Szenarien),
  `TestEvaluateChunk` (15 Tests: Compliance-Mapping, Critical-Penalty,
  Schema-Validierung, Frozen-Model, Empty-Inputs),
  `TestParseAndClassify` (11 Tests: Text- und PDF-Pipeline, File-Validation,
  Iterator-Laziness, Requirement-Map, Empty-Input)
- Public-Eval/CLI-Tests: `test_public_nis2_fixtures.py`,
  `test_cli_triage.py`, `test_cli_eval.py`, `test_cli_pilot_run.py`,
  `test_report_schema.py`, `test_nis2_control_coverage.py`,
  `test_redaction_preflight.py`, `test_review_workflow.py`
- Paid-Pilot-Hardening-Tests: `test_audit_ledger.py`,
  `test_adversarial_fixtures.py`, `test_report_handover.py`,
  `test_public_real_docs_manifest.py`, `test_pilot_readiness_check.py`
- Pilot-Ops-Tests: `test_customer_like_eval.py`,
  `test_calibration_report.py`, `test_public_url_check.py`
- Outreach-Prep-Tests: `test_outreach_docs.py` prueft Pflichtdateien, Disclaimer,
  Sample-Pack-Verbote, company-level Target-Template, Go/No-Go und enge Claims.
- Berlin-Research-Tests: `test_berlin_target_research_docs.py` prueft
  company-level Kontaktwege, keine LinkedIn-/Xing-Quellen, Owner-Gate und enge Claims.
- First-Wave-Outreach-Tests: `test_first_wave_outreach_docs.py` prueft max. 3
  Firmen, `draft_ready`, company-level Kanaele, keine privaten Kontakte, keine
  Anhaenge und keine verbotenen Claims.
- C-SCRM-MVP-Tests: `test_scrm_workflow.py` prueft eindeutige Control-IDs,
  gueltige Cross-Framework-Refs, `needs_evidence` ohne Evidence, Drafts nur
  mit `evidence_refs`, Secret-/PII-Maskierung in Reports und deterministische
  Supplier-Risk-Scores.
- Evidence-Bridge-Tests: `test_evidence_bridge.py` prueft accepted/reviewed
  Findings, rejected/needs-evidence Ausschluss, stabile Evidence-IDs,
  fehlende/doppelte `finding_id`, private Rohfelder und Questionnaire-Integration
  inklusive E2E-Flow bis Review-Apply und Supplier-Risk.
- Trust-Bundle-Tests: `test_trust_bundle.py` prueft erwartete Preview-Dateien,
  deterministisches Manifest, konservative Statuswerte, Missing-Input-Fehler und
  Ausschluss von Rohclaims, Fragen, Drafts, privaten Pfaden und Compliance-Claims.
- SBOM-Tests: `test_sbom_workflow.py` prueft offline CycloneDX-Inventar,
  lokale Metadata-Gap-Findings, SPDX-Unsupported-Fehler, sichere Output-Pfade und
  Ausschluss roher/private SBOM-Felder.
- Supplier-Profile-Tests: `test_supplier_profile_contract.py` prueft Contract-
  Normalisierung, ungueltige Kritikalitaet, fehlende `supplier_id` und Blockade
  privater/raw Felder.
- Pilot-Full-Flow-Tests: `test_pilot_full_local_flow.py` prueft `demo-pilot`,
  finale Trust-Bundle-Artefakte, deterministischen Bundle-Rebuild und das
  manifest-only Public-Data-Decision-File.
- Docker-Delivery-Tests: `test_docker_delivery.py` prueft Dockerfile, Compose,
  `.dockerignore`, non-root Entry Point, offline Mount-Konzept und statische
  Docker-Kontext-Safety.
- Low-Compute-ML-Tests: `test_ml_features.py`, `test_ml_bm25.py`,
  `test_ml_simhash.py`, `test_ml_weak_labels.py`, `test_ml_doc_classifier.py`,
  `test_ml_control_mapper.py`, `test_ml_severity.py`, `test_ml_active_learning.py`,
  `test_ml_cli.py` pruefen metadata-only Outputs, optionale/fallbackfaehige Modelle,
  Review-only Control-Vorschlaege, Dedupe, Weak-Label-Konflikte und CLI-Komposition.
- Pilot-Product-Slice-Tests: `test_document_ingest.py`, `test_answer_vault.py`,
  `test_pilot_product_slice.py` pruefen Multi-Format-Ingest, stabile Evidence-IDs,
  SQLite-Migration/Versioning, reviewed Answer-Reuse, Missing-Evidence, Review Queue,
  Shareable-Output-Redaction und Workspace-Inspect/Purge-Dry-Run.
- Diagnostics-/Support-Bundle-Tests: `test_diagnostics.py`, `test_support_bundle.py`
  pruefen Doctor-Reports ohne Rohinhalte, Debug-JSONL-Split, stabile Error-Codes,
  redacted ZIP-Inhalte und Privacy-Guard-Blockade fuer verbotene Marker.
- CLI-Document-Ingest-Tests: `test_cli_document_ingest.py` prueft den `main()`-Pfad:
  Happy-Path-Artefakte, fehlender Input (Exit 8), `--out`-Sandbox-Blockade,
  `--no-local-excerpts` (kein `redacted_excerpt` in der Evidence-Map) und `--debug`-JSONL-Logs.
- Pilot-Delivery-Artefakt-Tests: `test_delivery_artifact.py` prueft Blockaden fuer
  `.git`, `tests/`, `reports/`, `local_private/`, DBs, `.env`, Agent-Dateien,
  Secret-Marker und Source-Claim-Konsistenz.

## Bekannte Gotchas

- `pytest --strict-config` ist aktiv in `.pytest.ini`. Test-Discovery,
  `addopts` und Warnings muessen dort gepflegt werden.
- `dash`-Plugin ist global registriert
  und kaputt (`werkzeug`-Import fehlt). Loesung: `$env:PYTEST_DISABLE_PLUGIN_AUTOLOAD = "1"`
  vor `pytest` setzen, oder als Pre-Commit-Hook dokumentieren.
- `requirement_map`-Keys werden case-insensitive normalisiert. Tests muessen
  auch Uppercase-Matches abdecken, damit Mapping nicht auf Textschreibweise
  angewiesen ist.
- Keyword-Suche priorisiert laengere Keywords am selben Startpunkt, damit
  `risk assessment` nicht durch `risk` verschluckt wird.
- `classifier.PENALTY_TERMS` darf nicht allgemeine Risk-Begriffe wie
  `risiko` enthalten, weil sonst `risikoanalyse` als Gap bestraft wird.
- Marketing- oder Negationsformulierungen wie `no evidence` und
  `intentionally avoids` sind bewusst Penalty-Terme, um Scheinbelege zu
  verhindern.
- Pydantic v2 `ConfigDict` statt `class Config` — die alte Form ist deprecated.
- `frozen=True` auf `ComplianceEvidence` — Mutationen werfen `ValidationError`.
- `isinstance(path, Path)` bricht, wenn `Path` per `mock.patch` gemockt wird
  (Type wird zu MagicMock-Instance). Deshalb: `Path(path)` immer aufrufen
  (idempotent fuer Path-Args, parst Strings).
- **Circular-Import**: `document_parser` und `pdf_handler` importieren
  wechselseitig. `pdf_handler` braucht `MAX_FILE_SIZE_BYTES` +
  `DocumentParserError`. `document_parser._parse_pdf_pages` braucht
  `stream_pdf_pages`. Loesung: lokaler Import in `_parse_pdf_pages`,
  Tests muessen `aethelgard.mvp1.pdf_handler.stream_pdf_pages` patchen
  (NICHT `aethelgard.mvp1.document_parser.stream_pdf_pages`).
- **Circular-Import Classifier**: `classifier.py` braucht `DocumentParserError`
  aus `document_parser.py`. `document_parser._classify_text/_classify_pdf_pages`
  brauchen `evaluate_chunk` aus `classifier.py`. Loesung: lokaler Import
  in `_classify_text` und `_classify_pdf_pages`. Tests muessen
  `aethelgard.mvp1.classifier.evaluate_chunk` patchen ODER die
  `stream_pdf_pages`-Mocking-Strategie folgen.
- **Mocking pypdf-Konstruktor-Fehler**: `mock_pypdf.PdfReader.side_effect = X`
  statt `return_value=reader_ctor` (sonst wird der Fehler nie geworfen,
  weil `return_value` den Mock zurueckgibt).
- **pypdf 6.x Exception-Namen**: `WrongFileTypeError`/`PermissionDeniedError`
  existieren NICHT. Stattdessen: `ParseError` und `WrongPasswordError`.

## Boy Scout Rule (siehe `conventions.md`)

Bei jeder Aenderung: Code im selben Verzeichnis mit aufraeumen. Keine
auskommentierten Bloecke hinterlassen, keine toten Imports.

## Status

| Stufe | Status | Datum |
|---|---|---|
| MVP1 Schritt 1 (Infrastruktur + Core Parser) | OK | 2026-06-27 |
| MVP1 Schritt 2 (PDF-Handler + Integration) | OK | 2026-06-27 |
| MVP1 Schritt 3 (Classifier + Pipeline-Integration) | OK | 2026-06-27 |
| Paid-Pilot Hardening (Audit, Handover, Readiness) | OK | 2026-06-28 |
| Paid Pilot Ops Readiness (Customer-like Pack, Calibration, Demo/Legal/Backup) | OK | 2026-06-28 |
| Outreach Preparation (Docs, ICP, Follow-up, Objections, Call Pack) | OUTREACH_READY_WITH_OWNER_GATE | 2026-06-28 |
| NIS2 Article 21 Coverage | OK: 10 Artikel-21(2)-Themen als Coverage-Matrix, keine Legal-/Audit-Claims | 2026-06-28 |
| Controlled First Outreach Wave | DRAFT_READY_BLOCKED_BY_SENDER: 3 Firmen verifiziert, Drafts/Tracker/Runbooks erstellt, kein Versand ohne Absenderkonto | 2026-06-28 |
| Pilot Run Flow | OK: redaction preflight, `pilot-run`, Demo-Bundle und `review_items.csv`; `reports/pilot-demo`: 8/8 Dokumente, 57 Evidenzen, Preflight `pass` | 2026-06-28 |
| Human Review Apply Flow | OK: stabile `finding_id`, `review-apply`, `reviewed_report.json`, `reviewed_report.md`, `review_summary.json`; strict/nonstrict CSV-Validation und Review-Notiz-Maskierung | 2026-06-28 |
| Technical C-SCRM MVP | OK: lokale Control-Kataloge, Evidence Store, Questionnaire-Drafts mit Review-CSV und Supplier-Risk-Reports; keine Rohdaten/Secrets in Reports | 2026-06-29 |
| Reviewed Evidence Bridge | OK: `evidence from-reviewed-report`, accepted/reviewed Findings -> Evidence Store, Questionnaire-Integration; rejected/needs-evidence ausgeschlossen | 2026-06-29 |
| Trust Bundle Preview | OK: `trust-bundle build` erzeugt deterministic metadata-only Preview (`manifest`, Evidence-Index, Questionnaire-/Risk-Summary, README); keine Rohzitate, Drafts, privaten Pfade oder Compliance-Claims | 2026-06-29 |
| Offline SBOM + Supplier Contracts | OK: `sbom ingest`, `sbom findings` und `supplier-profile validate`; CycloneDX-only, SPDX unsupported, stabile IDs, keine CVE/API/Netzwerk-Abfragen | 2026-06-29 |
| Pilot Readiness Slice | OK: Review-Metadaten-Sanitization fuer `reviewer`, `reviewed_at`, `review_note`; `demo-pilot` E2E-Flow mit synthetischem Pack und manifest-only Public-Data-Entscheidung | 2026-06-30 |
| Docker Local Delivery | RUNTIME_READY_WITH_ML_PROOF: Dockerfile, `.dockerignore`, Compose, statischer Delivery-Gate, `docker_smoke`, `docker_ml_smoke` und `consultant_laptop_smoke` gruen; `docker_smoke` prueft `pilot-product`, `doctor` und `support-bundle --redacted`; ML-CLI im Container unter `--network none` getestet | 2026-07-02 |
| Low-Compute ML Baselines | OK: pure-Python Feature-JSONL, BM25, SimHash, Weak Labels, fallback Doc-Type-Classifier, Control-Suggestions, Severity Ranking, Active-Review-Queue und redigierter Learning-Export; experimental, metadata-only, Human Review/Owner-Gate erforderlich | 2026-06-30 |
| Delivery Profile | OK: metadata-only `delivery-profile validate`, synthetisches Demo-Profil, keine PII/Secrets/private Pfade, keine Safety-Overrides | 2026-06-30 |
| Pilot Product Slice | OK: `pilot-product`, `document-ingest`, `answer-vault`, `workspace inspect/purge`; SQLite Answer Vault, shareable/private Output-Split, Missing Evidence, Review Queue und HTML Preview; CLI-DB-Pfade projektgebunden, explizite Review-Disclaimer, keine Compliance-Garantie | 2026-07-01 |
| Pilot Demo Marketing Pack | OK: statische Landingpage, Demo-Video-Script, Outreach-Pack, `docs/pilot_quickstart.md`, reproduzierbarer redacted `pilot-product` Demo-Run und `check_marketing_claims.py`; Docker-Runtime bleibt Owner-Gate | 2026-07-01 |
| Pilot Diagnostics Support | OK: `doctor`, `support-bundle --redacted`, `pilot-product --debug`, lokale JSONL-Logs, stabile Error-Taxonomie, Privacy-Guard und `docs/pilot_support.md`; keine Telemetrie, kein Cloud-Monitoring, keine Kundendokumente/DBs im Bundle | 2026-07-01 |
| Pilot Delivery Packaging Layer | DEV_RUNTIME_READY_NOT_CUSTOMER_CLOSED: `build_pilot_artifact.py`, `check_delivery_artifact.py`, `docs/pilot_delivery_security.md`, `docs/pilot_license_notice.md`; dev-runtime ist source-visible und nicht als geschlossenes Kundenartefakt auslieferbar | 2026-07-02 |
| CLI Exit-Code Konsolidierung | OK: Codes 3-8 zentral in `errors.py` (EXIT_*-Konstanten), `cli.py` re-exportiert die bisherigen Alias-Namen (Testimporte stabil); `document-ingest` erstmals CLI-getestet (5 Tests via `main()`) | 2026-07-04 |
| Tests | 372/373 gruen, 1 skipped opt-in Netzwerk-Test, 17 subtests | 2026-07-04 |
| Public Eval | PILOT_READY: 17/17 Fixtures, 0 Parserfehler, 1.0 Category-Hit-Rate, 0 FP/FN | 2026-06-28 |
| Customer-like Eval | PILOT_READY: 8/8 Fixtures, Calibration Report vorhanden, Warnungen erwartet | 2026-06-28 |
| Fixture Safety | `python scripts/check_public_fixtures.py` gruen (30 Dateien) | 2026-07-01 |
| Real Public Source URL Check | Opt-in; 403/Timeout werden fuer offizielle Quellen als WARN klassifiziert | 2026-06-28 |
| Paid Pilot Readiness | `python scripts/check_pilot_readiness.py --out reports/readiness` => `PILOT_PUBLIC_DATA_READY`; Docker-Runtime bleibt Owner-Gate | 2026-07-01 |
| Outreach Demo/Eval | `reports/outreach-demo` + `reports/outreach-eval`: 8/8 Dokumente, 57 Evidenzen, 31 erwartete Warnings, Eval `PILOT_READY` | 2026-06-28 |
| Fresh-Venv | `.[all]`, pytest, triage, eval, ruff und mypy gruen | 2026-06-27 |
| Lint | `.venv-fresh\Scripts\python.exe -m ruff check .` gruen | 2026-07-01 |
| Mypy strict | `.venv-fresh\Scripts\python.exe -m mypy src` gruen (39 Source-Dateien) | 2026-07-01 |
| Git init | vorhanden, Branch `codex/nis2-control-coverage`, kein Push ausgefuehrt | 2026-06-28 |

## Naechste Schritte (geplant, ausserhalb dieses Schritts)

- Owner ersetzt `TODO_CONTACT`, laesst Landingpage/Outreach-Texte legal/privacy-reviewen und deployt danach `marketing/landing/index.html`.
- Owner nimmt das 60-90s Demo-Video anhand `marketing/demo_video_script.md` mit synthetischem `reports/pilot-product-demo` Output auf.
- First-Wave-Outreach gezielt und manuell ueber owner-gepruefte Kanaele starten; keine echten Kundendokumente ohne Privacy-/Legal-Gate.
