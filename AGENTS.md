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
  mvp1/
    __init__.py            # Public API Re-Exports (Schemas + Parser + PDF + Classifier)
    schemas.py             # pydantic v2 Schemas (ComplianceEvidence)
    document_parser.py     # Parser (OOP + Functional), Text + PDF-Dispatch, parse_and_classify
    pdf_handler.py         # PDF Page-Streaming (optional pypdf)
    classifier.py          # Klassifikations-Engine (deterministische Heuristik)
  audit.py                 # Append-only JSONL Run-Ledger (Metadaten, keine Inhalte)
  cli.py                   # CLI: triage + eval
  public_sources.py        # Pure URL-Check-Klassifikation fuer offizielle Quellen
  triage.py                # Report-, Quality-, Calibration- und Evaluations-Engine
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
  evaluation/              # Public/Synthetic Eval-Plan, Quellenmanifest, Labeling
  research/                 # Berlin-Recherche, First-Wave-Drafts, Tracker, Response-/Demo-Runbooks
scripts/
  check_public_fixtures.py # statischer Fixture Safety Gate
  check_pilot_readiness.py # kontrollierter Paid-Pilot Gate-Report
tests/fixtures/public_nis2/ # 17 synthetische Fixtures + golden_labels.json
tests/fixtures/customer_like_nis2/ # 8 customer-like synthetische Fixtures + Labels
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

- **200 Tests**, vollstaendig deterministisch (1 opt-in Netzwerk-Test standardmaessig skipped)
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
  `test_cli_triage.py`, `test_cli_eval.py`, `test_report_schema.py`,
  `test_nis2_control_coverage.py`
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
| Tests | 207/207 gruen, 1 skipped opt-in Netzwerk-Test, 17 subtests | 2026-06-28 |
| Public Eval | PILOT_READY: 17/17 Fixtures, 0 Parserfehler, 1.0 Category-Hit-Rate, 0 FP/FN | 2026-06-28 |
| Customer-like Eval | PILOT_READY: 8/8 Fixtures, Calibration Report vorhanden, Warnungen erwartet | 2026-06-28 |
| Fixture Safety | `python scripts/check_public_fixtures.py` gruen (27 Dateien) | 2026-06-28 |
| Real Public Source URL Check | Opt-in; 403/Timeout werden fuer offizielle Quellen als WARN klassifiziert | 2026-06-28 |
| Paid Pilot Readiness | `python scripts/check_pilot_readiness.py --out reports/readiness` => `PILOT_OPS_READY` | 2026-06-28 |
| Outreach Demo/Eval | `reports/outreach-demo` + `reports/outreach-eval`: 8/8 Dokumente, 57 Evidenzen, 31 erwartete Warnings, Eval `PILOT_READY` | 2026-06-28 |
| Fresh-Venv | `.[all]`, pytest, triage, eval, ruff und mypy gruen | 2026-06-27 |
| Lint | `.venv-fresh\Scripts\python.exe -m ruff check .` gruen | 2026-06-28 |
| Mypy strict | `.venv-fresh\Scripts\python.exe -m mypy src` gruen (11 Source-Dateien) | 2026-06-28 |
| Git init | vorhanden, Branch `codex/nis2-control-coverage`, kein Push ausgefuehrt | 2026-06-28 |

## Naechste Schritte (geplant, ausserhalb dieses Schritts)

- Owner waehlt manuell 3-5 Zielunternehmen aus und nutzt die MSP/Security-Beratung-E-Mail mit engem Claim fuer eine 15-Minuten-Demo-Anfrage.
- Naechster Produkthebel: Demo-Report mit NIS2-Control-Coverage an synthetischen oder explizit owner-freigegebenen redacted Dokumenten zeigen.
- First-Wave-Drafts manuell ueber oeffentliche Firmenkanaele senden: NETWORK ASSISTANCE, 030-IT, procado; danach Tracker aktualisieren und keine Follow-ups ohne neues Owner-Gate senden.
