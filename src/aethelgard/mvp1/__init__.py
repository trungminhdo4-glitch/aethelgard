"""AethelGard MVP1: Lokale Compliance-Dokumentenverarbeitung.

Dieses Submodul stellt strikt typisierte Schemas, einen speichereffizienten
Parser und eine deterministische Klassifikations-Engine fuer lokale
NIS-2-Compliance-Dokumente bereit. Ziel ist die Extraktion von Text-Chunks
um Schluesselwoerter herum, mit anschliessender heuristischer Bewertung
als ``ComplianceEvidence``-Datensaetze.

Layer-Aufteilung:
- :mod:`aethelgard.mvp1.schemas` - Datenvertraege (pydantic v2)
- :mod:`aethelgard.mvp1.document_parser` - Text/PDF-Parser (OOP + Functional)
- :mod:`aethelgard.mvp1.pdf_handler` - PDF-Stream-Handler (optional pypdf)
- :mod:`aethelgard.mvp1.classifier` - Klassifikations-Engine (Heuristik)
- :mod:`aethelgard.mvp1.streaming` - Block-Quellen + Fensterung (grosse Dokumente)
- :mod:`aethelgard.mvp1.evaluators` - Evaluator-Protokoll + RuleBasedEvaluator
"""

from __future__ import annotations

from aethelgard.mvp1.classifier import (
    BASE_SCORE,
    BOOST_CAP,
    BOOST_DELTA,
    BOOST_TERMS,
    COMPLIANCE_THRESHOLD,
    CRITICAL_PENALTY_TERMS,
    PENALTY_CAP,
    PENALTY_DELTA,
    PENALTY_TERMS,
    SCORE_MAX,
    SCORE_MIN,
    ClassifierError,
    compute_heuristic_score,
    evaluate_chunk,
)
from aethelgard.mvp1.document_parser import (
    DEFAULT_CHUNK_RADIUS,
    DEFAULT_MIN_CONFIDENCE,
    PDF_EXTENSION,
    STREAM_WINDOW_CHARS,
    STREAMING_TEXT_THRESHOLD_BYTES,
    DocumentParserError,
    EmptyDocumentError,
    EncodingError,
    FileSizeLimitExceededError,
    LocalDocumentParser,
    compute_confidence,
    extract_chunk,
    functional_chunk_extractor,
    locate_keyword_positions,
    normalize_text,
)
from aethelgard.mvp1.evaluators import (
    ChunkEvaluator,
    RuleBasedEvaluator,
    run_pipeline,
)
from aethelgard.mvp1.pdf_handler import (
    DEFAULT_PAGE_SEPARATOR,
    MAX_PDF_PAGES,
    CorruptPdfError,
    EncryptedPdfError,
    PdfDependencyMissingError,
    PdfParseError,
    extract_pdf_text,
    is_pypdf_available,
    stream_pdf_pages,
)
from aethelgard.mvp1.schemas import ComplianceEvidence
from aethelgard.mvp1.streaming import (
    DEFAULT_BLOCK_CHARS,
    DEFAULT_WINDOW_CHARS,
    DEFAULT_WINDOW_OVERLAP,
    TextWindow,
    iter_document_blocks,
    iter_pdf_blocks,
    iter_text_blocks,
    sliding_windows,
)

__all__: list[str] = [
    # Schemas
    "ComplianceEvidence",
    # Constants - Classifier
    "BASE_SCORE",
    "BOOST_CAP",
    "BOOST_DELTA",
    "BOOST_TERMS",
    "COMPLIANCE_THRESHOLD",
    "CRITICAL_PENALTY_TERMS",
    "PENALTY_CAP",
    "PENALTY_DELTA",
    "PENALTY_TERMS",
    "SCORE_MAX",
    "SCORE_MIN",
    # Constants - Parser
    "DEFAULT_CHUNK_RADIUS",
    "DEFAULT_MIN_CONFIDENCE",
    "DEFAULT_PAGE_SEPARATOR",
    "MAX_PDF_PAGES",
    "PDF_EXTENSION",
    "STREAMING_TEXT_THRESHOLD_BYTES",
    "STREAM_WINDOW_CHARS",
    # Exceptions
    "ClassifierError",
    "CorruptPdfError",
    "DocumentParserError",
    "EmptyDocumentError",
    "EncodingError",
    "EncryptedPdfError",
    "FileSizeLimitExceededError",
    "PdfDependencyMissingError",
    "PdfParseError",
    # Classifier
    "compute_heuristic_score",
    "evaluate_chunk",
    # Parser (Text)
    "LocalDocumentParser",
    "compute_confidence",
    "extract_chunk",
    "functional_chunk_extractor",
    "locate_keyword_positions",
    "normalize_text",
    # Parser (PDF)
    "extract_pdf_text",
    "is_pypdf_available",
    "stream_pdf_pages",
    # Streaming (grosse Dokumente)
    "DEFAULT_BLOCK_CHARS",
    "DEFAULT_WINDOW_CHARS",
    "DEFAULT_WINDOW_OVERLAP",
    "TextWindow",
    "iter_document_blocks",
    "iter_pdf_blocks",
    "iter_text_blocks",
    "sliding_windows",
    # Evaluators (Modus A: regelbasiert)
    "ChunkEvaluator",
    "RuleBasedEvaluator",
    "run_pipeline",
]
