"""AethelGard MVP1 - Speichereffizienter Document Parser.

Dieses Modul stellt zwei zueinander komplementaere API-Stile bereit:

1. **Objektorientiert**: ``LocalDocumentParser`` - zustandsbehafteter Parser
   mit konfigurierbarem Verhalten, der Iteratoren ueber
   ``ComplianceEvidence``-Instanzen liefert.

2. **Funktional**: ``functional_chunk_extractor`` - eine Pipeline aus
   reinen Funktionen (Pure Functions) ohne Seiteneffekte, die fuer
   Composition und Test-Isolation optimiert ist.

Beide Varianten arbeiten strikt **lazy** mittels Generatoren, um den
RAM-Footprint auch bei grossen Dokumenten (mehrere MB) minimal zu halten.
Es werden ausschliesslich Standardbibliotheksfunktionen (``re``,
``pathlib``) und ``pydantic`` verwendet - keine schweren NLP-Frameworks.
"""

from __future__ import annotations

import logging
import re
import unicodedata
from collections.abc import Iterator, Mapping, Sequence
from pathlib import Path
from typing import TYPE_CHECKING, Final

from aethelgard.mvp1.schemas import ComplianceEvidence

if TYPE_CHECKING:
    from aethelgard.mvp1.streaming import TextWindow

_LOGGER: Final[logging.Logger] = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Konstanten
# ---------------------------------------------------------------------------

#: Standard-Radius (in Zeichen) fuer die Extraktion um ein Keyword herum.
DEFAULT_CHUNK_RADIUS: Final[int] = 200

#: Minimaler Confidence-Score, ab dem ein ``ComplianceEvidence`` emittiert wird.
DEFAULT_MIN_CONFIDENCE: Final[float] = 0.5

#: Erwartete Text-Encoding. UTF-8 deckt den gesamten NIS-2-Dokumentenraum ab.
DEFAULT_ENCODING: Final[str] = "utf-8"

#: Datei-Extension fuer PDF-Dokumente. Case-insensitive Erkennung in
#: ``LocalDocumentParser.parse_file``. Wird NICHT mit fuehrendem Punkt
#: exportiert, da ``Path.suffix`` den Punkt bereits enthaelt.
PDF_EXTENSION: Final[str] = ".pdf"

#: Maximale Dateigroesse in Bytes, die der Parser akzeptiert (50 MB).
#: Schutz vor versehentlichem OOM bei mehrhundert-MB-Dateien.
MAX_FILE_SIZE_BYTES: Final[int] = 50 * 1024 * 1024

#: Maximale Textlaenge in Zeichen, die in einem Aufruf verarbeitet wird.
#: Schutz vor Memory-Exhaustion durch adversarial inputs.
MAX_TEXT_LENGTH: Final[int] = 1_000_000

#: Maximale Anzahl Keywords, die gleichzeitig registriert werden koennen.
MAX_KEYWORDS: Final[int] = 500

#: Maximale Keyword-Laenge in Zeichen.
MAX_KEYWORD_LENGTH: Final[int] = 100

#: Dateigroessen-Schwelle (Bytes), ab der Textdateien im Streaming-Modus
#: verarbeitet werden (ueberlappende Fenster statt Full-Read + Full-
#: Normalize). Dateien bis zur Schwelle behalten exakt das bisherige
#: Verhalten. 4 MiB liegt oberhalb aller Fixtures und weit unterhalb
#: des 50-MB-Dateilimits (25-MB-Dokumente laufen so RAM-flach).
STREAMING_TEXT_THRESHOLD_BYTES: Final[int] = 4 * 1024 * 1024

#: Fenstergroesse des Parser-Streaming-Pfads (64 KiB Text pro Fenster).
STREAM_WINDOW_CHARS: Final[int] = 65_536

#: Minimale Fenster-Ueberlappung; effektiv gilt
#: ``max(STREAM_WINDOW_MIN_OVERLAP, 2 * chunk_radius + STREAM_OVERLAP_MARGIN)``.
STREAM_WINDOW_MIN_OVERLAP: Final[int] = 512

#: Zusaetzliche Sicherheits-Marge der Ueberlappung ueber ``2 * chunk_radius``.
STREAM_OVERLAP_MARGIN: Final[int] = 64

#: Regex-Whitelist-Characters pro Keyword: erlaubt Buchstaben, Ziffern,
#: Bindestrich, Unterstrich, Punkt, Komma, Klammern. Verhindert, dass
#: Regex-Metazeichen ungewollt in die Suche einfliessen.
_KEYWORD_SANITIZE_PATTERN: Final[re.Pattern[str]] = re.compile(r"[^a-zA-Z0-9_\-.,()]+")

#: Kontextspezifische Begriffe, die das Confidence-Score positiv beeinflussen.
#: NIS-2-relevantes Vokabular, das typischerweise auf substantielle Aussagen
#: zur Konformitaet hinweist.
_CONTEXT_BOOST_TERMS: Final[frozenset[str]] = frozenset(
    {
        "verpflichtet",
        "umgesetzt",
        "implementiert",
        "dokumentiert",
        "verfahren",
        "richtlinie",
        "kontinuierlich",
        "regelmaessig",
        "risikoanalyse",
        "sicherheitsvorfall",
        "meldepflicht",
        "audit",
    }
)

#: Kontextspezifische Begriffe, die das Confidence-Score negativ beeinflussen
#: (deuten auf Luecken oder Verstoss hin).
_NEGATIVE_CONTEXT_TERMS: Final[frozenset[str]] = frozenset(
    {
        "fehlt",
        "luecke",
        "nicht umgesetzt",
        "nicht dokumentiert",
        "verstoss",
        "risiko",
        "unzureichend",
        "mangelhaft",
    }
)


# ---------------------------------------------------------------------------
# Custom Exceptions
# ---------------------------------------------------------------------------


class DocumentParserError(Exception):
    """Basisklasse fuer alle Parser-Fehler in AethelGard MVP1."""


class EmptyDocumentError(DocumentParserError, ValueError):
    """Wird ausgeloest, wenn das Eingabedokument leer ist oder nur Whitespace enthaelt."""


class EncodingError(DocumentParserError, UnicodeError):
    """Wird ausgeloest, wenn die Datei nicht mit dem erwarteten Encoding gelesen werden kann."""


class FileSizeLimitExceededError(DocumentParserError, OSError):
    """Wird ausgeloest, wenn eine Datei die maximale Groessenbeschrankung ueberschreitet."""


# ---------------------------------------------------------------------------
# Hilfsfunktionen (Pure Functions, einzeln testbar)
# ---------------------------------------------------------------------------


def _slugify_requirement_id(keyword: str) -> str:
    """Erzeugt eine NIS-2-konforme Requirement-ID aus einem Keyword.

    Die ID enthaelt nur Grossbuchstaben, Ziffern, Bindestriche und Punkte.
    Sie ist sicher als Identifier, Dateiname und Report-Key verwendbar.

    Args:
        keyword: Das Schluesselwort, aus dem die ID abgeleitet wird.

    Returns:
        Eine normalisierte Requirement-ID (oh fuehrendes 'NIS2-').
    """
    normalized = keyword.upper()
    normalized = _KEYWORD_SANITIZE_PATTERN.sub("-", normalized).strip("-")
    return normalized or "UNMAPPED"


def _normalize_requirement_map(requirement_map: Mapping[str, str] | None) -> dict[str, str]:
    """Normalisiert Requirement-Map-Keys fuer case-insensitive Keyword-Matches."""
    return {
        keyword.strip().lower(): requirement_id
        for keyword, requirement_id in (requirement_map or {}).items()
        if keyword and keyword.strip()
    }


def normalize_text(text: str) -> str:
    """Normalisiert Text fuer stabile Chunk-Extraktion.

    Operationen (in dieser Reihenfolge):
    1. Vollstaendige NFC-Normalisierung der Unicode-Zeichen.
    2. Vereinheitlichung aller Zeilenumbrueche auf ``\\n``.
    3. Entfernung von Nullbytes.
    4. Reduktion von 3+ aufeinanderfolgenden Leerzeichen auf 1.
    5. Trim des Gesamttextes.

    Args:
        text: Der zu normalisierende Rohtext.

    Returns:
        Der normalisierte Text. Leere Strings bleiben leer.
    """
    if not text:
        return ""
    normalized = unicodedata.normalize("NFC", text)
    normalized = normalized.encode("utf-8", errors="ignore").decode("utf-8", errors="ignore")
    normalized = normalized.replace("\r\n", "\n").replace("\r", "\n")
    normalized = normalized.replace("\x00", "")
    normalized = re.sub(r" {3,}", " ", normalized)
    return normalized.strip()


def locate_keyword_positions(
    text: str,
    keywords: Sequence[str],
) -> Iterator[tuple[int, str]]:
    """Liefert Generator ueber (Position, Keyword)-Tupel im Text.

    Diese Funktion ist eine Pure Function ohne Seiteneffekte. Sie arbeitet
    lazy, d. h. die Suche wird bei jedem ``next()``-Aufruf um ein Zeichen
    fortgesetzt - niemals wird die gesamte Trefferliste im Speicher gehalten.

    Die Suche ist **case-insensitive** und nutzt Wortgrenzen
    (``\\b``-Anker), um Substring-Treffer zu vermeiden (z. B. findet
    ``risk`` nicht ``riskmanagement``).

    Args:
        text: Der zu durchsuchende Text (typischerweise vorher normalisiert).
        keywords: Sequenz von Schluesselwoertern.

    Yields:
        Tupel ``(position, keyword)`` fuer jeden Treffer, in aufsteigender
        Reihenfolge der Position.

    Raises:
        ValueError: Wenn ``keywords`` mehr als ``MAX_KEYWORDS`` enthaelt
            oder ein Keyword ``MAX_KEYWORD_LENGTH`` ueberschreitet.
    """
    if len(keywords) > MAX_KEYWORDS:
        raise ValueError("Too many keywords: %d (max %d)" % (len(keywords), MAX_KEYWORDS))
    for kw in keywords:
        if kw and len(kw) > MAX_KEYWORD_LENGTH:
            raise ValueError("Keyword too long: %d chars (max %d)" % (len(kw), MAX_KEYWORD_LENGTH))

    sorted_keywords = sorted(
        {k.strip().lower() for k in keywords if k and k.strip()},
        key=lambda keyword: (-len(keyword), keyword),
    )
    if not sorted_keywords:
        return

    pattern = re.compile(
        r"\b(" + "|".join(re.escape(k) for k in sorted_keywords) + r")\b",
        flags=re.IGNORECASE | re.UNICODE,
    )

    for match in pattern.finditer(text):
        yield (match.start(), match.group(0))


def extract_chunk(text: str, position: int, radius: int) -> str:
    """Extrahiert einen Text-Chunk um die gegebene Position.

    Der Chunk reicht von ``max(0, position - radius)`` bis
    ``min(len(text), position + radius)``. Wenn das Ende des Textes
    erreicht ist, wird der Chunk entsprechend gekuerzt.

    Args:
        text: Quelltext.
        position: 0-basierte Position des Keyword-Treffers.
        radius: Anzahl Zeichen links und rechts vom Treffer.

    Returns:
        Der extrahierte Chunk als String. Bei ``position < 0`` oder
        ``position >= len(text)`` wird ein leerer String zurueckgegeben.
    """
    if not text or position < 0 or position >= len(text):
        return ""
    if radius < 0:
        raise ValueError("radius must be non-negative, got %d" % radius)

    start = max(0, position - radius)
    end = min(len(text), position + radius)
    chunk = text[start:end]

    chunk = re.sub(r" {2,}", " ", chunk)
    chunk = chunk.replace("\n", " ").replace("\t", " ")
    return chunk.strip()


def compute_confidence(
    chunk: str,
    keyword: str,
    full_text: str,
) -> float:
    """Berechnet einen heuristischen Confidence-Score fuer einen Chunk.

    Heuristik (additiv, mit Cap bei 1.0):
    - Basis: 0.5 (Treffer an sich ist ein starkes Signal)
    - Keyword-Dichte im Chunk: +0.05 pro zusaetzlichem Vorkommen, max +0.2
    - Kontext-Boost: +0.05 pro positivem Kontextbegriff, max +0.2
    - Negativer Kontext: -0.1 pro negativem Kontextbegriff, max -0.3
    - Keyword in Grossbuchstaben: +0.05 (deutet auf Hervorhebung)

    Die Funktion ist eine Pure Function. Sie veraendert weder Eingaben
    noch externe Zustande.

    Args:
        chunk: Der extrahierte Text-Chunk.
        keyword: Das gefundene Schluesselwort.
        full_text: Der gesamte normalisierte Text (fuer Verhaeltnis-Berechnung).

    Returns:
        Confidence-Score im Intervall ``[0.0, 1.0]``.
    """
    if not chunk:
        return 0.0

    score = 0.5

    chunk_lower = chunk.lower()
    keyword_lower = keyword.lower()
    occurrences = chunk_lower.count(keyword_lower)
    if occurrences > 1:
        score += min(0.2, 0.05 * (occurrences - 1))

    positive_hits = sum(1 for term in _CONTEXT_BOOST_TERMS if term in chunk_lower)
    score += min(0.2, 0.05 * positive_hits)

    negative_hits = sum(1 for term in _NEGATIVE_CONTEXT_TERMS if term in chunk_lower)
    score -= min(0.3, 0.1 * negative_hits)

    if keyword.isupper() and any(c.isalpha() for c in keyword):
        score += 0.05

    return max(0.0, min(1.0, score))


# ---------------------------------------------------------------------------
# Funktionale Pipeline
# ---------------------------------------------------------------------------


def functional_chunk_extractor(
    text: str,
    keywords: Sequence[str],
    chunk_radius: int = DEFAULT_CHUNK_RADIUS,
    min_confidence: float = DEFAULT_MIN_CONFIDENCE,
    requirement_map: Mapping[str, str] | None = None,
) -> Iterator[ComplianceEvidence]:
    """Funktionale Pipeline: Text -> Chunks -> ComplianceEvidence.

    Reine Funktion ohne Seiteneffekte: Bei identischer Eingabe wird die
    gleiche Ausgabe-Streame erzeugt. Verwendet Generatoren, sodass der
    Speicherverbrauch pro Chunk konstant ist (O(1) im RAM).

    Args:
        text: Rohtext, wird intern normalisiert.
        keywords: Sequenz von Schluesselwoertern (case-insensitive).
        chunk_radius: Radius (Zeichen) links/rechts vom Treffer.
        min_confidence: Untergrenze fuer emittierte Evidenz.
        requirement_map: Optionales Mapping ``keyword -> requirement_id``.
            Fehlt der Eintrag, wird aus dem Keyword eine ID slugifiziert.

    Yields:
        ``ComplianceEvidence``-Instanzen mit Score ``>= min_confidence``.

    Raises:
        EmptyDocumentError: Wenn der Text nach Normalisierung leer ist.
        ValueError: Bei ungueltigen Parametern.
    """
    if chunk_radius < 0:
        raise ValueError("chunk_radius must be non-negative, got %d" % chunk_radius)
    if not 0.0 <= min_confidence <= 1.0:
        raise ValueError("min_confidence must be in [0.0, 1.0], got %s" % min_confidence)
    if len(text) > MAX_TEXT_LENGTH:
        raise ValueError("text too long: %d chars (max %d)" % (len(text), MAX_TEXT_LENGTH))

    normalized = normalize_text(text)
    if not normalized:
        raise EmptyDocumentError("Cannot extract chunks from empty document")

    positions = locate_keyword_positions(normalized, keywords)
    requirement_lookup = _normalize_requirement_map(requirement_map)

    for position, keyword in positions:
        chunk = extract_chunk(normalized, position, chunk_radius)
        if not chunk:
            continue
        score = compute_confidence(chunk, keyword, normalized)
        if score < min_confidence:
            continue
        requirement_id = requirement_lookup.get(keyword.lower()) or _slugify_requirement_id(keyword)
        is_compliant = _derive_compliance_flag(chunk)
        yield ComplianceEvidence(
            requirement_id=requirement_id,
            is_compliant=is_compliant,
            confidence_score=score,
            source_citation=chunk,
        )


def _derive_compliance_flag(chunk: str) -> bool:
    """Bestimmt, ob ein Chunk konform ist, anhand negativer Kontextbegriffe.

    Args:
        chunk: Zu pruefender Text-Chunk.

    Returns:
        ``False``, wenn mindestens ein negativer Kontextbegriff vorkommt,
        sonst ``True``.
    """
    chunk_lower = chunk.lower()
    return not any(term in chunk_lower for term in _NEGATIVE_CONTEXT_TERMS)


# ---------------------------------------------------------------------------
# OOP-Wrapper
# ---------------------------------------------------------------------------


class LocalDocumentParser:
    """Strikt typisierter Parser fuer lokale Compliance-Dokumente.

    Diese Klasse kapselt die Konfiguration (Keywords, Radius, Confidence-
    Schwelle) und stellt zwei Methoden bereit:

    - ``parse_text(text)``: Parser fuer bereits gelesenen Text.
    - ``parse_file(path)``: Liest die Datei sicher (Groessencheck, Encoding)
      und reicht sie an ``parse_text`` weiter.

    Beide Methoden geben **Iteratoren** zurueck, die erst bei Iteration
    tatsaechlich Chunks allokieren. Damit bleibt der RAM-Footprint auch
    bei grossen Dokumenten konstant niedrig.

    Attributes:
        keywords: Tuple der registrierten Schluesselwoerter.
        chunk_radius: Radius in Zeichen um jeden Treffer.
        min_confidence: Untergrenze fuer emittierte Evidenz.
        requirement_map: Optionales Mapping ``keyword -> requirement_id``.

    Examples:
        >>> parser = LocalDocumentParser(
        ...     keywords=("risk assessment", "incident response"),
        ...     chunk_radius=150,
        ... )
        >>> for ev in parser.parse_text("Our risk assessment is documented ..."):
        ...     print(ev.requirement_id, ev.confidence_score)
    """

    __slots__ = (
        "_keywords",
        "_chunk_radius",
        "_min_confidence",
        "_requirement_map",
    )

    def __init__(
        self,
        keywords: Sequence[str],
        chunk_radius: int = DEFAULT_CHUNK_RADIUS,
        min_confidence: float = DEFAULT_MIN_CONFIDENCE,
        requirement_map: Mapping[str, str] | None = None,
    ) -> None:
        """Initialisiert den Parser mit den angegebenen Konfigurationswerten.

        Args:
            keywords: Schluesselwoerter, nach denen gesucht wird.
            chunk_radius: Radius (Zeichen) um jeden Treffer herum.
            min_confidence: Untergrenze fuer emittierte Evidenz.
            requirement_map: Optionales Mapping ``keyword -> requirement_id``.

        Raises:
            ValueError: Bei ungueltigen Werten oder leerer Keyword-Liste.
        """
        if not keywords:
            raise ValueError("keywords must not be empty")
        if chunk_radius < 0:
            raise ValueError("chunk_radius must be non-negative, got %d" % chunk_radius)
        if not 0.0 <= min_confidence <= 1.0:
            raise ValueError("min_confidence must be in [0.0, 1.0], got %s" % min_confidence)

        normalized_keywords: tuple[str, ...] = tuple(
            dict.fromkeys(k.strip() for k in keywords if k.strip())
        )
        if not normalized_keywords:
            raise ValueError("keywords must contain at least one non-empty value")

        self._keywords: Final[tuple[str, ...]] = normalized_keywords
        self._chunk_radius: Final[int] = chunk_radius
        self._min_confidence: Final[float] = min_confidence
        self._requirement_map: Final[Mapping[str, str]] = _normalize_requirement_map(
            requirement_map
        )

    @property
    def keywords(self) -> tuple[str, ...]:
        """Tuple der registrierten Schluesselwoerter (unveraenderlich)."""
        return self._keywords

    @property
    def chunk_radius(self) -> int:
        """Aktueller Chunk-Radius in Zeichen."""
        return self._chunk_radius

    @property
    def min_confidence(self) -> float:
        """Aktueller Confidence-Schwellwert."""
        return self._min_confidence

    def parse_text(self, text: str) -> Iterator[ComplianceEvidence]:
        """Parst Text und liefert einen Iterator ueber Evidenzen.

        Args:
            text: Rohtext.

        Returns:
            Iterator ueber ``ComplianceEvidence``-Instanzen.

        Raises:
            EmptyDocumentError: Wenn der Text nach Normalisierung leer ist.
            ValueError: Bei ungueltigen Konfigurationswerten.
        """
        _LOGGER.info(
            "parse_text called: %d chars, %d keywords, radius=%d, min_conf=%.2f",
            len(text),
            len(self._keywords),
            self._chunk_radius,
            self._min_confidence,
        )
        return functional_chunk_extractor(
            text=text,
            keywords=self._keywords,
            chunk_radius=self._chunk_radius,
            min_confidence=self._min_confidence,
            requirement_map=self._requirement_map,
        )

    def parse_file(self, path: Path | str) -> Iterator[ComplianceEvidence]:
        """Liest eine Datei und parst sie. Datei-IO wird validiert.

        Sicherheits-Checks:
        - Pfad muss existieren und regulaere Datei sein.
        - Dateigroesse <= ``MAX_FILE_SIZE_BYTES``.
        - Encoding = UTF-8 (Fallback mit ``errors='replace'`` bei Fehler).
        - PDF-Dateien (Endung ``.pdf``, case-insensitive) werden
          speicherschonend Seite fuer Seite via ``stream_pdf_pages``
          verarbeitet.

        Args:
            path: Pfad zur Text- oder PDF-Datei.

        Returns:
            Iterator ueber ``ComplianceEvidence``-Instanzen.

        Raises:
            FileNotFoundError: Wenn der Pfad nicht existiert.
            IsADirectoryError: Wenn der Pfad ein Verzeichnis ist.
            FileSizeLimitExceededError: Bei zu grossen Dateien.
            EncodingError: Bei nicht dekodierbarem Text.
            PdfParseError / EncryptedPdfError / CorruptPdfError:
                Bei PDF-spezifischen Fehlern.
        """
        file_path = Path(path)
        self._validate_file(file_path)

        if self._is_pdf_path(file_path):
            _LOGGER.debug("Dispatching %s to PDF page-stream handler", file_path)
            return self._parse_pdf_pages(file_path)

        if file_path.stat().st_size > STREAMING_TEXT_THRESHOLD_BYTES:
            _LOGGER.info("Dispatching %s to text window-stream parser", file_path)
            return self._parse_text_stream(file_path)

        text = self._read_text_safely(file_path)
        return self.parse_text(text)

    def parse_and_classify(self, file_path: Path | str) -> Iterator[ComplianceEvidence]:
        """Parst eine Datei und klassifiziert Chunks on-the-fly.

        Diese Methode kombiniert die Parsing-Pipeline mit dem
        ``classifier.evaluate_chunk``. Sie arbeitet strikt **lazy**:
        Jeder Chunk wird erst beim Iterieren aus dem Dokument extrahiert
        und unmittelbar klassifiziert. Der RAM-Footprint bleibt
        konstant niedrig (O(1) Wachstum pro Chunk), unabhängig
        von der Dateigroesse.

        **Unterschied zu ``parse_file``**:
        - ``parse_file`` nutzt die integrierte Heuristik aus
          ``compute_confidence`` (Keyword-Dichte + Kontext-Boost).
        - ``parse_and_classify`` nutzt die striktere Heuristik aus
          ``classifier.compute_heuristic_score`` (reine Boost/Penalty-
          Term-Bewertung mit NIS-2-Schwellwert + kritischem Penalty-Check).

        Args:
            file_path: Pfad zur Text- oder PDF-Datei.

        Yields:
            ``ComplianceEvidence``-Instanzen, lazy emittiert pro Chunk.

        Raises:
            FileNotFoundError: Wenn der Pfad nicht existiert.
            IsADirectoryError: Wenn der Pfad ein Verzeichnis ist.
            FileSizeLimitExceededError: Bei zu grossen Dateien.
            EncodingError: Bei nicht dekodierbarem Text.
            PdfParseError / EncryptedPdfError / CorruptPdfError:
                Bei PDF-spezifischen Fehlern.
        """
        file_path = Path(file_path)
        self._validate_file(file_path)

        file_size = file_path.stat().st_size
        _LOGGER.info("parse_and_classify: %s (%d bytes)", file_path, file_size)

        if self._is_pdf_path(file_path):
            _LOGGER.debug("Dispatching %s to PDF page-stream + classifier", file_path)
            yield from self._classify_pdf_pages(file_path)
            return

        if file_size > STREAMING_TEXT_THRESHOLD_BYTES:
            _LOGGER.info("Dispatching %s to text window-stream classifier", file_path)
            yield from self._classify_text_stream(file_path)
            return

        text = self._read_text_safely(file_path)
        yield from self._classify_text(text)

    def _validate_file(self, file_path: Path) -> None:
        """Prueft Pfad-Existenz, Typ und Groesse (Boy-Scout: gemeinsame Logik).

        Args:
            file_path: Zu pruefender Pfad.

        Raises:
            FileNotFoundError: Pfad existiert nicht.
            IsADirectoryError: Pfad ist Verzeichnis.
            FileSizeLimitExceededError: Datei ueberschreitet ``MAX_FILE_SIZE_BYTES``.
        """
        if not file_path.exists():
            raise FileNotFoundError("File not found: %s" % file_path)
        if not file_path.is_file():
            raise IsADirectoryError("Path is not a file: %s" % file_path)

        file_size = file_path.stat().st_size
        if file_size > MAX_FILE_SIZE_BYTES:
            raise FileSizeLimitExceededError(
                "File too large: %d bytes (max %d): %s"
                % (file_size, MAX_FILE_SIZE_BYTES, file_path)
            )

    def _read_text_safely(self, file_path: Path) -> str:
        """Liest Text mit UTF-8 und Fallback auf ``errors='replace'``.

        Args:
            file_path: Pfad zur Textdatei.

        Returns:
            Dekodierter Text-Inhalt.

        Raises:
            EncodingError: Wenn auch der Fallback fehlschlaegt.
            DocumentParserError: Bei sonstigen OS-Errors.
        """
        try:
            text = file_path.read_text(encoding=DEFAULT_ENCODING)
        except UnicodeDecodeError as exc:
            _LOGGER.warning(
                "UTF-8 decode failed for %s, retrying with replace: %s",
                file_path,
                exc,
            )
            try:
                text = file_path.read_text(encoding=DEFAULT_ENCODING, errors="replace")
            except (OSError, UnicodeDecodeError) as decode_exc:
                raise EncodingError(
                    "Cannot decode file %s: %s" % (file_path, decode_exc)
                ) from decode_exc
        except OSError as os_exc:
            raise DocumentParserError("Cannot read file %s: %s" % (file_path, os_exc)) from os_exc
        return text

    def _classify_text(self, text: str) -> Iterator[ComplianceEvidence]:
        """Klassifiziert alle Chunks in einem Text (lazy, On-the-Fly).

        Args:
            text: Rohtext.

        Yields:
            ``ComplianceEvidence`` pro gefundenem Keyword-Match.
        """
        from aethelgard.mvp1.classifier import evaluate_chunk

        normalized = normalize_text(text)
        if not normalized:
            return

        for position, keyword in locate_keyword_positions(normalized, self._keywords):
            chunk = extract_chunk(normalized, position, self._chunk_radius)
            if not chunk:
                continue
            requirement_id = self._requirement_map.get(keyword.lower()) or _slugify_requirement_id(
                keyword
            )
            yield evaluate_chunk(
                chunk=chunk,
                requirement_id=requirement_id,
                keywords=list(self._keywords),
            )

    @property
    def _stream_overlap(self) -> int:
        """Effektive Fenster-Ueberlappung des Streaming-Pfads.

        Mindestens ``STREAM_WINDOW_MIN_OVERLAP``, mindestens
        ``2 * chunk_radius + STREAM_OVERLAP_MARGIN``, damit jeder Treffer
        im Fenster-Kern seinen vollen Kontext-Radius behaelt.
        """
        return max(STREAM_WINDOW_MIN_OVERLAP, 2 * self._chunk_radius + STREAM_OVERLAP_MARGIN)

    def _validate_stream_geometry(self) -> int:
        """Prueft die Fenster-Geometrie und liefert die effektive Ueberlappung.

        Raises:
            ValueError: Wenn der ``chunk_radius`` zu gross fuer ein
                Fenster ist (Overlap wuerde das ganze Fenster fuellen).
        """
        overlap = self._stream_overlap
        if overlap >= STREAM_WINDOW_CHARS:
            raise ValueError(
                "chunk_radius %d too large for streaming window (%d chars)"
                % (self._chunk_radius, STREAM_WINDOW_CHARS)
            )
        return overlap

    def _iter_window_hits(self, window: TextWindow, overlap: int) -> Iterator[tuple[str, str]]:
        """Liefert ``(chunk, keyword)``-Treffer im besessenen Kern eines Fensters.

        Der Kern reicht bis ``len(normalized) - overlap`` (Tail-Fenster: bis
        zum Ende). Treffer im Ueberlappungsbereich emittiert das Folgefenster;
        so bleibt die Emission ueber Fenstergrenzen hinweg verlustfrei und
        doppelungsfrei (Ownership-Partition).
        """
        normalized = normalize_text(window.text)
        if not normalized:
            return
        core_end = len(normalized) if window.is_tail else max(0, len(normalized) - overlap)
        for position, keyword in locate_keyword_positions(normalized, self._keywords):
            if position >= core_end:
                break  # Positionen sind aufsteigend sortiert.
            chunk = extract_chunk(normalized, position, self._chunk_radius)
            if chunk:
                yield chunk, keyword

    def _parse_text_stream(self, file_path: Path) -> Iterator[ComplianceEvidence]:
        """Parst grosse Textdateien fensterweise (Functional-Semantik).

        Entspricht ``functional_chunk_extractor`` (``compute_confidence``
        + ``min_confidence``-Filter + ``_derive_compliance_flag``), aber mit
        O(window)-RAM statt O(file). Pro Fenster gilt implizit
        ``MAX_TEXT_LENGTH`` (Fenstergroesse << Limit).

        Args:
            file_path: Pfad zur Textdatei (bereits validiert).

        Yields:
            ``ComplianceEvidence``-Instanzen, lazy pro Fenster.
        """
        from aethelgard.mvp1.streaming import iter_text_blocks, sliding_windows

        overlap = self._validate_stream_geometry()
        blocks = iter_text_blocks(file_path)
        windows = sliding_windows(blocks, window_chars=STREAM_WINDOW_CHARS, overlap=overlap)
        for window in windows:
            for chunk, keyword in self._iter_window_hits(window, overlap):
                score = compute_confidence(chunk, keyword, window.text)
                if score < self._min_confidence:
                    continue
                requirement_id = self._requirement_map.get(
                    keyword.lower()
                ) or _slugify_requirement_id(keyword)
                yield ComplianceEvidence(
                    requirement_id=requirement_id,
                    is_compliant=_derive_compliance_flag(chunk),
                    confidence_score=score,
                    source_citation=chunk,
                )

    def _classify_text_stream(self, file_path: Path) -> Iterator[ComplianceEvidence]:
        """Klassifiziert grosse Textdateien fensterweise (Classifier-Semantik).

        Entspricht ``_classify_text`` (``classifier.evaluate_chunk``), aber
        mit O(window)-RAM statt O(file).

        Args:
            file_path: Pfad zur Textdatei (bereits validiert).

        Yields:
            ``ComplianceEvidence``-Instanzen, lazy pro Fenster.
        """
        from aethelgard.mvp1.classifier import evaluate_chunk
        from aethelgard.mvp1.streaming import iter_text_blocks, sliding_windows

        overlap = self._validate_stream_geometry()
        blocks = iter_text_blocks(file_path)
        windows = sliding_windows(blocks, window_chars=STREAM_WINDOW_CHARS, overlap=overlap)
        for window in windows:
            for chunk, keyword in self._iter_window_hits(window, overlap):
                requirement_id = self._requirement_map.get(
                    keyword.lower()
                ) or _slugify_requirement_id(keyword)
                yield evaluate_chunk(
                    chunk=chunk,
                    requirement_id=requirement_id,
                    keywords=list(self._keywords),
                )

    def _classify_pdf_pages(self, file_path: Path) -> Iterator[ComplianceEvidence]:
        """Klassifiziert Chunks in einer PDF-Datei seitenweise.

        Args:
            file_path: Pfad zur PDF-Datei.

        Yields:
            ``ComplianceEvidence`` aus jeder Seite (lazy, eine nach der anderen).
        """
        from aethelgard.mvp1.pdf_handler import stream_pdf_pages

        for page_idx, page_text in enumerate(stream_pdf_pages(file_path), start=1):
            _LOGGER.debug(
                "PDF %s: page %d (%d chars), running classifier",
                file_path,
                page_idx,
                len(page_text),
            )
            yield from self._classify_text(page_text)

    def _parse_pdf_pages(self, file_path: Path) -> Iterator[ComplianceEvidence]:
        """Parst eine PDF-Datei seitenweise und emittiert Compliance-Evidenzen.

        Diese Methode delegiert an ``stream_pdf_pages`` (lazy) und
        ruft ``functional_chunk_extractor`` pro Seite auf. Der RAM-
        Footprint ist O(max_page_size), nicht O(pdf_total_size).

        Args:
            file_path: Pfad zur PDF-Datei.

        Yields:
            ``ComplianceEvidence``-Instanzen aus jeder Seite.

        Raises:
            Siehe :func:`aethelgard.mvp1.pdf_handler.stream_pdf_pages`.
        """
        # Lokaler Import, um zirkulaere Importe zu vermeiden.
        from aethelgard.mvp1.pdf_handler import stream_pdf_pages

        for page_idx, page_text in enumerate(stream_pdf_pages(file_path), start=1):
            _LOGGER.debug(
                "PDF %s: page %d (%d chars), running chunk extractor",
                file_path,
                page_idx,
                len(page_text),
            )
            yield from functional_chunk_extractor(
                text=page_text,
                keywords=self._keywords,
                chunk_radius=self._chunk_radius,
                min_confidence=self._min_confidence,
                requirement_map=self._requirement_map,
            )

    def _is_pdf_path(self, file_path: Path) -> bool:
        """Prueft, ob ein Pfad auf eine PDF-Datei zeigt (case-insensitive).

        Args:
            file_path: Zu pruefender Pfad.

        Returns:
            ``True`` wenn die Dateiendung ``.pdf`` ist (Gross-/Kleinschreibung egal).
        """
        return file_path.suffix.lower() == PDF_EXTENSION
