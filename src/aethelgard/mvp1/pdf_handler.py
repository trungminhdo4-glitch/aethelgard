"""AethelGard MVP1 - Speichereffizienter PDF-Handler.

Dieses Modul stellt eine stream-basierte API zur Extraktion von Text
aus PDF-Dateien bereit. Es nutzt die Bibliothek ``pypdf`` (optionale
Dependency) und arbeitet strikt **lazy**: Der PDF-Inhalt wird NICHT
in den Speicher geladen, sondern Seite fuer Seite aus einem File-Handle
gelesen.

Architektur-Hinweise:
    - ``pypdf`` ist eine optionale Dependency (``pip install aethelgard[pdf]``).
      Bei nicht-installierter Bibliothek wird ``PdfDependencyMissingError``
      geworfen - der uebrige Parser funktioniert weiterhin fuer Text.
    - File-Size-Limit ``MAX_FILE_SIZE_BYTES`` (50 MB) wird VOR dem
      Oeffnen geprueft (Schutz vor OOM).
    - Page-Limit ``MAX_PDF_PAGES`` (10 000) verhindert Endlos-Loops
      in pathologisch kaputten PDFs.
    - pypdf-Exceptions werden auf spezifische Custom-Exceptions gemappt.
    - ``strict=True`` (Default) laesst Strukturfehler durchschlagen;
      ``strict=False`` ueberspringt fehlerhafte Seiten mit WARNING.
"""

from __future__ import annotations

import logging
from collections.abc import Iterator
from pathlib import Path
from types import ModuleType
from typing import Final

from aethelgard.mvp1.document_parser import (
    MAX_FILE_SIZE_BYTES,
    DocumentParserError,
    FileSizeLimitExceededError,
)

_LOGGER: Final[logging.Logger] = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Konstanten
# ---------------------------------------------------------------------------

#: Maximale Anzahl Seiten, die aus einem PDF extrahiert werden.
#: Schutz vor Pathologien (z. B. zirkulaere Referenzen, kaputte Cross-Ref).
MAX_PDF_PAGES: Final[int] = 10_000

#: Standard-Seitentrenner fuer ``extract_pdf_text``.
DEFAULT_PAGE_SEPARATOR: Final[str] = "\n\n"

# ---------------------------------------------------------------------------
# Optionale pypdf-Dependency
# ---------------------------------------------------------------------------


def _init_pypdf() -> tuple[ModuleType | None, ModuleType | None, tuple[type[BaseException], ...]]:
    """Lazy import von pypdf ohne harte Abhaengigkeit.

    Returns:
        Tupel ``(pypdf_module, errors_module, exception_tuple)``.
        Bei fehlgeschlagenem Import sind alle drei ``None`` bzw. leer.
    """
    try:
        import pypdf
        from pypdf import errors as pypdf_errors
    except ImportError:
        return None, None, ()
    return (
        pypdf,
        pypdf_errors,
        (
            pypdf_errors.PdfReadError,
            pypdf_errors.EmptyFileError,
            pypdf_errors.FileNotDecryptedError,
            pypdf_errors.WrongPasswordError,
            pypdf_errors.ParseError,
        ),
    )


_pypdf_module, _pypdf_errors, _pypdf_exceptions = _init_pypdf()
_PYPDF_AVAILABLE: Final[bool] = _pypdf_module is not None
_PYPDF_READ_EXCEPTIONS: Final[tuple[type[BaseException], ...]] = _pypdf_exceptions
pypdf: Final[ModuleType | None] = _pypdf_module


# ---------------------------------------------------------------------------
# Custom Exceptions
# ---------------------------------------------------------------------------


class PdfParseError(DocumentParserError):
    """Wird ausgeloest, wenn eine PDF-Datei nicht gelesen werden kann.

    Generischer Fallback fuer unklassifizierte pypdf-Fehler. Spezifischere
    Unterklassen (``EncryptedPdfError``, ``CorruptPdfError``) existieren
    fuer bekannte Fehlerbilder.
    """


class EncryptedPdfError(PdfParseError):
    """Wird ausgeloest, wenn die PDF-Datei verschluesselt ist (passwortpflichtig).

    pypdf kann verschluesselte PDFs ohne Passwort nicht parsen. Diese
    Exception signalisiert, dass ein Passwort erforderlich waere.
    """


class CorruptPdfError(PdfParseError):
    """Wird ausgeloest, wenn die PDF-Datei strukturell beschaedigt ist.

    Beispiele: leere Datei, falsches Format, zerstoerte Cross-Reference-Tabelle.
    """


class PdfDependencyMissingError(DocumentParserError, ImportError):
    """Wird ausgeloest, wenn ``pypdf`` nicht installiert ist.

    Mehrfach-Vererbung von ``DocumentParserError`` (Projekt-Konvention)
    und ``ImportError`` (Python-Standard) - so kann der Aufrufer
    entweder projektweit oder standardkonform reagieren.
    """


# ---------------------------------------------------------------------------
# Hilfsfunktionen
# ---------------------------------------------------------------------------


def is_pypdf_available() -> bool:
    """Prueft, ob ``pypdf`` installiert und importierbar ist.

    Diese Funktion ist ein dünner Wrapper, der das Modul-Flag
    ``_PYPDF_AVAILABLE`` exponiert ohne interne Details zu leaken.

    Returns:
        ``True`` wenn ``pypdf`` importiert werden konnte.
    """
    return _PYPDF_AVAILABLE


def _get_pypdf() -> ModuleType:
    """Lazy lookup des pypdf-Moduls.

    Returns:
        Das ``pypdf``-Modul.

    Raises:
        PdfDependencyMissingError: Wenn ``pypdf`` nicht installiert ist.
    """
    if pypdf is None or not _PYPDF_AVAILABLE:
        raise PdfDependencyMissingError(
            "pypdf is not installed. Install via 'pip install aethelgard[pdf]'."
        )
    return pypdf


def _classify_pypdf_error(
    exc: BaseException,
    file_path: Path,
) -> PdfParseError:
    """Mappt eine pypdf-Exception auf eine spezifische Custom-Exception.

    Args:
        exc: Die originale pypdf-Exception.
        file_path: Pfad zur PDF-Datei (fuer Fehlermeldung).

    Returns:
        Passende Custom-Exception (Subklasse von ``PdfParseError``).
    """
    if _pypdf_errors is None:
        return PdfParseError("PDF parse error in %s: %s" % (file_path, exc))
    errors_mod = _pypdf_errors
    if isinstance(exc, errors_mod.EmptyFileError):
        return CorruptPdfError("PDF is empty: %s" % file_path)
    if isinstance(exc, errors_mod.ParseError):
        return CorruptPdfError("File is not a valid PDF (parse error): %s" % file_path)
    if isinstance(exc, errors_mod.FileNotDecryptedError):
        return EncryptedPdfError("PDF is password-protected: %s" % file_path)
    if isinstance(exc, errors_mod.WrongPasswordError):
        return EncryptedPdfError("PDF wrong password: %s" % file_path)
    return PdfParseError("PDF parse error in %s: %s" % (file_path, exc))


# ---------------------------------------------------------------------------
# Public API - Streaming
# ---------------------------------------------------------------------------


def stream_pdf_pages(
    path: Path | str,
    *,
    strict: bool = True,
) -> Iterator[str]:
    """Streamt Text-Inhalt aus einer PDF-Datei seitenweise.

    Diese Funktion ist ein **Generator** und arbeitet strikt **lazy**:

    - Die PDF-Datei wird NICHT komplett in den Speicher geladen.
    - ``pypdf`` erhaelt einen offenen File-Handle (``open(..., "rb")``)
      und liest Seiten on-demand.
    - Pro ``yield`` wird nur der Text **einer** Seite emittiert.
    - Bei ``break`` aus der Aufrufer-Schleife wird der File-Handle
      sauber geschlossen (Python schliesst Generatoren mit ``__exit__``).

    Args:
        path: Pfad zur PDF-Datei (str oder ``Path``).
        strict: Wenn ``True`` (Default), fuehren Strukturfehler einzelner
            Seiten zu ``CorruptPdfError``. Bei ``False`` werden
            fehlerhafte Seiten mit WARNING uebersprungen.

    Yields:
        Text-Inhalt jeder erfolgreich extrahierten Seite. Leere Seiten
        (z. B. Bilder ohne Text) werden uebersprungen.

    Raises:
        FileNotFoundError: Wenn ``path`` nicht existiert.
        IsADirectoryError: Wenn ``path`` ein Verzeichnis ist.
        FileSizeLimitExceededError: Bei Dateien > ``MAX_FILE_SIZE_BYTES`` (50 MB).
        PdfDependencyMissingError: Wenn ``pypdf`` nicht installiert ist.
        EncryptedPdfError: Wenn das PDF passwortpflichtig ist.
        CorruptPdfError: Bei strukturell beschaedigten PDFs (nur ``strict=True``).
        PdfParseError: Bei sonstigen Lese-/Extraktionsfehlern.

    Examples:
        >>> for page_text in stream_pdf_pages("policy.pdf"):
        ...     print(page_text[:80])  # erste 80 Zeichen pro Seite
    """
    file_path = Path(path)

    if not file_path.exists():
        raise FileNotFoundError("File not found: %s" % file_path)
    if not file_path.is_file():
        raise IsADirectoryError("Path is not a file: %s" % file_path)

    file_size = file_path.stat().st_size
    if file_size > MAX_FILE_SIZE_BYTES:
        raise FileSizeLimitExceededError(
            "PDF too large: %d bytes (max %d): %s" % (file_size, MAX_FILE_SIZE_BYTES, file_path)
        )

    _LOGGER.info("stream_pdf_pages: %s (%d bytes)", file_path, file_size)

    pypdf_lib = _get_pypdf()

    with file_path.open("rb") as file_handle:
        try:
            reader = pypdf_lib.PdfReader(file_handle, strict=strict)
        except _PYPDF_READ_EXCEPTIONS as exc:
            _LOGGER.warning("PDF read failed for %s: %s", file_path, exc)
            raise _classify_pypdf_error(exc, file_path) from exc

        if reader.is_encrypted:
            raise EncryptedPdfError("PDF is encrypted (password required): %s" % file_path)

        page_count = 0
        for page_idx, page in enumerate(reader.pages, start=1):
            if page_idx > MAX_PDF_PAGES:
                _LOGGER.warning(
                    "PDF %s exceeds page limit (%d), stopping",
                    file_path,
                    MAX_PDF_PAGES,
                )
                break
            page_count += 1
            try:
                text = page.extract_text()
            except _PYPDF_READ_EXCEPTIONS as exc:
                if strict:
                    raise CorruptPdfError(
                        "Failed to extract text from page %d of %s: %s" % (page_idx, file_path, exc)
                    ) from exc
                _LOGGER.warning(
                    "Skipping corrupt page %d of %s: %s",
                    page_idx,
                    file_path,
                    exc,
                )
                continue
            if text:
                yield text

        _LOGGER.debug(
            "stream_pdf_pages completed: %d pages from %s",
            page_count,
            file_path,
        )


# ---------------------------------------------------------------------------
# Public API - Convenience
# ---------------------------------------------------------------------------


def extract_pdf_text(
    path: Path | str,
    *,
    page_separator: str = DEFAULT_PAGE_SEPARATOR,
    strict: bool = True,
) -> str:
    """Extrahiert den gesamten Text einer PDF-Datei in einen einzelnen String.

    Convenience-Wrapper um ``stream_pdf_pages``, der alle Seiten
    materialisiert. **Vorsicht**: Laedt den gesamten Text in den
    Speicher (typischerweise 2-10 % der PDF-Dateigroesse). Fuer
    grosse PDFs oder Streaming-Szenarien sollte
    ``stream_pdf_pages`` direkt verwendet werden.

    Args:
        path: Pfad zur PDF-Datei.
        page_separator: String zwischen den Seiten (Default: zwei Newlines).
        strict: Siehe ``stream_pdf_pages``.

    Returns:
        Vollstaendiger Text-Inhalt der PDF-Datei, getrennt durch
        ``page_separator``.

    Raises:
        Siehe ``stream_pdf_pages``.
    """
    return page_separator.join(stream_pdf_pages(path, strict=strict))
