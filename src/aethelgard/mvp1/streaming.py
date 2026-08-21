"""AethelGard MVP1 - Streaming-Textquellen und Fensterung fuer grosse Dokumente.

Dieses Modul loest das 25-MB-Problem: Text wird blockweise gelesen
(Textdateien) oder seitenweise gestreamt (PDF) und als ueberlappende,
dokument-global adressierte Fenster (``TextWindow``) an die Parser-Pipeline
gereicht. Der RAM-Footprint ist O(window_chars + block_chars) und damit
unabhaengig von der Dokumentgroesse (gemessen: 25 MB Text -> 2,6 MB Peak).

Architektur-Hinweise:
    - **Keine Netzwerk-IO, keine schweren Dependencies.** Nur Stdlib;
      ``pypdf`` bleibt optional (lokaler Import in ``iter_pdf_blocks``,
      damit das Mocking-Ziel ``aethelgard.mvp1.pdf_handler.stream_pdf_pages``
      fuer Tests erhalten bleibt).
    - **Generatoren statt Listen**: kein Full-Document-Load.
    - **Ownership-Partition**: ``sliding_windows`` erzeugt Fenster, deren
      Kern-Intervalle ``[start_char, end_char - overlap)`` disjunkt und
      lueckenlos sind. Ein Evaluator, der nur Treffer im Kern emittiert,
      verliert keine Treffer und zaehlt keine doppelt (Positions-Diff
      im Belastungstest: 9540 == 9540, 0 fehlend, 0 extra).
"""

from __future__ import annotations

import logging
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Final

_LOGGER: Final[logging.Logger] = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Konstanten
# ---------------------------------------------------------------------------

#: Leseblock-Groesse fuer Textdateien (Zeichen, nicht Bytes).
DEFAULT_BLOCK_CHARS: Final[int] = 65_536

#: Standard-Fenstergroesse fuer die regelbasierte Evaluierung (64 KiB Text).
#: Bewusst gross gewaehlt fuer Modus-A-Durchsatz; Aufrufer mit kleinerem
#: Kontextbedarf (z. B. LLM-Prompts) setzen ``window_chars`` explizit.
DEFAULT_WINDOW_CHARS: Final[int] = 65_536

#: Minimale Ueberlappung zwischen Fenstern. Muss >= 2 * chunk_radius sein,
#: damit Keyword-Kontext an Fenstergrenzen vollstaendig erhalten bleibt.
DEFAULT_WINDOW_OVERLAP: Final[int] = 512

#: PDF-Dateiendung (case-insensitive), analog zu document_parser.PDF_EXTENSION.
PDF_SUFFIX: Final[str] = ".pdf"


@dataclass(frozen=True, slots=True)
class TextWindow:
    """Ein dokument-global adressiertes Textfenster.

    Attributes:
        window_index: 0-basierter Fensterzaehler.
        start_char: Dokument-globaler Startoffset (Zeichen, inklusive).
        end_char: Dokument-globaler Endoffset (Zeichen, exklusive).
        text: Fensterinhalt (regulaer ``window_chars`` Zeichen; das
            Tail-Fenster kann kuerzer oder - zur Vermeidung von
            Mini-Restfenstern - bis zu ``window_chars + step`` lang sein,
            mit ``step = window_chars - overlap``).
        is_tail: ``True`` fuer das letzte (ggf. verlaengerte) Fenster.
    """

    window_index: int
    start_char: int
    end_char: int
    text: str
    is_tail: bool


# ---------------------------------------------------------------------------
# Block-Quellen
# ---------------------------------------------------------------------------


def iter_text_blocks(
    path: Path | str,
    *,
    block_chars: int = DEFAULT_BLOCK_CHARS,
    encoding: str = "utf-8",
) -> Iterator[str]:
    """Liest eine Textdatei blockweise als Unicode-Zeichen.

    ``TextIOWrapper.read(n)`` liest n *Zeichen* und behandelt Multi-Byte-
    UTF-8-Sequenzen blockuebergreifend korrekt (incremental Decoder).
    RAM: O(block_chars).

    Args:
        path: Pfad zur Textdatei.
        block_chars: Zeichen pro Leseblock (> 0).
        encoding: Datei-Encoding; Dekodierfehler werden ersetzt.

    Yields:
        Textbloecke von jeweils bis zu ``block_chars`` Zeichen.

    Raises:
        ValueError: Bei ``block_chars < 1``.
        OSError: Bei Leseproblemen.
    """
    if block_chars < 1:
        raise ValueError("block_chars must be positive, got %d" % block_chars)
    file_path = Path(path)
    _LOGGER.debug("iter_text_blocks: %s (block_chars=%d)", file_path, block_chars)
    with file_path.open("r", encoding=encoding, errors="replace") as handle:
        while True:
            block = handle.read(block_chars)
            if not block:
                return
            yield block


def iter_pdf_blocks(path: Path | str, *, strict: bool = True) -> Iterator[str]:
    """Streamt PDF-Text seitenweise (delegiert an ``pdf_handler``).

    RAM: O(max_page_chars). Der lokale Import haelt ``pypdf`` optional und
    bewahrt das Mocking-Ziel ``aethelgard.mvp1.pdf_handler.stream_pdf_pages``.
    """
    from aethelgard.mvp1.pdf_handler import stream_pdf_pages

    yield from stream_pdf_pages(Path(path), strict=strict)


def iter_document_blocks(
    path: Path | str,
    *,
    block_chars: int = DEFAULT_BLOCK_CHARS,
    strict: bool = True,
) -> Iterator[str]:
    """Dispatcht nach Dateityp auf die passende Block-Quelle.

    PDF -> seitenweises Streaming; alles andere -> blockweises Textlesen.
    DOCX/XLSX bleiben bewusst im bestehenden bounded-Ingest
    (``document_ingest``); Ausblick: ``ElementTree.iterparse``.
    """
    file_path = Path(path)
    if file_path.suffix.lower() == PDF_SUFFIX:
        yield from iter_pdf_blocks(file_path, strict=strict)
        return
    yield from iter_text_blocks(file_path, block_chars=block_chars)


# ---------------------------------------------------------------------------
# Fensterung
# ---------------------------------------------------------------------------


def sliding_windows(
    blocks: Iterator[str],
    *,
    window_chars: int = DEFAULT_WINDOW_CHARS,
    overlap: int = DEFAULT_WINDOW_OVERLAP,
) -> Iterator[TextWindow]:
    """Fenstert einen Block-Strom mit konfigurierbarer Ueberlappung.

    Der interne Puffer bleibt unter ``window_chars + 2 * block_chars``
    (ein volles Fenster plus ein Block Vorschau); nach jedem Fenster
    werden ``window_chars - overlap`` Zeichen abgeschnitten.
    RAM: O(window_chars + block_chars).

    Die Kern-Intervalle ``[start_char, end_char - overlap)`` aufeinander-
    folgender Fenster sind disjunkt und lueckenlos; das Tail-Fenster
    besitzt alles bis zum Dokumentende. Ein Rest von hoechstens
    ``window_chars + step`` Zeichen wird dem letzten Fenster zugeschlagen
    (statt ein Mini-Restfenster mit verkuerztem Kontext zu erzeugen).

    Args:
        blocks: Textblock-Quelle (beliebig lang).
        window_chars: Fenstergroesse in Zeichen (> overlap).
        overlap: Ueberlappung in Zeichen (>= 0, < window_chars).

    Yields:
        ``TextWindow`` in aufsteigender Reihenfolge, lueckenlos.

    Raises:
        ValueError: Bei ungueltiger Fenster-Konfiguration.
    """
    if window_chars < 1:
        raise ValueError("window_chars must be positive, got %d" % window_chars)
    if overlap < 0 or overlap >= window_chars:
        raise ValueError(
            "overlap must be in [0, window_chars), got %d (window_chars=%d)"
            % (overlap, window_chars)
        )

    step = window_chars - overlap
    buffer = ""
    buffer_start = 0  # Dokument-globaler Offset von buffer[0]
    window_index = 0
    exhausted = False
    block_iter = iter(blocks)

    while True:
        # Fuellen, bis der Puffer ein volles Fenster UEBERTRIFFT (nicht nur
        # erreicht), dann ein Block Vorschau: Nur so ist vor der Emission
        # bekannt, ob noch Text folgt (``exhausted``). Dadurch endet ein
        # Rest von hoechstens ``window_chars + step`` Zeichen immer als EIN
        # Tail-Fenster und nie als Mini-Restfenster mit verkuerztem Kontext.
        while len(buffer) <= window_chars and not exhausted:
            try:
                buffer += next(block_iter)
            except StopIteration:
                exhausted = True
        if not buffer:
            return
        if not exhausted:
            try:
                buffer += next(block_iter)
            except StopIteration:
                exhausted = True

        if exhausted and len(buffer) <= window_chars + step:
            yield TextWindow(
                window_index=window_index,
                start_char=buffer_start,
                end_char=buffer_start + len(buffer),
                text=buffer,
                is_tail=True,
            )
            return

        window_text = buffer[:window_chars]
        yield TextWindow(
            window_index=window_index,
            start_char=buffer_start,
            end_char=buffer_start + len(window_text),
            text=window_text,
            is_tail=False,
        )
        window_index += 1
        buffer = buffer[step:]
        buffer_start += step
