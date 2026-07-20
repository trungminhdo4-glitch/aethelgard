"""AethelGard MVP1 - Evaluator-Abstraktion ueber der Streaming-Fensterung.

Trennt die Dokumentenquelle von der Bewertung: Die Pipeline
(``run_pipeline``) kennt nur das ``ChunkEvaluator``-Protokoll und ist damit
modus-agnostisch. ``RuleBasedEvaluator`` ist die Modus-A-Implementierung
(rein regelbasiert, deterministisch, keine KI-Dependency); spaetere Modi
(lokale KI, externe API, MCP-Fassade) implementieren dasselbe Protokoll.

Gegenueber dem klassischen ``LocalDocumentParser``-Pfad loest der
Evaluator zwei gemessene Probleme grosser Dokumente:

- **Ownership-Partition**: Fenster ``i`` besitzt alle Treffer-Positionen
  ``[s_i, s_i + step)`` (``step = window_chars - overlap``). Diese
  Intervalle sind disjunkt und lueckenlos; wegen ``overlap >= 2 *
  chunk_radius`` hat jeder besessene Treffer seinen vollen rechten
  Kontext im Fenster. Ergebnis: kein Doppelzaehlen, kein Kontextverlust.
- **Deduplizierung**: identische Zitate pro Requirement werden nur
  einmal emittiert (Boilerplate-Schutz; Belastungstest Dense-Dokument:
  10 000 Treffer -> 3 einzigartige Zitate).
"""

from __future__ import annotations

import hashlib
import logging
from collections.abc import Iterator, Mapping, Sequence
from pathlib import Path
from typing import Final, Protocol

from aethelgard.mvp1.classifier import evaluate_chunk
from aethelgard.mvp1.document_parser import (
    DEFAULT_CHUNK_RADIUS,
    extract_chunk,
    locate_keyword_positions,
)
from aethelgard.mvp1.schemas import ComplianceEvidence
from aethelgard.mvp1.streaming import (
    DEFAULT_WINDOW_CHARS,
    DEFAULT_WINDOW_OVERLAP,
    TextWindow,
    iter_document_blocks,
    sliding_windows,
)

_LOGGER: Final[logging.Logger] = logging.getLogger(__name__)


class ChunkEvaluator(Protocol):
    """Einheitliche Schnittstelle aller Evaluierungs-Modi.

    Implementierungen duerfen internen State halten (Dedupe, Batching),
    muessen ihn aber ueber ``finalize`` abschliessen.
    """

    def evaluate(self, window: TextWindow) -> tuple[ComplianceEvidence, ...]:
        """Bewertet ein Fenster und liefert 0..n Evidenzen."""
        ...

    def finalize(self) -> tuple[ComplianceEvidence, ...]:
        """Schliesst die Auswertung ab (Default: keine Restarbeit)."""
        ...


class RuleBasedEvaluator:
    """Modus A: deterministische Keyword-/Heuristik-Evaluierung (no KI).

    Nutzt die bestehenden Bausteine ``locate_keyword_positions``,
    ``extract_chunk`` und ``classifier.evaluate_chunk`` - die Bewertungs-
    logik selbst bleibt unveraendert. Neu sind Ownership-Partition und
    Zitat-Deduplizierung (sha256 ueber Requirement + casefold-Zitat).
    """

    __slots__ = ("_chunk_radius", "_dedupe_seen", "_keywords", "_overlap", "_requirement_map")

    def __init__(
        self,
        keywords: Sequence[str],
        *,
        requirement_map: Mapping[str, str] | None = None,
        chunk_radius: int = DEFAULT_CHUNK_RADIUS,
        overlap: int = DEFAULT_WINDOW_OVERLAP,
    ) -> None:
        """Initialisiert den Evaluator.

        Args:
            keywords: Schluesselwoerter (case-insensitive, mind. eines).
            requirement_map: Optionales Mapping ``keyword -> requirement_id``.
            chunk_radius: Radius (Zeichen) um jeden Treffer (> 0).
            overlap: Fenster-Ueberlappung; muss >= ``2 * chunk_radius``
                sein, damit der Kern-Bereich vollen Treffer-Kontext hat.

        Raises:
            ValueError: Bei ungueltiger Konfiguration.
        """
        if not keywords:
            raise ValueError("keywords must not be empty")
        if chunk_radius < 1:
            raise ValueError("chunk_radius must be positive, got %d" % chunk_radius)
        if overlap < 2 * chunk_radius:
            raise ValueError(
                "overlap must be >= 2 * chunk_radius (%d), got %d" % (2 * chunk_radius, overlap)
            )
        self._keywords: Final[tuple[str, ...]] = tuple(dict.fromkeys(keywords))
        self._requirement_map: Final[dict[str, str]] = {
            key.strip().lower(): value
            for key, value in (requirement_map or {}).items()
            if key.strip()
        }
        self._chunk_radius: Final[int] = chunk_radius
        self._overlap: Final[int] = overlap
        self._dedupe_seen: set[tuple[str, str]] = set()

    def reset(self) -> None:
        """Leert den Dedupe-State (pro Dokument aufrufen)."""
        self._dedupe_seen.clear()

    def evaluate(self, window: TextWindow) -> tuple[ComplianceEvidence, ...]:
        """Emittiert Evidenzen fuer Treffer im besessenen Kern des Fensters."""
        core_end = len(window.text) if window.is_tail else len(window.text) - self._overlap
        found: list[ComplianceEvidence] = []
        for position, keyword in locate_keyword_positions(window.text, self._keywords):
            if position >= core_end:
                break  # Positionen sind aufsteigend sortiert.
            chunk = extract_chunk(window.text, position, self._chunk_radius)
            if not chunk:
                continue
            requirement_id = self._requirement_map.get(keyword.lower()) or keyword.upper()
            dedupe_key = (
                requirement_id,
                hashlib.sha256(chunk.casefold().encode("utf-8")).hexdigest(),
            )
            if dedupe_key in self._dedupe_seen:
                continue
            self._dedupe_seen.add(dedupe_key)
            found.append(
                evaluate_chunk(
                    chunk=chunk,
                    requirement_id=requirement_id,
                    keywords=list(self._keywords),
                )
            )
        return tuple(found)

    def finalize(self) -> tuple[ComplianceEvidence, ...]:
        """Keine Restarbeit (regelbasiert ist sofortig)."""
        return ()


def run_pipeline(
    path: Path | str,
    evaluator: ChunkEvaluator,
    *,
    window_chars: int = DEFAULT_WINDOW_CHARS,
    overlap: int = DEFAULT_WINDOW_OVERLAP,
    strict: bool = True,
) -> Iterator[ComplianceEvidence]:
    """Streamt ein Dokument durch Fensterung und Evaluator.

    Lazy: Evidenzen werden emittiert, sobald der Evaluator sie liefert.
    RAM: O(window_chars + block_chars + evaluator_state).

    Args:
        path: Pfad zur Text- oder PDF-Datei.
        evaluator: Beliebige ``ChunkEvaluator``-Implementierung.
        window_chars: Fenstergroesse in Zeichen (> overlap).
        overlap: Fenster-Ueberlappung (>= 2 * chunk_radius des Evaluators).
        strict: PDF-Fehlerbehandlung (durchgereicht).

    Yields:
        ``ComplianceEvidence`` in Dokumentreihenfolge.
    """
    _LOGGER.info(
        "run_pipeline: %s (window=%d, overlap=%d, evaluator=%s)",
        path,
        window_chars,
        overlap,
        type(evaluator).__name__,
    )
    blocks = iter_document_blocks(path, strict=strict)
    for window in sliding_windows(blocks, window_chars=window_chars, overlap=overlap):
        yield from evaluator.evaluate(window)
    yield from evaluator.finalize()
