"""AethelGard MVP1 - Lokale Klassifikations-Engine.

Dieses Modul stellt eine ressourceneffiziente, deterministische
Klassifikations-Engine fuer extrahierte Text-Chunks bereit. Sie nutzt eine
mathematische Heuristik (kein ML-Modell, keine externen Dependencies) und
produziert strikt typisierte ``ComplianceEvidence``-Instanzen.

Architektur-Hinweise:
    - **Kein ONNX, kein numpy, keine schweren ML-Frameworks.** Die Engine
      arbeitet rein auf String-Operationen und einer einfachen
      mathematischen Formel. Sie ist bewusst so dimensioniert, dass sie
      auf einer 16 GB Workstation laeuft.
    - **Deterministisch**: Bei gleicher Eingabe wird stets die gleiche
      Ausgabe produziert (kein Zufalls-Sampling, keine probabilistischen
      Modelle).
    - **Pure Functions**: ``compute_heuristic_score`` ist seiteneffekt-frei
      und einzeln testbar.
    - **Zweistufige Bewertung** (Stufe 1 dieser Implementierung):
      1. ``compute_heuristic_score`` berechnet einen numerischen Score
         auf Basis von Boost- und Penalty-Termen.
      2. ``evaluate_chunk`` mappt das Ergebnis deterministisch in
         ``is_compliant`` (Score-Schwelle + harter Check auf
         kritische Penalty-Terme).
    - **Stufe 2 (Vorbereitung fuer ONNX)**: Eine zukuenftige
      Sequence-Classifier-Integration kann ``evaluate_chunk`` ersetzen
      oder ergaenzen, ohne die externe API zu brechen (gleiche
      Signatur, gleiches Rueckgabe-Schema).
"""

from __future__ import annotations

import logging
from typing import Final

from aethelgard.mvp1.document_parser import DocumentParserError
from aethelgard.mvp1.schemas import ComplianceEvidence

_LOGGER: Final[logging.Logger] = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Konstanten - Scoring
# ---------------------------------------------------------------------------

#: Basis-Score, der jedem klassifizierten Chunk zugeteilt wird.
#: Der Score wird durch Boost/Penalty-Terme angepasst.
BASE_SCORE: Final[float] = 0.5

#: Inkrement pro gefundenem Boost-Term (Addition auf den Basis-Score).
BOOST_DELTA: Final[float] = 0.05

#: Maximaler Boost durch Boost-Terme (Cap der kumulierten Boosts).
BOOST_CAP: Final[float] = 0.2

#: Dekrement pro gefundenem Penalty-Term (Subtraktion vom Basis-Score).
PENALTY_DELTA: Final[float] = 0.1

#: Maximaler Penalty durch Penalty-Terme (Cap der kumulierten Penalties).
PENALTY_CAP: Final[float] = 0.3

#: Untere Grenze des Confidence-Score (immer clamp).
SCORE_MIN: Final[float] = 0.0

#: Obere Grenze des Confidence-Score (immer clamp).
SCORE_MAX: Final[float] = 1.0

#: Schwellwert, ab dem ein Chunk als konform eingestuft wird,
#: sofern kein kritischer Penalty-Term vorliegt.
COMPLIANCE_THRESHOLD: Final[float] = 0.7

# ---------------------------------------------------------------------------
# NIS-2-spezifische Term-Sets
# ---------------------------------------------------------------------------

#: Boost-Terme: NIS-2-relevantes Vokabular, das auf substantielle Aussagen
#: zur Konformitaet hinweist. Substantielle, etablierte Begriffe.
BOOST_TERMS: Final[frozenset[str]] = frozenset(
    {
        "verfahren",
        "dokumentiert",
        "umgesetzt",
        "implementiert",
        "verpflichtet",
        "richtlinie",
        "kontinuierlich",
        "regelmaessig",
        "risikoanalyse",
        "sicherheitsvorfall",
        "meldepflicht",
        "audit",
        "approved",
        "continuous",
        "documented",
        "implemented",
        "monitored",
        "owner",
        "policy",
        "procedure",
        "regularly",
        "review",
        "tested",
    }
)

#: Penalty-Terme: NIS-2-relevantes Vokabular, das auf Luecken oder
#: Verstoesse hinweist.
PENALTY_TERMS: Final[frozenset[str]] = frozenset(
    {
        "fehlt",
        "luecke",
        "nicht umgesetzt",
        "nicht dokumentiert",
        "verstoss",
        "unzureichend",
        "mangelhaft",
        "nicht definiert",
        "ad hoc",
        "gap",
        "intentionally avoids",
        "missing",
        "no evidence",
        "no owner",
        "no review",
        "not defined",
        "not documented",
        "not implemented",
        "planned only",
        "unclear",
        "vague",
    }
)

#: Kritische Penalty-Terme: Subset der Penalty-Terme, deren blosses
#: Vorhandensein im Chunk ``is_compliant`` zwingend auf ``False`` setzt,
#: unabhaengig vom numerischen Score. Dies verhindert, dass ein formal
#: hoher Score einen offensichtlichen Verstoss verschleiert.
CRITICAL_PENALTY_TERMS: Final[frozenset[str]] = frozenset(
    {
        "verstoss",
        "luecke",
        "nicht definiert",
        "mangelhaft",
        "gap",
        "missing",
        "no evidence",
        "no review",
        "not defined",
        "not documented",
    }
)


# ---------------------------------------------------------------------------
# Custom Exceptions
# ---------------------------------------------------------------------------


class ClassifierError(DocumentParserError, ValueError):
    """Wird ausgeloest, wenn der Klassifikator ungueltige Eingaben erhaelt.

    Mehrfach-Vererbung von ``DocumentParserError`` (Projekt-Konvention) und
    ``ValueError`` (Python-Standard fuer ungueltige Werte).
    """


# ---------------------------------------------------------------------------
# Hilfsfunktionen
# ---------------------------------------------------------------------------


def _clamp(value: float, lower: float, upper: float) -> float:
    """Begrenzt ``value`` auf das Intervall ``[lower, upper]``.

    Args:
        value: Zu begrenzender Wert.
        lower: Untere Grenze (inklusive).
        upper: Obere Grenze (inklusive).

    Returns:
        ``value`` begrenzt auf ``[lower, upper]``.
    """
    if value < lower:
        return lower
    if value > upper:
        return upper
    return value


# ---------------------------------------------------------------------------
# Public API - Heuristik
# ---------------------------------------------------------------------------


def compute_heuristic_score(
    chunk: str,
    boost_terms: list[str] | tuple[str, ...] | frozenset[str],
    penalty_terms: list[str] | tuple[str, ...] | frozenset[str],
) -> float:
    """Berechnet den Heuristik-Score fuer einen Text-Chunk.

    Die Funktion ist **pure** (seiteneffekt-frei) und damit ideal testbar.
    Die Berechnung folgt strikt der NIS-2-Formel:

    1. **Basis**: ``BASE_SCORE`` (0.5)
    2. **Boost**: ``+BOOST_DELTA`` (0.05) pro gefundenem Boost-Term,
       kumuliert bis maximal ``BOOST_CAP`` (0.2).
    3. **Penalty**: ``-PENALTY_DELTA`` (0.1) pro gefundenem Penalty-Term,
       kumuliert bis maximal ``PENALTY_CAP`` (0.3) in der Magnitude.
    4. **Clamp**: Ergebnis wird auf ``[SCORE_MIN, SCORE_MAX]``
       (= ``[0.0, 1.0]``) begrenzt.

    Args:
        chunk: Zu bewertender Text-Chunk. Bei leerem String wird ``0.0``
            zurueckgegeben (kein Treffer = kein Vertrauen).
        boost_terms: Iterierbare Sammlung von Begriffen, die den Score
            erhoehen. Case-insensitive.
        penalty_terms: Iterierbare Sammlung von Begriffen, die den Score
            verringern. Case-insensitive.

    Returns:
        Confidence-Score im Intervall ``[SCORE_MIN, SCORE_MAX]`` (=
        ``[0.0, 1.0]``).

    Examples:
        >>> compute_heuristic_score("verfahren dokumentiert", ["verfahren"], [])
        0.55
        >>> compute_heuristic_score("verstoss", [], ["verstoss"])
        0.4
    """
    if not chunk or not chunk.strip():
        return SCORE_MIN

    chunk_lower = chunk.lower()

    boost_hits = sum(1 for term in boost_terms if term and term.lower() in chunk_lower)
    penalty_hits = sum(1 for term in penalty_terms if term and term.lower() in chunk_lower)

    boost_contribution = min(BOOST_CAP, BOOST_DELTA * boost_hits)
    penalty_contribution = min(PENALTY_CAP, PENALTY_DELTA * penalty_hits)

    raw_score = BASE_SCORE + boost_contribution - penalty_contribution
    return _clamp(raw_score, SCORE_MIN, SCORE_MAX)


# ---------------------------------------------------------------------------
# Public API - Klassifikation
# ---------------------------------------------------------------------------


def evaluate_chunk(
    chunk: str,
    requirement_id: str,
    keywords: list[str],
) -> ComplianceEvidence:
    """Klassifiziert einen Text-Chunk und liefert ein ``ComplianceEvidence``.

    Diese Funktion ist der zentrale Einstiegspunkt der Engine. Sie kombiniert
    die heuristische Score-Berechnung mit der deterministischen Ableitung
    des ``is_compliant``-Flags.

    **Mapping-Regeln**:
    - ``confidence_score`` = ``compute_heuristic_score(chunk, BOOST_TERMS, PENALTY_TERMS)``
    - ``is_compliant`` = ``True`` gdw.
      ``confidence_score >= COMPLIANCE_THRESHOLD`` **UND**
      kein kritischer Penalty-Term (``CRITICAL_PENALTY_TERMS``) im Chunk.
    - ``source_citation`` = der Chunk selbst (Original, untransformiert).
    - ``requirement_id`` = durchgereicht wie gegeben.

    Args:
        chunk: Zu bewertender Text-Chunk. Darf nicht leer sein.
        requirement_id: NIS-2-Anforderungs-ID (z. B. ``"NIS2-ART-21(1)(a)"``).
            Darf nicht leer sein.
        keywords: Liste der fuer diesen Chunk erwarteten Keywords.
            Aktuell **informativ** (wird in der Score-Formel nicht
            verwendet). Reserviert fuer zukuenftige Heuristik-Erweiterungen
            (z. B. Keyword-Dichte-Bonus).

    Returns:
        Strikt typisierte ``ComplianceEvidence``-Instanz mit
        deterministisch abgeleiteten Feldern.

    Raises:
        ClassifierError: Bei leerem Chunk oder leerer ``requirement_id``.
            Auch bei ``requirement_id`` laenger als 100 Zeichen
            (Schema-Constraint, wird hier fruehzeitig abgefangen).

    Examples:
        >>> ev = evaluate_chunk(
        ...     "verfahren dokumentiert umgesetzt implementiert audit",
        ...     "NIS2-ART-21",
        ...     ["verfahren"],
        ... )
        >>> ev.is_compliant
        True
        >>> ev.confidence_score >= 0.7
        True
    """
    if not isinstance(chunk, str) or not chunk.strip():
        raise ClassifierError("chunk must be a non-empty string")
    if not isinstance(requirement_id, str) or not requirement_id.strip():
        raise ClassifierError("requirement_id must be a non-empty string")
    if len(requirement_id) > 100:
        raise ClassifierError("requirement_id exceeds 100 chars: %d" % len(requirement_id))

    score = compute_heuristic_score(
        chunk=chunk,
        boost_terms=list(BOOST_TERMS),
        penalty_terms=list(PENALTY_TERMS),
    )

    chunk_lower = chunk.lower()
    has_critical_penalty = any(term in chunk_lower for term in CRITICAL_PENALTY_TERMS)
    is_compliant = bool(score >= COMPLIANCE_THRESHOLD and not has_critical_penalty)

    _LOGGER.debug(
        "evaluate_chunk: req=%s, score=%.3f, critical=%s, compliant=%s, "
        "keywords=%d (informational)",
        requirement_id,
        score,
        has_critical_penalty,
        is_compliant,
        len(keywords),
    )

    return ComplianceEvidence(
        requirement_id=requirement_id,
        is_compliant=is_compliant,
        confidence_score=score,
        source_citation=chunk,
    )
