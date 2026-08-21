"""Strikt typisierte Schemas fuer AethelGard MVP1.

Dieses Modul enthaelt ausschliesslich pydantic-Modelle, die als Datenvertrag
zwischen Parser, Pipeline und Downstream-Consumern dienen. Alle Modelle sind
``frozen=True`` und ``extra='forbid'``, um unbemerkte Schema-Drift zu
verhindern.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field


class ComplianceEvidence(BaseModel):
    """Strikt typisiertes Schema fuer einen einzelnen Compliance-Nachweis.

    Ein ``ComplianceEvidence``-Objekt repraesentiert einen aus einem
    Quelldokument extrahierten Text-Chunk um ein Compliance-Keyword herum.
    Es bildet die kleinste semantische Einheit, die spaetere Stufen der
    Pipeline (Klassifikation, Reporting, Audit) konsumieren.

    Attributes:
        requirement_id: Eindeutige Kennung der NIS-2-Anforderung
            (z. B. ``"NIS2-ART-21(1)(a)"``). Wird zur Aggregation und zum
            Reporting verwendet.
        is_compliant: Heuristische Konformitaetsbewertung dieses Chunks.
            ``True`` bedeutet, dass der Chunk die Anforderung erfuellt,
            ``False`` bedeutet, dass ein Verstoss oder eine Luecke
            detektiert wurde.
        confidence_score: Numerisches Vertrauen in die Bewertung als
            Gleitkommazahl im Intervall ``[0.0, 1.0]``. Werte nahe ``1.0``
            sind sehr sicher, Werte nahe ``0.0`` sind Spekulation.
        source_citation: Direktes Zitat oder exakter Text-Snippet aus dem
            Quelldokument (max. 2000 Zeichen), das die Bewertung
            nachvollziehbar macht. Darf keine Zeilenumbrueche enthalten,
            um Downstream-Renderer nicht zu brechen.
    """

    model_config = ConfigDict(
        frozen=True,
        extra="forbid",
        str_strip_whitespace=True,
        validate_assignment=True,
    )

    requirement_id: str = Field(
        min_length=1,
        max_length=100,
        description="Eindeutige NIS-2-Anforderungs-ID.",
    )
    is_compliant: bool = Field(
        description="Heuristische Konformitaetsbewertung dieses Chunks.",
    )
    confidence_score: float = Field(
        ge=0.0,
        le=1.0,
        description="Vertrauen in die Bewertung im Intervall [0.0, 1.0].",
    )
    source_citation: str = Field(
        min_length=1,
        max_length=2000,
        description="Direktes Zitat aus dem Quelldokument (eine Zeile).",
    )
