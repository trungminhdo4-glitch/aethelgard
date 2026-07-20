"""Tests fuer den Streaming-Pfad von ``LocalDocumentParser``.

Der Parser schaltet Textdateien oberhalb ``STREAMING_TEXT_THRESHOLD_BYTES``
auf den Fenster-Streaming-Pfad um. Die Tests patchen die Schwelle, damit
kleine tmp-Dateien den Streaming-Pfad ausloesen, und pruefen die
Ergebnis-Identitaet mit dem klassischen Pfad.
"""

from __future__ import annotations

import tempfile
import unittest
from collections.abc import Iterator
from pathlib import Path
from unittest import mock

from aethelgard.mvp1.document_parser import (
    STREAMING_TEXT_THRESHOLD_BYTES,
    LocalDocumentParser,
)

PARSER_MODULE = "aethelgard.mvp1.document_parser"
POSITIVE_SENTENCE = "verfahren dokumentiert umgesetzt implementiert audit"
NEGATIVE_SENTENCE = "luecke im verfahren, nicht dokumentiert und unzureichend"


def _build_document(evidence_count: int = 6) -> str:
    filler = "allgemeine organisationsbeschreibung ohne besonderes signal. " * 15 + "\n"
    parts: list[str] = []
    for i in range(evidence_count):
        parts.append(filler)
        parts.append("abschnitt %02d: %s.\n" % (i, POSITIVE_SENTENCE))
    return "".join(parts)


class TestParseAndClassifyStreaming(unittest.TestCase):
    """Streaming-Dispatch und Ergebnis-Identitaet (Classifier-Semantik)."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(self._tmp.name)
        self.doc_path = self.root / "controls.txt"
        self.doc_path.write_text(_build_document(), encoding="utf-8")

    def _parse_with_threshold(self, threshold: int) -> list[tuple[str, str, bool, float]]:
        parser = LocalDocumentParser(keywords=["verfahren"], chunk_radius=150)
        with mock.patch(PARSER_MODULE + ".STREAMING_TEXT_THRESHOLD_BYTES", threshold):
            return [
                (e.requirement_id, e.source_citation, e.is_compliant, e.confidence_score)
                for e in parser.parse_and_classify(self.doc_path)
            ]

    def test_default_threshold_is_above_fixtures(self) -> None:
        self.assertEqual(STREAMING_TEXT_THRESHOLD_BYTES, 4 * 1024 * 1024)
        self.assertLess(self.doc_path.stat().st_size, STREAMING_TEXT_THRESHOLD_BYTES)

    def test_stream_results_match_classic_results(self) -> None:
        classic = self._parse_with_threshold(10 * 1024 * 1024)
        streamed = self._parse_with_threshold(1_024)
        self.assertEqual(len(streamed), 6)
        self.assertEqual(streamed, classic)

    def test_stream_returns_iterator(self) -> None:
        parser = LocalDocumentParser(keywords=["verfahren"])
        with mock.patch(PARSER_MODULE + ".STREAMING_TEXT_THRESHOLD_BYTES", 1):
            result = parser.parse_and_classify(self.doc_path)
        self.assertIsInstance(result, Iterator)

    def test_chunk_radius_too_large_for_window_raises(self) -> None:
        parser = LocalDocumentParser(keywords=["verfahren"], chunk_radius=40_000)
        with mock.patch(PARSER_MODULE + ".STREAMING_TEXT_THRESHOLD_BYTES", 1):
            with self.assertRaises(ValueError):
                list(parser.parse_and_classify(self.doc_path))

    def test_whitespace_only_stream_yields_nothing(self) -> None:
        blank = self.root / "blank.txt"
        blank.write_text("   \n\t  \n", encoding="utf-8")
        parser = LocalDocumentParser(keywords=["verfahren"])
        with mock.patch(PARSER_MODULE + ".STREAMING_TEXT_THRESHOLD_BYTES", 1):
            self.assertEqual(list(parser.parse_and_classify(blank)), [])

    def test_requirement_map_used_in_stream(self) -> None:
        parser = LocalDocumentParser(
            keywords=["verfahren"],
            requirement_map={"verfahren": "NIS2-ART-21(1)(a)"},
        )
        with mock.patch(PARSER_MODULE + ".STREAMING_TEXT_THRESHOLD_BYTES", 1):
            results = list(parser.parse_and_classify(self.doc_path))
        self.assertTrue(results)
        self.assertTrue(all(r.requirement_id == "NIS2-ART-21(1)(a)" for r in results))


class TestParseFileStreaming(unittest.TestCase):
    """Streaming-Dispatch und Functional-Semantik (compute_confidence)."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(self._tmp.name)
        self.doc_path = self.root / "controls.txt"
        self.doc_path.write_text(_build_document(), encoding="utf-8")

    def test_parse_file_stream_results_match_classic(self) -> None:
        parser = LocalDocumentParser(keywords=["verfahren"], chunk_radius=150)
        with mock.patch(PARSER_MODULE + ".STREAMING_TEXT_THRESHOLD_BYTES", 10 * 1024 * 1024):
            classic = [
                (e.requirement_id, e.source_citation, e.is_compliant, e.confidence_score)
                for e in parser.parse_file(self.doc_path)
            ]
        with mock.patch(PARSER_MODULE + ".STREAMING_TEXT_THRESHOLD_BYTES", 1_024):
            streamed = [
                (e.requirement_id, e.source_citation, e.is_compliant, e.confidence_score)
                for e in parser.parse_file(self.doc_path)
            ]
        self.assertEqual(len(streamed), 6)
        self.assertEqual(streamed, classic)

    def test_min_confidence_filter_applies_in_stream(self) -> None:
        strict_parser = LocalDocumentParser(keywords=["verfahren"], min_confidence=0.99)
        lenient_parser = LocalDocumentParser(keywords=["verfahren"], min_confidence=0.6)
        with mock.patch(PARSER_MODULE + ".STREAMING_TEXT_THRESHOLD_BYTES", 1):
            self.assertEqual(list(strict_parser.parse_file(self.doc_path)), [])
        with mock.patch(PARSER_MODULE + ".STREAMING_TEXT_THRESHOLD_BYTES", 1):
            self.assertEqual(len(list(lenient_parser.parse_file(self.doc_path))), 6)

    def test_negative_context_marks_non_compliant_in_stream(self) -> None:
        path = self.root / "gap.txt"
        path.write_text(NEGATIVE_SENTENCE, encoding="utf-8")
        # Score 0.25 (0.5 + 0.05 Boost - 0.3 Penalty): min_confidence 0.2 noetig.
        parser = LocalDocumentParser(keywords=["verfahren"], chunk_radius=150, min_confidence=0.2)
        with mock.patch(PARSER_MODULE + ".STREAMING_TEXT_THRESHOLD_BYTES", 1):
            results = list(parser.parse_file(path))
        self.assertTrue(results)
        self.assertTrue(all(not r.is_compliant for r in results))


if __name__ == "__main__":
    unittest.main()
