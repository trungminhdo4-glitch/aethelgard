"""Unit-Tests fuer AethelGard MVP1 Document Parser.

Alle externen Interaktionen (Dateisystem) sind ueber ``unittest.mock``
abstrahiert. Es werden keine realen Dateien geschrieben, gelesen oder
veraendert. Die Tests sind voneinander isoliert und folgen AAA (Arrange,
Act, Assert).
"""

from __future__ import annotations

import unittest
from collections.abc import Iterator
from pathlib import Path
from typing import Any
from unittest import mock

from pydantic import ValidationError

from aethelgard.mvp1.document_parser import (
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
from aethelgard.mvp1.schemas import ComplianceEvidence

# ---------------------------------------------------------------------------
# ComplianceEvidence Schema Tests
# ---------------------------------------------------------------------------


class TestComplianceEvidenceSchema(unittest.TestCase):
    """Validiert das strikt typisierte pydantic-Schema ComplianceEvidence."""

    def test_valid_construction(self) -> None:
        evidence = ComplianceEvidence(
            requirement_id="NIS2-ART-21(1)(a)",
            is_compliant=True,
            confidence_score=0.85,
            source_citation="Das Unternehmen fuehrt regelmaessige Risikoanalysen durch.",
        )
        self.assertEqual(evidence.requirement_id, "NIS2-ART-21(1)(a)")
        self.assertTrue(evidence.is_compliant)
        self.assertEqual(evidence.confidence_score, 0.85)
        self.assertIn("Risikoanalysen", evidence.source_citation)

    def test_frozen_model(self) -> None:
        evidence = ComplianceEvidence(
            requirement_id="X-1",
            is_compliant=False,
            confidence_score=0.1,
            source_citation="negativ",
        )
        with self.assertRaises(ValidationError):
            evidence.is_compliant = True

    def test_extra_fields_forbidden(self) -> None:
        with self.assertRaises(ValidationError):
            ComplianceEvidence(
                requirement_id="X-1",
                is_compliant=True,
                confidence_score=0.5,
                source_citation="ok",
                unknown_field="boom",  # type: ignore[call-arg]
            )

    def test_confidence_score_bounds(self) -> None:
        for bad_score in (-0.1, 1.1, 2.0, -1.0):
            with self.subTest(score=bad_score):
                with self.assertRaises(ValidationError):
                    ComplianceEvidence(
                        requirement_id="X-1",
                        is_compliant=True,
                        confidence_score=bad_score,
                        source_citation="ok",
                    )

    def test_requirement_id_must_not_be_empty(self) -> None:
        with self.assertRaises(ValidationError):
            ComplianceEvidence(
                requirement_id="",
                is_compliant=True,
                confidence_score=0.5,
                source_citation="ok",
            )

    def test_source_citation_strips_whitespace(self) -> None:
        evidence = ComplianceEvidence(
            requirement_id="X-1",
            is_compliant=True,
            confidence_score=0.5,
            source_citation="   gepaddeter text   ",
        )
        self.assertEqual(evidence.source_citation, "gepaddeter text")


# ---------------------------------------------------------------------------
# normalize_text Tests
# ---------------------------------------------------------------------------


class TestNormalizeText(unittest.TestCase):
    """Tests fuer die pure normalization-Funktion."""

    def test_empty_string(self) -> None:
        self.assertEqual(normalize_text(""), "")

    def test_none_like(self) -> None:
        self.assertEqual(normalize_text("   \n\t  "), "")

    def test_collapses_excess_spaces(self) -> None:
        self.assertEqual(normalize_text("a    b      c"), "a b c")

    def test_unifies_line_endings(self) -> None:
        self.assertEqual(
            normalize_text("a\r\nb\rc\nd"),
            "a\nb\nc\nd",
        )

    def test_removes_null_bytes(self) -> None:
        self.assertEqual(normalize_text("a\x00b\x00c"), "abc")

    def test_trims_outer_whitespace(self) -> None:
        self.assertEqual(normalize_text("  hello world  "), "hello world")

    def test_applies_nfc_normalization(self) -> None:
        self.assertEqual(normalize_text("Cafe\u0301"), "Caf\u00e9")


# ---------------------------------------------------------------------------
# locate_keyword_positions Tests
# ---------------------------------------------------------------------------


class TestLocateKeywordPositions(unittest.TestCase):
    """Tests fuer die positionsbasierte Keyword-Suche."""

    def test_no_keywords_yields_nothing(self) -> None:
        result: list[tuple[int, str]] = list(locate_keyword_positions("hello world", []))
        self.assertEqual(result, [])

    def test_empty_keywords_filtered(self) -> None:
        result = list(locate_keyword_positions("hello world", ["", "  "]))
        self.assertEqual(result, [])

    def test_finds_keyword(self) -> None:
        result = list(locate_keyword_positions("risk assessment here", ["risk"]))
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0][0], 0)
        self.assertEqual(result[0][1].lower(), "risk")

    def test_word_boundary_protection(self) -> None:
        result = list(locate_keyword_positions("riskmanagement is not risk", ["risk"]))
        positions = [pos for pos, _ in result]
        self.assertEqual(len(positions), 1)
        self.assertEqual(positions[0], len("riskmanagement is not "))

    def test_case_insensitive(self) -> None:
        result = list(locate_keyword_positions("RISK and Risk and risk", ["risk"]))
        self.assertEqual(len(result), 3)

    def test_yields_generator_not_list(self) -> None:
        result = locate_keyword_positions("risk", ["risk"])
        self.assertIsInstance(result, Iterator)

    def test_too_many_keywords_raises(self) -> None:
        keywords = ["k%d" % i for i in range(501)]
        with self.assertRaises(ValueError):
            list(locate_keyword_positions("x", keywords))

    def test_keyword_too_long_raises(self) -> None:
        long_kw = "x" * 200
        with self.assertRaises(ValueError):
            list(locate_keyword_positions("text", [long_kw]))

    def test_keyword_dedup_case_insensitive(self) -> None:
        result = list(locate_keyword_positions("risk and RISK and Risk", ["risk"]))
        self.assertEqual(len(result), 3)

    def test_prefers_longest_keyword_at_same_position(self) -> None:
        result = list(locate_keyword_positions("risk assessment done", ["risk", "risk assessment"]))
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0][1].lower(), "risk assessment")


# ---------------------------------------------------------------------------
# extract_chunk Tests
# ---------------------------------------------------------------------------


class TestExtractChunk(unittest.TestCase):
    """Tests fuer die Chunk-Extraktion um eine Position."""

    def test_basic_extraction(self) -> None:
        text = "abcdefghij" * 10
        chunk = extract_chunk(text, position=50, radius=5)
        self.assertEqual(len(chunk), 10)
        self.assertIn("fghij", chunk)

    def test_at_start(self) -> None:
        text = "hello world"
        chunk = extract_chunk(text, position=0, radius=5)
        self.assertIn("hello", chunk)

    def test_at_end(self) -> None:
        text = "hello world"
        chunk = extract_chunk(text, position=len(text), radius=5)
        self.assertEqual(chunk, "")

    def test_position_out_of_bounds(self) -> None:
        self.assertEqual(extract_chunk("abc", position=10, radius=5), "")
        self.assertEqual(extract_chunk("abc", position=-1, radius=5), "")

    def test_empty_text(self) -> None:
        self.assertEqual(extract_chunk("", position=0, radius=5), "")

    def test_negative_radius_raises(self) -> None:
        with self.assertRaises(ValueError):
            extract_chunk("abc", position=0, radius=-1)

    def test_collapses_whitespace_in_chunk(self) -> None:
        chunk = extract_chunk("a\n\nb\t\tc", position=2, radius=1)
        self.assertNotIn("\t", chunk)
        self.assertNotIn("\n", chunk)


# ---------------------------------------------------------------------------
# compute_confidence Tests
# ---------------------------------------------------------------------------


class TestComputeConfidence(unittest.TestCase):
    """Tests fuer die heuristische Confidence-Berechnung."""

    def test_empty_chunk_returns_zero(self) -> None:
        self.assertEqual(compute_confidence("", "risk", "full text"), 0.0)

    def test_base_score(self) -> None:
        score = compute_confidence("risk", "risk", "full risk text")
        self.assertGreaterEqual(score, 0.5)

    def test_cap_at_one(self) -> None:
        long_text = ("implementiert dokumentiert verfahren " * 20) + "RISK"
        score = compute_confidence(long_text, "RISK", long_text)
        self.assertLessEqual(score, 1.0)

    def test_min_zero(self) -> None:
        chunk = "fehlt luecke nicht umgesetzt nicht dokumentiert"
        score = compute_confidence(chunk, "fehlt", "text")
        self.assertGreaterEqual(score, 0.0)

    def test_negative_context_lowers_score(self) -> None:
        positive = compute_confidence("verfahren dokumentiert", "verfahren", "x")
        negative = compute_confidence("verfahren fehlt luecke", "verfahren", "x")
        self.assertGreater(positive, negative)


# ---------------------------------------------------------------------------
# functional_chunk_extractor Tests
# ---------------------------------------------------------------------------


class TestFunctionalChunkExtractor(unittest.TestCase):
    """Tests fuer die funktionale End-to-End-Pipeline."""

    def test_empty_text_raises(self) -> None:
        with self.assertRaises(EmptyDocumentError):
            list(functional_chunk_extractor("", ["risk"]))

    def test_whitespace_only_raises(self) -> None:
        with self.assertRaises(EmptyDocumentError):
            list(functional_chunk_extractor("   \n\t  ", ["risk"]))

    def test_no_keyword_match_yields_nothing(self) -> None:
        result = list(functional_chunk_extractor("hello world", ["risk", "audit"]))
        self.assertEqual(result, [])

    def test_basic_extraction(self) -> None:
        text = "Our risk assessment is fully documented and implemented."
        result = list(functional_chunk_extractor(text, ["risk assessment"]))
        self.assertEqual(len(result), 1)
        evidence = result[0]
        self.assertIn("risk assessment", evidence.source_citation.lower())
        self.assertGreater(evidence.confidence_score, 0.0)

    def test_min_confidence_filters(self) -> None:
        text = "risk"
        all_evidence = list(functional_chunk_extractor(text, ["risk"], min_confidence=0.0))
        filtered = list(functional_chunk_extractor(text, ["risk"], min_confidence=0.99))
        self.assertGreater(len(all_evidence), 0)
        self.assertEqual(len(filtered), 0)

    def test_requirement_map_used(self) -> None:
        text = "risk is mentioned here"
        result = list(
            functional_chunk_extractor(
                text,
                ["risk"],
                requirement_map={"risk": "NIS2-ART-21-1-A"},
            )
        )
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].requirement_id, "NIS2-ART-21-1-A")

    def test_requirement_map_is_case_insensitive(self) -> None:
        text = "RISK is mentioned here"
        result = list(
            functional_chunk_extractor(
                text,
                ["risk"],
                requirement_map={"risk": "NIS2-ART-21-1-A"},
            )
        )
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].requirement_id, "NIS2-ART-21-1-A")

    def test_requirement_id_slugified_when_unmapped(self) -> None:
        text = "risk assessment performed"
        result = list(functional_chunk_extractor(text, ["risk assessment"]))
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].requirement_id, "RISK-ASSESSMENT")

    def test_chunk_radius_validation(self) -> None:
        with self.assertRaises(ValueError):
            list(functional_chunk_extractor("text", ["x"], chunk_radius=-1))

    def test_min_confidence_validation(self) -> None:
        with self.assertRaises(ValueError):
            list(functional_chunk_extractor("text", ["x"], min_confidence=1.5))

    def test_text_length_cap(self) -> None:
        huge = "x" * 1_000_001
        with self.assertRaises(ValueError):
            list(functional_chunk_extractor(huge, ["x"]))

    def test_multiple_keywords(self) -> None:
        text = (
            "We perform risk assessment. "
            "We have incident response procedures. "
            "We document everything."
        )
        result = list(
            functional_chunk_extractor(
                text,
                ["risk assessment", "incident response"],
                chunk_radius=50,
            )
        )
        self.assertGreaterEqual(len(result), 2)
        req_ids = {ev.requirement_id for ev in result}
        self.assertIn("RISK-ASSESSMENT", req_ids)
        self.assertIn("INCIDENT-RESPONSE", req_ids)

    def test_negative_context_marks_non_compliant(self) -> None:
        text = "Das Verfahren fehlt in unserer Dokumentation."
        result = list(functional_chunk_extractor(text, ["Verfahren"], min_confidence=0.0))
        self.assertEqual(len(result), 1)
        self.assertFalse(result[0].is_compliant)


# ---------------------------------------------------------------------------
# LocalDocumentParser OOP Tests
# ---------------------------------------------------------------------------


class TestLocalDocumentParserInit(unittest.TestCase):
    """Tests fuer die Konstruktor-Validierung."""

    def test_empty_keywords_raises(self) -> None:
        with self.assertRaises(ValueError):
            LocalDocumentParser(keywords=[])

    def test_only_whitespace_keywords_raises(self) -> None:
        with self.assertRaises(ValueError):
            LocalDocumentParser(keywords=["", "   "])

    def test_invalid_chunk_radius(self) -> None:
        with self.assertRaises(ValueError):
            LocalDocumentParser(keywords=["x"], chunk_radius=-1)

    def test_invalid_min_confidence(self) -> None:
        with self.assertRaises(ValueError):
            LocalDocumentParser(keywords=["x"], min_confidence=1.5)

    def test_keywords_deduplicated(self) -> None:
        parser = LocalDocumentParser(keywords=["risk", "risk", "audit"])
        self.assertEqual(len(parser.keywords), 2)

    def test_keywords_stripped(self) -> None:
        parser = LocalDocumentParser(keywords=["  risk  ", "audit"])
        self.assertIn("risk", parser.keywords)
        self.assertIn("audit", parser.keywords)

    def test_properties(self) -> None:
        parser = LocalDocumentParser(
            keywords=["risk"],
            chunk_radius=150,
            min_confidence=0.7,
        )
        self.assertEqual(parser.chunk_radius, 150)
        self.assertEqual(parser.min_confidence, 0.7)
        self.assertEqual(parser.keywords, ("risk",))


class TestLocalDocumentParserParseText(unittest.TestCase):
    """Tests fuer ``parse_text`` ohne Datei-IO."""

    def test_basic_parse(self) -> None:
        parser = LocalDocumentParser(
            keywords=["risk assessment"],
            chunk_radius=80,
        )
        results = list(parser.parse_text("Our risk assessment is documented and complete."))
        self.assertEqual(len(results), 1)

    def test_empty_text_raises(self) -> None:
        parser = LocalDocumentParser(keywords=["risk"])
        with self.assertRaises(EmptyDocumentError):
            list(parser.parse_text(""))


class TestLocalDocumentParserParseFile(unittest.TestCase):
    """Tests fuer ``parse_file`` mit vollstaendig gemocktem Dateisystem."""

    def test_file_not_found(self) -> None:
        parser = LocalDocumentParser(keywords=["risk"])
        with self.assertRaises(FileNotFoundError):
            list(parser.parse_file(Path("D:/nonexistent/file.txt")))

    @mock.patch("aethelgard.mvp1.document_parser.Path")
    def test_directory_instead_of_file_raises(self, mock_path_cls: Any) -> None:
        mock_path = mock.MagicMock(spec=Path)
        mock_path.exists.return_value = True
        mock_path.is_file.return_value = False
        mock_path_cls.return_value = mock_path

        parser = LocalDocumentParser(keywords=["risk"])
        with self.assertRaises(IsADirectoryError):
            list(parser.parse_file(mock_path))

    @mock.patch("aethelgard.mvp1.document_parser.Path")
    def test_file_too_large_raises(self, mock_path_cls: Any) -> None:
        mock_path = mock.MagicMock(spec=Path)
        mock_path.exists.return_value = True
        mock_path.is_file.return_value = True
        mock_path.stat.return_value = mock.MagicMock(st_size=100 * 1024 * 1024)
        mock_path_cls.return_value = mock_path

        parser = LocalDocumentParser(keywords=["risk"])
        with self.assertRaises(FileSizeLimitExceededError):
            list(parser.parse_file(mock_path))

    @mock.patch("aethelgard.mvp1.document_parser.Path")
    def test_successful_file_read(self, mock_path_cls: Any) -> None:
        mock_path = mock.MagicMock(spec=Path)
        mock_path.exists.return_value = True
        mock_path.is_file.return_value = True
        mock_path.stat.return_value = mock.MagicMock(st_size=1024)
        mock_path.read_text.return_value = "Our risk assessment is implemented."
        mock_path_cls.return_value = mock_path

        parser = LocalDocumentParser(
            keywords=["risk assessment"],
            chunk_radius=100,
        )
        results = list(parser.parse_file(mock_path))
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].requirement_id, "RISK-ASSESSMENT")

    @mock.patch("aethelgard.mvp1.document_parser.Path")
    def test_encoding_fallback_succeeds(self, mock_path_cls: Any) -> None:
        mock_path = mock.MagicMock(spec=Path)
        mock_path.exists.return_value = True
        mock_path.is_file.return_value = True
        mock_path.stat.return_value = mock.MagicMock(st_size=512)
        mock_path.read_text.side_effect = [
            UnicodeDecodeError("utf-8", b"\x80\x81", 0, 1, "invalid"),
            "fallback text with risk keyword",
        ]
        mock_path_cls.return_value = mock_path

        parser = LocalDocumentParser(keywords=["risk"], chunk_radius=100)
        results = list(parser.parse_file(mock_path))
        self.assertGreater(len(results), 0)

    @mock.patch("aethelgard.mvp1.document_parser.Path")
    def test_encoding_unrecoverable_wrapped(self, mock_path_cls: Any) -> None:
        mock_path = mock.MagicMock(spec=Path)
        mock_path.exists.return_value = True
        mock_path.is_file.return_value = True
        mock_path.stat.return_value = mock.MagicMock(st_size=512)
        mock_path.read_text.side_effect = [
            UnicodeDecodeError("utf-8", b"\x80\x81", 0, 1, "invalid"),
            UnicodeDecodeError("utf-8", b"\x80\x81", 0, 1, "still invalid"),
        ]
        mock_path_cls.return_value = mock_path

        parser = LocalDocumentParser(keywords=["risk"])
        with self.assertRaises(EncodingError):
            list(parser.parse_file(mock_path))

    @mock.patch("aethelgard.mvp1.document_parser.Path")
    def test_os_error_wrapped(self, mock_path_cls: Any) -> None:
        mock_path = mock.MagicMock(spec=Path)
        mock_path.exists.return_value = True
        mock_path.is_file.return_value = True
        mock_path.stat.return_value = mock.MagicMock(st_size=512)
        mock_path.read_text.side_effect = OSError("disk failure")
        mock_path_cls.return_value = mock_path

        parser = LocalDocumentParser(keywords=["risk"])
        with self.assertRaises(DocumentParserError):
            list(parser.parse_file(mock_path))

    def test_string_path_accepted(self) -> None:
        parser = LocalDocumentParser(keywords=["risk"])
        with mock.patch("aethelgard.mvp1.document_parser.Path") as mock_path_cls:
            mock_path = mock.MagicMock(spec=Path)
            mock_path.exists.return_value = False
            mock_path_cls.return_value = mock_path
            with self.assertRaises(FileNotFoundError):
                list(parser.parse_file("D:/some/file.txt"))


# ---------------------------------------------------------------------------
# Memory-Efficiency / Generator Tests
# ---------------------------------------------------------------------------


class TestGeneratorBehavior(unittest.TestCase):
    """Stellt sicher, dass die API lazy arbeitet (Generatoren)."""

    def test_locate_returns_iterator(self) -> None:
        result = locate_keyword_positions("risk", ["risk"])
        self.assertIsInstance(result, Iterator)

    def test_functional_returns_iterator(self) -> None:
        result = functional_chunk_extractor("risk", ["risk"])
        self.assertIsInstance(result, Iterator)

    def test_oop_parse_text_returns_iterator(self) -> None:
        parser = LocalDocumentParser(keywords=["risk"])
        result = parser.parse_text("risk text")
        self.assertIsInstance(result, Iterator)

    def test_oop_parse_file_returns_iterator(self) -> None:
        parser = LocalDocumentParser(keywords=["risk"])
        with mock.patch("aethelgard.mvp1.document_parser.Path") as mock_path_cls:
            mock_path = mock.MagicMock(spec=Path)
            mock_path.exists.return_value = True
            mock_path.is_file.return_value = True
            mock_path.stat.return_value = mock.MagicMock(st_size=512)
            mock_path.read_text.return_value = "risk"
            mock_path_cls.return_value = mock_path
            result = parser.parse_file(mock_path)
            self.assertIsInstance(result, Iterator)


if __name__ == "__main__":
    unittest.main()
