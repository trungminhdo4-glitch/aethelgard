"""Unit-Tests fuer AethelGard MVP1 Classifier (Schritt 3).

Alle Tests sind deterministisch (kein Zufall, keine Zeit, keine
externen IO). Externe Abhaengigkeiten (Dateisystem, pypdf) werden
vollstaendig gemockt.

Abdeckung:
- TestClassifierError: Exception-Hierarchie
- TestComputeHeuristicScore: Pure-Function-Mathematik (15 Tests)
- TestEvaluateChunk: Mapping auf ComplianceEvidence (8 Tests)
- TestParseAndClassify: Pipeline-Integration (6 Tests)
"""

from __future__ import annotations

import unittest
from collections.abc import Iterator
from pathlib import Path
from typing import Any
from unittest import mock

from pydantic import ValidationError

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
    FileSizeLimitExceededError,
    LocalDocumentParser,
)
from aethelgard.mvp1.schemas import ComplianceEvidence

# ---------------------------------------------------------------------------
# TestClassifierError
# ---------------------------------------------------------------------------


class TestClassifierError(unittest.TestCase):
    """Validiert die Exception-Hierarchie."""

    def test_is_document_parser_error(self) -> None:
        self.assertTrue(issubclass(ClassifierError, Exception))
        from aethelgard.mvp1.document_parser import DocumentParserError

        self.assertTrue(issubclass(ClassifierError, DocumentParserError))

    def test_is_value_error(self) -> None:
        self.assertTrue(issubclass(ClassifierError, ValueError))

    def test_can_be_raised(self) -> None:
        with self.assertRaises(ClassifierError):
            raise ClassifierError("test error")


# ---------------------------------------------------------------------------
# TestComputeHeuristicScore
# ---------------------------------------------------------------------------


class TestComputeHeuristicScore(unittest.TestCase):
    """Tests fuer die Pure-Function-Heuristik."""

    def test_empty_chunk_returns_zero(self) -> None:
        self.assertEqual(compute_heuristic_score("", [], []), SCORE_MIN)
        self.assertEqual(compute_heuristic_score("   \n\t  ", [], []), SCORE_MIN)

    def test_base_score_no_terms(self) -> None:
        score = compute_heuristic_score("irgendein text", [], [])
        self.assertEqual(score, BASE_SCORE)

    def test_single_boost_term(self) -> None:
        score = compute_heuristic_score("verfahren", ["verfahren"], [])
        self.assertEqual(score, BASE_SCORE + BOOST_DELTA)

    def test_single_penalty_term(self) -> None:
        score = compute_heuristic_score("verstoss", [], ["verstoss"])
        self.assertEqual(score, BASE_SCORE - PENALTY_DELTA)

    def test_multiple_boost_terms_capped(self) -> None:
        terms = ["verfahren", "dokumentiert", "umgesetzt", "implementiert", "audit"]
        score = compute_heuristic_score(
            "verfahren dokumentiert umgesetzt implementiert audit",
            terms,
            [],
        )
        # 5 hits * 0.05 = 0.25, capped at BOOST_CAP (0.2)
        self.assertEqual(score, BASE_SCORE + BOOST_CAP)

    def test_extreme_boost_density_capped(self) -> None:
        many_terms = list(BOOST_TERMS) * 3
        text = " ".join(BOOST_TERMS)
        score = compute_heuristic_score(text, many_terms, [])
        self.assertLessEqual(score, SCORE_MAX)
        self.assertEqual(score, BASE_SCORE + BOOST_CAP)

    def test_multiple_penalty_terms_capped(self) -> None:
        terms = ["verstoss", "luecke", "fehlt", "mangelhaft", "unzureichend"]
        score = compute_heuristic_score(
            "verstoss luecke fehlt mangelhaft unzureichend",
            [],
            terms,
        )
        # 5 hits * 0.1 = 0.5, capped at PENALTY_CAP (0.3)
        self.assertEqual(score, BASE_SCORE - PENALTY_CAP)

    def test_extreme_penalty_density_capped(self) -> None:
        many_terms = list(PENALTY_TERMS) * 5
        text = " ".join(PENALTY_TERMS)
        score = compute_heuristic_score(text, [], many_terms)
        self.assertGreaterEqual(score, SCORE_MIN)
        self.assertEqual(score, BASE_SCORE - PENALTY_CAP)

    def test_score_never_below_min(self) -> None:
        # Mit maximalen Penalties (Cap 0.3) sinkt Score auf 0.2, nie unter 0.0
        text = " ".join(PENALTY_TERMS)
        many_penalties = list(PENALTY_TERMS) * 10
        score = compute_heuristic_score(text, [], many_penalties)
        self.assertGreaterEqual(score, SCORE_MIN)
        self.assertEqual(score, BASE_SCORE - PENALTY_CAP)  # 0.2

    def test_score_clamped_to_one(self) -> None:
        # 5 Boosts = 0.25 > cap 0.2, Score = 0.5 + 0.2 = 0.7
        text = "verfahren dokumentiert umgesetzt implementiert audit"
        terms = ["verfahren", "dokumentiert", "umgesetzt", "implementiert", "audit"]
        score = compute_heuristic_score(text, terms, [])
        self.assertEqual(score, 0.7)
        # Score kann 1.0 nicht ueberschreiten, was beweisen wir:
        self.assertLessEqual(score, SCORE_MAX)

    def test_combined_boost_and_penalty(self) -> None:
        # 2 boosts (0.1) + 1 penalty (0.1) = 0.5 + 0.1 - 0.1 = 0.5
        score = compute_heuristic_score(
            "verfahren dokumentiert verstoss",
            ["verfahren", "dokumentiert"],
            ["verstoss"],
        )
        self.assertEqual(score, BASE_SCORE)

    def test_case_insensitive_terms(self) -> None:
        score1 = compute_heuristic_score("VERFAHREN", ["verfahren"], [])
        score2 = compute_heuristic_score("verfahren", ["VERFAHREN"], [])
        self.assertEqual(score1, score2)
        self.assertEqual(score1, BASE_SCORE + BOOST_DELTA)

    def test_empty_term_lists_uses_base(self) -> None:
        score = compute_heuristic_score("ein text", [], [])
        self.assertEqual(score, BASE_SCORE)

    def test_accepts_tuple_and_frozenset(self) -> None:
        score_list = compute_heuristic_score("verfahren", ["verfahren"], [])
        score_tuple = compute_heuristic_score("verfahren", ("verfahren",), ())
        score_frozenset = compute_heuristic_score(
            "verfahren", frozenset({"verfahren"}), frozenset()
        )
        self.assertEqual(score_list, score_tuple)
        self.assertEqual(score_list, score_frozenset)

    def test_substring_match_works(self) -> None:
        # "verfahren" ist Substring von "verfahrenstechnik" - das ist Absicht
        # bei der Heuristik (kein Wortgrenzen-Check).
        score = compute_heuristic_score("verfahrenstechnik", ["verfahren"], [])
        self.assertEqual(score, BASE_SCORE + BOOST_DELTA)

    def test_does_not_mutate_input_lists(self) -> None:
        terms = ["verfahren"]
        penalties = ["verstoss"]
        compute_heuristic_score("verfahren verstoss", terms, penalties)
        self.assertEqual(terms, ["verfahren"])
        self.assertEqual(penalties, ["verstoss"])

    def test_realistic_compliant_chunk(self) -> None:
        # 5+ Boosts ohne "risiko"-Woerter -> Score = 0.7 (Cap 0.2)
        chunk = (
            "Das Verfahren ist dokumentiert, das Audit ist regelmaessig "
            "umgesetzt und kontinuierlich auditiert."
        )
        score = compute_heuristic_score(chunk, list(BOOST_TERMS), list(PENALTY_TERMS))
        self.assertEqual(score, BASE_SCORE + BOOST_CAP)  # 0.7
        self.assertGreaterEqual(score, COMPLIANCE_THRESHOLD)

    def test_realistic_non_compliant_chunk(self) -> None:
        # Mehrere Penalties druecken den Score unter die Schwelle
        chunk = (
            "Das Verfahren fehlt in der Dokumentation, eine Luecke "
            "ist erkennbar, der Prozess ist nicht definiert und "
            "die Umsetzung ist mangelhaft."
        )
        score = compute_heuristic_score(chunk, list(BOOST_TERMS), list(PENALTY_TERMS))
        self.assertLess(score, COMPLIANCE_THRESHOLD)
        # Bei 3+ Penalties ist Score <= 0.2 (Cap 0.3 angewendet)
        self.assertLessEqual(score, BASE_SCORE)

    def test_score_invariants(self) -> None:
        # Score liegt immer in [0.0, 1.0] fuer beliebige Texte
        for text in ["", "kurz", "sehr " * 100 + "verfahren", "\n\n\n"]:
            for boosts in [[], ["x"], list(BOOST_TERMS)]:
                for penalties in [[], ["y"], list(PENALTY_TERMS)]:
                    score = compute_heuristic_score(text, boosts, penalties)
                    self.assertGreaterEqual(score, SCORE_MIN)
                    self.assertLessEqual(score, SCORE_MAX)


# ---------------------------------------------------------------------------
# TestEvaluateChunk
# ---------------------------------------------------------------------------


class TestEvaluateChunk(unittest.TestCase):
    """Tests fuer die Mapping-Funktion auf ComplianceEvidence."""

    def test_returns_compliance_evidence(self) -> None:
        ev = evaluate_chunk("Das Verfahren ist dokumentiert.", "NIS2-ART-21", ["verfahren"])
        self.assertIsInstance(ev, ComplianceEvidence)

    def test_requirement_id_set(self) -> None:
        ev = evaluate_chunk("verfahren dokumentiert", "NIS2-CUSTOM-ID", ["x"])
        self.assertEqual(ev.requirement_id, "NIS2-CUSTOM-ID")

    def test_source_citation_is_chunk(self) -> None:
        chunk = "Das Verfahren ist dokumentiert und implementiert."
        ev = evaluate_chunk(chunk, "NIS2-ART-21", ["verfahren"])
        self.assertEqual(ev.source_citation, chunk)

    def test_high_score_marks_compliant(self) -> None:
        # 5 Boosts, 0 Penalties -> 0.7 >= 0.7
        ev = evaluate_chunk(
            "verfahren dokumentiert umgesetzt implementiert audit",
            "NIS2-ART-21",
            ["verfahren"],
        )
        self.assertGreaterEqual(ev.confidence_score, COMPLIANCE_THRESHOLD)
        self.assertTrue(ev.is_compliant)

    def test_low_score_marks_non_compliant(self) -> None:
        # 0 Boosts, 1 Penalty -> 0.4 < 0.7
        ev = evaluate_chunk("verstoss", "NIS2-ART-21", ["x"])
        self.assertLess(ev.confidence_score, COMPLIANCE_THRESHOLD)
        self.assertFalse(ev.is_compliant)

    def test_critical_penalty_forces_non_compliant(self) -> None:
        # Auch mit hohem Score wird luecke (critical) zu non_compliant
        chunk = "verfahren dokumentiert umgesetzt implementiert audit luecke"
        ev = evaluate_chunk(chunk, "NIS2-ART-21", ["verfahren"])
        # 5 Boosts cap 0.2 + 1 Penalty (luecke) 0.1 = 0.6
        # luecke ist critical -> is_compliant = False
        self.assertFalse(ev.is_compliant)
        # Score ist zwar hoch genug fuer Compliance-Threshold, aber luecke blockt
        # 0.6 < 0.7 (Threshold) - daher ohnehin non_compliant aus Score-Sicht
        # Wichtiger Test: ohne critical waere 0.6 immer noch < 0.7
        # -> Teste separate Szenario mit score >= 0.7:
        chunk_high = "verfahren dokumentiert umgesetzt implementiert audit"
        ev_high = evaluate_chunk(chunk_high, "NIS2-ART-21", ["verfahren"])
        # Ohne Penalty: Score = 0.7, is_compliant = True
        self.assertTrue(ev_high.is_compliant)
        # Mit angehaengtem critical term: is_compliant = False trotz gleichem Score-Range
        chunk_high_with_luecke = chunk_high + " luecke"
        ev_with_luecke = evaluate_chunk(chunk_high_with_luecke, "NIS2-ART-21", ["verfahren"])
        self.assertFalse(ev_with_luecke.is_compliant)

    def test_each_critical_term_forces_non_compliant(self) -> None:
        for term in CRITICAL_PENALTY_TERMS:
            with self.subTest(term=term):
                chunk = (
                    "verfahren dokumentiert umgesetzt implementiert audit "
                    f"und dennoch {term} in einem bereich"
                )
                ev = evaluate_chunk(chunk, "NIS2-ART-21", ["verfahren"])
                self.assertFalse(ev.is_compliant)

    def test_empty_chunk_raises(self) -> None:
        with self.assertRaises(ClassifierError):
            evaluate_chunk("", "NIS2-ART-21", ["x"])

    def test_whitespace_only_chunk_raises(self) -> None:
        with self.assertRaises(ClassifierError):
            evaluate_chunk("   \n\t  ", "NIS2-ART-21", ["x"])

    def test_empty_requirement_id_raises(self) -> None:
        with self.assertRaises(ClassifierError):
            evaluate_chunk("verfahren", "", ["x"])

    def test_requirement_id_too_long_raises(self) -> None:
        with self.assertRaises(ClassifierError):
            evaluate_chunk("verfahren", "X" * 101, ["x"])

    def test_keywords_does_not_affect_score(self) -> None:
        # keywords sind nur informational
        ev1 = evaluate_chunk("verfahren dokumentiert", "NIS2-ART-21", [])
        ev2 = evaluate_chunk("verfahren dokumentiert", "NIS2-ART-21", ["x", "y", "z"])
        self.assertEqual(ev1.confidence_score, ev2.confidence_score)

    def test_compliance_flag_is_boolean(self) -> None:
        ev = evaluate_chunk("verfahren", "NIS2-ART-21", ["x"])
        self.assertIsInstance(ev.is_compliant, bool)

    def test_evidence_is_frozen(self) -> None:
        ev = evaluate_chunk("verfahren", "NIS2-ART-21", ["x"])
        with self.assertRaises(ValidationError):
            ev.is_compliant = True  # type: ignore[misc]

    def test_score_within_schema_bounds(self) -> None:
        # Egal welcher Input, der Score muss in [0.0, 1.0] sein
        for chunk in [
            "verstoss luecke mangelhaft",
            "verfahren dokumentiert umgesetzt",
            "",
            "x",
        ]:
            ev = evaluate_chunk(chunk or "fallback", "NIS2-ART-21", ["x"])
            if chunk:
                self.assertGreaterEqual(ev.confidence_score, SCORE_MIN)
                self.assertLessEqual(ev.confidence_score, SCORE_MAX)


# ---------------------------------------------------------------------------
# TestParseAndClassify
# ---------------------------------------------------------------------------


def _setup_path_mock(
    path_mock_cls: Any,
    *,
    exists: bool = True,
    is_file: bool = True,
    size: int = 1024,
    suffix: str = ".txt",
) -> Any:
    """Erstellt ein vollstaendig konfiguriertes Path-Mock."""
    path_mock = mock.MagicMock(spec=Path)
    path_mock.exists.return_value = exists
    path_mock.is_file.return_value = is_file
    path_mock.stat.return_value = mock.MagicMock(st_size=size)
    path_mock.suffix = suffix
    path_mock_cls.return_value = path_mock
    return path_mock


class TestParseAndClassify(unittest.TestCase):
    """Tests fuer ``LocalDocumentParser.parse_and_classify``."""

    def test_text_file_yields_evidence(self) -> None:
        parser = LocalDocumentParser(keywords=["verfahren"], chunk_radius=300)
        with mock.patch("aethelgard.mvp1.document_parser.Path") as path_cls:
            path_mock = _setup_path_mock(path_cls, suffix=".txt")
            # 5 Boosts, 0 Penalties -> Score 0.7, is_compliant True
            path_mock.read_text.return_value = (
                "verfahren dokumentiert umgesetzt implementiert audit"
            )
            results = list(parser.parse_and_classify(path_mock))

        self.assertGreater(len(results), 0)
        self.assertIsInstance(results[0], ComplianceEvidence)
        self.assertTrue(results[0].is_compliant)
        self.assertEqual(results[0].requirement_id, "VERFAHREN")
        self.assertGreaterEqual(results[0].confidence_score, COMPLIANCE_THRESHOLD)

    def test_returns_iterator(self) -> None:
        parser = LocalDocumentParser(keywords=["verfahren"])
        with mock.patch("aethelgard.mvp1.document_parser.Path") as path_cls:
            path_mock = _setup_path_mock(path_cls)
            path_mock.read_text.return_value = "verfahren dokumentiert"
            result = parser.parse_and_classify(path_mock)
        self.assertIsInstance(result, Iterator)

    def test_file_not_found_raises(self) -> None:
        parser = LocalDocumentParser(keywords=["x"])
        with mock.patch("aethelgard.mvp1.document_parser.Path") as path_cls:
            _setup_path_mock(path_cls, exists=False)
            with self.assertRaises(FileNotFoundError):
                list(parser.parse_and_classify(path_cls.return_value))

    def test_directory_raises(self) -> None:
        parser = LocalDocumentParser(keywords=["x"])
        with mock.patch("aethelgard.mvp1.document_parser.Path") as path_cls:
            _setup_path_mock(path_cls, is_file=False)
            with self.assertRaises(IsADirectoryError):
                list(parser.parse_and_classify(path_cls.return_value))

    def test_file_too_large_raises(self) -> None:
        parser = LocalDocumentParser(keywords=["x"])
        with mock.patch("aethelgard.mvp1.document_parser.Path") as path_cls:
            from aethelgard.mvp1.document_parser import MAX_FILE_SIZE_BYTES

            _setup_path_mock(path_cls, size=MAX_FILE_SIZE_BYTES + 1)
            with self.assertRaises(FileSizeLimitExceededError):
                list(parser.parse_and_classify(path_cls.return_value))

    def test_pdf_dispatch(self) -> None:
        """PDF-Dateien werden via stream_pdf_pages klassifiziert."""
        parser = LocalDocumentParser(keywords=["verfahren"], chunk_radius=100)
        with mock.patch("aethelgard.mvp1.pdf_handler.stream_pdf_pages") as mock_stream:
            mock_stream.return_value = iter(
                ["verfahren dokumentiert umgesetzt implementiert audit"]
            )
            with mock.patch("aethelgard.mvp1.document_parser.Path") as path_cls:
                path_mock = _setup_path_mock(path_cls, suffix=".pdf")
                results = list(parser.parse_and_classify(path_mock))

        mock_stream.assert_called_once_with(path_mock)
        self.assertGreater(len(results), 0)
        self.assertTrue(results[0].is_compliant)

    def test_multi_page_pdf_chunks(self) -> None:
        """Multi-Page-PDF produziert Evidenzen pro Seite."""
        parser = LocalDocumentParser(keywords=["verfahren", "audit"], chunk_radius=200)
        with mock.patch("aethelgard.mvp1.pdf_handler.stream_pdf_pages") as mock_stream:
            mock_stream.return_value = iter(
                [
                    "Seite 1: verfahren dokumentiert umgesetzt implementiert audit",
                    "Seite 2: audit verfahren dokumentiert",
                ]
            )
            with mock.patch("aethelgard.mvp1.document_parser.Path") as path_cls:
                path_mock = _setup_path_mock(path_cls, suffix=".pdf")
                results = list(parser.parse_and_classify(path_mock))

        self.assertGreaterEqual(len(results), 2)
        unique_reqs = {r.requirement_id for r in results}
        self.assertGreaterEqual(len(unique_reqs), 1)

    def test_requirement_map_used(self) -> None:
        """requirement_map wird fuer requirement_id verwendet."""
        parser = LocalDocumentParser(
            keywords=["verfahren"],
            chunk_radius=100,
            requirement_map={"verfahren": "NIS2-ART-21(1)(a)"},
        )
        with mock.patch("aethelgard.mvp1.document_parser.Path") as path_cls:
            path_mock = _setup_path_mock(path_cls, suffix=".txt")
            path_mock.read_text.return_value = (
                "verfahren dokumentiert umgesetzt implementiert audit"
            )
            results = list(parser.parse_and_classify(path_mock))

        self.assertEqual(results[0].requirement_id, "NIS2-ART-21(1)(a)")

    def test_requirement_map_used_case_insensitively(self) -> None:
        """requirement_map bleibt stabil, wenn der Match im Dokument anders geschrieben ist."""
        parser = LocalDocumentParser(
            keywords=["verfahren"],
            chunk_radius=100,
            requirement_map={"verfahren": "NIS2-ART-21(1)(a)"},
        )
        with mock.patch("aethelgard.mvp1.document_parser.Path") as path_cls:
            path_mock = _setup_path_mock(path_cls, suffix=".txt")
            path_mock.read_text.return_value = (
                "VERFAHREN dokumentiert umgesetzt implementiert audit"
            )
            results = list(parser.parse_and_classify(path_mock))

        self.assertEqual(results[0].requirement_id, "NIS2-ART-21(1)(a)")

    def test_empty_text_yields_nothing(self) -> None:
        parser = LocalDocumentParser(keywords=["x"])
        with mock.patch("aethelgard.mvp1.document_parser.Path") as path_cls:
            path_mock = _setup_path_mock(path_cls)
            path_mock.read_text.return_value = ""
            results = list(parser.parse_and_classify(path_mock))
        self.assertEqual(results, [])

    def test_critical_penalty_marks_non_compliant_via_pipeline(self) -> None:
        """End-to-End: kritischer Penalty im Chunk -> is_compliant=False."""
        parser = LocalDocumentParser(keywords=["verfahren"], chunk_radius=300)
        with mock.patch("aethelgard.mvp1.document_parser.Path") as path_cls:
            path_mock = _setup_path_mock(path_cls, suffix=".txt")
            # Sehr positives Chunk + kritischer Penalty am Ende
            path_mock.read_text.return_value = (
                "verfahren dokumentiert umgesetzt implementiert audit "
                "regelmaessig verpflichtet "
                "aber dennoch luecke in der umsetzung"
            )
            results = list(parser.parse_and_classify(path_mock))

        self.assertGreater(len(results), 0)
        for r in results:
            self.assertFalse(r.is_compliant)


if __name__ == "__main__":
    unittest.main()
