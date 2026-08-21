"""Tests fuer ``aethelgard.mvp1.evaluators`` (RuleBasedEvaluator + run_pipeline).

Deckt Ownership-Partition (kein Doppelzaehlen ueber Fenstergrenzen),
Zitat-Deduplizierung und die Streaming-Pipeline auf echten tmp-Dateien ab.
"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest import mock

from aethelgard.mvp1.evaluators import RuleBasedEvaluator, run_pipeline
from aethelgard.mvp1.schemas import ComplianceEvidence
from aethelgard.mvp1.streaming import TextWindow

POSITIVE_SENTENCE = "verfahren dokumentiert umgesetzt implementiert audit"


def _window(text: str, *, index: int = 0, start: int = 0, is_tail: bool = True) -> TextWindow:
    return TextWindow(
        window_index=index,
        start_char=start,
        end_char=start + len(text),
        text=text,
        is_tail=is_tail,
    )


class TestRuleBasedEvaluatorInit(unittest.TestCase):
    """Konfigurations-Validierung."""

    def test_empty_keywords_raise(self) -> None:
        with self.assertRaises(ValueError):
            RuleBasedEvaluator([])

    def test_non_positive_radius_raises(self) -> None:
        with self.assertRaises(ValueError):
            RuleBasedEvaluator(["verfahren"], chunk_radius=0)

    def test_overlap_below_double_radius_raises(self) -> None:
        with self.assertRaises(ValueError):
            RuleBasedEvaluator(["verfahren"], chunk_radius=200, overlap=399)

    def test_overlap_equal_double_radius_ok(self) -> None:
        evaluator = RuleBasedEvaluator(["verfahren"], chunk_radius=100, overlap=200)
        self.assertIsNotNone(evaluator)


class TestRuleBasedEvaluatorEvaluate(unittest.TestCase):
    """Emission, Ownership und Dedupe."""

    def test_tail_window_emits_evidence(self) -> None:
        evaluator = RuleBasedEvaluator(["verfahren"], chunk_radius=100, overlap=200)
        results = evaluator.evaluate(_window(POSITIVE_SENTENCE))
        self.assertEqual(len(results), 1)
        evidence = results[0]
        self.assertIsInstance(evidence, ComplianceEvidence)
        self.assertEqual(evidence.requirement_id, "VERFAHREN")
        self.assertTrue(evidence.is_compliant)

    def test_requirement_map_applied(self) -> None:
        evaluator = RuleBasedEvaluator(
            ["verfahren"],
            requirement_map={"verfahren": "NIS2-ART-21(1)(a)"},
            chunk_radius=100,
            overlap=200,
        )
        results = evaluator.evaluate(_window(POSITIVE_SENTENCE))
        self.assertEqual(results[0].requirement_id, "NIS2-ART-21(1)(a)")

    def test_ownership_no_double_count_across_windows(self) -> None:
        # Keyword liegt im Ueberlappungsbereich beider Fenster; der Kern von
        # Fenster A endet davor, Fenster B besitzt es.
        overlap = 100
        text_a = ("x" * 900) + " " + POSITIVE_SENTENCE  # Treffer bei 901
        evaluator = RuleBasedEvaluator(["verfahren"], chunk_radius=50, overlap=overlap)
        window_a = _window(text_a, index=0, start=0, is_tail=False)
        results_a = evaluator.evaluate(window_a)
        core_end = len(text_a) - overlap  # 853 < 901 -> Treffer nicht besessen
        self.assertEqual(results_a, ())
        self.assertLess(core_end, 901)

        text_b = text_a[len(text_a) - overlap :] + (" y" * 100)
        window_b = _window(text_b, index=1, start=len(text_a) - overlap, is_tail=True)
        results_b = evaluator.evaluate(window_b)
        self.assertEqual(len(results_b), 1)

    def test_non_tail_window_defers_overlap_hits(self) -> None:
        evaluator = RuleBasedEvaluator(["verfahren"], chunk_radius=50, overlap=100)
        # Treffer bei Position 1010, Kern endet bei 1002 -> keine Emission.
        text = ("a" * 1010) + POSITIVE_SENTENCE + ("b" * 40)
        results = evaluator.evaluate(_window(text, is_tail=False))
        self.assertEqual(results, ())

    def test_dedupe_suppresses_identical_citations(self) -> None:
        # Periodische Boilerplate: beide Treffer liefern byte-identische Chunks.
        unit = ("p" * 100) + " " + POSITIVE_SENTENCE + " " + ("q" * 100)
        evaluator = RuleBasedEvaluator(["verfahren"], chunk_radius=50, overlap=200)
        results = evaluator.evaluate(_window(unit * 2))
        self.assertEqual(len(results), 1)

    def test_reset_clears_dedupe_state(self) -> None:
        unit = ("p" * 100) + " " + POSITIVE_SENTENCE + " " + ("q" * 100)
        evaluator = RuleBasedEvaluator(["verfahren"], chunk_radius=50, overlap=200)
        evaluator.evaluate(_window(unit * 2))
        self.assertEqual(evaluator.evaluate(_window(unit)), ())
        evaluator.reset()
        self.assertEqual(len(evaluator.evaluate(_window(unit))), 1)

    def test_finalize_returns_empty(self) -> None:
        evaluator = RuleBasedEvaluator(["verfahren"])
        self.assertEqual(evaluator.finalize(), ())


class TestRunPipeline(unittest.TestCase):
    """End-to-End: Datei -> Fenster -> Evaluator -> Evidenzen."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(self._tmp.name)

    def test_multi_window_text_file_all_hits_found_once(self) -> None:
        filler = "allgemeine organisationsbeschreibung ohne signal. " * 20 + "\n"
        parts: list[str] = []
        for i in range(12):
            parts.append(filler)
            parts.append("abschnitt %02d: %s.\n" % (i, POSITIVE_SENTENCE))
        path = self.root / "controls.txt"
        path.write_text("".join(parts), encoding="utf-8")

        evaluator = RuleBasedEvaluator(["verfahren"], chunk_radius=100, overlap=200)
        results = list(run_pipeline(path, evaluator, window_chars=2_000, overlap=200))
        self.assertEqual(len(results), 12)
        self.assertTrue(all(r.is_compliant for r in results))

    def test_pdf_dispatch_via_pipeline(self) -> None:
        with mock.patch("aethelgard.mvp1.pdf_handler.stream_pdf_pages") as mock_stream:
            mock_stream.return_value = iter([POSITIVE_SENTENCE, "zweite seite ohne treffer"])
            evaluator = RuleBasedEvaluator(["verfahren"], chunk_radius=100, overlap=200)
            results = list(run_pipeline(self.root / "doc.pdf", evaluator))
        self.assertEqual(len(results), 1)
        mock_stream.assert_called_once()

    def test_empty_file_yields_nothing(self) -> None:
        path = self.root / "empty.txt"
        path.write_text("", encoding="utf-8")
        evaluator = RuleBasedEvaluator(["verfahren"])
        self.assertEqual(list(run_pipeline(path, evaluator)), [])

    def test_no_keyword_yields_nothing(self) -> None:
        path = self.root / "plain.txt"
        path.write_text("keine relevanten begriffe in diesem text.", encoding="utf-8")
        evaluator = RuleBasedEvaluator(["verfahren"])
        self.assertEqual(list(run_pipeline(path, evaluator)), [])


if __name__ == "__main__":
    unittest.main()
