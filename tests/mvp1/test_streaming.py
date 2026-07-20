"""Tests fuer ``aethelgard.mvp1.streaming`` (Block-Quellen + Fensterung).

AAA-Pattern; Datei-IO laeuft ueber echte tmp-Verzeichnisse (wie
``TestStreamPdfPagesWithRealTmpFile``), pypdf bleibt gemockt.
"""

from __future__ import annotations

import tempfile
import unittest
from dataclasses import FrozenInstanceError
from pathlib import Path
from unittest import mock

from aethelgard.mvp1 import streaming
from aethelgard.mvp1.streaming import (
    TextWindow,
    iter_document_blocks,
    iter_pdf_blocks,
    iter_text_blocks,
    sliding_windows,
)


class TestTextWindow(unittest.TestCase):
    """Datenvertrag des Fensters."""

    def test_fields_and_frozen(self) -> None:
        window = TextWindow(
            window_index=3, start_char=10, end_char=20, text="abcdefghij", is_tail=False
        )
        self.assertEqual(window.window_index, 3)
        self.assertEqual(window.start_char, 10)
        self.assertEqual(window.end_char, 20)
        self.assertFalse(window.is_tail)
        with self.assertRaises(FrozenInstanceError):
            window.text = "x"  # type: ignore[misc]


class TestIterTextBlocks(unittest.TestCase):
    """Blockweises Lesen von Textdateien."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(self._tmp.name)

    def _write(self, name: str, content: str) -> Path:
        path = self.root / name
        path.write_text(content, encoding="utf-8")
        return path

    def test_small_file_single_block(self) -> None:
        path = self._write("small.txt", "hello world")
        blocks = list(iter_text_blocks(path, block_chars=64))
        self.assertEqual(blocks, ["hello world"])

    def test_multiple_blocks_exact_and_remainder(self) -> None:
        path = self._write("multi.txt", "a" * 25)
        blocks = list(iter_text_blocks(path, block_chars=10))
        self.assertEqual([len(block) for block in blocks], [10, 10, 5])
        self.assertEqual("".join(blocks), "a" * 25)

    def test_multibyte_utf8_survives_block_boundaries(self) -> None:
        path = self._write("umlaut.txt", "äöüß" * 10)
        blocks = list(iter_text_blocks(path, block_chars=1))
        self.assertEqual("".join(blocks), "äöüß" * 10)
        self.assertNotIn("�", "".join(blocks))

    def test_empty_file_yields_nothing(self) -> None:
        path = self._write("empty.txt", "")
        self.assertEqual(list(iter_text_blocks(path)), [])

    def test_invalid_block_chars_raises(self) -> None:
        path = self._write("x.txt", "x")
        for invalid in (0, -5):
            with self.assertRaises(ValueError):
                list(iter_text_blocks(path, block_chars=invalid))

    def test_decode_errors_are_replaced(self) -> None:
        path = self.root / "broken.txt"
        path.write_bytes(b"ok \xff\xfe broken")
        text = "".join(iter_text_blocks(path))
        self.assertTrue(text.startswith("ok "))
        self.assertIn("�", text)


class TestIterPdfBlocks(unittest.TestCase):
    """PDF-Dispatch delegiert an pdf_handler (Mocking-Ziel bleibt stabil)."""

    def test_delegates_to_stream_pdf_pages(self) -> None:
        with mock.patch("aethelgard.mvp1.pdf_handler.stream_pdf_pages") as mock_stream:
            mock_stream.return_value = iter(["Seite 1", "Seite 2"])
            blocks = list(iter_pdf_blocks("dummy.pdf"))
        self.assertEqual(blocks, ["Seite 1", "Seite 2"])
        mock_stream.assert_called_once_with(Path("dummy.pdf"), strict=True)


class TestIterDocumentBlocks(unittest.TestCase):
    """Typ-Dispatch: PDF seitenweise, alles andere blockweise."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(self._tmp.name)

    def test_text_suffix_uses_text_blocks(self) -> None:
        path = self.root / "doc.md"
        path.write_text("inhalt", encoding="utf-8")
        self.assertEqual(list(iter_document_blocks(path)), ["inhalt"])

    def test_pdf_suffix_uses_pdf_blocks(self) -> None:
        with mock.patch("aethelgard.mvp1.pdf_handler.stream_pdf_pages") as mock_stream:
            mock_stream.return_value = iter(["seite"])
            blocks = list(iter_document_blocks(self.root / "doc.PDF"))
        self.assertEqual(blocks, ["seite"])
        self.assertEqual(mock_stream.call_count, 1)


class TestSlidingWindows(unittest.TestCase):
    """Fenster-Geometrie und Ownership-Partition."""

    def test_short_text_single_tail_window(self) -> None:
        windows = list(sliding_windows(iter(["x" * 100]), window_chars=1000, overlap=100))
        self.assertEqual(len(windows), 1)
        window = windows[0]
        self.assertTrue(window.is_tail)
        self.assertEqual((window.start_char, window.end_char), (0, 100))
        self.assertEqual(window.text, "x" * 100)

    def test_exact_window_chars_single_window(self) -> None:
        windows = list(
            sliding_windows(iter(["a" * 500, "b" * 500]), window_chars=1000, overlap=100)
        )
        self.assertEqual(len(windows), 1)
        self.assertTrue(windows[0].is_tail)
        self.assertEqual(len(windows[0].text), 1000)

    def test_multi_window_geometry_is_gapless(self) -> None:
        text = "0123456789" * 25  # 250 Zeichen
        windows = list(sliding_windows(iter([text]), window_chars=100, overlap=20))
        self.assertEqual([w.window_index for w in windows], [0, 1])
        # step = 80: Fenster [0,100); Rest (170 <= window + step) wird Tail [80,250).
        self.assertEqual([(w.start_char, w.end_char) for w in windows], [(0, 100), (80, 250)])
        self.assertEqual([w.is_tail for w in windows], [False, True])
        # Kern-Intervalle [start, end - overlap) sind lueckenlos:
        core = [(w.start_char, w.end_char if w.is_tail else w.end_char - 20) for w in windows]
        self.assertEqual(core, [(0, 80), (80, 250)])
        # Jeder Fenstertext stimmt mit dem Quelltext ueberein:
        for window in windows:
            self.assertEqual(window.text, text[window.start_char : window.end_char])

    def test_no_mini_tail_window_after_full_window(self) -> None:
        # 1100 Zeichen bei window=1000, overlap=100 (Tail-Schwelle 1900):
        # EIN Tail-Fenster statt Fenster + 100-Zeichen-Mini-Rest.
        text = "z" * 1100
        windows = list(sliding_windows(iter([text]), window_chars=1000, overlap=100))
        self.assertEqual(len(windows), 1)
        self.assertTrue(windows[0].is_tail)
        self.assertEqual((windows[0].start_char, windows[0].end_char), (0, 1100))
        # 1901 Zeichen: non-tail [0,1000), Tail [900,1901) - kein Mini-Rest.
        text = "z" * 1901
        windows = list(sliding_windows(iter([text]), window_chars=1000, overlap=100))
        self.assertEqual([(w.start_char, w.end_char) for w in windows], [(0, 1000), (900, 1901)])
        self.assertEqual([w.is_tail for w in windows], [False, True])
        # Kern-Intervalle lueckenlos:
        core = [(w.start_char, w.end_char if w.is_tail else w.end_char - 100) for w in windows]
        self.assertEqual(core, [(0, 900), (900, 1901)])

    def test_windows_cover_arbitrary_block_splits(self) -> None:
        text = "Das verfahren ist dokumentiert. " * 97  # 3104 Zeichen
        blocks = iter([text[i : i + 7] for i in range(0, len(text), 7)])  # 7-Zeichen-Bloecke
        windows = list(sliding_windows(blocks, window_chars=1000, overlap=120))
        reconstructed = ""
        for window in windows:
            core_end = window.end_char if window.is_tail else window.end_char - 120
            reconstructed += text[window.start_char : core_end]
        self.assertEqual(reconstructed, text)

    def test_validation_raises(self) -> None:
        with self.assertRaises(ValueError):
            list(sliding_windows(iter(["x"]), window_chars=0, overlap=0))
        with self.assertRaises(ValueError):
            list(sliding_windows(iter(["x"]), window_chars=100, overlap=100))
        with self.assertRaises(ValueError):
            list(sliding_windows(iter(["x"]), window_chars=100, overlap=-1))

    def test_empty_input_yields_nothing(self) -> None:
        self.assertEqual(list(sliding_windows(iter([]), window_chars=100, overlap=10)), [])

    def test_defaults_match_module_constants(self) -> None:
        self.assertEqual(streaming.DEFAULT_WINDOW_CHARS, 65_536)
        self.assertEqual(streaming.DEFAULT_WINDOW_OVERLAP, 512)
        self.assertEqual(streaming.DEFAULT_BLOCK_CHARS, 65_536)


if __name__ == "__main__":
    unittest.main()
