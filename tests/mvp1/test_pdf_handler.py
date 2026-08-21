"""Unit-Tests fuer AethelGard MVP1 PDF-Handler.

Mocking-Strategie:
- pypdf.PdfReader wird ueber ``mock.patch`` auf Modul-Ebene ersetzt,
  sodass keine echten PDFs benoetigt werden.
- Dateisystem-Operationen (Path.stat, Path.open) werden teilweise
  gemockt, teilweise mit echten tmp-Files getestet.
- pypdf-Exceptions werden aus der echten pypdf-Bibliothek importiert,
  um realistische Hierarchien zu testen.
"""

from __future__ import annotations

import unittest
from collections.abc import Iterator
from pathlib import Path
from typing import Any
from unittest import mock

from pypdf.errors import (
    EmptyFileError,
    FileNotDecryptedError,
    ParseError,
    PdfReadError,
    WrongPasswordError,
)

from aethelgard.mvp1.document_parser import (
    MAX_FILE_SIZE_BYTES,
    FileSizeLimitExceededError,
    LocalDocumentParser,
)
from aethelgard.mvp1.pdf_handler import (
    CorruptPdfError,
    EncryptedPdfError,
    PdfDependencyMissingError,
    PdfParseError,
    _classify_pypdf_error,
    extract_pdf_text,
    is_pypdf_available,
    stream_pdf_pages,
)

# ---------------------------------------------------------------------------
# Hilfsfunktionen zum Bauen von pypdf-Mocks
# ---------------------------------------------------------------------------


def _build_reader_mock(
    *,
    pages: list[Any] | None = None,
    is_encrypted: bool = False,
) -> Any:
    """Erzeugt einen vollstaendig konfigurierten Mock fuer ``pypdf.PdfReader``.

    Args:
        pages: Liste von Page-Mocks mit ``extract_text()``-Stub.
        is_encrypted: Wert fuer ``reader.is_encrypted``.

    Returns:
        Mock-Objekt, das wie ein ``PdfReader`` aussieht.
    """
    reader = mock.MagicMock()
    reader.is_encrypted = is_encrypted
    reader.pages = pages or []
    return reader


def _build_page_mock(
    text: str = "",
    *,
    side_effect: BaseException | None = None,
) -> Any:
    """Erzeugt einen Page-Mock mit ``extract_text()``-Stub."""
    page = mock.MagicMock()
    if side_effect is not None:
        page.extract_text.side_effect = side_effect
    else:
        page.extract_text.return_value = text
    return page


# ---------------------------------------------------------------------------
# Tests fuer is_pypdf_available
# ---------------------------------------------------------------------------


class TestIsPypdfAvailable(unittest.TestCase):
    """Smoke-Test fuer den Dependency-Check."""

    def test_returns_bool(self) -> None:
        result = is_pypdf_available()
        self.assertIsInstance(result, bool)

    def test_returns_true_when_pypdf_installed(self) -> None:
        # pypdf wurde fuer die Tests installiert.
        self.assertTrue(is_pypdf_available())


# ---------------------------------------------------------------------------
# Tests fuer stream_pdf_pages
# ---------------------------------------------------------------------------


class TestStreamPdfPagesFileValidation(unittest.TestCase):
    """Tests fuer Pfad- und Groessen-Validierung VOR dem Oeffnen."""

    def test_file_not_found_raises(self) -> None:
        nonexistent = Path("D:/nonexistent_file_xyz_for_test.pdf")
        with self.assertRaises(FileNotFoundError):
            list(stream_pdf_pages(nonexistent))

    def test_directory_instead_of_file_raises(self) -> None:
        # Echte Directory statt File
        with self.assertRaises(IsADirectoryError):
            list(stream_pdf_pages(Path.cwd()))

    def test_file_too_large_raises(self) -> None:
        # Mock mit Size > 50 MB
        with mock.patch("aethelgard.mvp1.pdf_handler.Path") as mock_path_cls:
            mock_path = mock.MagicMock(spec=Path)
            mock_path.exists.return_value = True
            mock_path.is_file.return_value = True
            mock_path.stat.return_value = mock.MagicMock(st_size=MAX_FILE_SIZE_BYTES + 1)
            mock_path_cls.return_value = mock_path
            with self.assertRaises(FileSizeLimitExceededError):
                list(stream_pdf_pages(mock_path))


class TestStreamPdfPagesSuccessful(unittest.TestCase):
    """Tests fuer erfolgreiches Page-Streaming."""

    def test_yields_single_page(self) -> None:
        page1 = _build_page_mock("Seite 1 Inhalt: risk assessment dokumentiert")
        reader = _build_reader_mock(pages=[page1])

        with mock.patch("aethelgard.mvp1.pdf_handler._get_pypdf") as mock_get_pypdf:
            mock_pypdf = mock.MagicMock()
            mock_pypdf.PdfReader.return_value = reader
            mock_get_pypdf.return_value = mock_pypdf

            with mock.patch("aethelgard.mvp1.pdf_handler.Path") as mock_path_cls:
                mock_path = mock.MagicMock(spec=Path)
                mock_path.exists.return_value = True
                mock_path.is_file.return_value = True
                mock_path.stat.return_value = mock.MagicMock(st_size=1024)
                mock_file = mock.MagicMock()
                mock_path.open.return_value.__enter__.return_value = mock_file
                mock_path_cls.return_value = mock_path

                pages = list(stream_pdf_pages(mock_path))

        self.assertEqual(len(pages), 1)
        self.assertIn("risk assessment", pages[0])

    def test_yields_multiple_pages_in_order(self) -> None:
        page1 = _build_page_mock("Seite 1: risk")
        page2 = _build_page_mock("Seite 2: audit")
        page3 = _build_page_mock("Seite 3: verfahren")
        reader = _build_reader_mock(pages=[page1, page2, page3])

        with mock.patch("aethelgard.mvp1.pdf_handler._get_pypdf") as mock_get_pypdf:
            mock_pypdf = mock.MagicMock()
            mock_pypdf.PdfReader.return_value = reader
            mock_get_pypdf.return_value = mock_pypdf

            with mock.patch("aethelgard.mvp1.pdf_handler.Path") as mock_path_cls:
                mock_path = mock.MagicMock(spec=Path)
                mock_path.exists.return_value = True
                mock_path.is_file.return_value = True
                mock_path.stat.return_value = mock.MagicMock(st_size=2048)
                mock_path.open.return_value.__enter__.return_value = mock.MagicMock()
                mock_path_cls.return_value = mock_path

                pages = list(stream_pdf_pages(mock_path))

        self.assertEqual(pages, ["Seite 1: risk", "Seite 2: audit", "Seite 3: verfahren"])

    def test_skips_empty_pages(self) -> None:
        page1 = _build_page_mock("Seite 1: risk")
        page_empty = _build_page_mock("")  # leerer Text
        page3 = _build_page_mock("Seite 3: audit")
        reader = _build_reader_mock(pages=[page1, page_empty, page3])

        with mock.patch("aethelgard.mvp1.pdf_handler._get_pypdf") as mock_get_pypdf:
            mock_pypdf = mock.MagicMock()
            mock_pypdf.PdfReader.return_value = reader
            mock_get_pypdf.return_value = mock_pypdf

            with mock.patch("aethelgard.mvp1.pdf_handler.Path") as mock_path_cls:
                mock_path = mock.MagicMock(spec=Path)
                mock_path.exists.return_value = True
                mock_path.is_file.return_value = True
                mock_path.stat.return_value = mock.MagicMock(st_size=1024)
                mock_path.open.return_value.__enter__.return_value = mock.MagicMock()
                mock_path_cls.return_value = mock_path

                pages = list(stream_pdf_pages(mock_path))

        self.assertEqual(len(pages), 2)
        self.assertIn("Seite 1: risk", pages[0])
        self.assertIn("Seite 3: audit", pages[1])

    def test_returns_iterator(self) -> None:
        page1 = _build_page_mock("text")
        reader = _build_reader_mock(pages=[page1])

        with mock.patch("aethelgard.mvp1.pdf_handler._get_pypdf") as mock_get_pypdf:
            mock_pypdf = mock.MagicMock()
            mock_pypdf.PdfReader.return_value = reader
            mock_get_pypdf.return_value = mock_pypdf

            with mock.patch("aethelgard.mvp1.pdf_handler.Path") as mock_path_cls:
                mock_path = mock.MagicMock(spec=Path)
                mock_path.exists.return_value = True
                mock_path.is_file.return_value = True
                mock_path.stat.return_value = mock.MagicMock(st_size=1024)
                mock_path.open.return_value.__enter__.return_value = mock.MagicMock()
                mock_path_cls.return_value = mock_path

                result = stream_pdf_pages(mock_path)
                self.assertIsInstance(result, Iterator)

    def test_opens_file_in_binary_mode(self) -> None:
        """Verifiziert, dass die Datei im Binaermodus geoeffnet wird."""
        page1 = _build_page_mock("text")
        reader = _build_reader_mock(pages=[page1])

        with mock.patch("aethelgard.mvp1.pdf_handler._get_pypdf") as mock_get_pypdf:
            mock_pypdf = mock.MagicMock()
            mock_pypdf.PdfReader.return_value = reader
            mock_get_pypdf.return_value = mock_pypdf

            with mock.patch("aethelgard.mvp1.pdf_handler.Path") as mock_path_cls:
                mock_path = mock.MagicMock(spec=Path)
                mock_path.exists.return_value = True
                mock_path.is_file.return_value = True
                mock_path.stat.return_value = mock.MagicMock(st_size=1024)
                mock_path.open.return_value.__enter__.return_value = mock.MagicMock()
                mock_path_cls.return_value = mock_path

                list(stream_pdf_pages(mock_path))

                mock_path.open.assert_called_with("rb")

    def test_passes_strict_true_by_default(self) -> None:
        """Verifiziert, dass pypdf.PdfReader mit strict=True aufgerufen wird."""
        page1 = _build_page_mock("text")
        reader = _build_reader_mock(pages=[page1])

        with mock.patch("aethelgard.mvp1.pdf_handler._get_pypdf") as mock_get_pypdf:
            mock_pypdf = mock.MagicMock()
            mock_pypdf.PdfReader.return_value = reader
            mock_get_pypdf.return_value = mock_pypdf

            with mock.patch("aethelgard.mvp1.pdf_handler.Path") as mock_path_cls:
                mock_path = mock.MagicMock(spec=Path)
                mock_path.exists.return_value = True
                mock_path.is_file.return_value = True
                mock_path.stat.return_value = mock.MagicMock(st_size=1024)
                mock_path.open.return_value.__enter__.return_value = mock.MagicMock()
                mock_path_cls.return_value = mock_path

                list(stream_pdf_pages(mock_path))

                call_args = mock_pypdf.PdfReader.call_args
                self.assertIn("strict", call_args.kwargs)
                self.assertTrue(call_args.kwargs["strict"])


# ---------------------------------------------------------------------------
# Tests fuer Fehler-Klassifizierung
# ---------------------------------------------------------------------------


class TestStreamPdfPagesErrors(unittest.TestCase):
    """Tests fuer PDF-spezifische Exceptions."""

    def _setup_path_mock(self) -> Any:
        """Erzeugt ein Path-Mock, das alle Standard-Checks besteht."""
        mock_path = mock.MagicMock(spec=Path)
        mock_path.exists.return_value = True
        mock_path.is_file.return_value = True
        mock_path.stat.return_value = mock.MagicMock(st_size=1024)
        mock_path.open.return_value.__enter__.return_value = mock.MagicMock()
        return mock_path

    def test_encrypted_pdf_raises(self) -> None:
        """Encrypted PDFs (is_encrypted=True) werden EncryptedPdfError."""
        reader = _build_reader_mock(pages=[], is_encrypted=True)

        with mock.patch("aethelgard.mvp1.pdf_handler._get_pypdf") as mock_get_pypdf:
            mock_pypdf = mock.MagicMock()
            mock_pypdf.PdfReader.return_value = reader
            mock_get_pypdf.return_value = mock_pypdf

            with mock.patch("aethelgard.mvp1.pdf_handler.Path") as mock_path_cls:
                mock_path = self._setup_path_mock()
                mock_path_cls.return_value = mock_path

                with self.assertRaises(EncryptedPdfError):
                    list(stream_pdf_pages(mock_path))

    def test_empty_file_raises_corrupt(self) -> None:
        with mock.patch("aethelgard.mvp1.pdf_handler._get_pypdf") as mock_get_pypdf:
            mock_pypdf = mock.MagicMock()
            mock_pypdf.PdfReader.side_effect = EmptyFileError("file is empty")
            mock_get_pypdf.return_value = mock_pypdf

            with mock.patch("aethelgard.mvp1.pdf_handler.Path") as mock_path_cls:
                mock_path = self._setup_path_mock()
                mock_path_cls.return_value = mock_path

                with self.assertRaises(CorruptPdfError):
                    list(stream_pdf_pages(mock_path))

    def test_parse_error_raises_corrupt(self) -> None:
        with mock.patch("aethelgard.mvp1.pdf_handler._get_pypdf") as mock_get_pypdf:
            mock_pypdf = mock.MagicMock()
            mock_pypdf.PdfReader.side_effect = ParseError("not a PDF")
            mock_get_pypdf.return_value = mock_pypdf

            with mock.patch("aethelgard.mvp1.pdf_handler.Path") as mock_path_cls:
                mock_path = self._setup_path_mock()
                mock_path_cls.return_value = mock_path

                with self.assertRaises(CorruptPdfError):
                    list(stream_pdf_pages(mock_path))

    def test_wrong_password_raises_encrypted(self) -> None:
        with mock.patch("aethelgard.mvp1.pdf_handler._get_pypdf") as mock_get_pypdf:
            mock_pypdf = mock.MagicMock()
            mock_pypdf.PdfReader.side_effect = WrongPasswordError("bad password")
            mock_get_pypdf.return_value = mock_pypdf

            with mock.patch("aethelgard.mvp1.pdf_handler.Path") as mock_path_cls:
                mock_path = self._setup_path_mock()
                mock_path_cls.return_value = mock_path

                with self.assertRaises(EncryptedPdfError):
                    list(stream_pdf_pages(mock_path))

    def test_generic_pdf_read_error_wrapped(self) -> None:
        with mock.patch("aethelgard.mvp1.pdf_handler._get_pypdf") as mock_get_pypdf:
            mock_pypdf = mock.MagicMock()
            mock_pypdf.PdfReader.side_effect = PdfReadError("malformed")
            mock_get_pypdf.return_value = mock_pypdf

            with mock.patch("aethelgard.mvp1.pdf_handler.Path") as mock_path_cls:
                mock_path = self._setup_path_mock()
                mock_path_cls.return_value = mock_path

                with self.assertRaises(PdfParseError):
                    list(stream_pdf_pages(mock_path))

    def test_corrupt_page_in_strict_mode_raises(self) -> None:
        page1 = _build_page_mock("ok")
        page_corrupt = _build_page_mock(side_effect=PdfReadError("page broken"))
        reader = _build_reader_mock(pages=[page1, page_corrupt])

        with mock.patch("aethelgard.mvp1.pdf_handler._get_pypdf") as mock_get_pypdf:
            mock_pypdf = mock.MagicMock()
            mock_pypdf.PdfReader.return_value = reader
            mock_get_pypdf.return_value = mock_pypdf

            with mock.patch("aethelgard.mvp1.pdf_handler.Path") as mock_path_cls:
                mock_path = self._setup_path_mock()
                mock_path_cls.return_value = mock_path

                with self.assertRaises(CorruptPdfError):
                    list(stream_pdf_pages(mock_path, strict=True))

    def test_corrupt_page_in_non_strict_mode_skipped(self) -> None:
        page1 = _build_page_mock("ok")
        page_corrupt = _build_page_mock(side_effect=PdfReadError("page broken"))
        page3 = _build_page_mock("auch ok")
        reader = _build_reader_mock(pages=[page1, page_corrupt, page3])

        with mock.patch("aethelgard.mvp1.pdf_handler._get_pypdf") as mock_get_pypdf:
            mock_pypdf = mock.MagicMock()
            mock_pypdf.PdfReader.return_value = reader
            mock_get_pypdf.return_value = mock_pypdf

            with mock.patch("aethelgard.mvp1.pdf_handler.Path") as mock_path_cls:
                mock_path = self._setup_path_mock()
                mock_path_cls.return_value = mock_path

                pages = list(stream_pdf_pages(mock_path, strict=False))

        self.assertEqual(pages, ["ok", "auch ok"])

    def test_page_limit_enforced(self) -> None:
        """Mehr als MAX_PDF_PAGES Seiten fuehren zu fruehzeitigem Stop."""
        # 5 Seiten, Limit 3
        pages_mock = [_build_page_mock(f"page {i}") for i in range(5)]
        reader = _build_reader_mock(pages=pages_mock)

        with mock.patch("aethelgard.mvp1.pdf_handler._get_pypdf") as mock_get_pypdf:
            mock_pypdf = mock.MagicMock()
            mock_pypdf.PdfReader.return_value = reader
            mock_get_pypdf.return_value = mock_pypdf

            with (
                mock.patch("aethelgard.mvp1.pdf_handler.MAX_PDF_PAGES", 3),
                mock.patch("aethelgard.mvp1.pdf_handler.Path") as mock_path_cls,
            ):
                mock_path = self._setup_path_mock()
                mock_path_cls.return_value = mock_path

                result = list(stream_pdf_pages(mock_path))

        self.assertEqual(len(result), 3)


# ---------------------------------------------------------------------------
# Tests fuer pypdf-Missing-Pfad
# ---------------------------------------------------------------------------


class TestPypdfMissing(unittest.TestCase):
    """Tests fuer den Fall, dass pypdf nicht installiert ist."""

    def test_dependency_missing_raises(self) -> None:
        with mock.patch("aethelgard.mvp1.pdf_handler._get_pypdf") as mock_get_pypdf:
            mock_get_pypdf.side_effect = PdfDependencyMissingError("pypdf is not installed")

            mock_path = mock.MagicMock(spec=Path)
            mock_path.exists.return_value = True
            mock_path.is_file.return_value = True
            mock_path.stat.return_value = mock.MagicMock(st_size=1024)
            mock_path.open.return_value.__enter__.return_value = mock.MagicMock()

            with mock.patch("aethelgard.mvp1.pdf_handler.Path") as mock_path_cls:
                mock_path_cls.return_value = mock_path

                with self.assertRaises(PdfDependencyMissingError):
                    list(stream_pdf_pages(mock_path))


# ---------------------------------------------------------------------------
# Tests fuer _classify_pypdf_error
# ---------------------------------------------------------------------------


class TestClassifyPypdfError(unittest.TestCase):
    """Tests fuer die Fehler-Klassifizierungs-Funktion."""

    def test_empty_file_error_mapped(self) -> None:
        exc = EmptyFileError("empty")
        result = _classify_pypdf_error(exc, Path("test.pdf"))
        self.assertIsInstance(result, CorruptPdfError)

    def test_parse_error_mapped(self) -> None:
        exc = ParseError("bad")
        result = _classify_pypdf_error(exc, Path("test.pdf"))
        self.assertIsInstance(result, CorruptPdfError)

    def test_file_not_decrypted_mapped(self) -> None:
        exc = FileNotDecryptedError("encrypted")
        result = _classify_pypdf_error(exc, Path("test.pdf"))
        self.assertIsInstance(result, EncryptedPdfError)

    def test_wrong_password_mapped(self) -> None:
        exc = WrongPasswordError("bad pw")
        result = _classify_pypdf_error(exc, Path("test.pdf"))
        self.assertIsInstance(result, EncryptedPdfError)

    def test_generic_pdf_read_error_falls_back(self) -> None:
        exc = PdfReadError("malformed structure")
        result = _classify_pypdf_error(exc, Path("test.pdf"))
        self.assertIsInstance(result, PdfParseError)
        self.assertNotIsInstance(result, CorruptPdfError)
        self.assertNotIsInstance(result, EncryptedPdfError)

    def test_error_message_contains_path(self) -> None:
        exc = PdfReadError("malformed")
        result = _classify_pypdf_error(exc, Path("D:/test/policy.pdf"))
        self.assertIn("policy.pdf", str(result))


# ---------------------------------------------------------------------------
# Tests fuer extract_pdf_text
# ---------------------------------------------------------------------------


class TestExtractPdfText(unittest.TestCase):
    """Tests fuer den Convenience-Wrapper."""

    def test_joins_pages_with_default_separator(self) -> None:
        page1 = _build_page_mock("Hello")
        page2 = _build_page_mock("World")
        reader = _build_reader_mock(pages=[page1, page2])

        with mock.patch("aethelgard.mvp1.pdf_handler._get_pypdf") as mock_get_pypdf:
            mock_pypdf = mock.MagicMock()
            mock_pypdf.PdfReader.return_value = reader
            mock_get_pypdf.return_value = mock_pypdf

            with mock.patch("aethelgard.mvp1.pdf_handler.Path") as mock_path_cls:
                mock_path = mock.MagicMock(spec=Path)
                mock_path.exists.return_value = True
                mock_path.is_file.return_value = True
                mock_path.stat.return_value = mock.MagicMock(st_size=1024)
                mock_path.open.return_value.__enter__.return_value = mock.MagicMock()
                mock_path_cls.return_value = mock_path

                text = extract_pdf_text(mock_path)

        self.assertEqual(text, "Hello\n\nWorld")

    def test_custom_separator(self) -> None:
        page1 = _build_page_mock("A")
        page2 = _build_page_mock("B")
        reader = _build_reader_mock(pages=[page1, page2])

        with mock.patch("aethelgard.mvp1.pdf_handler._get_pypdf") as mock_get_pypdf:
            mock_pypdf = mock.MagicMock()
            mock_pypdf.PdfReader.return_value = reader
            mock_get_pypdf.return_value = mock_pypdf

            with mock.patch("aethelgard.mvp1.pdf_handler.Path") as mock_path_cls:
                mock_path = mock.MagicMock(spec=Path)
                mock_path.exists.return_value = True
                mock_path.is_file.return_value = True
                mock_path.stat.return_value = mock.MagicMock(st_size=1024)
                mock_path.open.return_value.__enter__.return_value = mock.MagicMock()
                mock_path_cls.return_value = mock_path

                text = extract_pdf_text(mock_path, page_separator="---")

        self.assertEqual(text, "A---B")

    def test_empty_pdf_returns_empty_string(self) -> None:
        reader = _build_reader_mock(pages=[])

        with mock.patch("aethelgard.mvp1.pdf_handler._get_pypdf") as mock_get_pypdf:
            mock_pypdf = mock.MagicMock()
            mock_pypdf.PdfReader.return_value = reader
            mock_get_pypdf.return_value = mock_pypdf

            with mock.patch("aethelgard.mvp1.pdf_handler.Path") as mock_path_cls:
                mock_path = mock.MagicMock(spec=Path)
                mock_path.exists.return_value = True
                mock_path.is_file.return_value = True
                mock_path.stat.return_value = mock.MagicMock(st_size=1024)
                mock_path.open.return_value.__enter__.return_value = mock.MagicMock()
                mock_path_cls.return_value = mock_path

                text = extract_pdf_text(mock_path)

        self.assertEqual(text, "")

    def test_encrypted_error_propagates(self) -> None:
        reader = _build_reader_mock(pages=[], is_encrypted=True)

        with mock.patch("aethelgard.mvp1.pdf_handler._get_pypdf") as mock_get_pypdf:
            mock_pypdf = mock.MagicMock()
            mock_pypdf.PdfReader.return_value = reader
            mock_get_pypdf.return_value = mock_pypdf

            with mock.patch("aethelgard.mvp1.pdf_handler.Path") as mock_path_cls:
                mock_path = mock.MagicMock(spec=Path)
                mock_path.exists.return_value = True
                mock_path.is_file.return_value = True
                mock_path.stat.return_value = mock.MagicMock(st_size=1024)
                mock_path.open.return_value.__enter__.return_value = mock.MagicMock()
                mock_path_cls.return_value = mock_path

                with self.assertRaises(EncryptedPdfError):
                    extract_pdf_text(mock_path)


# ---------------------------------------------------------------------------
# Tests fuer LocalDocumentParser-Integration
# ---------------------------------------------------------------------------


class TestLocalDocumentParserPDFDispatch(unittest.TestCase):
    """Tests fuer die automatische PDF-Erkennung in ``parse_file``."""

    def test_pdf_extension_triggers_pdf_path(self) -> None:
        parser = LocalDocumentParser(
            keywords=["risk assessment"],
            chunk_radius=100,
        )
        with mock.patch("aethelgard.mvp1.pdf_handler.stream_pdf_pages") as mock_stream:
            mock_stream.return_value = iter(["risk assessment dokumentiert und implementiert"])

            mock_path = mock.MagicMock(spec=Path)
            mock_path.exists.return_value = True
            mock_path.is_file.return_value = True
            mock_path.suffix = ".pdf"
            mock_path.stat.return_value = mock.MagicMock(st_size=2048)

            with mock.patch("aethelgard.mvp1.document_parser.Path") as mock_path_cls:
                mock_path_cls.return_value = mock_path
                results = list(parser.parse_file(mock_path))

        mock_stream.assert_called_once_with(mock_path)
        self.assertGreater(len(results), 0)
        self.assertIn("risk", results[0].source_citation.lower())

    def test_pdf_extension_uppercase_also_triggers(self) -> None:
        """Case-insensitive: .PDF und .Pdf muessen funktionieren."""
        parser = LocalDocumentParser(keywords=["risk"])

        for ext in (".PDF", ".Pdf", ".pdf"):
            with self.subTest(extension=ext):
                with mock.patch("aethelgard.mvp1.pdf_handler.stream_pdf_pages") as mock_stream:
                    mock_stream.return_value = iter(["risk text"])

                    mock_path = mock.MagicMock(spec=Path)
                    mock_path.exists.return_value = True
                    mock_path.is_file.return_value = True
                    mock_path.suffix = ext
                    mock_path.stat.return_value = mock.MagicMock(st_size=1024)

                    with mock.patch("aethelgard.mvp1.document_parser.Path") as mock_path_cls:
                        mock_path_cls.return_value = mock_path
                        results = list(parser.parse_file(mock_path))

                    self.assertGreater(len(results), 0)

    def test_non_pdf_uses_text_path(self) -> None:
        """Nicht-PDF-Dateien (z. B. .txt) gehen durch den Text-Pfad."""
        parser = LocalDocumentParser(keywords=["risk"])

        with mock.patch("aethelgard.mvp1.pdf_handler.stream_pdf_pages") as mock_stream:
            mock_path = mock.MagicMock(spec=Path)
            mock_path.exists.return_value = True
            mock_path.is_file.return_value = True
            mock_path.suffix = ".txt"
            mock_path.stat.return_value = mock.MagicMock(st_size=1024)
            mock_path.read_text.return_value = "risk text dokumentiert"

            with mock.patch("aethelgard.mvp1.document_parser.Path") as mock_path_cls:
                mock_path_cls.return_value = mock_path
                results = list(parser.parse_file(mock_path))

        mock_stream.assert_not_called()
        self.assertGreater(len(results), 0)

    def test_no_extension_uses_text_path(self) -> None:
        """Dateien ohne Endung fallen auf den Text-Pfad zurueck."""
        parser = LocalDocumentParser(keywords=["risk"])

        with mock.patch("aethelgard.mvp1.pdf_handler.stream_pdf_pages") as mock_stream:
            mock_path = mock.MagicMock(spec=Path)
            mock_path.exists.return_value = True
            mock_path.is_file.return_value = True
            mock_path.suffix = ""
            mock_path.stat.return_value = mock.MagicMock(st_size=1024)
            mock_path.read_text.return_value = "risk text"

            with mock.patch("aethelgard.mvp1.document_parser.Path") as mock_path_cls:
                mock_path_cls.return_value = mock_path
                list(parser.parse_file(mock_path))

        mock_stream.assert_not_called()

    def test_pdf_multi_page_yields_chunks_per_page(self) -> None:
        """Multi-Page-PDF: Chunks aus jeder Seite."""
        parser = LocalDocumentParser(
            keywords=["risk", "audit"],
            chunk_radius=200,
        )
        with mock.patch("aethelgard.mvp1.pdf_handler.stream_pdf_pages") as mock_stream:
            mock_stream.return_value = iter(
                [
                    "Seite 1: risk assessment dokumentiert.",
                    "Seite 2: audit procedure verfahren implementiert.",
                ]
            )

            mock_path = mock.MagicMock(spec=Path)
            mock_path.exists.return_value = True
            mock_path.is_file.return_value = True
            mock_path.suffix = ".pdf"
            mock_path.stat.return_value = mock.MagicMock(st_size=4096)

            with mock.patch("aethelgard.mvp1.document_parser.Path") as mock_path_cls:
                mock_path_cls.return_value = mock_path
                results = list(parser.parse_file(mock_path))

        # Mindestens 2 Evidenzen (1 pro Seite)
        self.assertGreaterEqual(len(results), 2)
        # Mindestens 2 unterschiedliche requirement_ids
        unique_reqs = {r.requirement_id for r in results}
        self.assertGreaterEqual(len(unique_reqs), 2)

    def test_pdf_size_limit_applies_before_streaming(self) -> None:
        """PDF > 50 MB wird abgelehnt, bevor pypdf aufgerufen wird."""
        parser = LocalDocumentParser(keywords=["risk"])
        with mock.patch("aethelgard.mvp1.pdf_handler.stream_pdf_pages") as mock_stream:
            mock_path = mock.MagicMock(spec=Path)
            mock_path.exists.return_value = True
            mock_path.is_file.return_value = True
            mock_path.suffix = ".pdf"
            mock_path.stat.return_value = mock.MagicMock(st_size=MAX_FILE_SIZE_BYTES + 1)

            with mock.patch("aethelgard.mvp1.document_parser.Path") as mock_path_cls:
                mock_path_cls.return_value = mock_path
                with self.assertRaises(FileSizeLimitExceededError):
                    list(parser.parse_file(mock_path))

        mock_stream.assert_not_called()

    def test_pdf_encrypted_error_wrapped(self) -> None:
        """EncryptedPdfError aus stream_pdf_pages propagiert."""
        parser = LocalDocumentParser(keywords=["risk"])
        with mock.patch("aethelgard.mvp1.pdf_handler.stream_pdf_pages") as mock_stream:
            mock_stream.side_effect = EncryptedPdfError("encrypted")

            mock_path = mock.MagicMock(spec=Path)
            mock_path.exists.return_value = True
            mock_path.is_file.return_value = True
            mock_path.suffix = ".pdf"
            mock_path.stat.return_value = mock.MagicMock(st_size=2048)

            with mock.patch("aethelgard.mvp1.document_parser.Path") as mock_path_cls:
                mock_path_cls.return_value = mock_path
                with self.assertRaises(EncryptedPdfError):
                    list(parser.parse_file(mock_path))

    def test_pdf_corrupt_error_wrapped(self) -> None:
        """CorruptPdfError aus stream_pdf_pages propagiert."""
        parser = LocalDocumentParser(keywords=["risk"])
        with mock.patch("aethelgard.mvp1.pdf_handler.stream_pdf_pages") as mock_stream:
            mock_stream.side_effect = CorruptPdfError("corrupt")

            mock_path = mock.MagicMock(spec=Path)
            mock_path.exists.return_value = True
            mock_path.is_file.return_value = True
            mock_path.suffix = ".pdf"
            mock_path.stat.return_value = mock.MagicMock(st_size=2048)

            with mock.patch("aethelgard.mvp1.document_parser.Path") as mock_path_cls:
                mock_path_cls.return_value = mock_path
                with self.assertRaises(CorruptPdfError):
                    list(parser.parse_file(mock_path))


# ---------------------------------------------------------------------------
# Integration mit echten tmp-Files
# ---------------------------------------------------------------------------


class TestStreamPdfPagesWithRealTmpFile(unittest.TestCase):
    """Integrationstest mit echtem temporaerem File (Inhalt egal)."""

    def test_real_file_path_accepted(self) -> None:
        """Ein wirklich existierendes File wird akzeptiert (Validierung
        passiert, pypdf.Open schlaegt dann fehl wegen ungueltigem Inhalt)."""
        import tempfile

        with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False, mode="wb") as tmp:
            tmp.write(b"%PDF-1.4 fake content")
            tmp_path = Path(tmp.name)

        try:
            page1 = _build_page_mock("extracted text")
            reader = _build_reader_mock(pages=[page1])

            with mock.patch("aethelgard.mvp1.pdf_handler._get_pypdf") as mock_get_pypdf:
                mock_pypdf = mock.MagicMock()
                mock_pypdf.PdfReader.return_value = reader
                mock_get_pypdf.return_value = mock_pypdf

                pages = list(stream_pdf_pages(tmp_path))

            self.assertEqual(pages, ["extracted text"])
        finally:
            tmp_path.unlink(missing_ok=True)

    def test_string_path_accepted(self) -> None:
        """String-Pfade werden zu Path konvertiert."""
        page1 = _build_page_mock("text")
        reader = _build_reader_mock(pages=[page1])

        with mock.patch("aethelgard.mvp1.pdf_handler._get_pypdf") as mock_get_pypdf:
            mock_pypdf = mock.MagicMock()
            mock_pypdf.PdfReader.return_value = reader
            mock_get_pypdf.return_value = mock_pypdf

            with mock.patch("aethelgard.mvp1.pdf_handler.Path") as mock_path_cls:
                mock_path = mock.MagicMock(spec=Path)
                mock_path.exists.return_value = True
                mock_path.is_file.return_value = True
                mock_path.stat.return_value = mock.MagicMock(st_size=1024)
                mock_path.open.return_value.__enter__.return_value = mock.MagicMock()
                mock_path_cls.return_value = mock_path

                pages = list(stream_pdf_pages("D:/some/file.pdf"))

        self.assertEqual(pages, ["text"])


if __name__ == "__main__":
    unittest.main()
