"""Setuptools hook for packaging the canonical control catalogs."""

from __future__ import annotations

import shutil
from pathlib import Path

from setuptools import setup
from setuptools.command.build_py import build_py

PROJECT_ROOT = Path(__file__).resolve().parent
CATALOG_SOURCE_DIR = PROJECT_ROOT / "data" / "control_catalogs"


class CatalogBuildPy(build_py):
    """Copy canonical repository catalogs into the installed package."""

    def run(self) -> None:
        catalog_sources = sorted(CATALOG_SOURCE_DIR.glob("*.json"))
        if not catalog_sources:
            raise FileNotFoundError("no canonical control catalogs found")

        super().run()
        destination = Path(self.build_lib) / "aethelgard" / "data" / "control_catalogs"
        if destination.exists():
            shutil.rmtree(destination)
        self.mkpath(str(destination))
        for source in catalog_sources:
            self.copy_file(str(source), str(destination / source.name))


setup(cmdclass={"build_py": CatalogBuildPy})
