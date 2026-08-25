"""Installed-wheel integration checks."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path
from zipfile import ZipFile

PROJECT_ROOT = Path(__file__).resolve().parents[1]
CATALOG_SOURCE_DIR = PROJECT_ROOT / "data" / "control_catalogs"
PACKAGE_CATALOG_DIR = "aethelgard/data/control_catalogs"


def test_wheel_installs_catalogs_and_validates_outside_checkout(tmp_path: Path) -> None:
    outside_dir = tmp_path / "outside"
    wheel_dir = tmp_path / "wheels"
    install_target = tmp_path / "installed"
    outside_dir.mkdir()
    wheel_dir.mkdir()

    build = _run(
        [
            sys.executable,
            "-m",
            "pip",
            "wheel",
            "--no-deps",
            "--wheel-dir",
            str(wheel_dir),
            str(PROJECT_ROOT),
        ],
        cwd=outside_dir,
    )
    assert build.returncode == 0, build.stdout

    wheels = tuple(wheel_dir.glob("aethelgard-*.whl"))
    assert len(wheels) == 1
    wheel_path = wheels[0]
    with ZipFile(wheel_path) as wheel:
        for source in sorted(CATALOG_SOURCE_DIR.glob("*.json")):
            packaged = wheel.read(f"{PACKAGE_CATALOG_DIR}/{source.name}")
            assert packaged == source.read_bytes()

    install = _run(
        [
            sys.executable,
            "-m",
            "pip",
            "install",
            "--no-deps",
            "--target",
            str(install_target),
            str(wheel_path),
        ],
        cwd=outside_dir,
    )
    assert install.returncode == 0, install.stdout

    environment = os.environ.copy()
    environment["PYTHONNOUSERSITE"] = "1"
    environment["PYTHONPATH"] = str(install_target)
    script = (
        "from pathlib import Path\n"
        "import aethelgard\n"
        "from aethelgard.cli import main\n"
        f"target = Path({str(install_target)!r}).resolve()\n"
        "package_path = Path(aethelgard.__file__).resolve()\n"
        "assert package_path.is_relative_to(target), package_path\n"
        "raise SystemExit(main(['validate-controls']))\n"
    )
    validate = _run(
        [sys.executable, "-c", script],
        cwd=outside_dir,
        env=environment,
    )

    assert validate.returncode == 0, validate.stdout
    assert "'status': 'pass'" in validate.stdout


def _run(
    command: list[str],
    *,
    cwd: Path,
    env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        cwd=cwd,
        env=env,
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=180,
    )
