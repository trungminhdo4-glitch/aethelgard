"""Build a bounded local pilot artifact without copying the repository root."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Final

PROJECT_ROOT: Final[Path] = Path(__file__).resolve().parents[1]
DEFAULT_OUT: Final[Path] = Path("dist") / "aethelgard-pilot"
MODE_DEV_RUNTIME: Final[str] = "dev-runtime"
MODE_BINARY: Final[str] = "binary"
VALID_MODES: Final[tuple[str, str]] = (MODE_DEV_RUNTIME, MODE_BINARY)
BUILD_TIMEOUT_SECONDS: Final[int] = 300
GIT_TIMEOUT_SECONDS: Final[int] = 10
BUILD_WORK_ROOT: Final[Path] = PROJECT_ROOT / "build" / "pilot_artifact"
ENTRYPOINT_NAME: Final[str] = "aethelgard_pilot_entrypoint.py"
PYINSTALLER_APP_NAME: Final[str] = "aethelgard-pilot"

COPY_IGNORE_PATTERNS: Final[tuple[str, ...]] = (
    "__pycache__",
    "*.pyc",
    "*.pyo",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    "*.log",
    "*.db",
    "*.sqlite",
    "*.sqlite3",
)

DEV_INCLUDED_COMPONENTS: Final[tuple[str, ...]] = (
    "src/aethelgard",
    "data/control_catalogs",
    "examples/pilot",
    "examples/public",
    "pyproject.toml",
    "README_PILOT.md",
    "PILOT_NOTICE.md",
    "THIRD_PARTY_NOTICE.md",
    "build_manifest.json",
)

BINARY_INCLUDED_COMPONENTS: Final[tuple[str, ...]] = (
    "aethelgard-pilot executable",
    "data/control_catalogs",
    "examples/pilot",
    "examples/public",
    "README_PILOT.md",
    "PILOT_NOTICE.md",
    "THIRD_PARTY_NOTICE.md",
    "build_manifest.json",
)

EXCLUDED_COMPONENTS: Final[tuple[str, ...]] = (
    ".git",
    "tests",
    "AGENTS.md",
    "AGENT_LOG.md",
    "reports",
    "local_private",
    "dist",
    "build",
    ".env",
    ".env.*",
    "virtual environments",
    "databases",
    "debug logs",
    "internal prompts",
    "private workspaces",
)

DEV_PILOT_NOTICE: Final[str] = (
    "Technical dev-runtime pilot artifact. Source is visible, so this package is for "
    "internal demonstration only and must not be delivered to pilot customers as a "
    "closed artifact. No compliance guarantee; human review is required."
)

BINARY_PILOT_NOTICE: Final[str] = (
    "Technical binary pilot artifact prototype. Treat as owner-gated until legal, "
    "privacy, and runtime review are complete. No compliance guarantee; human review "
    "is required."
)

README_PILOT: Final[str] = """# AethelGard Pilot Artifact

This folder is a bounded local pilot artifact, not the source repository.

## Status

- Local-only pilot runtime.
- Customer documents stay local.
- Human review is required before any handover.
- No compliance guarantee, certification, audit opinion, or legal advice.
- If `build_manifest.json` has `source_visible: true`, do not deliver this artifact
  to a pilot customer as a closed package.

## Dev-runtime command

```powershell
python -m venv .venv
.\\.venv\\Scripts\\Activate.ps1
pip install -e ".[pdf]"
python -m aethelgard.cli --help
python -m aethelgard.cli demo-pilot --examples examples/pilot --out reports/pilot-demo
python -m aethelgard.cli doctor --workspace examples/pilot --out reports/doctor
python -m aethelgard.cli support-bundle --workspace examples/pilot `
  --out reports/support_bundle.zip --redacted
```

Write outputs under `reports/` or another local output folder that is not shared
without review.
"""

PILOT_NOTICE: Final[str] = """# Pilot Notice

This notice is technical packaging guidance, not a final legal agreement.

- No source access is granted unless the manifest explicitly marks source as visible.
- No redistribution.
- No reverse engineering.
- Time-limited pilot use only.
- No production use without a separate agreement.
- No compliance guarantee, certification, audit opinion, or legal advice.
- Human review is required before decisions or customer handover.
- Customer documents stay local.
- Support bundles are redacted by default and must be reviewed before sharing.
"""

THIRD_PARTY_NOTICE: Final[str] = """# Third-Party Notice

This pilot artifact is prepared from the local AethelGard project metadata.

Runtime dependencies are declared in `pyproject.toml` for dev-runtime artifacts.
Binary artifacts, when produced, require a separate dependency and license review
before customer delivery.
"""


class ArtifactBuildError(RuntimeError):
    """Raised when an artifact cannot be safely built."""


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Build a local AethelGard pilot artifact.")
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT, help="Artifact output directory.")
    parser.add_argument("--mode", choices=VALID_MODES, default=MODE_DEV_RUNTIME)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        out_path = _resolve_output_path(Path(args.out))
        mode = str(args.mode)
        if mode == MODE_DEV_RUNTIME:
            manifest = build_dev_runtime_artifact(out_path)
        elif mode == MODE_BINARY:
            manifest = build_binary_artifact(out_path)
        else:  # pragma: no cover - argparse choices keep this unreachable.
            raise ArtifactBuildError("unsupported build mode: %s" % mode)
    except ArtifactBuildError as exc:
        print("pilot artifact build failed: %s" % exc, file=sys.stderr)
        return 2

    print("Pilot artifact built: %s" % _display_path(out_path))
    print("Mode: %s" % manifest["package_mode"])
    print("Source visible: %s" % manifest["source_visible"])
    return 0


def build_dev_runtime_artifact(out_path: Path) -> dict[str, object]:
    _reset_output_dir(out_path)
    _copy_tree(PROJECT_ROOT / "src", out_path / "src")
    _copy_tree(PROJECT_ROOT / "data", out_path / "data")
    _copy_optional_tree(PROJECT_ROOT / "examples" / "pilot", out_path / "examples" / "pilot")
    _copy_optional_tree(PROJECT_ROOT / "examples" / "public", out_path / "examples" / "public")
    _copy_file(PROJECT_ROOT / "pyproject.toml", out_path / "pyproject.toml")
    _write_standard_docs(out_path)
    manifest = _build_manifest(
        mode=MODE_DEV_RUNTIME,
        included_components=DEV_INCLUDED_COMPONENTS,
        no_source_claim=False,
        source_visible=True,
        not_for_customer_delivery=True,
        pilot_notice=DEV_PILOT_NOTICE,
    )
    _write_manifest(out_path, manifest)
    return manifest


def build_binary_artifact(out_path: Path) -> dict[str, object]:
    if not _module_is_available("PyInstaller"):
        raise ArtifactBuildError(
            "binary mode requires PyInstaller, which is not installed; "
            "no dependency was installed"
        )

    _reset_output_dir(out_path)
    BUILD_WORK_ROOT.mkdir(parents=True, exist_ok=True)
    entrypoint_path = BUILD_WORK_ROOT / ENTRYPOINT_NAME
    entrypoint_path.write_text(
        "from aethelgard.cli import main\n\nraise SystemExit(main())\n",
        encoding="utf-8",
    )

    command = [
        sys.executable,
        "-m",
        "PyInstaller",
        "--clean",
        "--noconfirm",
        "--onefile",
        "--name",
        PYINSTALLER_APP_NAME,
        "--distpath",
        str(out_path),
        "--workpath",
        str(BUILD_WORK_ROOT / "work"),
        "--specpath",
        str(BUILD_WORK_ROOT / "spec"),
        str(entrypoint_path),
    ]
    environment = os.environ.copy()
    environment["PYTHONPATH"] = str(PROJECT_ROOT / "src")
    completed = subprocess.run(
        command,
        cwd=PROJECT_ROOT,
        check=False,
        env=environment,
        text=True,
        capture_output=True,
        timeout=BUILD_TIMEOUT_SECONDS,
    )
    if completed.returncode != 0:
        raise ArtifactBuildError(_format_subprocess_failure("PyInstaller", completed))

    executable_path = out_path / _binary_name()
    if not executable_path.is_file():
        raise ArtifactBuildError("PyInstaller completed but no executable was produced")

    _copy_tree(PROJECT_ROOT / "data", out_path / "data")
    _copy_optional_tree(PROJECT_ROOT / "examples" / "pilot", out_path / "examples" / "pilot")
    _copy_optional_tree(PROJECT_ROOT / "examples" / "public", out_path / "examples" / "public")
    _write_standard_docs(out_path)
    manifest = _build_manifest(
        mode=MODE_BINARY,
        included_components=BINARY_INCLUDED_COMPONENTS,
        no_source_claim=True,
        source_visible=False,
        not_for_customer_delivery=False,
        pilot_notice=BINARY_PILOT_NOTICE,
    )
    _write_manifest(out_path, manifest)
    return manifest


def _resolve_output_path(path: Path) -> Path:
    candidate = path if path.is_absolute() else PROJECT_ROOT / path
    resolved = candidate.resolve()
    project_root = PROJECT_ROOT.resolve()
    try:
        resolved.relative_to(project_root)
    except ValueError as exc:
        raise ArtifactBuildError("output path must stay inside the project folder") from exc
    if resolved == project_root:
        raise ArtifactBuildError("output path cannot be the project root")
    if any(part in {".git", ".venv", ".venv-fresh"} for part in resolved.parts):
        raise ArtifactBuildError("output path cannot target internal project state")
    return resolved


def _reset_output_dir(path: Path) -> None:
    resolved = path.resolve()
    project_root = PROJECT_ROOT.resolve()
    if resolved == project_root or project_root not in resolved.parents:
        raise ArtifactBuildError("refusing to clear unsafe output path")
    if resolved.exists() and not resolved.is_dir():
        raise ArtifactBuildError("output path exists and is not a directory")
    if resolved.exists():
        shutil.rmtree(resolved)
    resolved.mkdir(parents=True, exist_ok=True)


def _copy_tree(source: Path, target: Path) -> None:
    if not source.is_dir():
        raise ArtifactBuildError("required source directory is missing: %s" % _display_path(source))
    shutil.copytree(
        source,
        target,
        ignore=shutil.ignore_patterns(*COPY_IGNORE_PATTERNS),
        dirs_exist_ok=True,
    )


def _copy_optional_tree(source: Path, target: Path) -> None:
    if source.is_dir():
        _copy_tree(source, target)


def _copy_file(source: Path, target: Path) -> None:
    if not source.is_file():
        raise ArtifactBuildError("required source file is missing: %s" % _display_path(source))
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, target)


def _write_standard_docs(out_path: Path) -> None:
    (out_path / "README_PILOT.md").write_text(README_PILOT, encoding="utf-8")
    (out_path / "PILOT_NOTICE.md").write_text(PILOT_NOTICE, encoding="utf-8")
    (out_path / "THIRD_PARTY_NOTICE.md").write_text(THIRD_PARTY_NOTICE, encoding="utf-8")


def _build_manifest(
    *,
    mode: str,
    included_components: tuple[str, ...],
    no_source_claim: bool,
    source_visible: bool,
    not_for_customer_delivery: bool,
    pilot_notice: str,
) -> dict[str, object]:
    build_time = datetime.now(UTC).replace(microsecond=0)
    git_commit = _git_value(("rev-parse", "HEAD"))
    git_branch = _git_value(("branch", "--show-current"))
    build_id = _build_id(mode, build_time, git_commit, git_branch)
    return {
        "build_id": build_id,
        "build_time": build_time.isoformat().replace("+00:00", "Z"),
        "git_commit": git_commit,
        "git_branch": git_branch,
        "package_mode": mode,
        "included_components": list(included_components),
        "excluded_components": list(EXCLUDED_COMPONENTS),
        "no_source_claim": no_source_claim,
        "source_visible": source_visible,
        "not_for_customer_delivery": not_for_customer_delivery,
        "pilot_notice": pilot_notice,
        "expires_at": None,
    }


def _write_manifest(out_path: Path, manifest: dict[str, object]) -> None:
    manifest_path = out_path / "build_manifest.json"
    manifest_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def _build_id(mode: str, build_time: datetime, git_commit: str, git_branch: str) -> str:
    payload = "|".join((mode, build_time.isoformat(), git_commit, git_branch))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]


def _git_value(arguments: tuple[str, ...]) -> str:
    completed = subprocess.run(
        ["git", *arguments],
        cwd=PROJECT_ROOT,
        check=False,
        text=True,
        capture_output=True,
        timeout=GIT_TIMEOUT_SECONDS,
    )
    if completed.returncode != 0:
        return "unknown"
    value = completed.stdout.strip()
    return value if value else "unknown"


def _module_is_available(module_name: str) -> bool:
    completed = subprocess.run(
        [sys.executable, "-m", module_name, "--version"],
        cwd=PROJECT_ROOT,
        check=False,
        text=True,
        capture_output=True,
        timeout=GIT_TIMEOUT_SECONDS,
    )
    return completed.returncode == 0


def _format_subprocess_failure(name: str, completed: subprocess.CompletedProcess[str]) -> str:
    stderr_tail = completed.stderr.strip().splitlines()[-1:] or ["no stderr"]
    stdout_tail = completed.stdout.strip().splitlines()[-1:] or ["no stdout"]
    return "%s failed with code %s; stdout=%s; stderr=%s" % (
        name,
        completed.returncode,
        stdout_tail[0],
        stderr_tail[0],
    )


def _binary_name() -> str:
    if os.name == "nt":
        return PYINSTALLER_APP_NAME + ".exe"
    return PYINSTALLER_APP_NAME


def _display_path(path: Path) -> str:
    try:
        return path.resolve().relative_to(PROJECT_ROOT.resolve()).as_posix()
    except ValueError:
        return path.as_posix()


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
