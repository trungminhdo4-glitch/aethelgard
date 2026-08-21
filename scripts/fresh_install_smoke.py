"""Prove a built pilot artifact runs outside the dev repo, offline, without pip.

This smoke copies a built dev-runtime artifact into an isolated temporary folder,
runs the AethelGard CLI from that copy via ``PYTHONPATH`` (no network, no pip
install, no dev tree on the path), and asserts the demo outputs are produced and
free of leak markers. It complements the Docker smoke: it proves the *native*
consultant-laptop path without a container runtime.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Final

PROJECT_ROOT: Final[Path] = Path(__file__).resolve().parents[1]
DEFAULT_ARTIFACT: Final[Path] = Path("dist") / "aethelgard-pilot"
DEFAULT_OUT: Final[Path] = Path("reports") / "readiness" / "fresh_install_proof.json"
DEMO_OUT_REL: Final[str] = "reports/fresh-demo"
RUN_TIMEOUT_SECONDS: Final[int] = 180
STATUS_READY: Final[str] = "FRESH_INSTALL_READY"
STATUS_NOT_READY: Final[str] = "NOT_READY"

# Pfad-/Datei-Marker: schon die Erwaehnung ist ein Leak (lokale Pfade, .env-Referenzen).
FORBIDDEN_PATH_MARKERS: Final[tuple[str, ...]] = (
    ".env",
    "c:\\users",
    "c:/users",
    "/home/",
)
# Credential-Marker NUR als Zuweisungs-/Header-Form ("cookie: ...", "token=..."):
# Prosa wie "no cookies are included" (Trust-Bundle-README) ist KEIN Leak.
# Muster gespiegelt aus aethelgard.diagnostics (Secret-Assignment-Idiom).
CREDENTIAL_ASSIGNMENT_PATTERN: Final[re.Pattern[str]] = re.compile(
    r"\b(api[_-]?key|authorization|bearer|cookie|password|secret|token)\b\s*[:=]",
    re.IGNORECASE,
)
EMAIL_PATTERN: Final[re.Pattern[str]] = re.compile(
    r"[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}", re.IGNORECASE
)
SCANNED_OUTPUT_SUFFIXES: Final[frozenset[str]] = frozenset({".json", ".md", ".csv", ".txt"})


class FreshInstallError(RuntimeError):
    """Raised when the fresh-install smoke cannot complete safely."""


def scan_text_for_leaks(text: str) -> list[str]:
    """Return leak-marker identifiers found in a customer-facing output file."""
    findings: list[str] = []
    lowered = text.casefold()
    for marker in FORBIDDEN_PATH_MARKERS:
        if marker in lowered:
            findings.append("forbidden_marker:%s" % marker)
    match = CREDENTIAL_ASSIGNMENT_PATTERN.search(text)
    if match:
        findings.append("credential_assignment:%s" % match.group(1).casefold())
    if EMAIL_PATTERN.search(text):
        findings.append("email_address")
    return findings


def scan_outputs_for_leaks(output_dir: Path) -> list[str]:
    """Scan every text-like output file under a directory for leak markers."""
    findings: list[str] = []
    for path in sorted(output_dir.rglob("*")):
        if not path.is_file() or path.suffix.casefold() not in SCANNED_OUTPUT_SUFFIXES:
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        for marker in scan_text_for_leaks(text):
            findings.append("%s@%s" % (marker, path.name))
    return findings


def resolve_artifact(path: Path) -> Path:
    """Resolve and validate the built dev-runtime artifact directory."""
    candidate = path if path.is_absolute() else PROJECT_ROOT / path
    resolved = candidate.resolve()
    if not resolved.is_dir():
        raise FreshInstallError("artifact directory does not exist: %s" % resolved)
    if not (resolved / "src" / "aethelgard").is_dir():
        raise FreshInstallError("artifact is missing src/aethelgard: %s" % resolved)
    if not (resolved / "examples" / "pilot").is_dir():
        raise FreshInstallError("artifact is missing examples/pilot: %s" % resolved)
    return resolved


def _isolated_env(app_dir: Path) -> dict[str, str]:
    env = dict(os.environ)
    env["PYTHONPATH"] = str(app_dir / "src")
    env["PYTHONNOUSERSITE"] = "1"
    return env


def _run_cli(app_dir: Path, arguments: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "aethelgard.cli", *arguments],
        cwd=app_dir,
        env=_isolated_env(app_dir),
        check=False,
        text=True,
        capture_output=True,
        timeout=RUN_TIMEOUT_SECONDS,
    )


def _assert_import_isolated(app_dir: Path) -> str:
    env = _isolated_env(app_dir)
    completed = subprocess.run(
        [sys.executable, "-c", "import aethelgard, sys; sys.stdout.write(aethelgard.__file__)"],
        cwd=app_dir,
        env=env,
        check=False,
        text=True,
        capture_output=True,
        timeout=RUN_TIMEOUT_SECONDS,
    )
    if completed.returncode != 0:
        raise FreshInstallError("could not import aethelgard from the copy: %s" % completed.stderr)
    resolved_module = Path(completed.stdout.strip()).resolve()
    try:
        resolved_module.relative_to(app_dir.resolve())
    except ValueError as exc:
        raise FreshInstallError(
            "import leaked to the dev tree instead of the copy: %s" % resolved_module
        ) from exc
    return resolved_module.as_posix()


def run_fresh_install_smoke(artifact: Path) -> dict[str, object]:
    """Copy the artifact to an isolated folder and prove the CLI runs from it."""
    artifact_dir = resolve_artifact(artifact)
    temp_root = Path(tempfile.mkdtemp(prefix="aethelgard-fresh-"))
    app_dir = temp_root / "aethelgard-pilot"
    try:
        shutil.copytree(artifact_dir, app_dir)
        module_path = _assert_import_isolated(app_dir)

        help_result = _run_cli(app_dir, ["--help"])
        if help_result.returncode != 0:
            raise FreshInstallError("CLI --help failed: %s" % help_result.stderr.strip())

        demo_result = _run_cli(
            app_dir, ["demo-pilot", "--examples", "examples/pilot", "--out", DEMO_OUT_REL]
        )
        if demo_result.returncode != 0:
            raise FreshInstallError("demo-pilot failed: %s" % demo_result.stderr.strip())

        demo_out = app_dir / DEMO_OUT_REL
        produced = sorted(
            p.relative_to(app_dir).as_posix() for p in demo_out.rglob("*") if p.is_file()
        )
        if not produced:
            raise FreshInstallError("demo-pilot produced no output files")

        leaks = scan_outputs_for_leaks(demo_out)
        status = STATUS_READY if not leaks else STATUS_NOT_READY
        return {
            "status": status,
            "runtime_verified": True,
            "temp_root_kind": "system_tempdir_outside_repo",
            "module_resolved_from_copy": module_path,
            "output_file_count": len(produced),
            "output_files": produced[:20],
            "leak_findings": leaks,
        }
    finally:
        shutil.rmtree(temp_root, ignore_errors=True)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Prove a built pilot artifact runs outside the dev repo (offline)."
    )
    parser.add_argument("--artifact", type=Path, default=DEFAULT_ARTIFACT)
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        report = run_fresh_install_smoke(Path(args.artifact))
    except FreshInstallError as exc:
        print("fresh-install smoke failed: %s" % exc, file=sys.stderr)
        return 2
    out_path = Path(args.out)
    if not out_path.is_absolute():
        out_path = PROJECT_ROOT / out_path
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print("Fresh-install smoke: %s" % report["status"])
    print("Module resolved from copy: %s" % report["module_resolved_from_copy"])
    print("Output files produced: %s" % report["output_file_count"])
    return 0 if report["status"] == STATUS_READY else 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
