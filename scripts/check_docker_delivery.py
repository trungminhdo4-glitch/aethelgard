"""Static Docker delivery checks for the local AethelGard pilot workflow."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Final

PROJECT_ROOT: Final[Path] = Path(__file__).resolve().parents[1]
DEFAULT_OUT: Final[Path] = Path("reports") / "readiness" / "docker_delivery.json"
REQUIRED_DOCKERIGNORE_MARKERS: Final[tuple[str, ...]] = (
    ".git/",
    ".env",
    ".env.*",
    ".venv/",
    ".venv*/",
    "dist/",
    "reports/",
    "*.log",
    "*.db",
    "docs/research/",
)
EXCLUDED_CONTEXT_PARTS: Final[frozenset[str]] = frozenset(
    {
        ".git",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        ".venv",
        ".venv-fresh",
        "reports",
        "__pycache__",
    }
)
FORBIDDEN_CONTEXT_SUFFIXES: Final[tuple[str, ...]] = (
    ".db",
    ".sqlite",
    ".sqlite3",
    ".log",
    ".pem",
    ".key",
    ".p12",
    ".pfx",
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Check Docker delivery static safety.")
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT, help="Output JSON path.")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    report = build_report()
    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print("Docker delivery: %s" % report["status"])
    return 0 if report["status"] == "DOCKER_STATIC_READY" else 2


def build_report() -> dict[str, object]:
    checks = [
        _check("dockerfile_exists", (PROJECT_ROOT / "Dockerfile").is_file()),
        _check("dockerignore_exists", (PROJECT_ROOT / ".dockerignore").is_file()),
        _check("compose_exists", (PROJECT_ROOT / "compose.yaml").is_file()),
        _check("dockerfile_non_root", _dockerfile_contains("USER 10001:10001")),
        _check(
            "dockerfile_cli_entrypoint",
            _dockerfile_contains('"python", "-m", "aethelgard.cli"'),
        ),
        _check("compose_network_none", _compose_contains('network_mode: "none"')),
        _check("compose_read_only", _compose_contains("read_only: true")),
        _check(
            "compose_examples_read_only",
            _compose_contains("./examples:/workspace/examples:ro"),
        ),
        _check("compose_reports_writable", _compose_contains("./reports:/workspace/reports:rw")),
        _check("dockerignore_required_markers", _dockerignore_has_required_markers()),
        _check("docker_context_filename_safety", not _forbidden_context_names()),
        _check(
            "docker_smoke_writes_runtime_proof",
            _script_contains(
                "docker_smoke.ps1",
                ("docker_runtime_proof.json", "DOCKER_RUNTIME_READY", "public-data validate"),
            ),
        ),
        _check(
            "consultant_laptop_smoke_exists",
            _script_contains(
                "consultant_laptop_smoke.ps1",
                ("docker build", "public-data validate", "Assert-CleanOutput"),
            ),
        ),
        _check(
            "release_package_script_exists",
            _script_contains(
                "build_release_package.ps1",
                ("git rev-parse --short=12 HEAD", "SHA256SUMS.txt", "docker save"),
            ),
        ),
        _check(
            "readme_consultant_delivery",
            _readme_contains(
                (
                    "Consultant Laptop Delivery",
                    "No VM is required",
                    "Native Python fallback",
                    "SHA256SUMS.txt",
                )
            ),
        ),
    ]
    status = "DOCKER_STATIC_READY" if all(check["passed"] for check in checks) else "NOT_READY"
    return {
        "status": status,
        "runtime_verified": False,
        "runtime_note": "Static gate only; run scripts/docker_smoke.ps1 for Docker runtime proof.",
        "checks": checks,
    }


def _dockerfile_contains(marker: str) -> bool:
    return _path_contains(PROJECT_ROOT / "Dockerfile", marker)


def _compose_contains(marker: str) -> bool:
    return _path_contains(PROJECT_ROOT / "compose.yaml", marker)


def _script_contains(name: str, markers: tuple[str, ...]) -> bool:
    return _path_contains(PROJECT_ROOT / "scripts" / name, markers)


def _readme_contains(markers: tuple[str, ...]) -> bool:
    return _path_contains(PROJECT_ROOT / "README.md", markers)


def _path_contains(path: Path, marker: str | tuple[str, ...]) -> bool:
    if not path.is_file():
        return False
    text = path.read_text(encoding="utf-8")
    if isinstance(marker, str):
        return marker in text
    return all(item in text for item in marker)


def _dockerignore_has_required_markers() -> bool:
    path = PROJECT_ROOT / ".dockerignore"
    if not path.is_file():
        return False
    lines = {
        line.strip()
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.strip().startswith("#")
    }
    return all(marker in lines for marker in REQUIRED_DOCKERIGNORE_MARKERS)


def _forbidden_context_names() -> list[str]:
    findings: list[str] = []
    for path in PROJECT_ROOT.rglob("*"):
        if not path.is_file() or any(part in EXCLUDED_CONTEXT_PARTS for part in path.parts):
            continue
        lowered_name = path.name.casefold()
        if lowered_name == ".env" or lowered_name.startswith(".env."):
            findings.append(path.relative_to(PROJECT_ROOT).as_posix())
            continue
        if lowered_name.endswith(FORBIDDEN_CONTEXT_SUFFIXES):
            findings.append(path.relative_to(PROJECT_ROOT).as_posix())
    return findings


def _check(check_id: str, passed: bool) -> dict[str, object]:
    return {"id": check_id, "passed": passed}


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
