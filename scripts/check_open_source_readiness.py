"""Check repository metadata and tracked-path hygiene before a public GitHub push."""

from __future__ import annotations

import json
import subprocess
import sys
import tomllib
from pathlib import Path
from typing import cast

REQUIRED_FILES = (
    "LICENSE",
    "README.md",
    "CONTRIBUTING.md",
    "CODE_OF_CONDUCT.md",
    "SECURITY.md",
    ".github/workflows/ci.yml",
    ".github/workflows/codeql.yml",
    ".github/dependabot.yml",
    ".github/PULL_REQUEST_TEMPLATE.md",
    ".github/ISSUE_TEMPLATE/bug_report.md",
    ".github/ISSUE_TEMPLATE/feature_request.md",
)

FORBIDDEN_INTERNAL_PREFIXES = (
    "docs/research/",
    "docs/internal/",
    "docs/private/",
    "local_private/",
)

FORBIDDEN_INTERNAL_FILES = frozenset(
    {
        "AGENTS.md",
        "AGENT_LOG.md",
        "tests/test_berlin_target_research_docs.py",
        "tests/test_first_wave_outreach_docs.py",
        "tests/test_outreach_docs.py",
        "docs/icp-scoring.md",
        "docs/target-selection-guide.md",
        "docs/outreach-readiness.md",
        "docs/follow-up-sequence.md",
        "docs/objection-handling.md",
        "docs/pilot-email.md",
        "docs/pilot-outreach-readiness.md",
        "docs/pilot-call-notes-template.md",
        "docs/pilot-call-agenda.md",
        "docs/product-positioning.md",
        "docs/pilot-onepager.md",
        "docs/public-evidence-validation.md",
    }
)
FORBIDDEN_INTERNAL_NAME_MARKERS = (
    "agent_log",
    "agent-instructions",
    "internal-research",
    "private-research",
)

FORBIDDEN_TRACKED_SUFFIXES = (".db", ".sqlite", ".sqlite3", ".pem", ".p12", ".key")


def _tracked_files(repo_root: Path) -> tuple[str, ...]:
    result = subprocess.run(
        ["git", "ls-files", "-z"],
        cwd=repo_root,
        capture_output=True,
        check=True,
    )
    output = result.stdout.decode("utf-8")
    return tuple(item for item in output.split("\0") if item)


def _metadata_issues(repo_root: Path) -> list[str]:
    pyproject_path = repo_root / "pyproject.toml"
    with pyproject_path.open("rb") as handle:
        document = cast(dict[str, object], tomllib.load(handle))

    project = cast(dict[str, object], document.get("project", {}))
    license_spec = project.get("license")
    if not isinstance(license_spec, dict) or license_spec.get("file") != "LICENSE":
        return ["pyproject.toml must reference LICENSE through project.license.file"]

    issues: list[str] = []
    urls = project.get("urls")
    if isinstance(urls, dict):
        for name, value in urls.items():
            if isinstance(value, str) and "example.invalid" in value:
                issues.append("pyproject.toml contains an example.invalid project URL: %s" % name)
    return issues


def _path_review_categories(tracked: tuple[str, ...]) -> tuple[list[str], list[str]]:
    forbidden_internal: list[str] = []
    forbidden: list[str] = []
    for raw_path in tracked:
        path = raw_path.replace("\\", "/")
        lowered = path.lower()
        name = Path(path).name.lower()
        if path in FORBIDDEN_INTERNAL_FILES or any(
            path.startswith(prefix) for prefix in FORBIDDEN_INTERNAL_PREFIXES
        ) or any(
            marker in name for marker in FORBIDDEN_INTERNAL_NAME_MARKERS
        ):
            forbidden_internal.append(path)
        if (
            name.startswith(".env")
            or lowered.endswith(FORBIDDEN_TRACKED_SUFFIXES)
            or "credentials" in lowered
            or "private" in lowered
            or "secret" in lowered
            or "cookie" in lowered
        ):
            forbidden.append(path)
    return sorted(forbidden_internal), sorted(forbidden)


def build_report(repo_root: Path) -> dict[str, object]:
    missing = [path for path in REQUIRED_FILES if not (repo_root / path).is_file()]
    tracked = _tracked_files(repo_root)
    forbidden_internal, forbidden = _path_review_categories(tracked)
    metadata_issues = _metadata_issues(repo_root)
    status = "OPEN_SOURCE_READINESS_PASS"
    if missing or metadata_issues or forbidden or forbidden_internal:
        status = "NOT_READY"
    return {
        "status": status,
        "missing_files": missing,
        "metadata_issues": metadata_issues,
        "forbidden_tracked_paths": forbidden,
        "forbidden_internal_paths": forbidden_internal,
        "tracked_file_count": len(tracked),
    }


def main() -> int:
    repo_root = Path(__file__).resolve().parents[1]
    try:
        report = build_report(repo_root)
    except (OSError, subprocess.SubprocessError, tomllib.TOMLDecodeError) as error:
        print(json.dumps({"status": "CHECK_ERROR", "error": str(error)}, indent=2))
        return 3

    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["status"] == "OPEN_SOURCE_READINESS_PASS" else 2


if __name__ == "__main__":
    sys.exit(main())
