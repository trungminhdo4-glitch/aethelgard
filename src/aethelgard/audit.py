"""Append-only local run ledger for AethelGard CLI commands.

The ledger stores operational metadata only. It intentionally does not persist
document text, extracted citations, customer names, or raw parser output.
"""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Final, cast

DEFAULT_AUDIT_LEDGER: Final[Path] = Path("reports") / "audit" / "aethelgard_runs.jsonl"
KNOWN_COMMANDS: Final[frozenset[str]] = frozenset({"triage", "eval", "readiness"})

JsonScalar = str | int | float | bool | None
JsonValue = JsonScalar | list["JsonValue"] | dict[str, "JsonValue"]


def build_audit_entry(
    *,
    command: str,
    input_path: Path | str,
    output_path: Path | str,
    document_count: int,
    parsed_count: int,
    failed_count: int,
    evidence_count: int,
    run_id: str,
    evaluation_status: str | None = None,
    tool_version: str | None = None,
    content_hashes: Sequence[Mapping[str, str | int]] | None = None,
    warnings: Sequence[str] | None = None,
    errors: Sequence[Mapping[str, str]] | None = None,
    timestamp: str | None = None,
) -> dict[str, JsonValue]:
    """Build a JSON-serializable audit entry without document contents."""
    if command not in KNOWN_COMMANDS:
        raise ValueError("unknown audit command: %s" % command)
    if document_count < 0 or parsed_count < 0 or failed_count < 0 or evidence_count < 0:
        raise ValueError("audit counters must be non-negative")

    return {
        "run_id": run_id,
        "timestamp": timestamp or datetime.now(UTC).isoformat(),
        "command": command,
        "input_path": str(input_path),
        "output_path": str(output_path),
        "document_count": document_count,
        "parsed_count": parsed_count,
        "failed_count": failed_count,
        "evidence_count": evidence_count,
        "evaluation_status": evaluation_status,
        "tool_version": tool_version,
        "content_hashes": cast(JsonValue, _normalize_hashes(content_hashes or ())),
        "warnings": list(warnings or ()),
        "errors": cast(JsonValue, [dict(error) for error in errors or ()]),
    }


def append_audit_entry(
    entry: Mapping[str, JsonValue],
    ledger_path: Path | str = DEFAULT_AUDIT_LEDGER,
) -> Path:
    """Append one JSONL audit entry and return the ledger path."""
    target = Path(ledger_path)
    target.parent.mkdir(parents=True, exist_ok=True)
    with target.open("a", encoding="utf-8") as ledger_file:
        ledger_file.write(json.dumps(entry, sort_keys=True) + "\n")
    return target


def _normalize_hashes(
    content_hashes: Sequence[Mapping[str, str | int]],
) -> list[dict[str, JsonValue]]:
    normalized: list[dict[str, JsonValue]] = []
    for item in content_hashes:
        normalized.append({str(key): value for key, value in item.items()})
    return normalized
