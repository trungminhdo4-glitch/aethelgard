"""Model and feature metadata helpers for experimental ML baseline outputs."""

from __future__ import annotations

import json
from collections.abc import Mapping
from pathlib import Path
from typing import Final, NotRequired, TypedDict

from aethelgard import __version__
from aethelgard.ml_baselines.features import FEATURE_SCHEMA_VERSION
from aethelgard.diagnostics import GIT_COMMAND_TIMEOUT_SECONDS, git_commit as _git_commit

MODEL_REGISTRY_SCHEMA_VERSION: Final[str] = "ml-model-registry-v1"
DEFAULT_GENERATED_AT: Final[str] = "1970-01-01T00:00:00+00:00"


class ModelMetadata(TypedDict):
    """Metadata attached to every ML baseline artifact."""

    model_name: str
    model_type: str
    model_version: str
    training_data_ref: str
    feature_schema_version: str
    generated_at: str
    git_commit: str
    experimental: bool
    tool_version: str
    registry_schema_version: str
    sklearn_available: NotRequired[bool]


def build_model_metadata(
    *,
    model_name: str,
    model_type: str,
    training_data_ref: str,
    experimental: bool = True,
    generated_at: str | None = None,
    git_commit: str | None = None,
    sklearn_available: bool | None = None,
) -> ModelMetadata:
    """Build explicit metadata for a local experimental baseline output."""
    metadata: ModelMetadata = {
        "model_name": model_name,
        "model_type": model_type,
        "model_version": _model_version(model_name, model_type),
        "training_data_ref": training_data_ref,
        "feature_schema_version": FEATURE_SCHEMA_VERSION,
        "generated_at": generated_at or DEFAULT_GENERATED_AT,
        "git_commit": git_commit if git_commit is not None else _git_commit(),
        "experimental": experimental,
        "tool_version": __version__,
        "registry_schema_version": MODEL_REGISTRY_SCHEMA_VERSION,
    }
    if sklearn_available is not None:
        metadata["sklearn_available"] = sklearn_available
    return metadata


def attach_metadata(
    payload: Mapping[str, object],
    metadata: ModelMetadata,
) -> dict[str, object]:
    """Return a JSON-safe payload with model metadata attached."""
    result = dict(payload)
    result["model_metadata"] = metadata
    return result


def write_json(path: Path | str, payload: Mapping[str, object]) -> None:
    """Write deterministic JSON output with sorted keys."""
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def safe_training_ref(path: Path | str) -> str:
    """Return a non-private training-data reference."""
    value = Path(path)
    try:
        return value.resolve().relative_to(Path.cwd().resolve()).as_posix()
    except (OSError, ValueError):
        return value.name


def _model_version(model_name: str, model_type: str) -> str:
    basis = "%s:%s:%s:%s" % (
        MODEL_REGISTRY_SCHEMA_VERSION,
        FEATURE_SCHEMA_VERSION,
        model_name,
        model_type,
    )
    return basis.replace(" ", "_")
