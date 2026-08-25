"""Local C-SCRM control catalog loading and validation."""

from __future__ import annotations

import json
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Final, Literal, cast

from pydantic import BaseModel, ConfigDict, Field, field_validator

CATALOG_DIR_NAME: Final[str] = "control_catalogs"
NIS2_CATALOG_FILE: Final[str] = "nis2_supply_chain_controls.json"
DIN_LIGHT_CATALOG_FILE: Final[str] = "din_spec_27076_light.json"
CROSS_FRAMEWORK_MAP_FILE: Final[str] = "cross_framework_map.json"


def _default_control_catalog_dir() -> Path:
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent / "data" / CATALOG_DIR_NAME
    return Path(__file__).resolve().parents[2] / "data" / CATALOG_DIR_NAME


DEFAULT_CONTROL_CATALOG_DIR: Final[Path] = _default_control_catalog_dir()

MAX_CONTROL_ID_CHARS: Final[int] = 80
MAX_FRAMEWORK_CHARS: Final[int] = 80
MAX_TITLE_CHARS: Final[int] = 160
MAX_SUMMARY_CHARS: Final[int] = 600
MAX_EVIDENCE_NAME_CHARS: Final[int] = 120
MAX_KEYWORD_CHARS: Final[int] = 120
MAX_CATALOG_ID_CHARS: Final[int] = 120
MAX_VERSION_CHARS: Final[int] = 40

CONTROL_ID_PATTERN: Final[str] = r"^[A-Z0-9][A-Z0-9_.-]*$"
Relationship = Literal["supports", "overlaps", "equivalent", "related"]


class ControlCatalogError(ValueError):
    """Raised when a local C-SCRM control catalog is invalid."""


class ControlDefinition(BaseModel):
    """One local control definition used for questionnaire and risk mapping."""

    model_config = ConfigDict(
        frozen=True,
        extra="forbid",
        str_strip_whitespace=True,
    )

    control_id: str = Field(
        min_length=1,
        max_length=MAX_CONTROL_ID_CHARS,
        pattern=CONTROL_ID_PATTERN,
    )
    framework: str = Field(min_length=1, max_length=MAX_FRAMEWORK_CHARS)
    title: str = Field(min_length=1, max_length=MAX_TITLE_CHARS)
    summary: str = Field(min_length=1, max_length=MAX_SUMMARY_CHARS)
    required_evidence: tuple[str, ...] = Field(min_length=1)
    keywords: tuple[str, ...] = Field(default=())
    maps_to: tuple[str, ...] = Field(default=())

    @field_validator("required_evidence", "keywords", "maps_to", mode="before")
    @classmethod
    def _normalize_text_tuple(cls, value: object) -> tuple[str, ...]:
        return _normalize_text_tuple(value)

    @field_validator("required_evidence")
    @classmethod
    def _validate_required_evidence(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        for item in value:
            if len(item) > MAX_EVIDENCE_NAME_CHARS:
                raise ValueError("required_evidence item exceeds length limit")
        return value

    @field_validator("keywords")
    @classmethod
    def _validate_keywords(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        for item in value:
            if len(item) > MAX_KEYWORD_CHARS:
                raise ValueError("keyword exceeds length limit")
        return value


class ControlCatalog(BaseModel):
    """A small local control catalog document."""

    model_config = ConfigDict(
        frozen=True,
        extra="forbid",
        str_strip_whitespace=True,
    )

    catalog_id: str = Field(min_length=1, max_length=MAX_CATALOG_ID_CHARS)
    title: str = Field(min_length=1, max_length=MAX_TITLE_CHARS)
    version: str = Field(min_length=1, max_length=MAX_VERSION_CHARS)
    controls: tuple[ControlDefinition, ...] = Field(min_length=1)


class CrossFrameworkMapping(BaseModel):
    """A relationship from one local control to one or more local controls."""

    model_config = ConfigDict(
        frozen=True,
        extra="forbid",
        str_strip_whitespace=True,
    )

    source_control_id: str = Field(
        min_length=1,
        max_length=MAX_CONTROL_ID_CHARS,
        pattern=CONTROL_ID_PATTERN,
    )
    maps_to: tuple[str, ...] = Field(min_length=1)
    relationship: Relationship = "related"

    @field_validator("maps_to", mode="before")
    @classmethod
    def _normalize_maps_to(cls, value: object) -> tuple[str, ...]:
        return _normalize_text_tuple(value)


class CrossFrameworkMap(BaseModel):
    """The local cross-framework map document."""

    model_config = ConfigDict(
        frozen=True,
        extra="forbid",
        str_strip_whitespace=True,
    )

    map_id: str = Field(min_length=1, max_length=MAX_CATALOG_ID_CHARS)
    version: str = Field(min_length=1, max_length=MAX_VERSION_CHARS)
    mappings: tuple[CrossFrameworkMapping, ...] = Field(default=())


class ControlCatalogBundle(BaseModel):
    """All local catalogs plus the cross-framework relationship map."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    catalogs: tuple[ControlCatalog, ...]
    cross_framework_map: CrossFrameworkMap

    @property
    def controls_by_id(self) -> dict[str, ControlDefinition]:
        """Return all controls indexed by stable control ID."""
        return {
            control.control_id: control
            for catalog in self.catalogs
            for control in catalog.controls
        }

    @property
    def catalog_ids(self) -> tuple[str, ...]:
        """Return loaded catalog IDs in stable order."""
        return tuple(catalog.catalog_id for catalog in self.catalogs)


def load_control_catalog_bundle(
    catalog_dir: Path | str | None = None,
) -> ControlCatalogBundle:
    """Load and validate the bundled local C-SCRM control catalogs."""
    base_dir = _default_control_catalog_dir() if catalog_dir is None else Path(catalog_dir)
    catalogs = (
        _load_catalog(base_dir / NIS2_CATALOG_FILE),
        _load_catalog(base_dir / DIN_LIGHT_CATALOG_FILE),
    )
    cross_framework_map = _load_cross_framework_map(base_dir / CROSS_FRAMEWORK_MAP_FILE)
    bundle = ControlCatalogBundle(catalogs=catalogs, cross_framework_map=cross_framework_map)
    validate_control_catalog_bundle(bundle)
    return bundle


def validate_control_catalog_bundle(bundle: ControlCatalogBundle) -> None:
    """Validate ID uniqueness and all local mapping references."""
    seen: set[str] = set()
    duplicates: list[str] = []
    for catalog in bundle.catalogs:
        for control in catalog.controls:
            if control.control_id in seen:
                duplicates.append(control.control_id)
            seen.add(control.control_id)
            if not control.required_evidence:
                raise ControlCatalogError(
                    "control %s must declare required_evidence" % control.control_id
                )

    if duplicates:
        raise ControlCatalogError("duplicate control_id values: %s" % ", ".join(sorted(duplicates)))

    for catalog in bundle.catalogs:
        for control in catalog.controls:
            _validate_control_refs(control.control_id, control.maps_to, seen)

    for mapping in bundle.cross_framework_map.mappings:
        if mapping.source_control_id not in seen:
            raise ControlCatalogError(
                "cross-framework source_control_id does not exist: %s"
                % mapping.source_control_id
            )
        _validate_control_refs(mapping.source_control_id, mapping.maps_to, seen)


def build_catalog_validation_report(bundle: ControlCatalogBundle) -> dict[str, object]:
    """Build a metadata-only validation report for the local catalogs."""
    control_count = sum(len(catalog.controls) for catalog in bundle.catalogs)
    return {
        "status": "pass",
        "catalog_ids": bundle.catalog_ids,
        "control_count": control_count,
        "cross_framework_mapping_count": len(bundle.cross_framework_map.mappings),
        "control_ids": tuple(sorted(bundle.controls_by_id)),
    }


def _load_catalog(path: Path) -> ControlCatalog:
    return ControlCatalog.model_validate(_read_json(path))


def _load_cross_framework_map(path: Path) -> CrossFrameworkMap:
    return CrossFrameworkMap.model_validate(_read_json(path))


def _read_json(path: Path) -> Mapping[str, object]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ControlCatalogError("could not read control catalog file: %s" % path) from exc
    except json.JSONDecodeError as exc:
        raise ControlCatalogError("invalid JSON in control catalog file: %s" % path) from exc
    if not isinstance(payload, Mapping):
        raise ControlCatalogError("control catalog file must contain a JSON object: %s" % path)
    return cast(Mapping[str, object], payload)


def _normalize_text_tuple(value: object) -> tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, str):
        normalized = value.strip()
        return (normalized,) if normalized else ()
    if isinstance(value, Sequence) and not isinstance(value, (bytes, bytearray)):
        return tuple(str(item).strip() for item in value if str(item).strip())
    raise ValueError("expected a string or sequence of strings")


def _validate_control_refs(source_control_id: str, refs: Sequence[str], all_ids: set[str]) -> None:
    missing = sorted(ref for ref in refs if ref not in all_ids)
    if missing:
        raise ControlCatalogError(
            "control %s maps_to unknown control IDs: %s"
            % (source_control_id, ", ".join(missing))
        )
