"""Two-class local data gate: curated company metadata vs incidental third-party PII.

The pilot product distinguishes two fundamentally different kinds of personal-looking data:

* **Class 1 - curated company metadata.** Deliberately-maintained business contact data that a
  company chose to declare about *itself*: company name, legal entity, security-contact name/email/
  phone, DPO name/email/phone, ISO scope, HQ address, website, registration/VAT identifiers. This is
  business contact data provided with intent; it may persist locally and may appear in shareable
  answers and exports.

* **Class 2 - incidental third-party personal data.** Personal data of third parties that turns up
  by accident in ingested documents: employee mailboxes, private phone numbers, IP addresses from
  logs, names in tickets, incident subjects. This must never flow into a shareable answer or export.

Design invariant (privacy-critical): **Class 1 is structural, never heuristic.** A value is Class 1
only when it is supplied through a declared, named company-metadata field from the fixed allowlist
below *and* it validates for that field's kind. A sensitive marker found in free text has no field
context and is therefore Class 2 by default (deny-by-default). We never *infer* Class 1 from free
text - inferring "this email looks official" is exactly how third-party PII leaks into an output.

The gate composes on top of :mod:`aethelgard.redaction_preflight`: that module *detects* sensitive
markers; this module *classifies* them and, at output time, preserves declared Class-1 values while
masking everything else. Input-folder preflight stays deny-by-default (no field context there).
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Final, Literal, cast

from aethelgard.redaction_preflight import (
    EMAIL_PATTERN,
    PHONE_PATTERN,
    has_sensitive_markers,
    mask_sensitive_text,
)

PiiClass = Literal["class1_company_metadata", "class2_personal_data"]
CLASS_1: Final[PiiClass] = "class1_company_metadata"
CLASS_2: Final[PiiClass] = "class2_personal_data"

FieldKind = Literal["freeform", "email", "phone", "url", "identifier"]

# The fixed Class-1 allowlist. A field name outside this map is never company metadata, and the
# value it carries is therefore Class 2. Adding a field here is a deliberate policy decision.
COMPANY_METADATA_FIELDS: Final[dict[str, FieldKind]] = {
    "company_name": "freeform",
    "legal_entity": "freeform",
    "registration_number": "identifier",
    "vat_id": "identifier",
    "hq_address": "freeform",
    "website": "url",
    "iso_scope": "freeform",
    "security_contact_name": "freeform",
    "security_contact_email": "email",
    "security_contact_phone": "phone",
    "dpo_name": "freeform",
    "dpo_email": "email",
    "dpo_phone": "phone",
}

MAX_FREEFORM_CHARS: Final[int] = 200
MAX_IDENTIFIER_CHARS: Final[int] = 60
MAX_URL_CHARS: Final[int] = 200
MIN_PHONE_DIGITS: Final[int] = 7
MAX_PHONE_DIGITS: Final[int] = 15

_MatchPredicate = Callable[[str], bool]

_EMAIL_FULLMATCH: Final[re.Pattern[str]] = re.compile(
    r"[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}", re.IGNORECASE
)
_URL_FULLMATCH: Final[re.Pattern[str]] = re.compile(
    r"https?://[A-Z0-9.-]+\.[A-Z]{2,}(?:/[^\s]*)?", re.IGNORECASE
)
_IDENTIFIER_FULLMATCH: Final[re.Pattern[str]] = re.compile(
    r"[A-Z0-9][A-Z0-9 ./-]{0,58}[A-Z0-9]", re.IGNORECASE
)
# Class-1 declared values are only ever email/phone/url/freeform/identifier. IBAN, IP, token and
# secret markers are never company metadata, so guard_shareable_text never preserves them.
_PROTECT_PLACEHOLDER_PREFIX: Final[str] = "aegprotect"
_PROTECT_PLACEHOLDER_SUFFIX: Final[str] = "end"


class PiiClassificationError(ValueError):
    """Raised when company metadata cannot be parsed or classified safely."""


@dataclass(frozen=True)
class FieldClassification:
    """Result of classifying one candidate field value."""

    field_name: str
    pii_class: PiiClass
    value: str
    reason: str


@dataclass(frozen=True)
class GuardResult:
    """Result of guarding a shareable free-text field."""

    text: str
    had_sensitive: bool
    preserved: tuple[str, ...] = ()
    masked_types: tuple[str, ...] = ()


@dataclass(frozen=True)
class CompanyMetadata:
    """Validated set of declared Class-1 company-metadata fields.

    Only allowlisted fields that pass their kind validation are retained. Unknown field names and
    values that fail validation are recorded in ``ignored_fields`` and are *not* treated as Class 1.
    """

    fields: Mapping[str, str]
    ignored_fields: tuple[str, ...] = field(default_factory=tuple)

    def emails(self) -> frozenset[str]:
        """Return declared email values, casefolded for matching."""
        return frozenset(
            self.fields[name].casefold()
            for name, kind in COMPANY_METADATA_FIELDS.items()
            if kind == "email" and name in self.fields
        )

    def phone_digit_keys(self) -> frozenset[str]:
        """Return declared phone values reduced to their digit sequence for matching."""
        return frozenset(
            _digits(self.fields[name])
            for name, kind in COMPANY_METADATA_FIELDS.items()
            if kind == "phone" and name in self.fields
        )

    def has_preservable_values(self) -> bool:
        """Return whether any declared value can be preserved inside free text."""
        return bool(self.emails() or self.phone_digit_keys())


def classify_field(field_name: str, value: str) -> FieldClassification:
    """Classify a single candidate field value as Class 1 or Class 2.

    Class 1 requires an allowlisted field name *and* a value that validates for that field's kind.
    Everything else is Class 2 (deny-by-default), including allowlisted fields whose value fails
    validation (a ``security_contact_email`` that is not a valid email is not trusted).
    """
    normalized_name = field_name.strip().lower()
    raw_value = " ".join(value.split())
    kind = COMPANY_METADATA_FIELDS.get(normalized_name)
    if kind is None:
        return FieldClassification(
            normalized_name, CLASS_2, raw_value, "field_not_company_metadata"
        )
    valid, bounded = _validate_field_value(kind, raw_value)
    if not valid:
        return FieldClassification(
            normalized_name, CLASS_2, bounded, "declared_field_failed_validation"
        )
    return FieldClassification(normalized_name, CLASS_1, bounded, "declared_company_metadata")


def build_company_metadata(raw: Mapping[str, object]) -> CompanyMetadata:
    """Build a validated :class:`CompanyMetadata` from a raw mapping.

    Retains only allowlisted fields whose values validate. Any other key - unknown name or a
    declared field that fails validation - is dropped and recorded in ``ignored_fields``.
    """
    accepted: dict[str, str] = {}
    ignored: list[str] = []
    for key, value in raw.items():
        classification = classify_field(str(key), _coerce_text(value))
        if classification.pii_class == CLASS_1 and classification.value:
            accepted[classification.field_name] = classification.value
        else:
            ignored.append(str(key).strip().lower())
    return CompanyMetadata(
        fields=dict(sorted(accepted.items())), ignored_fields=tuple(sorted(ignored))
    )


def load_company_metadata(path: Path | str) -> CompanyMetadata:
    """Load and validate a company-metadata JSON document."""
    source = Path(path)
    try:
        payload = json.loads(source.read_text(encoding="utf-8"))
    except OSError as exc:
        raise PiiClassificationError("could not read company metadata: %s" % source.name) from exc
    except json.JSONDecodeError as exc:
        raise PiiClassificationError("invalid company metadata JSON: %s" % source.name) from exc
    if not isinstance(payload, Mapping):
        raise PiiClassificationError("company metadata JSON must be an object")
    fields = payload.get("company_metadata", payload)
    if not isinstance(fields, Mapping):
        raise PiiClassificationError("company_metadata must be an object")
    return build_company_metadata(cast(Mapping[str, object], fields))


def guard_shareable_text(text: str, metadata: CompanyMetadata | None = None) -> GuardResult:
    """Mask Class-2 markers in free text while preserving declared Class-1 values.

    With no metadata (or no preservable values) this is byte-for-byte identical to the canonical
    ``mask_sensitive_text`` masking, so existing behaviour is unchanged unless company metadata is
    explicitly declared.
    """
    had_sensitive = has_sensitive_markers(text)
    if metadata is None or not metadata.has_preservable_values():
        masked = mask_sensitive_text(text) if had_sensitive else text
        return GuardResult(text=masked, had_sensitive=had_sensitive)
    protected, placeholders, preserved = _protect_declared_values(text, metadata)
    masked_protected = (
        mask_sensitive_text(protected) if has_sensitive_markers(protected) else protected
    )
    restored = masked_protected
    for placeholder, original in placeholders.items():
        restored = restored.replace(placeholder, original)
    masked_types = _detect_masked_types(masked_protected)
    return GuardResult(
        text=restored,
        had_sensitive=had_sensitive,
        preserved=tuple(preserved),
        masked_types=masked_types,
    )


def _protect_declared_values(
    text: str, metadata: CompanyMetadata
) -> tuple[str, dict[str, str], list[str]]:
    """Replace declared Class-1 email/phone occurrences with inert placeholders."""
    allowed_emails = metadata.emails()
    allowed_phone_keys = metadata.phone_digit_keys()
    placeholders: dict[str, str] = {}
    preserved: list[str] = []
    counter = 0
    protected = text
    if allowed_emails:
        protected, counter = _protect_matches(
            protected,
            EMAIL_PATTERN,
            lambda matched: matched.casefold() in allowed_emails,
            placeholders,
            preserved,
            counter,
        )
    if allowed_phone_keys:
        protected, counter = _protect_matches(
            protected,
            PHONE_PATTERN,
            lambda matched: _digits(matched) in allowed_phone_keys,
            placeholders,
            preserved,
            counter,
        )
    return protected, placeholders, preserved


def _protect_matches(
    text: str,
    pattern: re.Pattern[str],
    predicate: _MatchPredicate,
    placeholders: dict[str, str],
    preserved: list[str],
    counter: int,
) -> tuple[str, int]:
    result = text
    for match in list(pattern.finditer(text)):
        matched = match.group(0)
        if not predicate(matched):
            continue
        placeholder = "%s%s%s" % (
            _PROTECT_PLACEHOLDER_PREFIX,
            _int_to_alpha(counter),
            _PROTECT_PLACEHOLDER_SUFFIX,
        )
        counter += 1
        placeholders[placeholder] = matched
        preserved.append(matched)
        result = result.replace(matched, placeholder)
    return result, counter


def _validate_field_value(kind: FieldKind, value: str) -> tuple[bool, str]:
    if not value:
        return False, value
    if kind == "email":
        bounded = value[:MAX_FREEFORM_CHARS]
        return bool(_EMAIL_FULLMATCH.fullmatch(bounded)), bounded
    if kind == "phone":
        digits = _digits(value)
        return MIN_PHONE_DIGITS <= len(digits) <= MAX_PHONE_DIGITS, value[:MAX_IDENTIFIER_CHARS]
    if kind == "url":
        bounded = value[:MAX_URL_CHARS]
        return bool(_URL_FULLMATCH.fullmatch(bounded)), bounded
    if kind == "identifier":
        bounded = value[:MAX_IDENTIFIER_CHARS]
        return bool(_IDENTIFIER_FULLMATCH.fullmatch(bounded)), bounded
    bounded = value[:MAX_FREEFORM_CHARS]
    return True, bounded


def _detect_masked_types(masked_text: str) -> tuple[str, ...]:
    found = sorted(set(re.findall(r"\[([a-z_]+):redacted\]", masked_text)))
    return tuple(found)


def _digits(value: str) -> str:
    return "".join(character for character in value if character.isdigit())


def _coerce_text(value: object) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, (int, float, bool)):
        return str(value)
    return ""


def _int_to_alpha(index: int) -> str:
    number = index + 1
    letters = ""
    while number > 0:
        number, remainder = divmod(number - 1, 26)
        letters = chr(ord("a") + remainder) + letters
    return letters


__all__ = [
    "CLASS_1",
    "CLASS_2",
    "COMPANY_METADATA_FIELDS",
    "CompanyMetadata",
    "FieldClassification",
    "GuardResult",
    "PiiClass",
    "PiiClassificationError",
    "build_company_metadata",
    "classify_field",
    "guard_shareable_text",
    "load_company_metadata",
]
