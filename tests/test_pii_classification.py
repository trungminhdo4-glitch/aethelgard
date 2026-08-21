"""Tests for the two-class local data gate (company metadata vs third-party PII)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from aethelgard.pii_classification import (
    CLASS_1,
    CLASS_2,
    CompanyMetadata,
    PiiClassificationError,
    build_company_metadata,
    classify_field,
    guard_shareable_text,
    load_company_metadata,
)
from aethelgard.redaction_preflight import has_sensitive_markers, mask_sensitive_text


def test_classify_field_allowlisted_valid_email_is_class1() -> None:
    result = classify_field("security_contact_email", "SecOps@Client.Example")
    assert result.pii_class == CLASS_1
    assert result.reason == "declared_company_metadata"
    assert result.value == "SecOps@Client.Example"


def test_classify_field_is_structural_not_heuristic() -> None:
    # The identical value is Class 1 only because of its declared field context. In free-text or an
    # unknown field it is Class 2 - the gate never infers "this email looks official".
    email = "SecOps@Client.Example"
    assert classify_field("security_contact_email", email).pii_class == CLASS_1
    assert classify_field("note", email).pii_class == CLASS_2
    assert classify_field("comment", email).reason == "field_not_company_metadata"


def test_classify_field_declared_field_with_invalid_value_is_class2() -> None:
    # Fail-closed: a security-contact email that is not a valid email is not trusted.
    result = classify_field("security_contact_email", "not-an-email")
    assert result.pii_class == CLASS_2
    assert result.reason == "declared_field_failed_validation"


def test_classify_field_phone_and_url_and_identifier_kinds() -> None:
    assert classify_field("security_contact_phone", "+00 000 000 0000").pii_class == CLASS_1
    assert classify_field("website", "https://client.example/security").pii_class == CLASS_1
    assert classify_field("vat_id", "DE123456789").pii_class == CLASS_1
    assert classify_field("security_contact_phone", "12").pii_class == CLASS_2  # too few digits
    assert classify_field("website", "client.example").pii_class == CLASS_2  # not an https url


def test_classify_field_name_is_case_insensitive_and_trimmed() -> None:
    assert classify_field("  Security_Contact_Email ", "a@b.example").pii_class == CLASS_1


def test_classify_field_empty_value_is_class2() -> None:
    assert classify_field("company_name", "   ").pii_class == CLASS_2


def test_build_company_metadata_keeps_valid_and_ignores_the_rest() -> None:
    metadata = build_company_metadata(
        {
            "company_name": "Client GmbH",
            "security_contact_email": "secops@client.example",
            "security_contact_phone": "+00 000 000 0000",
            "dpo_name": "Jane Doe",
            "unknown_key": "value",
            "security_contact_email_typo": "x@y.example",
        }
    )
    assert metadata.fields["company_name"] == "Client GmbH"
    assert metadata.fields["security_contact_email"] == "secops@client.example"
    assert "unknown_key" in metadata.ignored_fields
    assert "security_contact_email_typo" in metadata.ignored_fields
    assert "company_name" not in metadata.ignored_fields


def test_build_company_metadata_coerces_non_string_values() -> None:
    metadata = build_company_metadata({"vat_id": 123456789, "company_name": True})
    # int coerces to a valid identifier; bool coerces to "True" (a valid freeform value)
    assert metadata.fields.get("vat_id") == "123456789"
    assert metadata.fields.get("company_name") == "True"


def test_guard_preserves_declared_contact_and_masks_incidental_pii() -> None:
    metadata = build_company_metadata(
        {
            "security_contact_email": "secops@client.example",
            "security_contact_phone": "+00 000 000 0000",
        }
    )
    body = (
        "Incidents go to secops@client.example (+00 0000000000). "
        "Reported by john.private@example.test from 10.2.3.4."
    )
    result = guard_shareable_text(body, metadata)
    assert "secops@client.example" in result.text
    assert "+00 0000000000" in result.text
    assert "john.private@example.test" not in result.text
    assert "[email:redacted]" in result.text
    assert "10.2.3.4" not in result.text
    assert "secops@client.example" in result.preserved


def test_guard_matches_declared_phone_despite_spacing_differences() -> None:
    metadata = build_company_metadata({"security_contact_phone": "+00 000 000 0000"})
    result = guard_shareable_text("Call +00-000-000-0000 for security.", metadata)
    assert "+00-000-000-0000" in result.text
    assert "[phone:redacted]" not in result.text


def test_guard_default_is_byte_identical_to_canonical_masker() -> None:
    # Regression guarantee: without declared metadata the gate must not change existing output.
    body = "Contact a@b.example or +00 0000000000; token ghp_ABCDEFGHIJKLMNOPQRSTUVWX at 10.0.0.9"
    legacy = mask_sensitive_text(body) if has_sensitive_markers(body) else body
    assert guard_shareable_text(body, None).text == legacy
    assert guard_shareable_text(body, CompanyMetadata(fields={})).text == legacy


def test_guard_does_not_preserve_third_party_email_in_free_text() -> None:
    # A third-party email that is *not* declared company metadata is always masked, even next to a
    # declared one - the operator cannot smuggle it by putting it in the answer body.
    metadata = build_company_metadata({"security_contact_email": "secops@client.example"})
    result = guard_shareable_text("attacker@evil.example and secops@client.example", metadata)
    assert "secops@client.example" in result.text
    assert "attacker@evil.example" not in result.text


def test_guard_never_preserves_iban_or_token_even_with_metadata() -> None:
    # No company-metadata field is of kind IBAN/token, so these are always Class 2.
    metadata = build_company_metadata({"company_name": "Client GmbH"})
    body = "IBAN DE89 3704 0044 0532 0130 00 token ghp_ABCDEFGHIJKLMNOPQRSTUVWX"
    result = guard_shareable_text(body, metadata)
    assert "[iban:redacted]" in result.text
    assert "[token:redacted]" in result.text


def test_guard_reports_had_sensitive_flag() -> None:
    assert guard_shareable_text("no markers here", None).had_sensitive is False
    assert guard_shareable_text("email a@b.example", None).had_sensitive is True


def test_load_company_metadata_reads_nested_and_flat_shapes(tmp_path: Path) -> None:
    nested = tmp_path / "nested.json"
    nested.write_text(
        json.dumps({"company_metadata": {"company_name": "Client GmbH"}}), encoding="utf-8"
    )
    flat = tmp_path / "flat.json"
    flat.write_text(json.dumps({"company_name": "Client GmbH"}), encoding="utf-8")
    assert load_company_metadata(nested).fields["company_name"] == "Client GmbH"
    assert load_company_metadata(flat).fields["company_name"] == "Client GmbH"


def test_load_company_metadata_rejects_bad_input(tmp_path: Path) -> None:
    missing = tmp_path / "missing.json"
    with pytest.raises(PiiClassificationError):
        load_company_metadata(missing)
    broken = tmp_path / "broken.json"
    broken.write_text("{not json", encoding="utf-8")
    with pytest.raises(PiiClassificationError):
        load_company_metadata(broken)
    non_object = tmp_path / "list.json"
    non_object.write_text("[1, 2, 3]", encoding="utf-8")
    with pytest.raises(PiiClassificationError):
        load_company_metadata(non_object)


def test_answer_vault_preserves_declared_company_contact(tmp_path: Path) -> None:
    # Wiring proof: importing a reviewed answer that legitimately names the client's own declared
    # security contact must keep that contact, while masking an incidental third-party email.
    from aethelgard.answer_vault import import_answer_library_json, list_answer_library

    db_path = tmp_path / "vault.sqlite"
    answers = tmp_path / "answers.json"
    answers.write_text(
        json.dumps(
            {
                "answers": [
                    {
                        "question_cluster": "incident_response",
                        "answer_de": (
                            "Vorfaelle gehen an secops@client.example. "
                            "Ein Nutzer meldete john.private@example.test."
                        ),
                        "evidence_refs": ["EV-1"],
                        "review_status": "reviewed",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    metadata = build_company_metadata({"security_contact_email": "secops@client.example"})

    import_answer_library_json(
        db_path, answers, client_id="client-a", company_metadata=metadata
    )
    stored = list_answer_library(db_path, client_id="client-a")
    assert len(stored) == 1
    body = str(stored[0]["answer_de"])
    assert "secops@client.example" in body
    assert "john.private@example.test" not in body
    assert "[email:redacted]" in body


def test_answer_vault_default_masks_all_contacts(tmp_path: Path) -> None:
    # Without declared metadata the vault behaves exactly as before: every email is masked.
    from aethelgard.answer_vault import import_answer_library_json, list_answer_library

    db_path = tmp_path / "vault.sqlite"
    answers = tmp_path / "answers.json"
    answers.write_text(
        json.dumps(
            {
                "answers": [
                    {
                        "question_cluster": "incident_response",
                        "answer_de": "Vorfaelle gehen an secops@client.example.",
                        "evidence_refs": ["EV-1"],
                        "review_status": "reviewed",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    import_answer_library_json(db_path, answers, client_id="client-a")
    body = str(list_answer_library(db_path, client_id="client-a")[0]["answer_de"])
    assert "secops@client.example" not in body
    assert "[email:redacted]" in body
