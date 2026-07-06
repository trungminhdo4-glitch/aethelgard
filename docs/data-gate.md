# AethelGard Data Gate: Two Classes of Personal-Looking Data

AethelGard treats "data that looks like PII" as **two different things**, because they carry
different intent and different risk. The distinction is a named architecture concept, not a
side effect of scanning. It is implemented in `src/aethelgard/pii_classification.py` and is the
technical backbone of AethelGard's local, privacy-first positioning.

## The two classes

### Class 1 — curated company metadata (allowed)

Business contact data that a company deliberately declares **about itself**:

- `company_name`, `legal_entity`, `registration_number`, `vat_id`
- `hq_address`, `website`, `iso_scope`
- `security_contact_name`, `security_contact_email`, `security_contact_phone`
- `dpo_name`, `dpo_email`, `dpo_phone`

This is contact data the organisation provides with intent and a lawful basis (a company chooses
to publish its security contact). It may persist locally and may appear in shareable answers and
exports.

### Class 2 — incidental third-party personal data (never shared)

Personal data of third parties that turns up by accident in ingested documents: employee
mailboxes, private phone numbers, IP addresses from logs, names in tickets, incident subjects.
This must **never** flow into a shareable answer or export.

## The invariant: Class 1 is structural, never heuristic

A value is Class 1 **only** when it is supplied through a declared, allowlisted company-metadata
field *and* it validates for that field's kind (a `security_contact_email` must be a valid email,
a `security_contact_phone` must have 7–15 digits, and so on). A sensitive marker found in free
text has **no field context** and is therefore Class 2 by default — deny-by-default.

The gate never infers "this email looks official". Inferring Class 1 from free text is exactly how
third-party PII leaks into an output, so it is prohibited by design. An allowlisted field whose
value fails validation is downgraded to Class 2 (fail-closed) rather than trusted.

Operator accountability: the operator is responsible for what they declare as company metadata.
Declaring a third party's address in `security_contact_email` is a policy misuse, not a technical
bypass — the gate's job is to ensure nothing *undeclared* leaks, and it does.

## Where each class is enforced

| Stage | Behaviour |
|---|---|
| Input-folder preflight (`redaction_preflight`) | No field context exists for raw input files, so everything is Class 2 by default. Databases/archives/keys are blocked outright. |
| Answer vault storage (`answer_vault`) | Answer bodies are guarded: declared Class-1 values are preserved, Class-2 markers are masked. Without declared company metadata, behaviour is byte-for-byte identical to before. |
| `datagate` CLI | `validate-metadata` reports which declared fields are accepted vs ignored; `guard` masks a shareable text file while preserving declared Class-1 values. |

Concrete example — importing a reviewed answer that names the client's own security contact:

- **Without company metadata (default):** `Incidents go to [email:redacted] ([phone:redacted]).`
- **With declared company metadata:** `Incidents go to secops@client.example (+49 30 5550100).`
  while an incidental `john.private@gmail.com` and internal IP in the same sentence are still masked.

## Why this matters for positioning

Questionnaire-automation workflows (import documents → build a reusable answer base → draft new
questionnaires → review with evidence) are now common across the market. The workflow mechanics are
not, on their own, a differentiator.

AethelGard's differentiator is **where the data lives and how it is gated**: it runs locally inside
the customer's network, calls no external APIs or model endpoints, and separates curated company
metadata from incidental third-party PII by construction. Compliance documents never leave the
customer's network, and third-party personal data never reaches a shareable output. For NIS2-exposed
EU SMEs weighing cloud-SaaS alternatives, "your compliance documents never leave your network" is a
concrete, verifiable claim — and this data gate is the mechanism that backs it.

## CLI usage

```
# Validate a declared company-metadata file (reports accepted vs ignored fields)
python -m aethelgard.cli datagate validate-metadata \
    --company-metadata company_metadata.json --out reports/datagate/metadata_report.json

# Guard a shareable text file (preserves declared company metadata, masks Class-2 PII)
python -m aethelgard.cli datagate guard \
    --text-file answer.txt --company-metadata company_metadata.json \
    --out reports/datagate/guarded.json
```

`company_metadata.json` accepts either a flat object of fields or `{ "company_metadata": { ... } }`.
Output paths must stay inside the project folder, consistent with every other AethelGard command.

See also: [data-handling.md](data-handling.md) for the overall accepted/not-accepted data boundary.
