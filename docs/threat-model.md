# Public Evidence Validation Threat Model

Status: internal threat model, 2026-07-14. This is not an independent security
assessment.

## Assets and trust boundaries

Protected assets are local evidence documents, normalized analysis, review
decisions, tenant/run identity, the audit chain, and controlled exports. The main
boundaries are the local filesystem, the CLI/core API boundary, the operator to
reviewer handoff, and the reviewer to auditor handoff.

The OS account and project directory are trusted. CLI identity and role values are
audit assertions, not authentication. Anyone who can modify the repository or its
Python runtime can modify the program and is outside the current integrity model.

## Data flow

1. A trusted operator selects a committed local benchmark and supplies an audit
   identity.
2. The core validates source-register parity, licensing/storage flags, paths,
   symlinks, sizes, types, and SHA-256 hashes.
3. Local parsers produce normalized text. Deterministic rules create source-backed
   candidates with categorical confidence and no final compliance decision.
4. Analysis and provisional metrics are hashed. Critical events enter a
   tenant/run-bound hash chain.
5. A distinct reviewer submits one decision per finding. The reviewed report hash
   is bound to analysis and review audit events.
6. A distinct auditor exports accepted findings through a metadata allowlist. The
   bundle anchors the pre-export audit hash; the export event binds the bundle hash.

## Threats and controls

| Threat | Implemented control | Residual risk |
|---|---|---|
| Invented source reference | Exact normalized span and quote-hash validation; page claims require a reliable page | Current production parser does not emit PDF page or table-cell coordinates |
| Changed or substituted source | Manifest SHA-256 check, register parity, detected/declarative type check | A repository writer can change code and manifests together |
| Forged reviewed report | Strict field allowlists, content-hash verification, matching analysis/review audit proof | No digital signature or external timestamp authority |
| Review bypass | Complete review required; three distinct actor IDs; export accepts only reviewed statuses | Actor IDs are caller assertions, not authenticated principals |
| Cross-tenant mix | Mandatory tenant ID on context, reports, findings, and every audit event; mismatch fails closed | Not a production multi-tenant isolation boundary |
| Sensitive export | Metadata allowlist excludes filename, quote, and review comment | Allowed metadata may still be commercially sensitive and needs human inspection |
| Path traversal/symlink write | Resolved containment, forbidden path markers, symlink rejection, atomic replacement | Local TOCTOU remains possible against a hostile same-user process |
| Resource exhaustion | JSON/audit/source byte limits and source/case count caps | Parser-specific decompression expansion needs further adversarial testing |
| Network exfiltration | Public-evidence core has no network client; offline/deterministic literals are mandatory | Python/runtime compromise is outside scope |
| False-green metrics | Zero-FP/FN pass gate; inapplicable security metrics report `not_measured` | Lab fixtures and provisional references are self-created and narrow |

## Required external validation

Independent security review, penetration testing, privacy/legal review, and expert
NIS-2/ISO 27001 assessment remain owner gates. Internal tests do not replace them.
