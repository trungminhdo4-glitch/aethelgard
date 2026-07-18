# Public Evidence Data Flow

```text
approved local fixture + manifest + source register
  -> path / license / hash / type validation
  -> local parser
  -> normalized text and exact span
  -> deterministic topic mapping
  -> evidence candidate + categorical confidence
  -> hash-bound analysis report + audit events
  -> distinct human reviewer decisions
  -> hash-bound reviewed report + audit events
  -> distinct auditor
  -> accepted metadata allowlist
  -> trust-bundle preview + export audit event
```

No step in this mode contains a network client, telemetry call, upload, external AI
call, or exchange connection. Raw normalized quotes remain in the private analysis
and reviewed report. They are not copied into the approved report or evidence index.
The audit ledger contains metadata and hashes, not document content.

The flow is single-workstation and local-process only. Tenant and role values are
mandatory workflow/audit labels; production authentication and OS-enforced tenant
storage are not present.

