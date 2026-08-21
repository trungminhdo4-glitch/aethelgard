# Known Limitations

- The benchmark contains ten project-created lab records. It includes no vendored
  third-party public document and no independently observed operational evidence.
- All twenty expected cases are `provisional_internal_reference`; no NIS-2 or
  ISO 27001 professional has approved them.
- PDF text can be parsed, but the current public-evidence production path does not
  preserve reliable PDF page numbers. CSV/XLSX table-cell coordinates are likewise
  not emitted. Page accuracy therefore reports `not_measured`.
- The deterministic keyword rules are narrow. Long, noisy, multilingual, repeated,
  or adversarially phrased documents need a broader expert-labelled benchmark.
- Multiple findings for the same source/control pair are rejected during benchmark
  evaluation rather than aggregated.
- CLI roles and actors are trusted local assertions, not authentication. Actor
  separation prevents accidental same-identity workflow reuse, not a malicious
  local user with repository access.
- Hash chains detect accidental or unsophisticated tampering but are not signed or
  externally timestamped.
- Offline mode means the workflow has no network client; it does not configure an OS
  firewall or defend against a compromised Python interpreter.
- The dependency SBOM and license inventory are snapshots. No live vulnerability
  database scan was authorized or executed in this run.
- No external legal, privacy, licensing, security, penetration, or compliance
opinion exists. The software must not be represented as certified or audit-ready.
