# Security Policy

## Scope

AethelGard 0.1.0 is an alpha, local-first consultant-pilot prototype. The Public
Evidence Validation Mode is suitable for generated lab evidence and expert review.
It is not certified, is not a legal or audit opinion, and is not approved for real
customer data.

The mode performs local parsing, deterministic rule evaluation, hash-bound review,
and metadata-only controlled export. It does not make a final NIS-2, ISO 27001, or
control-fulfilment decision.

## Reporting a vulnerability

Do not include customer documents, credentials, private paths, database contents,
or exploit payloads in an initial report. If GitHub private vulnerability reporting
is enabled for this repository, use the **Security** tab and choose **Report a
vulnerability**. If it is not enabled, contact the repository maintainers through
an owner-configured private channel before publication; do not open a public issue
for an undisclosed vulnerability. Include:

- affected version and command;
- minimal synthetic reproduction;
- impact and expected boundary;
- whether disclosure is time-sensitive.

The repository owner must enable and verify a private reporting channel before
announcing a public release. No public vulnerability intake SLA is claimed yet.

## Supported security boundary

- The CLI runs as the current local OS user and inherits that user's filesystem
  permissions.
- `tenant_id`, `actor_id`, and `role` are mandatory audit identities supplied by a
  trusted local operator. They enforce workflow separation in the core, but they
  are not authentication and do not prove the caller's real identity.
- Operator, reviewer, and auditor actor IDs must differ. Production multi-user use
  needs OS- or service-backed authentication and an owner-controlled authorization
  policy.
- Review and export validate exact schemas, content hashes, tenant/run binding, and
  the hash-chained lifecycle ledger. Export includes only an explicit metadata
  allowlist for accepted findings.
- The benchmark command accepts datasets only below the project's `benchmarks/`
  directory. Local source, metadata, output, and auxiliary symlinks are rejected.

## Dependency and scanning process

Before a pilot release, the owner must:

1. recreate an isolated environment from `requirements-pilot.lock`;
2. run the complete test, Ruff, and mypy gates documented in the README;
3. compare installed versions with `security/sbom.cdx.json` and
   `security/dependency-licenses.csv`;
4. run an owner-approved offline dependency/vulnerability scanner and record tool,
   database date, findings, and disposition;
5. regenerate `security/release-hash-manifest.json` after every artifact change;
6. obtain an independent code/security review before real-data use.

No vulnerability database was queried in this run because network and external
scanner execution were not authorized. An SBOM is inventory, not a clean scan.
