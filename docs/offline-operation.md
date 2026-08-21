# Offline Operation: Public Evidence Validation

## Preconditions

- Work from the repository root.
- Use Python 3.11 or 3.12 and an isolated environment.
- Install only from an owner-approved local cache or a separately approved setup
  session. Package installation itself is not an offline guarantee.
- Use only the committed `benchmarks/public-evidence-v1` dataset. Do not add public
  documents until storage and redistribution rights are reviewed.

## Run

```powershell
$env:PYTHONPATH = "D:\projects\aethelgard\src"
python -m aethelgard.cli benchmark run `
  --dataset benchmarks\public-evidence-v1 `
  --offline --deterministic `
  --tenant-id public-lab `
  --actor-id local-operator `
  --role operator `
  --out reports\public-evidence-v1
```

Copy `review_template.json` to a new project-local JSON file, replace every pending
decision, add reviewer identity/time/comments, and set
`human_review_confirmed` to `true`. A distinct reviewer runs `benchmark review`;
a distinct auditor runs `benchmark export`. The CLI help lists the required paths.

## Offline guarantees and checks

- `--offline` and `--deterministic` are mandatory literal flags in the core context.
- The mode contains no network implementation or external model call.
- A missing local source fails with `network retrieval is blocked`; there is no
  download fallback.
- Dataset paths are limited to the project `benchmarks/` subtree; outputs and review
  artifacts are limited to the current project folder by the CLI.
- For stronger assurance, run on a disconnected host or an owner-approved OS-level
  egress-denied sandbox. This run did not configure the OS firewall.

## Failure handling

Treat hash, schema, tenant, run, role, lifecycle, license, type, or symlink errors as
blocked actions. Do not edit generated hashes to make a run pass. Start with a new
output directory after a failed or completed lifecycle. Preserve only synthetic,
metadata-safe artifacts for support.
