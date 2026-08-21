# Public Evidence File and Network Access Matrix

| Stage | Reads | Writes | Network |
|---|---|---|---|
| `benchmark run` | Dataset manifest, source register, expected cases, approved local source files | Analysis report, provisional benchmark report, review template, metadata audit chain | None implemented; missing local input fails closed |
| `benchmark review` | Analysis report, complete review JSON, matching audit chain | Reviewed report and review audit events | None |
| `benchmark export` | Reviewed report and matching audit chain | Bundle manifest, approved metadata report, evidence index, README, export audit event | None |
| Tests | Committed generated lab fixtures and temporary test copies | Pytest temporary directories/caches | None; opt-in repository network test remains skipped by default |
| Dependency setup | Package indexes or local wheel cache, only when separately approved | Virtual environment | Potential network; outside benchmark runtime |
| Vulnerability scan | SBOM/lockfile and scanner database | Owner-selected scan report | Database refresh may require network and was not run here |

The public-evidence workflow does not read environment files, customer data,
databases, application logs, cookies, or private configuration. It rejects
sensitive path markers and database/log suffixes for benchmark sources.
