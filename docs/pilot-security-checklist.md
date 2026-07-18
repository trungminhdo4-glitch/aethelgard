# Consultant Pilot Security Checklist

## Required before every expert-review session

- [ ] Use only generated or explicitly licensed benchmark material.
- [ ] Confirm source-register and manifest changes received owner review.
- [ ] Create a fresh isolated environment from `requirements-pilot.lock`.
- [ ] Run full pytest, Ruff, mypy, fixture safety, and `git diff --check` gates.
- [ ] Run the benchmark twice and compare analysis and benchmark content hashes.
- [ ] Use distinct operator, reviewer, and auditor identities.
- [ ] Inspect accepted metadata before export; never copy raw customer documents.
- [ ] Rebuild and verify the release-hash manifest.
- [ ] Record known limitations and all `not_measured` metrics in the handoff.

## Additional gates before anonymized or real-data use

- [ ] Owner-backed authentication/authorization and tenant storage isolation.
- [ ] Independent code/security review and penetration test.
- [ ] Legal, privacy, licensing, liability, NDA, and DPA review.
- [ ] Expert NIS-2/ISO 27001 review of provisional benchmark references.
- [ ] Deletion/retention procedure validated with pilot participants.
- [ ] Code signing, release process, vulnerability contact, and response SLA.
- [ ] Explicit owner approval for any real or anonymized customer dataset.

Unchecked additional gates mean the build remains `EXPERT_REVIEW_READY`, not a
real-data pilot.

