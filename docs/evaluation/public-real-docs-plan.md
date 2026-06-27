# Public Real-Document Evaluation Plan

## Purpose

Use official public sources to validate category design and future manual tests without
committing third-party documents to the repository.

## Source Rules

- Store URLs, publisher names, purpose, and license notes in
  `docs/evaluation/public-real-docs-manifest.json`.
- Do not commit full PDFs, full webpages, or long copied excerpts.
- Do not make automatic downloads part of the default test suite.
- Use public documents only as optional manual evaluation inputs or live URL checks.
- Keep customer data out of this evaluation path.

## Manual Evaluation Flow

1. Review the manifest and choose one official source.
2. Download the document manually only if redistribution and internal use are acceptable.
3. Store the downloaded file outside Git or under ignored `reports/public-real-docs/`.
4. Run `python -m aethelgard.cli triage --input <local-file-or-folder> --out reports/public-real-docs --audit`.
5. Compare findings against the human-review checklist.
6. Delete downloaded source documents after the manual evaluation unless retention is approved.

## Optional Network Check

The default tests do not touch the network. To verify that public source URLs are still
reachable, run:

```powershell
$env:AETHELGARD_RUN_NETWORK_TESTS = "1"
python -m pytest tests/test_public_real_docs_manifest.py -q
```

The network test reads only a small response prefix and does not store public source
content in the repository.

## Non-Goals

- No legal interpretation.
- No redistribution of third-party documents.
- No customer-data evaluation.
- No scraping workflow.
- No paid API or LLM usage.
