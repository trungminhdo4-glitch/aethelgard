# Labeling Guide

## Label Unit

Each fixture document receives one golden-label row in
`tests/fixtures/public_nis2/golden_labels.json`.

## Fields

- `file`: Fixture filename.
- `expected_categories`: Categories that should produce strong evidence.
- `expected_evidence_min`: Minimum number of strong evidence items.
- `expected_gaps`: Categories that should be treated as gaps or warnings.
- `must_include_terms`: Terms that must appear somewhere in emitted evidence.
- `must_not_include_categories`: Categories that must not produce strong evidence.
- `max_strong_evidence`: Optional cap for noisy or misleading documents.

## Strong Evidence

Strong evidence means:

- `is_compliant` is `true`.
- `confidence_score >= 0.7`.

## Gap Fixture Rule

Gap fixtures may mention a category keyword, but they must not become strong evidence.
They pass if they produce no strong evidence or clear gap warnings.

## Review Rule

Labels should test behavior, not exact snippets. Prefer category presence, minimum counts,
and required terms over brittle exact citation matching.
