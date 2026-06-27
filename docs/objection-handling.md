# Objection Handling

Keep answers short, honest, and scoped to the controlled pilot.

| Objection | Response |
| --- | --- |
| "We cannot share customer data." | That is expected. The pilot asks only for 3 to 10 redacted, non-sensitive documents. If a useful sample cannot be prepared safely, we should not run the pilot. |
| "Is this legal advice?" | No. AethelGard is not legal advice and does not interpret legal obligations. It prepares a structured evidence/gap report for qualified human review. |
| "Can it guarantee NIS-2 conformity?" | No. It cannot guarantee conformity, certify security, or replace an audit. It only supports first-pass document triage. |
| "Why not use ChatGPT or Claude directly?" | The MVP1 pilot is local, deterministic, scoped to approved files, and does not upload documents to external model providers in the pilot flow. |
| "How do you protect data?" | Inputs must be redacted and non-sensitive. Processing is local. Reports stay in the local ignored `reports/` folder, and deletion/retention is agreed before the run. |
| "What does it cost?" | For first validation, use a friendly or controlled paid pilot. The price should match the sample size, review effort, and agreed handover, not a broad compliance promise. |
| "How much effort is the pilot?" | Usually one 15-minute demo, a short sample-pack review, 3 to 10 approved documents, and one review call for the generated report. |
| "What happens after the pilot?" | Either stop and delete/retain data as agreed, or define a narrow next iteration such as better keyword mapping or a second redacted sample run. |
| "What happens with false positives?" | They are expected. The report flags warning signals and every finding is reviewed by a human before handover or use. |
| "Can this process real customer files?" | Not by default. Real customer files require prior approval, redaction, legal/privacy review if needed, and a controlled local-processing scope. |

## Strongest Boundaries

- No Compliance-Garantie.
- No legal advice.
- No audit opinion.
- No sensitive production data in MVP1 pilot flow.
- No external API calls in the pilot flow.
