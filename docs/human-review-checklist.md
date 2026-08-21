# Human Review Checklist

Use this checklist for every AethelGard report. The tool output is triage only, not a
final compliance decision.

## 1. Scope Check

- [ ] Confirm the document set was approved for this pilot.
- [ ] Confirm documents are non-sensitive and do not contain secrets or avoidable personal data.
- [ ] Confirm the report is limited to evidence triage and human pre-review.
- [ ] Set `needs manual follow-up` if the input scope is unclear or broader than agreed.
- [ ] Do not accept evidence from documents outside the approved input set.

## 2. Document Quality Check

- [ ] Confirm each document is readable and current enough for review.
- [ ] Confirm policies include an owner, review date, or approval signal where relevant.
- [ ] Confirm template-only documents are marked as weak evidence.
- [ ] Set `needs manual follow-up` if the document is outdated, incomplete, or not attributable.
- [ ] Do not accept evidence from a blank template, placeholder, or draft with no owner.

## 3. Evidence Review

- [ ] Check whether each strong evidence item describes an implemented control.
- [ ] Check whether the cited snippet is specific, not generic marketing text.
- [ ] Check whether the category mapping is plausible for the source document.
- [ ] Set `needs manual follow-up` if the citation lacks implementation detail.
- [ ] Do not accept evidence that only says a control is planned, vague, or aspirational.

## 4. Gap Review

- [ ] Review every gap warning against the source document.
- [ ] Decide whether the gap is real, wording-related, or out of scope.
- [ ] Record missing categories that the tool did not detect.
- [ ] Set `needs manual follow-up` if a required category has no clear evidence.
- [ ] Do not close a gap solely because one keyword appeared in the document.

## 5. False Positive Review

- [ ] Check marketing-only claims and high-level trust statements.
- [ ] Check empty policy templates and questionnaire boilerplate.
- [ ] Check outdated policies with no review owner.
- [ ] Set `needs manual follow-up` if strong evidence appears in generic text.
- [ ] Do not accept claims without a control owner, procedure, timing, or review signal.

## 6. False Negative Review

- [ ] Search manually for relevant evidence that the keyword map may have missed.
- [ ] Check German/English wording variants and customer-specific terminology.
- [ ] Check tables, headings, and PDF extraction artifacts.
- [ ] Set `needs manual follow-up` if the document appears relevant but has no findings.
- [ ] Do not assume absence of evidence means absence of a control.

## 7. Client Handover Notes

- [ ] Summarize what was processed.
- [ ] Summarize accepted evidence and rejected evidence.
- [ ] Summarize gaps requiring customer clarification.
- [ ] Set `needs manual follow-up` for each item needing customer confirmation.
- [ ] Do not send raw internal notes that include sensitive customer details.

## 8. Final Disclaimer

- [ ] Include the report disclaimer in the handover.
- [ ] State that human review is required.
- [ ] State that this is not legal advice, an audit opinion, or certification.
- [ ] Set `needs manual follow-up` if the customer asks for a compliance conclusion.
- [ ] Do not claim that the customer is NIS-2 compliant based on AethelGard output.
