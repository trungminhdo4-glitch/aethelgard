# First Outreach Wave

## Scope

Owner gate for this run is limited to three company-level first contacts:

- NETWORK ASSISTANCE
- 030-IT
- procado

No attachments, no private contacts, no LinkedIn/Xing, no lead databases, no automated
follow-ups, and no customer-document request in the first message.

## Local Preflight

Verified on 2026-06-28:

- Branch: `codex/nis2-control-coverage`
- HEAD: `65514fa feat: add NIS2 control coverage`
- Working tree before outreach docs: clean
- `python -m compileall src tests`: pass
- `pytest -q`: 200 passed, 1 skipped opt-in network, 17 subtests
- `ruff check .`: pass via `.venv-fresh`
- `mypy src`: pass via `.venv-fresh`
- `python scripts/check_public_fixtures.py`: pass, 27 synthetic fixture files
- `python scripts/check_pilot_readiness.py --out reports/readiness`: `PILOT_OPS_READY`
- `git diff --check`: pass

## Verification Summary

| Company | Fit verified | Public company contact path | Action | Status | Blocker |
|---|---|---|---|---|---|
| NETWORK ASSISTANCE | Berlin IT-Systemhaus/MSP for KMU, managed services, IT security, NIS2/security pages visible. | Website contact page and public company-level contact route. | Draft created for manual owner send. | `draft_ready` | Kein freigegebenes Absenderkonto/kein OWNER_NAME im lokalen Codex-Kontext; Owner muss manuell ueber Kontaktformular oder allgemeinen Firmenkanal senden. |
| 030-IT | Berlin MSP with managed services, IT security, branch focus, and general company inbox. | Contact page and `info@030-it.de`. | Draft created for manual owner send. | `draft_ready` | Kein freigegebenes Absenderkonto/kein OWNER_NAME im lokalen Codex-Kontext; Owner muss manuell ueber Kontaktformular oder allgemeinen Firmenkanal senden. |
| procado | Berlin IT service provider with MSP, managed security, information security, NIS2 and contact page. | Contact page and `info@procado.de`. | Draft created for manual owner send. | `draft_ready` | Kein freigegebenes Absenderkonto/kein OWNER_NAME im lokalen Codex-Kontext; Owner muss manuell ueber Kontaktformular oder allgemeinen Firmenkanal senden. |

## Sources Used

- NETWORK ASSISTANCE: `https://www.networkassistance.de/`, `https://www.networkassistance.de/kontakt/`
- 030-IT: `https://030-it.de/msp-berlin-managed-it-services-fuer-unternehmen`, `https://030-it.de/kontakt`
- procado: `https://www.procado.de/`, `https://www.procado.de/kontakt/`

## Send Rules For Owner

- Send each message individually.
- Use only a public company channel listed above.
- Replace `[OWNER_NAME]` before sending.
- Do not add attachments.
- Do not ask for real customer documents in the first message.
- Do not send follow-ups without a fresh owner gate.
- Record the manual send result in `docs/research/outreach-tracker.csv`.
