# AethelGard Pilot Risk Register

| Risiko | Fixbar durch Code? | Status | Fix/Alternative | Owner-Gate |
| ------ | -----------------: | ------ | --------------- | ---------- |
| Kein echter Kundensample | Nein | Alternative umgesetzt | Customer-like Sample Pack unter `tests/fixtures/customer_like_nis2/` plus public-real-doc manual plan. Echter Sample bleibt owner-approved und nicht-sensitiv. | Vor Outreach: nur redacted/non-sensitive Samples anfordern. |
| Kein Rechtsreview | Nein | Alternative umgesetzt | `docs/legal-review-checklist.md` als Review-Checkliste, keine Rechtsberatung und kein Vertragsersatz. | Qualified legal/privacy advisor muss Pilotunterlagen pruefen. |
| Keyword-Heuristik | Teilweise | Gehaertet | Quality-Signale, Calibration Report und Warning-Flags fuer Marketing, Templates, Outdated, fehlende Owner/Review/Timeline. | Nicht als Compliance-Entscheidung verkaufen; Human Review bleibt Pflicht. |
| Kein SaaS/Multi-Tenant | Nein, bewusst out of scope | Akzeptiert | MVP1 bleibt lokale CLI fuer owner-approved Dokumente. Kein Multi-Tenant-Bau vor Kundenbeweis. | SaaS-Scope nur mit separatem Security-/Legal-Design. |
| Kein Remote/Backup | Ja | Technisch adressiert | Lokales Git-Bundle nach gruenen Gates erstellen und verifizieren; `docs/backup-restore.md` dokumentiert Ablauf. | Kein Remote/Push ohne Owner-Freigabe. |
| CISA 403 | Ja | Technisch adressiert | Public-URL-Check klassifiziert offizielle 403/Timeouts als WARN, echte DNS/URL-Fehler weiter als FAIL. | Netzwerk-Test bleibt opt-in. |
| AGENT_LOG Commit-Feld `-` | Ja | Additiv korrigiert | Post-commit correction fuer `e17da1c feat: harden paid pilot readiness` in `AGENT_LOG.md`. | Historische Logs nicht umschreiben. |
