# Outreach Response Playbook

Use only after an owner-sent first message. Do not automate replies or follow-ups.

| Antworttyp | Kurze Antwortvorlage | Naechster Schritt | Stop-Kriterium |
|---|---|---|---|
| interessiert | Danke fuer die Rueckmeldung. Ich schlage eine kurze 15-Minuten-Demo mit synthetischen Daten vor, damit keine Kundendaten verarbeitet werden. | Demo-Termin vorschlagen und `demo-runbook-first-call.md` nutzen. | Stoppen, wenn echte Kundendokumente vor Datenschutz-/Scope-Klaerung geschickt werden sollen. |
| will Demo | Gern. Die Demo zeigt nur synthetische Beispielunterlagen, den Evidence-/Gap-Report und die Grenzen: keine Rechtsberatung, kein Audit, keine Compliance-Garantie. | Termin abstimmen, keine Anhaenge senden. | Stoppen, wenn eine Zertifizierung oder Rechtsbewertung erwartet wird. |
| fragt nach Datenschutz | Der erste Call nutzt keine echten Kundendaten. Ein Pilot duerfte nur redacted, nicht-sensitive Dokumente lokal verarbeiten; Secrets, Logs, personenbezogene Daten und produktive Incident-Daten bleiben draussen. | `docs/data-handling.md` und `docs/pilot-scope.md` vor dem Pilot-Gate zeigen. | Stoppen, wenn sensible Daten zwingend verarbeitet werden sollen. |
| fragt nach Rechtsberatung/Audit | Aethelgard ist keine Rechtsberatung, kein Audit und keine Zertifizierung. Es erzeugt nur eine strukturierte Vorpruefung fuer menschliche Review. | Demo nur fortsetzen, wenn diese Grenze akzeptiert wird. | Stoppen, wenn ein Audit- oder Compliance-Urteil verlangt wird. |
| fragt nach Kosten | Fuer die erste Validierung ist ein freundlicher oder kleiner kontrollierter Pilot denkbar. Preis erst nach Scope, Dokumentzahl und Review-Aufwand. | Erst Demo, dann Scope klaeren. | Stoppen, wenn ein breites Compliance-Versprechen erwartet wird. |
| keine Relevanz | Danke fuer die klare Rueckmeldung. Ich nehme Sie aus dieser ersten Welle heraus und sende keine weiteren Nachrichten. | Tracker auf `not_relevant` setzen. | Sofort stoppen. |
| falscher Ansprechpartner | Danke fuer den Hinweis. Ich nutze keine privaten Kontakte oder Profilrecherche. Falls es einen allgemeinen Firmenkanal gibt, prueft der Owner diesen manuell. | Kein Personenprofil speichern. | Stoppen, wenn nur private Kontaktdaten angeboten werden. |
| keine Antwort | Keine Reaktion nach Erstnachricht. | Nur mit frischem Owner-Gate nach 3/7/14 Werktagen manuell nachfassen. | Nach 14 Werktagen ohne Reaktion schliessen. |
