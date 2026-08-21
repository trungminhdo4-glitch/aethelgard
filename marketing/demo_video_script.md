# Demo-Video-Script

Ziel: 60 bis 90 Sekunden, ruhig, produktnah, keine Hype-Demo. Aethelgard bereitet vor;
der Mensch reviewed.

## Szenenplan

| Zeit | Screen | Voiceover |
|---|---|---|
| 0-10s | Sicherheitsfragebogen und drei synthetische Beispieldokumente im `examples/pilot`-Ordner | "Sicherheitsfragebögen wiederholen sich. Die Nachweise liegen oft verteilt in Policies, Anhängen und Tabellen." |
| 10-25s | Terminal mit lokalem Befehl | "Aethelgard läuft lokal. Für die Demo nutze ich nur synthetische Beispieldaten." |
| 25-40s | Terminal zeigt erzeugte Outputs unter `reports/pilot-product-demo/shareable_redacted` | "Der Lauf erstellt eine Evidence Map, einen Questionnaire Draft, eine Review Queue und einen Missing Evidence Report." |
| 40-60s | `coverage_report.html` im Browser | "Der HTML-Report zeigt, welche Dokumente Hinweise liefern und welche Punkte noch geprüft werden müssen." |
| 60-75s | `case_review_queue.csv` und `missing_evidence.csv` | "Offene Fragen verschwinden nicht. Sie landen sichtbar in der Review Queue oder im Lückenreport." |
| 75-90s | Landingpage-Kontaktbereich | "Ich suche zwei bis drei Berater für ehrliches Pilotfeedback. Aethelgard bereitet vor, der Mensch reviewed." |

## Terminalbefehl

```powershell
python -m aethelgard.cli pilot-product --workspace examples/pilot --out reports/pilot-product-demo --client-id demo-client --case-id case001
```

## Screens

- `examples/pilot/documents`: drei synthetische Eingangsdokumente
- Terminal: lokaler `pilot-product`-Lauf
- `reports/pilot-product-demo/shareable_redacted/coverage_report.html`
- `reports/pilot-product-demo/shareable_redacted/questionnaire_draft.csv`
- `reports/pilot-product-demo/shareable_redacted/case_review_queue.csv`
- `reports/pilot-product-demo/shareable_redacted/missing_evidence.csv`
- `marketing/landing/index.html`

## HTML-Report-Stellen

- oberer Disclaimer: local triage, human review required, no compliance guarantee
- Document Summary: welche synthetischen Dokumente verarbeitet wurden
- Questionnaire Draft: welche Antworten nur als Draft oder Review-Fall erscheinen
- Missing Evidence: sichtbare Lücken für den nächsten Prüfungsschritt

## Aufnahmehinweise

- Keine echten Kundendaten zeigen.
- Keine privaten Pfade, Datenbanken, Logs oder `local_private`-Inhalte zeigen.
- Keine Compliance-Garantie formulieren.
- Nicht sagen, dass Aethelgard alles automatisch entscheidet.
- Fokus: lokale Vorbereitung, strukturierte Review-Arbeit, klare Lücken.
