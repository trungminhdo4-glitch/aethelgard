# Pilot Quickstart

Aethelgard bereitet lokale Sicherheitsfragebögen vor: Dokumente rein, Evidence
finden, Answer Vault nutzen, Questionnaire Draft erzeugen, Review Queue und
Lückenreport ausgeben.

## Sample Smoke Command

```powershell
python -m aethelgard.cli pilot-product --workspace examples/pilot --out reports/pilot-product-demo --client-id demo-client --case-id case001
```

Der shareable HTML-Report liegt danach hier:

```text
reports/pilot-product-demo/shareable_redacted/coverage_report.html
```

Weitere shareable Demo-Outputs:

- `questionnaire_draft.csv`
- `case_review_queue.csv`
- `missing_evidence.csv`
- `pilot_readiness_report.json`

Private lokale Outputs wie SQLite, Document Inventory und Evidence Map bleiben unter
`reports/pilot-product-demo/local_private` und werden nicht für Screenshots oder
Outreach genutzt.

## Fresh-Install-Beweis (läuft Aethelgard außerhalb des Dev-Repos?)

```powershell
python scripts/build_pilot_artifact.py --out dist/aethelgard-pilot
python scripts/check_delivery_artifact.py --path dist/aethelgard-pilot
python scripts/fresh_install_smoke.py
```

Der Smoke kopiert das Artefakt in einen isolierten Temp-Ordner, startet die CLI dort
(ohne pip-Install, ohne Dev-Tree im Pfad), lässt die Demo-Pipeline laufen und scannt
alle Outputs auf Leak-Marker. Ergebnis: `reports/readiness/fresh_install_proof.json`
mit Status `FRESH_INSTALL_READY`.

## Docker-Status

Docker runtime smoke bleibt owner-gated. Ohne explizite Freigabe nur statisch prüfen:

```powershell
python scripts/check_docker_delivery.py --out reports/readiness/docker_delivery.json
```

Mit Freigabe + laufendem Docker Desktop ist der echte Runtime-Beweis:

```powershell
powershell -File scripts/docker_smoke.ps1
```

(baut das Image frisch, fährt Container-Smokes über CLI/Demo/Doctor/Support-Bundle
und schreibt `reports/readiness/docker_runtime_proof.json`).

## Landingpage und Demo

- Landingpage Preview: `marketing/landing/index.html`
- Demo-Video-Script: `marketing/demo_video_script.md`
- Pilot Email: `marketing/outreach/pilot_email_de.md`
- LinkedIn Message: `marketing/outreach/linkedin_message_de.md`

Vor einem öffentlichen Deploy:

- `TODO_CONTACT` durch owner-geprüfte Kontaktadresse ersetzen
- Legal-/Privacy-Review durchführen
- keine echten Kundendokumente in das Repo kopieren
- keine Reports, Datenbanken oder private Outputs committen

## Fehlerfall

Bei lokalen Pilotproblemen zuerst den Support-Leitfaden nutzen:

```text
docs/pilot_support.md
```

Die Standardbefehle sind:

```powershell
python -m aethelgard.cli doctor --workspace examples/pilot --out reports/doctor
python -m aethelgard.cli support-bundle --workspace examples/pilot --out reports/support_bundle.zip --redacted
```
