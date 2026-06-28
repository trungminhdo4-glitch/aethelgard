# Demo Runbook First Call

## 15-Minuten-Struktur

1. 2 Minuten Problemabgleich: Wie werden Security-/NIS2-/ISMS-Unterlagen heute vorsortiert?
2. 5 Minuten synthetische Demo: keine echten Kundendaten, keine externen API-Calls.
3. 4 Minuten Report-Struktur zeigen: Evidence-/Gap-Report, `control_coverage`, Warnungen.
4. 2 Minuten Datenschutz-/Scope-Grenzen: redacted, nicht-sensitive Dateien, Human Review.
5. 2 Minuten naechster Schritt: nur bei Fit einen kontrollierten Pilot-Scope klaeren.

## Demo Command

```powershell
$env:PYTHONPATH = "D:\projects\aethelgard\src"
python -m aethelgard.cli triage --input tests/fixtures/customer_like_nis2 --out reports/demo-call --audit
```

## Zeigen

- `reports/demo-call/evidence_report.md`
- `reports/demo-call/evidence_report.json`
- `docs/report-schema.md`
- `docs/pilot-scope.md`

## Nicht Tun

- Keine echten Kundendokumente im ersten Call fordern.
- Keine Anhaenge nachreichen, bevor Scope und Datenschutz geklaert sind.
- Keine Rechtsberatung, kein Audit, keine Compliance-Garantie behaupten.
