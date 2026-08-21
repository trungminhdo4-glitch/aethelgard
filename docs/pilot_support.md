# Pilot Support

Wenn ein lokaler Pilotlauf fehlschlaegt, bleiben alle Daten auf der Kunden- oder
Consultant-Maschine. Es gibt kein Cloud-Monitoring, keine Telemetrie und keine
automatische Uebertragung.

## Standarddiagnose

```powershell
python -m aethelgard.cli doctor --workspace examples/pilot --out reports/doctor
```

Der Doctor prueft Umgebung, Workspace-Struktur, lokale Abhaengigkeiten und passive
Docker-Erkennung. Er liest keine Rohinhalte aus Kundendokumenten.

## Redacted Support Bundle

```powershell
python -m aethelgard.cli support-bundle --workspace examples/pilot --out reports/support_bundle.zip --redacted
```

Das Bundle darf nach Human Review geteilt werden, wenn die Review bestaetigt, dass
keine Kundendokumente, Datenbanken, private Debug-Ordner, Zugangsdaten oder
unredigierte Logs enthalten sind.

Nicht verschicken:

- `local_private/`
- SQLite- oder Datenbankdateien
- Rohdokumente und Screenshots mit Kundendaten
- private Konfigurationsdateien
- Logs mit Tokens, Cookies, Zugangsdaten oder privaten Pfaden

## Lokales Debugging

```powershell
python -m aethelgard.cli pilot-product --workspace examples/pilot --out reports/pilot-product-demo --client-id demo-client --case-id case001 --debug
```

Debug schreibt lokal:

- `local_private/run_debug.jsonl`
- `shareable_redacted/run_summary.jsonl`

Stacktraces und technische Details bleiben in `local_private/`. Die shareable Summary
ist redigiert und enthaelt keine Rohdokumente.

## Grenzen

AethelGard erstellt lokale Review-Hilfen, keine Compliance-Garantie, keine
Rechtsberatung und keine Audit-Aussage. Echte Kundendokumente duerfen nur nach
Legal-/Privacy-Gate und mit expliziter Freigabe verarbeitet oder geteilt werden.
