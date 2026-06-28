# Target Scoring Model

## Score Fields

Each field is scored from 1 to 5.

- Pain: visible likelihood that the company sees messy security, policy, risk, supplier, access, incident, BCM or vulnerability documents.
- NIS2/ISMS Signal: public evidence of NIS2, ISMS, ISO 27001, information security, data protection or compliance work.
- KMU/MSP Access: likelihood that the company reaches SMEs or acts as a service partner.
- Partner Fit: likelihood that Aethelgard complements the company instead of competing directly.
- Trust Barrier: expected friction before they will test a new local tool.
- Competition Risk: risk that Aethelgard overlaps with their own tool, platform or core consulting offer.
- Pilot Simplicity: ease of running a 15-minute demo with synthetic data or a redacted sample pack.

Formula:

```text
score = Pain + NIS2/ISMS Signal + KMU/MSP Access + Partner Fit + Pilot Simplicity - Trust Barrier - Competition Risk
```

## Applied Scores

| Rank | Company | Pain | NIS2/ISMS Signal | KMU/MSP Access | Partner Fit | Pilot Simplicity | Trust Barrier | Competition Risk | Score | Decision |
| ---: | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| 1 | NETWORK ASSISTANCE | 5 | 3 | 5 | 5 | 5 | 2 | 1 | 20 | First batch |
| 2 | 030-IT | 5 | 3 | 5 | 5 | 5 | 2 | 1 | 20 | First batch |
| 3 | procado | 4 | 4 | 4 | 5 | 4 | 2 | 1 | 18 | First batch |
| 4 | Cyberport IT-Services Berlin | 4 | 2 | 5 | 4 | 4 | 2 | 1 | 16 | First batch candidate |
| 5 | microCAT Berlin | 4 | 5 | 4 | 3 | 4 | 3 | 3 | 15 | First batch candidate |
| 6 | M&H IT-Security | 4 | 5 | 3 | 4 | 4 | 3 | 3 | 14 | Later specialist |
| 7 | aptaro | 3 | 2 | 4 | 4 | 4 | 2 | 1 | 14 | Later MSP fallback |
| 8 | CASKAN IT-Security | 4 | 4 | 2 | 3 | 3 | 3 | 3 | 10 | Later specialist |
| 9 | NKMG Berlin | 4 | 4 | 2 | 3 | 3 | 3 | 3 | 10 | Manual validation |
| 10 | CCVOSSEL | 5 | 5 | 3 | 2 | 3 | 4 | 4 | 10 | Later only |
| 11 | HK2 Comtection | 4 | 4 | 2 | 2 | 3 | 4 | 3 | 8 | Later only |
| 12 | Cybervize | 5 | 5 | 4 | 1 | 2 | 4 | 5 | 8 | Later only |
| 13 | HiSolutions | 5 | 5 | 2 | 2 | 2 | 5 | 5 | 6 | Not first wave |
| 14 | Systemhaus Berlin | 2 | 1 | 3 | 2 | 2 | 2 | 1 | 7 | Reserve |
| 15 | Piltz Legal | 3 | 5 | 1 | 2 | 2 | 5 | 3 | 5 | Not first wave |

## Interpretation

The first outreach batch should prefer MSP-like companies where Aethelgard can reduce document triage friction without competing with core advisory revenue. Security consultancies with strong ISMS/NIS2 signals are useful later, but direct-service overlap and trust barriers are higher.

Recommended first batch:

1. NETWORK ASSISTANCE
2. 030-IT
3. procado
4. Cyberport IT-Services Berlin, if owner accepts weaker NIS2 signal
5. microCAT Berlin, if owner accepts a higher trust barrier
