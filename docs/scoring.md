# ThreatLens scoring policy

`scoring_v1` is a ThreatLens project policy, not an industry standard.

Weights are renormalized over providers that return interpretable scores:

| Indicator | VirusTotal | AbuseIPDB | URLhaus | OTX | Safe Browsing |
|---|---:|---:|---:|---:|---:|
| IP | 40 | 35 | 10 | 15 | n/a |
| Domain | 50 | n/a | 25 | 25 | n/a |
| URL | 35 | n/a | 30 | 10 | 25 |
| Hash | 60 | n/a | 25 | 15 | n/a |

VirusTotal uses `(malicious + 0.5 * suspicious) / total_engines * 100`,
with a minimum of 40 when at least three engines report malicious. AbuseIPDB
uses its abuse-confidence score. URLhaus uses 100 for an online listing, 60
for an offline listing, and excludes no-match results. Safe Browsing matches
score 100 and no-match results are excluded. OTX pulse evidence is capped at
60 unless corroborated by another provider.

An active URLhaus listing or Safe Browsing match enforces a minimum score of
70. Verdicts are `MALICIOUS` at 70+ with two independent sources or an
authoritative override; `SUSPICIOUS` for scores 20-69, conflicts, or a single
uncorroborated malicious signal; `CLEAN` only means no malicious findings in
at least two relevant successful checks; otherwise the verdict is `UNKNOWN`.

Severity boundaries are LOW 0-19, MEDIUM 20-39, HIGH 40-69, and CRITICAL 70-100.
