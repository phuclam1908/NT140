# Week 2 — Neris `/sn.php` HTTP timing analysis

## Source and method
- Zeek input (JSON-lines): `data/processed/scenario-01-neris/zeek/http.log`, `data/processed/scenario-01-neris/zeek/conn.log` (same run; joined by `uid`).
- Infected source IP filter: `147.32.84.165`. URI regex: `(?:^|/)sn\.php(?:\?|$)`.
- Group key: source IP, destination IP:port, protocol, HTTP Host, URI path (without query string).
- Times are Unix epoch seconds from Zeek, shown as UTC. IAT = consecutive HTTP request timestamp difference.
- Statistics exclude zero-length IATs from mean/std/CV, but count duplicates separately.
- Population standard deviation uses `ddof=0`; CV = std_population / mean_positive_IAT.
- Minimum request count for ranking: 10; threshold CV < 0.3 is an exploratory indicator only.

## Data coverage
- HTTP records in file: **1377**.
- HTTP records with no conn.log UID match: **0**.
- HTTP records with a different originator: **0**.
- Selected Neris `/sn.php` HTTP requests: **16** in **2** endpoint groups.

## Results
| Destination | Host | URI | Requests | Positive IATs | Median IAT (s) | CV | Interpretation |
|---|---|---|---:|---:|---:|---:|---|
| `60.190.223.75:888/tcp` | `w.nucleardiscover.com:888` | `/sn.php` | 8 | 7 | 1.381 | 2.3546 | insufficient_observations |
| `94.63.150.20:80/tcp` | `mewgost.com` | `/sn.php` | 8 | 7 | 10.941 | 1.1964 | insufficient_observations |

Top-group plots: `generated/sn_php_iat_histogram.png`, `generated/sn_php_request_scatter.png`.

## Limits and validation needed
- Low CV does **not** independently confirm C2 or an infected host's periodic beaconing; also assess protocol, failed/successful sessions, payload/packet evidence and benign alternatives.
- A CV >= 0.3 also does **not** exclude C2: gaps and session failures can inflate dispersion.
- No Argus ground-truth label mapping is performed here. Do not calculate TP/FP/Precision/Recall from this output.
- Do not mark FND-002 `VALIDATED` solely on the basis of a CV threshold. Reconcile FND numbering between Week 1 and the newer plan.
- A packet-level Wireshark review remains necessary before making content-level assertions.

## Next review
1. Check this summary against the current team Week 2 plan and existing Week 1 findings.
2. Send the event timeline and summary to Lâm; agree on evaluation unit and label policy.
3. Validate candidate traffic in Wireshark; use accepted examples to develop detection rules without leakage.
