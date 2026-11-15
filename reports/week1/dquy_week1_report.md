# Week 1 report — Traffic Analytics & Detection (DQUY)

## Scope and input
CTU-13 Scenario 1 (Neris), infected host `147.32.84.165`. Zeek 9.0.1 JSON logs generated from `botnet-capture-20110810-neris.pcap`; separate Argus labeled-flow dataset `capture20110810.binetflow`. All statistics below are historical observations in this lab capture and should not be treated as current network intelligence.

## Descriptive traffic statistics
- 31,735 Zeek connections; 31,361 initiated by Neris; 4,198 distinct destination IPs.
- Protocols initiated by Neris: TCP 22,417; UDP 8,938; ICMP 6.
- Top destination ports: 25 (16,931), 53 (8,863), 4506 (1,804), 6667 (1,600), and 80 (1,360).
- Missing values for Neris-originated connections: 22 in `duration`, 22 in `orig_bytes`, 22 in `resp_bytes`, none in `orig_ip_bytes` or `resp_ip_bytes`.
- `209.85.225.27:25` had 1,930 connections, all `S0`, TCP history `S`, and no observed response packets. `212.117.174.7:4506` similarly had 1,804 connections, all `S0`, with no response packets. These are repeated connection attempts, **not evidence of successful SMTP/C2 sessions**.

## HTTP C2 investigation (FND-001)
- Endpoint `147.32.84.165 → 31.192.109.167:80/TCP`; HTTP Host `finalcortex.com`.
- 54 Zeek connections, all `SF` and service `http`, with 54 HTTP records: 1 GET `/snapbn/ip.php` and 53 POST `/snapbn/gate.php`; HTTP status 200 in all 54 records.
- 52 positive intervals between the 53 POSTs: mean 146.752006 s, median 123.461849 s, population CV 0.541497; interquartile interval approximately 121.764508–126.217092 s. The mean/CV are affected by longer gaps (maximum 424.011299 s).
- Ground truth: 53 Argus flow records matching 53 distinct Zeek connections by exact 5-tuple and exploratory ±2-second start-time window. All 53 labeled `flow=From-Botnet-V42-TCP-CC53-HTTP-Not-Encrypted`.
- One further Zeek POST uses source port 2275 and overlaps in time with an Argus flow of the same 5-tuple that also corresponds at start-time to an earlier Zeek POST. This supports a possible 1:n Argus/Zeek relationship; not a confirmed independent label mapping for the later POST.

## Ground truth and time handling
- Full Argus dataset: 2,824,636 flows. `From-Botnet` 40,961; `From-Normal` 30,258; flows with Neris as source or destination 41,270.
- Label-prefix categories: Background 1,787,731; To-Background 965,055; From-Background 502; From-Botnet 40,961; From-Normal 30,258; To-Normal 120; Other/Unknown 9.
- `Background` and `To-Background` are **not automatically verified benign**.
- Zeek Unix timestamps interpreted as UTC. Argus local timestamps provisionally interpreted as `Europe/Prague`; 53 C2 matches have mean Argus−Zeek start offset +0.478152 s.

## Deliverables
Scripts under `src/analysis/`; output CSV/PNG in `reports/week1/generated/`; findings `evidence/findings/FND-001.md`–`FND-003.md`; alignment notes and addendum under `reports/week1/`; and `scripts/run_pipeline.sh` to run the analysis from local PCAP and flow dataset. Raw captures, raw Zeek logs, and generated artifacts are not intended for Git tracking.

## Limitations and week 2 handoff
- Beaconing CV alone is not proof of C2. This particular C2 interpretation is supported by original dataset labels; application response content has not been independently reconstructed from packets.
- The current matching method is validated **only on the named HTTP endpoint**, not across all protocols, and cannot directly yield detector-wide confusion matrices.
- Lâm: agree on evaluation unit and labeling policy; handle ambiguous / 1:n joins. Thi: investigate HTTP POST payload and C&C timeline. Thương: verify packet/stream evidence and the reused source port 2275 case.
- Next: test on other endpoints/protocols, define features and thresholds on training data, keep evaluation set separate, report Precision/Recall/F1/FPR only with validated labels.
