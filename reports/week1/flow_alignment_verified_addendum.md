# Day 6 verified addendum — HTTP C2 flow-label alignment

## Endpoint and time basis
- Dataset: CTU-13 Scenario 1 (Neris), source `147.32.84.165`, destination `31.192.109.167:80/TCP`.
- Zeek timestamp: Unix `ts`, converted to UTC.
- Argus timestamp: `StartTime` interpreted as `Europe/Prague`, converted to UTC. This timezone hypothesis is supported by endpoint/port matches; it is not independently proven for all flows.

## Verified start-time matching
- 54 Zeek connections; 53 Argus labeled flows.
- 53 unambiguous one-to-one start-time matches using exact 5-tuple and an **exploratory** ±2-second window.
- All 53 Argus flows have label `flow=From-Botnet-V42-TCP-CC53-HTTP-Not-Encrypted`.
- Argus minus Zeek start-time offset among these 53 matched pairs: mean **+0.478152 s**, sample standard deviation **0.023491 s**, min **+0.458735 s**, max **+0.625250 s**.

## Investigation of the remaining Zeek connection
- Unmatched Zeek UID `CyX70D31uZteVKQKja`, `147.32.84.165:2275 → 31.192.109.167:80/TCP`.
- Zeek timestamp **2011-08-10 10:31:25.469770 UTC**, duration **0.179690 s**, state `SF`.
- Corresponding HTTP record is `POST finalcortex.com/snapbn/gate.php`, status **200**, request-body length **62 bytes**, response-body length **3 bytes**.
- Another Zeek connection has the **same 5-tuple**: UID `C6eXbjsS9mQPm1IEe`, starts **10:12:54.127346 UTC**, duration **0.159288 s**, also `POST /snapbn/gate.php`, status **200**.
- Argus contains **one** flow with that 5-tuple, starting **10:12:54.604939 UTC**, duration **1111.622192 s**, ending approximately **10:31:26.227131 UTC**. Its time interval covers the later Zeek connection. Its label is `flow=From-Botnet-V42-TCP-CC53-HTTP-Not-Encrypted`.

## Interpretation and limits
The evidence is **consistent with one Argus flow spanning two separately recorded Zeek TCP connections with a reused 5-tuple**. The exact Argus aggregation mechanism has not been established from these logs alone. The 54th Zeek connection is **not necessarily unlabeled or benign**, but it also does **not** have a verified one-to-one start-time match. A time-window/5-tuple association is a separate, lower-certainty mapping and must not be silently treated as independent ground-truth confirmation.

For FND-001, the direct Zeek/HTTP evidence is 1 GET and 53 POST requests, of which the HTTP POST median inter-arrival time is **123.461849 s** (52 intervals). The set of **53 one-to-one Zeek–Argus pairs includes the GET and excludes one POST**; do not equate it to 53 matched POSTs.

## Next validation work
- Inspect original packet capture and Argus behavior for source port 2275; review why one flow spans two Zeek connections.
- Validate matching rules for DNS, SMTP attempts, and several additional endpoints.
- Agree with Lâm on evaluation unit, thresholds, treatment of background, ambiguous 1:n matches and missing ground truth before computing Precision, Recall, F1, or FPR.
