# NT140 Week 2 - Label Coverage Report

## Scope

- HTTP transactions: 1377
- Dataset: CTU-13 Scenario 1 (Neris)
- Evaluation unit: HTTP transaction
- Labels: provisional CTU-13 Argus alignment

## Label-specific alert coverage

| Cohort | Label family | Total | Any alert | T1571 | T1071.001 | T1105 | Coverage (%) |
|---|---|---:|---:|---:|---:|---:|---:|
| ALL_PROVISIONAL | CTU_BINARY_DOWNLOAD | 16 | 16 | 7 | 0 | 16 | 100.00 |
| ALL_PROVISIONAL | CTU_C2 | 318 | 92 | 39 | 61 | 0 | 28.93 |
| ALL_PROVISIONAL | CTU_HTTP_AD | 918 | 0 | 0 | 0 | 0 | 0.00 |
| ALL_PROVISIONAL | CTU_OTHER | 22 | 6 | 6 | 0 | 0 | 27.27 |
| ALL_PROVISIONAL | CTU_WEB | 103 | 8 | 0 | 8 | 0 | 7.77 |
| DIRECT_ONLY | CTU_BINARY_DOWNLOAD | 16 | 16 | 7 | 0 | 16 | 100.00 |
| DIRECT_ONLY | CTU_C2 | 283 | 91 | 39 | 60 | 0 | 32.16 |
| DIRECT_ONLY | CTU_HTTP_AD | 912 | 0 | 0 | 0 | 0 | 0.00 |
| DIRECT_ONLY | CTU_OTHER | 22 | 6 | 6 | 0 | 0 | 27.27 |
| DIRECT_ONLY | CTU_WEB | 103 | 8 | 0 | 8 | 0 | 7.77 |

## Evaluation limitations

- Coverage is descriptive, not Precision or FPR.
- Overlap associations are excluded in DIRECT_ONLY.
- From-Botnet does not imply every HTTP event is C2.
- HTTP-Ad/WEB labels are not verified benign negatives.
- Scenario 1 was used during rule development.
- Independent benign and hold-out evaluations are pending.
- TP/FP/TN/FN are intentionally not assigned.
