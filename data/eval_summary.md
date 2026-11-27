# RansomSentry evaluation results

## Attacks and evasions

| Mode | Scenario | Runs | Detected | Avg detection (s) | Avg time to kill (s) | Avg files hit | Avg files lost | Correct kill | Verdict by |
|---|---|---|---|---|---|---|---|---|---|
| full | sim_fast | 3 | 100% | 0.07 | 0.61 | 107.7 | 0.0 | 100% | rules x3 |
| no_canary | sim_fast | 3 | 100% | 0.25 | 0.91 | 61.3 | 0.0 | 100% | rules x3 |
| full | sim_medium | 3 | 100% | 0.11 | 0.65 | 23.0 | 0.0 | 100% | rules x3 |
| no_canary | sim_medium | 3 | 100% | 0.07 | 0.55 | 22.3 | 0.0 | 100% | rules x3 |
| full | sim_slow | 3 | 100% | 0.00 | 0.44 | 5.0 | 0.0 | 100% | rules x3 |
| no_canary | sim_slow | 3 | 100% | 0.02 | 0.43 | 5.0 | 0.0 | 100% | rules x3 |
| full | partial_512 | 3 | 100% | 0.01 | 0.47 | 22.0 | 0.0 | 100% | rules x3 |
| no_canary | partial_512 | 3 | 100% | 0.02 | 0.47 | 24.7 | 0.0 | 100% | rules x3 |
| full | partial_1k | 3 | 100% | 0.00 | 0.46 | 24.0 | 0.0 | 100% | rules x3 |
| no_canary | partial_1k | 3 | 100% | 0.05 | 0.51 | 24.3 | 0.0 | 100% | rules x3 |
| full | partial_4k | 3 | 100% | 0.00 | 0.48 | 24.7 | 0.0 | 100% | rules x3 |
| no_canary | partial_4k | 3 | 100% | 0.04 | 0.53 | 23.3 | 0.0 | 100% | rules x3 |
| full | no_note | 3 | 100% | 0.00 | 0.57 | 20.7 | 0.0 | 100% | rules x3 |
| no_canary | no_note | 3 | 100% | 0.04 | 0.47 | 22.3 | 0.0 | 100% | rules x3 |
| rules_only | sim_medium | 3 | 100% | 0.02 | 0.47 | 24.3 | 0.0 | 100% | rules x3 |
| ml_only | sim_medium | 3 | 100% | 1.51 | 1.93 | 48.3 | 0.0 | 100% | ML classifier x3 |
| rules_only | partial_1k | 3 | 100% | 0.03 | 0.48 | 24.3 | 0.0 | 100% | rules x3 |
| ml_only | partial_1k | 3 | 100% | 1.65 | 2.07 | 48.3 | 0.0 | 100% | ML classifier x3 |
| no_canary | no_rename | 3 | 100% | 0.03 | 0.46 | 25.7 | 0.0 | 100% | rules x3 |
| no_canary | no_rename_partial | 3 | 100% | 1.96 | - | 320.0 | 3.7 | 0% | rules x3 |
| no_canary | very_slow | 3 | 100% | 1.63 | - | 22.7 | 0.3 | 0% | ML classifier x3 |

## Benign workloads (false positives)

| Scenario | Runs | False alarms | Process killed |
|---|---|---|---|
| copy | 3 | 0 | 0 |
| zip | 3 | 0 | 0 |
| unzip | 3 | 0 | 0 |
| bulk_rename | 3 | 0 | 0 |
| edit | 3 | 0 | 0 |
| gzip_rotate | 3 | 0 | 0 |
| download | 3 | 0 | 0 |
| 7z_add | 3 | 0 | 0 |

**Overall false-positive rate: 0.0% (0/24 benign runs)**