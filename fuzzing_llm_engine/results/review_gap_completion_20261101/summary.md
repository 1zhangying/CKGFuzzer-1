# Reviewer-gap completion audit

No fuzzing or LLM calls were performed. This package recomputes analyses from frozen saved artifacts.

## Ground-truth audit

Current binary ground truth: {'non_target': 1002, 'target': 215}.
Final audit of the 145 previously pending reports: {'confirmed_non_target': 119, 'confirmed_target': 26}.

| Scenario | Samples | Precision | Recall | F1 |
|---|---:|---:|---:|---:|
| operational_binary_all_1217 | 1217 | 0.7654 | 0.9256 | 0.8379 |
| non_unanimous_audit_as_target_sensitivity | 1217 | 0.7923 | 0.7574 | 0.7744 |

## V0/V1 decomposition

| Scenario | Samples | Precision | Recall | F1 |
|---|---:|---:|---:|---:|
| V0_full_population | 1217 | 0.2817 | 0.7023 | 0.4021 |
| V0_restricted_to_V1_retained | 534 | 0.6537 | 0.7023 | 0.6771 |
| V1_full_population | 1217 | 0.5894 | 0.7209 | 0.6485 |
| V1_retained_population | 534 | 0.5894 | 0.7209 | 0.6485 |

V0 predictions restricted to the V1 retained population and the V1 metadata condition differ on 172 reports; 52 of those reports are current targets.

## Target diversity

The 14 projects contain 186 drivers; 179 (96.2%) invoke at least two distinct target APIs, and 168 (90.3%) show an initialization/use/cleanup or ordered-call pattern.

## Repeated-run stability

| Prompt | Runs | F1 mean | F1 SD | 95% bootstrap interval |
|---|---:|---:|---:|---:|
| P0 | 6 | 0.7788 | 0.0051 | [0.7741, 0.7815] |
| P1 | 6 | 0.8095 | 0.0063 | [0.8046, 0.8139] |
| P2 | 6 | 0.8260 | 0.0100 | [0.8178, 0.8342] |
| P3 | 6 | 0.8295 | 0.0085 | [0.8220, 0.8355] |

## Cross-model sensitivity

| Model | Precision | Recall | F1 |
|---|---:|---:|---:|
| qwen3-coder-flash | 0.7654 | 0.9256 | 0.8379 |
| qwen-flash | 0.7425 | 0.9256 | 0.8240 |
| qwen3.8-flash | 0.7636 | 0.9163 | 0.8330 |
| deepseek-flash-official | 0.7645 | 0.9209 | 0.8354 |
| gpt-5.6-sol | 0.7645 | 0.9209 | 0.8354 |
| glm-5.3-flash | 0.7606 | 0.9163 | 0.8312 |

## Representative-order sensitivity

Across 256 deterministic random permutations, the representative count remained 96 (original 96), while mean pairwise co-clustering Jaccard agreement was 0.1973 (range 0.1799 to 0.2208). CVE-pair precision remained 1.0000, with recall ranging from 0.3161 to 0.3565; root-pair precision remained 0.9899 with recall 0.2552 to 0.2552. The fixed saved discovery order must still be disclosed; a canonical order would change which reports become representatives and would require a controlled rerun.
