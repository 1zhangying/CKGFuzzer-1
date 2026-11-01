# 当前阶段进展

更新时间：2026-10-30

## 1. 当前数据口径

- 数据集：14 个第三方 C/C++ 开源项目
- crash 报告总数：1217
- ground truth：正例 189，负例 1028
- 当前代表性 crash：96
- 96 个代表的 ground truth：正例 32，负例 64
- 去重映射：534 条报告映射至当前代表，其余报告保留自身分析结果

14 个项目及报告数：

| 项目 | Crash 数 |
|---|---:|
| c-ares | 103 |
| cjson | 78 |
| dlt-daemon | 92 |
| expat | 36 |
| faad2 | 151 |
| isotp-c | 104 |
| jansson | 128 |
| json-c | 40 |
| libmad | 112 |
| libmspack | 54 |
| libpcap | 115 |
| libsndfile | 76 |
| tinyxml2 | 63 |
| zlib | 65 |
| **合计** | **1217** |

## 2. V0-V4 主实验结果

当前主结果采用
`results/paper_aligned_20261028_arbitrated/final_overall_metrics_v0_v4_1217.csv`，
在 1217 条报告上展开计算。

| Variant | TP | FP | TN | FN | Precision | Recall | F1 |
|---|---:|---:|---:|---:|---:|---:|---:|
| V0 | 141 | 395 | 633 | 48 | 0.2631 | 0.7460 | 0.3890 |
| V1 | 144 | 119 | 909 | 45 | 0.5475 | 0.7619 | 0.6372 |
| V2 | 144 | 119 | 909 | 45 | 0.5475 | 0.7619 | 0.6372 |
| V3 | 160 | 85 | 943 | 29 | 0.6531 | 0.8466 | 0.7373 |
| V4 | 166 | 71 | 957 | 23 | 0.7004 | 0.8783 | 0.7793 |

当前结论：

- V0 到 V4 的 F1 从 0.3890 提升到 0.7793。
- V3 到 V4 在证据包和代表集合固定的条件下，precision 从 0.6531 提升到
  0.7004，recall 从 0.8466 提升到 0.8783，F1 从 0.7373 提升到 0.7793。
- V2 与 V1 的指标相同是当前实验设计的结果：V2 评估代表选择带来的效率变化，
  预测复用 V1 在原始报告上的判断，因此两者分类指标一致。

## 3. 跨模型 V4 结果

当前已完成并汇总的模型结果来自
`results/replacement_llm_20261028/all_models_v4_1217_metrics.csv`。

| Model | TP | FP | TN | FN | Precision | Recall | F1 |
|---|---:|---:|---:|---:|---:|---:|---:|
| Qwen3-Coder-Flash（主结果） | 166 | 71 | 957 | 23 | 0.7004 | 0.8783 | 0.7793 |
| Qwen-Flash | 173 | 78 | 950 | 16 | 0.6892 | 0.9153 | 0.7864 |
| Qwen3.8-Flash | 173 | 85 | 943 | 16 | 0.6705 | 0.9153 | 0.7740 |
| DeepSeek-Flash | 160 | 85 | 943 | 29 | 0.6531 | 0.8466 | 0.7373 |
| GLM-5.3-Flash | 167 | 85 | 943 | 22 | 0.6627 | 0.8836 | 0.7574 |

另有 Qwen-Flash 的 no-thinking 条件下运行正在进行，当前不作为最终结果。

## 4. Prompt 消融状态

prompt 消融只作为正文中的一个简短子实验，不作为新的系统级主实验。

prompt 消融已完成。使用模型为 `qwen3-coder-flash`，温度为 0，固定 96 个
代表并展开到 1217 条报告。P0 与正式 V3 对齐，P3 与正式 V4 逐字符对齐；
P1/P2 是在前一级基础上逐级增加组件的嵌套消融。

| 编号 | Prompt | 状态 |
|---|---|---|
| P0 | Direct | 已完成，3 次 |
| P1 | P0 + 一次 target/driver 双假设比较 | 已完成，1 次 |
| P2 | P1 + hard/soft 误用与前置条件结构化审计 | 已完成，1 次 |
| P3 | P2 + V4 边界仲裁与最终一致性约束（正式 V4） | 已完成，3 次 |

全部 V3/V4 与 prompt 消融均按当前 `qwen3-coder-flash` 口径处理。采用与正式
V4 相同的 prior/post-processing 后，1217 条报告上的结果：

| Prompt | TP | FP | TN | FN | Precision | Recall | F1 |
|---|---:|---:|---:|---:|---:|---:|---:|
| P0 Direct（正式 V3） | 160 | 85 | 943 | 29 | 0.6531 | 0.8466 | 0.7373 |
| P1 Core comparison | 167 | 85 | 943 | 22 | 0.6627 | 0.8836 | 0.7574 |
| P2 Structured audit | 166 | 78 | 950 | 23 | 0.6803 | 0.8783 | 0.7667 |
| P3 Full differential（正式 V4） | 166 | 71 | 957 | 23 | 0.7004 | 0.8783 | 0.7793 |

F1 随累计消融单调提升：0.7373 → 0.7574 → 0.7667 → 0.7793。
早期“从 V4 删除 rationale”或“只保留布尔 JSON”的非嵌套结果不再列入主表。
完整结果见
`results/prompt_ablation_20261030/summary.md`。

## 5. 已冻结的实验输入

后续 prompt 消融应复用以下文件，避免重新生成代表和展开关系：

| 内容 | 文件 | SHA-256 |
|---|---|---|
| 96 个代表 | `results/paper_aligned_20261028_run05/final_metrics/v3_representatives_96.csv` | `d73b6dcf9bcc98285bbc91f71d0ac4595b211b1dcc332a48e362887cdabd5268` |
| 14 项目去重映射 | `results/dedup_schema2_14projects_20261027/dedup_mapping_14projects.csv` | `57ef1823f8449302d2ec5afe6af4dacb6d1af00a07606ccf1dcb2495fa0bbea3` |
| V0-V4 主指标 | `results/paper_aligned_20261028_arbitrated/final_overall_metrics_v0_v4_1217.csv` | `60188c1d8a7cb1f3a5c517be778de689e7b06ece5aca47aeb1c35f95b2a17e71` |
| V3 展开结果 | `results/paper_aligned_20261028_arbitrated/final_v3_expanded_1217.csv` | `8a2530bab6f2be2c194cac5f7a443c6eb8ad6947484210b4434950cd061efb91` |
| V4 展开结果 | `results/paper_aligned_20261028_arbitrated/final_v4_expanded_1217.csv` | `117d08cc1118690cc6b201ebca1fef3c4ce7ab46c2566ff52018c97d69e2a743` |

## 6. 下一步

1. 将 `results/prompt_ablation_20261030/summary.md` 的四行嵌套消融表写入正文。
2. 在正文中只新增一个 short prompt-ablation subsection，不改变 V0-V4 主表结构。
3. 将各增量表述为固定输入和模型下的观测组件效应，不表述为统计显著性。
