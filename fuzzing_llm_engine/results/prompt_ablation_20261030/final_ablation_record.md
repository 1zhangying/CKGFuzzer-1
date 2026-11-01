# Prompt 消融最终记录

记录日期：2026-10-30

状态：最终采用

模型：`qwen3-coder-flash`

温度：`0`

数据口径：14 个项目、96 个冻结代表，经冻结去重映射展开到 1217 条 crash
报告。

## 累计消融设计

| 编号 | Prompt | 相对上一级新增的组件 |
|---|---|---|
| P0 | Direct | 正式 V3 直接归因基线 |
| P1 | Core comparison | 一次对称的 target-defect / driver-misuse 双假设比较 |
| P2 | Structured audit | hard/soft 误用分类、调用方前置条件审计、完整结构化 JSON 证据契约 |
| P3 | Full differential | V4 边界仲裁与最终一致性约束；与正式 V4 prompt 逐字符一致 |

P0 和 P3 分别使用与正式 V3、V4 相同的 prompt 模板。P0–P3 均使用同一模型、
同一证据包和同一 96 个代表独立运行，每个版本均有三次完整运行。

## 1217 条报告上的最终结果

四个版本采用与正式 V4 相同的后处理：解析结构化结果、执行确定性一致性检查，
并使用原始 prompt 和冻结 V3 prediction 执行 prior-decision gate。

| Prompt | Runs | Precision | Recall | F1 |
|---|---:|---:|---:|---:|
| P0 Direct | 3 | 0.6531 ± 0.0000 | 0.8466 ± 0.0000 | 0.7373 ± 0.0000 |
| P1 Core comparison | 3 | 0.6627 ± 0.0000 | 0.8836 ± 0.0000 | 0.7574 ± 0.0000 |
| P2 Structured audit | 3 | 0.6776 ± 0.0047 | 0.8677 ± 0.0183 | 0.7610 ± 0.0100 |
| P3 Full differential | 3 | 0.6934 ± 0.0200 | 0.8783 ± 0.0370 | 0.7750 ± 0.0266 |

三次运行的平均 F1 单调提升：

`0.7373 -> 0.7574 -> 0.7610 -> 0.7750`

Precision 的平均值也随累计组件逐级提升。P1 的主要贡献是提高 recall；
P2 提高平均 precision 但略降低平均 recall；P3 取得最高平均 F1。P2 和 P3
存在运行间波动，因此只报告三次均值趋势，不声称某一次 P3 运行必然优于
所有 P2 运行。

## 与审稿问题的对应关系

- P0 → P1：双假设比较单独带来的贡献。
- P1 → P2：hard/soft 误用和调用方前置条件结构化审计带来的贡献。
- P2 → P3：V4 边界仲裁与最终一致性约束带来的贡献。
- P3 使用完整的 V4 differential prompt；其三次运行结果独立报告，不把某次运行
  单独定义为最终结果。

早期“从 V4 删除 rationale”或“仅保留布尔 JSON”的非嵌套实验不属于这组
累计消融，也未列入本记录的主表。

## 结果文件

| 内容 | 文件 | SHA-256 |
|---|---|---|
| 最终指标 | `repeated_metrics_20261030/three_run_summary.csv` | -- |
| P0 prompt | `nested_prompts/P0_direct.jsonl` | `364280a5b445f8cabde02674060c0631e1213f641194972bb8e95083e58f647b` |
| P1 prompt | `nested_prompts/P1_core_differential.jsonl` | `6a28a4c20927c816fbf7524f3c9cf32ec23082f19627262660ac0490595eb1c5` |
| P2 prompt | `nested_prompts/P2_structured_audit.jsonl` | `d0d52792556da8f8ae8615f38c7fb29b2b286c5f959fb1fec930be34a1ca98d6` |
| P3 prompt | `nested_prompts/P3_full_differential.jsonl` | `e69f9aeefb08e0b46036b7a2d967735ab8ac0cd7ea939f060adde77b753c613d` |

最终采用的数据目录：

- P0：`canonical/P0_run1/`、`canonical/P0_run2/`、`canonical/P0_run3/`
- P1：`nested_runs_v2_20261030/P1_core_differential/`、
  `nested_repeat2_20261030/P1_core_differential/`、
  `nested_repeat3_20261030/P1_core_differential/`
- P2：`nested_runs_20261030/P2_structured_audit/`、
  `nested_repeat2_20261030/P2_structured_audit/`、
  `nested_repeat3_20261030/P2_structured_audit/`
- P3：`canonical/P3_run1/`、`canonical/P3_run2/`、`canonical/P3_run3/`
- 三次运行汇总：`repeated_metrics_20261030/three_run_summary.csv`
- 论文口径记录：`prompt_aba_end.md`
