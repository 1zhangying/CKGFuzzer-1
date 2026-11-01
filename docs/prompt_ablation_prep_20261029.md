# Prompt 消融准备说明

## 范围

该实验只回答 V3/V4 之间 prompt 设计的作用，不重新评估过滤、代表选择或上下文
重建。正文预计使用一个短子小节、一张表，必要时在附录补充逐代表翻转。

## 固定条件

- 96 个代表性 crash
- 14 个项目、1217 条展开报告
- 相同的 ground truth 和 representative-to-report 映射
- 相同的模型、temperature、max tokens 和输出解析器
- 相同的完整证据包
- prompt 在测试前固定，不包含项目名、CVE、ground truth 或变体名

## 实验矩阵

| ID | Prompt | 用途 |
|---|---|---|
| P0 | Direct | 对应 V3 |
| P1 | Differential，删除 evidence rationale 要求 | 检验 evidence rationale |
| P2 | Differential，仅保留最小 JSON 输出 | 检验完整结构化输出 |
| P3 | Differential，完整双假设比较 | 对应 V4 |

P1/P2 均由 P3 删除一个组件得到，二者互不累加。P0/P3 使用现有 V3/V4
结果，不重复发起调用。

## 执行顺序

1. 当前跨模型 V4 运行结束后，冻结 V4 模型版本和 prompt 哈希。
2. 从当前 96 个 V4 证据 prompt 生成 P1/P2 的 dry-run prompt。
3. 校验每个变体只改变预期组件，并校验 96 个 `(project, crash_id)` 完整对应。
4. 分别运行 P1/P2 各 96 次，保存原始响应和最终解析结果。
5. 使用同一映射展开至 1217 条报告，计算指标和逐代表翻转。

## 输出

- `prompt_ablation_metrics.csv`
- `prompt_ablation_representative_decisions.csv`
- `prompt_ablation_expanded_1217.csv`
- `prompt_ablation_flips.csv`
- `prompt_ablation_manifest.json`

## 正文呈现边界

- 保留 V0-V4 作为系统级消融。
- P0-P3 只作为 V3/V4 的 prompt 子分析。
- P0/P3 与 V3/V4 数字对齐。
- 不将 P0-P3 描述为严格累加实验。
- 不根据单个项目的小样本结果推断 prompt 的普遍机制。
