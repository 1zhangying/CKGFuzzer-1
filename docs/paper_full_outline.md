# CrashSage: Context-enriched Crash Analysis for LLM-assisted Fuzz Testing

> **目标期刊**: Cybersecurity (Springer Open, CCF-B)  
> **建议页数**: 14–18 页 (Springer LaTeX 模板, 含参考文献)  
> **本文档**: 详细写作指南，每个 Section 标注了内容、篇幅、需要的图表

---

## 全文图表清单 (建议 8–10 张)

| 编号 | 图表类型 | 位置 | 内容描述 | 格式建议 |
|------|---------|------|---------|---------|
| Fig.1 | 架构总览图 | §1 或 §3.1 | CrashSage 六阶段流水线全貌 | TikZ/draw.io 横向流程图 |
| Fig.2 | Motivating Example | §1 | 一个具体 crash 的"旧方法 vs 新方法"对比 | 上下对比的两个 box |
| Fig.3 | CKGFuzzer 工作流 | §2 | 现有 CKGFuzzer 端到端流程（用于说明 crash 分析是最后一环）| 简化流程图 |
| Fig.4 | 规则引擎决策流程 | §3.3 | 13 条规则的分层判定逻辑 | 决策树 / 流程图 |
| Fig.5 | Prompt 构建策略图 | §3.7 | 各阶段输出如何汇聚成 LLM prompt | 信息汇聚示意图 |
| Table 1 | 规则表 | §3.3 | 13 条规则的条件 / 判定 / 置信度 | 三列表格 |
| Table 2 | 实验项目概况 | §5.0 | 被测项目、API 数量、driver 数量、crash 总数 | 基础表格 |
| Table 3 | RQ1 误判率对比 | §5.1 | Precision/Recall/F1 对比表 | 对比表格 |
| Table 4 | RQ2 粗筛标签分布 | §5.2 | 各项目 noise/driver_bug/likely_api_bug 分布 | 统计表 |
| Table 5 | RQ3 去重效果 | §5.3 | 去重前后 crash 数、LLM 调用节省 | 统计表 |
| Fig.6 | RQ1 柱状图 | §5.1 | Baseline vs Enhanced 各项目误判率 | matplotlib 柱状图 |
| Fig.7 | RQ3 饼图/柱状图 | §5.3 | 去重效果可视化 | 饼图或堆叠柱状图 |
| Fig.8 | Case Study 示意 | §5.4 | 一个完整 crash 走完 6 阶段的数据流展示 | 多列布局 |
| Table 6 | 各阶段耗时 | §5.5 | pipeline 各阶段的 wall-clock time | 统计表 |
| Table 7 | 与 Related Work 的能力对比 | §6 | 本文 vs CKGFuzzer/ClusterFuzz/!exploitable 的功能矩阵 | 对比表 ✓/✗ |

---

## Abstract (~200 词) [最后写]

### 写作模板

```
[背景] Fuzz testing assisted by Large Language Models (LLMs) has shown promise
       in automated vulnerability detection for C/C++ libraries.
[问题] However, the crash analysis stage in existing LLM-assisted fuzzing
       frameworks suffers from three critical issues: (1) high false-positive
       rates due to fuzz driver quality issues, (2) imprecise crash localization
       limited to driver-level granularity, and (3) redundant LLM analysis of
       duplicate crashes.
[方法] In this paper, we present CrashSage, a multi-stage context-enriched
       crash analysis pipeline that integrates: rule-based triage with 13
       deterministic rules, precise source-level crash localization,
       GDB-based runtime context collection, multi-level signature
       deduplication, and context-enriched structured LLM analysis.
[结果] We evaluate CrashSage on N open-source C libraries including c-ares,
       cJSON, and curl. Results show that our rule-based triage reduces
       false positives by XX%, multi-level deduplication achieves XX%
       crash reduction, and the overall pipeline saves XX% of LLM
       invocations while improving analysis precision.
[意义] CrashSage is the first work to systematically address crash analysis
       quality in LLM-assisted fuzzing frameworks.
```

---

## 1. Introduction (~1.5 页) ★★★ 第一批写

### 1.1 段落结构 (5 段)

**P1: 背景与热点 (4-5 句)**
- 模糊测试是发现内存安全漏洞的核心技术
- 近年 LLM 辅助 fuzz driver 生成成为热点（引用 ChatAFL, FuzzGPT, TitanFuzz, CKGFuzzer）
- 这些工具能自动为 C/C++ 库生成大量 fuzz driver
- 但生成的 driver 质量参差不齐，运行后产生大量 crash 需要分析

**P2: 问题陈述 — 五个痛点 (6-8 句)**
- **痛点 1 (高误判)**: LLM 在缺乏结构化证据时，倾向于将 driver 自身 bug 误判为目标库漏洞
  - 用数据支撑：c-ares 中旧版 92.3% 判为 API bug，但估算 FP 率达 41.7%
- **痛点 2 (定位模糊)**: 只知道"哪个 driver 触发了 crash"，不知道 crash 在目标库源码的哪一行
- **痛点 3 (缺乏复现)**: 没有自动用 PoC 复现 crash 并收集运行时上下文
- **痛点 4 (重复分析)**: 同一 root cause 触发多个 crash，每个都调用 LLM → 浪费 token 和时间
- **痛点 5 (输出单薄)**: 仅有 crash 类别 + 自由文本，缺少 root_cause/severity/fix 等结构化字段

**P3: Motivating Example (5-7 句 + 可选图)**
- 用 c-ares 的一个 deadly signal crash 做例子 (Fig.2)
- 旧版 CKGFuzzer: crash_info 仅含 `libFuzzer: deadly signal`，无 ASan 栈帧 → LLM 判定 is_api_bug=True
- 增强系统: 规则 R1 检测到"无 sanitizer 栈帧 + 仅 deadly signal" → 标记 noise (confidence=0.9)，不调用 LLM
- 另一个 cJSON 的 memory-leak 例子也可以用（已有实际数据：driver_42 被正确标记为 noise）

> 【需要的图】**Fig.2**: Motivating Example  
> 格式：左右或上下两个 box  
> - Box A "Original CKGFuzzer": crash_info 原文 → LLM → is_api_bug=True ✗  
> - Box B "CrashSage": crash_info → Sanitizer Parse → Rule R1 (no_asan_stack) → noise ✓  
> 用红色标注旧方法的错误判定，绿色标注新方法的正确判定

**P4: 我们的方案 (3-4 句)**
- 我们提出 CrashSage，一个六阶段上下文增强 crash 分析流水线
- 关键思想：在 LLM 之前插入确定性分析阶段，用结构化证据增强 LLM prompt
- 从"直接扔给 LLM"变为"Parse → Triage → Locate → Reproduce → Dedup → Enriched-LLM"

**P5: 贡献列表 (4-6 条)**
- (C1) 基于 13 条确定性规则的多阶段粗筛机制，有效过滤 fuzz driver 自身 bug 和噪声
- (C2) 精确的源码级 crash 定位 + 调用链上下文重建，为 LLM 提供准确的代码位置
- (C3) 基于 PoC 复现 + GDB 的运行时上下文收集，获取 crash 时刻的变量和内存状态
- (C4) 多级签名去重（DEDUP_TOKEN → 栈哈希 → 模糊签名），消除冗余分析
- (C5) 上下文增强的结构化 LLM 分析，输出 root_cause/severity/data_flow/fix_suggestion
- (C6) 在 N 个真实 C 库上的实验评估，证明方法的有效性

---

## 2. Background (~1 页) ★★★ 第一批写

### 2.1 Fuzz Testing and Sanitizers (~0.3 页)
- libFuzzer 的工作原理：coverage-guided, in-process, 语料库进化
- AddressSanitizer (ASan): 检测 heap-buffer-overflow, use-after-free, double-free, stack-buffer-overflow
- MemorySanitizer (MSan): 检测 use-of-uninitialized-value
- LeakSanitizer (LSan): 检测 memory leak
- Sanitizer 输出格式：error type + stack trace + SCARINESS score + DEDUP_TOKEN + artifact path
- **关键点**: libFuzzer 遇到第一个 crash 即停止（这决定了每个 driver 只产生一个 crash）

### 2.2 LLM-assisted Fuzz Driver Generation (~0.3 页)
- 动机：手写 fuzz driver 耗时费力
- 近年工作概述（2-3 句介绍 ChatAFL、FuzzGPT、TitanFuzz）
- CKGFuzzer：基于代码知识图谱 + RAG + 多 Agent 的 fuzz driver 生成框架
  - Planner (API 组合) → Generator (driver 生成) → CompilationFix (编译修复) → RunFuzzer (执行) → CrashAnalyzer (分析)
- **共同瓶颈**：driver 质量不稳定 → crash 分析成为瓶颈

> 【需要的图】**Fig.3**: CKGFuzzer end-to-end workflow  
> 格式：横向流程图，5 个阶段 box，最后一个 box (Crash Analysis) 用虚线框 + "本文关注" 标注  
> 在 Crash Analysis box 下方展开为 CrashSage 的 6 个子阶段（或用箭头指向 Fig.1）

### 2.3 Crash Triage and Deduplication (~0.3 页)
- 现有工具：!exploitable（基于规则判断可利用性）、ClusterFuzz（签名+聚类）、AFL-tmin（最小化）
- 局限性：!exploitable 仅用于 Windows/WinDbg；ClusterFuzz 不公开完整规则；AFL-tmin 只做最小化不分析
- **Gap**: 没有专门针对 LLM 辅助 fuzzing 场景的 crash 分析框架

---

## 3. Approach (~4 页) ★★★ 第一批写 — 核心方法论，篇幅最大

### 3.1 System Overview (~0.5 页)

> 【需要的图】**Fig.1**: CrashSage 系统架构总览（全文最重要的图）  
> 格式：横向 6 列，每列代表一个阶段，用不同颜色区分  
> 从左到右：  
> ① Sanitizer Parse (蓝) → ② Rule Triage (橙) → ③ Locate + Context (绿) → ④ Dedup (红) → ⑤ Enriched LLM (紫) → ⑥ Report (青)  
> 阶段 ② 有两个分支：noise/driver_bug → 直接输出报告；likely_api_bug/needs_review → 继续  
> 阶段 ④ 有分支：duplicate → 合并到 cluster；unique → 继续  
> 底部标注：阶段 ①②③④ = 确定性（无 LLM），阶段 ⑤ = LLM 驱动  
> **注意**：这个图可以直接改自 `paper_innovation.md` 中的 mermaid 图，但需要转为论文级矢量图

- 设计理念："deterministic-first, LLM-last"
  - 先用确定性分析尽可能多地提取结构化信息
  - 只在必要时才调用 LLM，并用丰富上下文指导其分析
- 输入：Sanitizer 原始输出 + PoC artifact + fuzz driver 源码
- 输出：结构化 crash 报告 (YAML/JSON)，含 verdict、root_cause、severity、fix_suggestion

### 3.2 Phase 1: Sanitizer Output Structured Parsing (~0.5 页)

**写什么**：
- 输入：Sanitizer 的原始文本输出（含 ANSI 转义码、多种格式）
- 解析目标：提取以下结构化字段：
  - `bug_type`: heap-buffer-overflow / use-after-free / memory-leak / ...
  - `stack_frames[]`: 每帧的 func, file, line, column, address
  - `signal_hint`: SEGV / ABRT / ...
  - `scariness_score`: ASan 的 SCARINESS 评分
  - `dedup_token`: libFuzzer 的去重令牌
  - `artifact_path`: 触发 crash 的 PoC 输入路径
  - `registers`: 寄存器状态
- 栈帧分类规则：
  - **project 帧**: 路径包含 `/src/{project}/` 的帧 → 目标库代码
  - **driver 帧**: 路径包含 `fuzz_driver` / `LLVMFuzzerTestOneInput` 的帧 → fuzz driver 代码
  - **runtime 帧**: 路径包含 `compiler-rt` / `FuzzerLoop` 的帧 → libFuzzer / runtime 代码
- 计算关键指标：
  - `driver_frame_ratio` = driver 帧数 / (driver 帧数 + project 帧数)
  - `api_frame_ratio` = project 帧数 / 非 runtime 帧数
  - `is_deadly_signal_only`: 是否仅有 deadly signal 而无 ASan 栈

**论文写作提示**：可以用一个小的代码示例（2-3 行 sanitizer 输出 → 解析后的结构化 JSON）来辅助说明

### 3.3 Phase 2: Rule-based Multi-stage Triage (~1 页) — 最核心的创新点

**写什么**：

> 【需要的表】**Table 1**: 13 条规则完整表（这是论文的核心表格之一）  
> 列：Rule ID | Condition | Label | Confidence | Category  
> 行：R1–R13  
> 分组展示：  
> - Noise 过滤 (R1, R7, R8, R9)  
> - Driver 质量问题 (R2, R3, R10, R11, R12)  
> - API 漏洞识别 (R4, R5)  
> - 低价值标记 (R6, R13)

> 【需要的图】**Fig.4**: 规则引擎的分层决策流程  
> 格式：决策树或流程图  
> 入口 → has_asan_stack? → NO → R1(noise)  
>                       → YES → driver_frame_ratio ≥ 0.8? → YES → R2(driver_bug)  
>                                                         → NO → bug_type 判断 → ...  
> 每个叶节点标注 label + confidence

- 设计原则：
  1. **保守策略**：宁可漏过 driver bug 也不误杀真实 API bug
  2. **置信度评估**：每条规则附带置信度，便于后续 LLM 参考
  3. **多规则叠加**：一个 crash 可能匹配多条规则，取最高置信度的判定
- Triage 输出 label：
  - `noise`: 无分析价值（如 deadly signal without ASan stack, leak-only）
  - `driver_bug`: fuzz driver 自身代码问题
  - `likely_api_bug`: 很可能是目标库的真实漏洞
  - `needs_review`: 证据不充分，需要人工或 LLM 复查
- **关键决策**：只有 `likely_api_bug` 和 `needs_review` 进入 LLM 深度分析
- 签名计算（为去重阶段准备）：
  - 精确签名：`dedup:{DEDUP_TOKEN}`
  - 栈签名：`stack:{SHA256(bug_type + top-N project frames)}`
  - 模糊签名：`fuzzy:{hash(bug_type + crash_function)}`

### 3.4 Phase 3: Precise Localization & Call-chain Context (~0.5 页)

**写什么**：
- 从 ASan 栈帧中提取精确的 file:line:column
- 区分"crash 发生在 project 帧"还是"crash 发生在 driver 帧"
- 如果 crash 在 project 帧：提取 crash 点 ± N 行源码上下文
- 调用链上下文重建：从 crash 帧向上回溯，为每个 project 帧提取代码上下文
  - 形成 caller → callee → crash point 的完整调用路径
- 输出：`crash_file`, `crash_line`, `crash_function`, `symbolized` 标志

**与 Phase 1 的区别**：Phase 1 仅做结构化解析，Phase 3 做语义级定位 + 源码读取

### 3.5 Phase 4: PoC Reproduction & Runtime Context (~0.5 页)

**写什么**：
- PoC 定位策略：
  1. 优先使用 `artifact_path` 中的路径
  2. 回退搜索 corpus 目录中的 crash-* / leak-* / oom-* 文件
  3. 安全复制到独立目录（防止被后续 fuzzing 覆盖）
- 复现验证：
  - 用 PoC 在 Docker 容器中重跑 3 次
  - 解析每次输出的 sanitizer 信息
  - 计算 `repro_rate` 和签名一致性
- GDB 运行时上下文收集（如果 binary 可用）：
  - 局部变量值、函数参数
  - 寄存器状态
  - 关键指针指向的内存
- 运行时上下文 + 源码上下文 = "crash 现场快照"

### 3.6 Phase 5: Multi-level Signature Deduplication (~0.5 页)

**写什么**：
- 三级签名体系：
  - Level 1 (精确)：直接使用 libFuzzer DEDUP_TOKEN
  - Level 2 (栈签名)：bug_type + top-N project 帧函数名的 SHA256
  - Level 3 (模糊签名)：bug_type + crash 所在函数名 → 忽略行号差异
- 匹配策略：先 Level 1 → 未命中则 Level 2 → 最后 Level 3
- Cluster 管理：
  - 每个 cluster 选一个 representative crash 做完整分析
  - 后续相同签名的 crash 标记 `duplicate_of`，只记录签名，不调用 LLM
- 持久化：dedup_db.yaml 在 session 内共享，跨 driver 去重

### 3.7 Phase 6: Context-enriched LLM Analysis (~0.5 页)

**写什么**：

> 【需要的图】**Fig.5**: Prompt 构建策略 — 信息汇聚图  
> 格式：五个 box (粗筛结论 / crash 代码上下文 / 调用链 / 运行时状态 / CWE 关联) → 汇聚箭头 → LLM Prompt → 结构化 JSON 输出  
> 每个 box 标注来源阶段（Phase 2/3/4）

- Prompt 构建策略（"staged context injection"）：
  - Section A: 粗筛结论 + 匹配的规则 + 置信度
  - Section B: crash 点源码上下文（±5 行）
  - Section C: 调用链每帧源码
  - Section D: 运行时变量/参数/寄存器（如果有）
  - Section E: CWE 关联提示
- 差异化引导：
  - 如果 triage = `likely_api_bug`: 引导 LLM 聚焦于 API 代码中的 root cause
  - 如果 triage = `needs_review`: 引导 LLM 判断 crash 是 driver 问题还是 API 问题
- 输出约束：
  - 要求 LLM 返回结构化 JSON
  - 字段：root_cause (type/location/trigger_condition)、severity、data_flow、fix_suggestion
  - Prompt 中明确禁止自由文本分析，必须填写每个字段
- Prompt 长度控制：
  - 各 section 有截断限制
  - 总量不超过安全阈值（防止超出 context window）

---

## 4. Implementation (~0.7 页) ★★

### 4.1 System Architecture
- 基于 CKGFuzzer 框架扩展，作为 crash 分析的替换模块
- Python 实现，crash/ 包 ~8 个模块:
  | 模块 | 文件 | SLOC (估) |
  |------|------|----------|
  | Sanitizer Parser | sanitizer_parser.py | ~200 |
  | Rule Engine | triage.py | ~300 |
  | Crash Locator | locator.py | ~150 |
  | GDB Debugger | debugger.py | ~200 |
  | Dedup Engine | dedup.py | ~250 |
  | PoC Handler | poc.py | ~100 |
  | Report Builder | report.py | ~200 |
  | Pipeline Orchestrator | run_fuzzer.py (部分) | ~230 |
- 六阶段流水线编排在 `run_enhanced_crash_pipeline()` 函数中

### 4.2 Integration with CKGFuzzer
- 与 `build_and_fuzz_one_file()` 的集成点
- 调用链：libFuzzer crash → 捕获 sanitizer 输出 → `run_enhanced_crash_pipeline()` → 保存报告
- Dedup DB 在 session 内跨 driver 共享
- 消融基线支持：`ABLATION_BASELINE=1` 环境变量可同时运行旧版 LLM 分析用于对比

### 4.3 Execution Environment
- Docker 容器隔离（OSS-Fuzz base-runner 镜像）
- libFuzzer 配置：ASan + UBSan, timeout per driver (1h)
- LLM 后端：Qwen3-Coder-Plus (通义千问)
- 硬件环境：[你的机器配置]

---

## 5. Evaluation (~4 页) ★★ 分步填充

### 5.0 Experimental Setup (~0.5 页)

> 【需要的表】**Table 2**: 被测项目概况  
> 列：Project | Domain | API Count | Fuzz Drivers Generated | Drivers Compiled | Total Crashes | Fuzzing Time/Driver  
> 行：c-ares, cJSON, curl, [+1-2个]

- 实验环境：硬件、OS、Docker 版本、LLM 模型与参数
- 被测项目选择理由：
  - c-ares (DNS库, 78 APIs) — 中等规模，crash 丰富
  - cJSON (JSON库, 78 APIs) — 小型项目，适合快速验证
  - curl (HTTP库, 53+ APIs) — 大型项目，复杂度高
  - [可选第4个，如 Little-CMS]
- Fuzzing 配置：libFuzzer, ASan+UBSan, 1h/driver
- 对比基线：原始 CKGFuzzer (直接 LLM `analyze_crash()`，无 triage/dedup/localization)

**Research Questions**:
- **RQ1**: 规则粗筛能否有效降低 crash 分类的误判率？
- **RQ2**: 粗筛标签分布如何？各类 crash 的比例是多少？
- **RQ3**: 多级去重能在多大程度上减少冗余分析？
- **RQ4**: 精确定位 + 上下文增强是否提升 LLM 分析质量？
- **RQ5 (可选)**: 各阶段的时间开销分别是多少？

### 5.1 RQ1: False Positive Reduction (~0.8 页)

> 【需要的表】**Table 3**: 误判率对比  
> 列：Project | Method | Predicted API Bug | Actual API Bug (GT) | FP | FN | Precision | Recall | F1  
> 行：每个项目两行（Baseline / CrashSage）

> 【需要的图】**Fig.6**: 各项目误判率柱状图  
> X 轴：项目名  
> Y 轴：False Positive Rate (%)  
> 两组柱子：Baseline (红) vs CrashSage (绿)

- 实验方法：
  1. 收集每个项目所有 crash
  2. 用 `ABLATION_BASELINE=1` 同时运行旧版和新版分析
  3. 人工标注 ground truth（每个 crash 是真实 API bug 还是 driver/noise）
  4. 计算 Precision, Recall, F1
- c-ares 已有数据：旧版 12/13 判为 API bug (FP率 41.7%)，新版 7/13 (下降显著)
- cJSON 已有数据：driver_42 的 LeakSanitizer → 新版正确标记 noise，旧版可能误判

### 5.2 RQ2: Triage Label Distribution (~0.5 页)

> 【需要的表】**Table 4**: 各项目的粗筛标签分布  
> 列：Project | Total | noise | driver_bug | likely_api_bug | needs_review | low_value  
> 行：每个项目一行 + 合计行

- 分析各类 crash 的比例
- 讨论：在 LLM 辅助 fuzzing 场景中，noise 和 driver_bug 占比通常很高
  - 这验证了"LLM 前置粗筛"的必要性

### 5.3 RQ3: Deduplication Effectiveness (~0.5 页)

> 【需要的表】**Table 5**: 去重效果  
> 列：Project | Total Crashes | Unique Clusters | Reduction Rate | LLM Calls Saved | Token Saved (est.)  
> 行：每个项目一行 + 合计行

> 【需要的图】**Fig.7**: 去重效果可视化  
> 方案 A: 饼图（unique vs duplicate 比例）  
> 方案 B: 堆叠柱状图（每个项目的 unique/dup 分布）

- c-ares 已有数据：13 → 4 clusters (69.2% reduction)
- 分析三级签名各自的贡献

### 5.4 RQ4: Analysis Quality Case Study (~1 页)

> 【需要的图】**Fig.8**: Case Study — 完整 pipeline 数据流  
> 选一个 likely_api_bug 的 crash，展示它走完 6 个阶段的完整数据  
> 格式：纵向 timeline，每个阶段一个 box，展示输入/输出

选 3-5 个典型 case，对比旧版 vs 新版的分析输出：

**Case 1: Deadly Signal 噪声过滤 (c-ares)**
- 旧版: is_api_bug=True → 错误
- 新版: label=noise, rule=no_asan_stack, confidence=0.9 → 正确

**Case 2: Memory Leak 低价值标记 (cJSON)**
- 旧版: is_api_bug=True, category=Memory Leak → 误判
- 新版: label=noise, rule=leak_only, confidence=0.65 → 正确
- 实际数据来自 cjson_fuzz_driver_False_qwen3-coder-plus_42

**Case 3: 真实 API Bug 保留 + 精确定位 (c-ares)**
- 旧版: is_api_bug=True (无定位)
- 新版: label=likely_api_bug, 定位到 ares_init.c:428, root_cause=heap-use-after-free

**Case 4: 重复 Crash 去重 (cJSON 或 c-ares)**
- 展示两个具有相同签名的 crash 被合并到同一 cluster

**Case 5 (可选): needs_review 的 LLM 增强分析**
- 展示增强 prompt vs 原始 prompt 的分析质量差异

### 5.5 RQ5 (可选): Efficiency Analysis (~0.3 页)

> 【需要的表】**Table 6**: Pipeline 各阶段耗时  
> 列：Stage | Mean Time (ms) | Median (ms) | Max (ms)  
> 行：Parse / Triage / Locate / Dedup / LLM(if called) / Total

- 利用已有 timings 数据（crash_analysis.yaml 中有每阶段 ms 级计时）
- cJSON driver_42 的数据：parse=8.3ms, triage=6.0ms, locate=1.5ms, dedup=1.4ms, llm=0.3ms (skipped)
- 讨论：确定性阶段总耗时 < 20ms，LLM 是唯一的高延迟阶段 → 跳过 LLM 的价值更大

### 5.6 Threats to Validity (~0.3 页)
- **外部有效性**: 仅在 C/C++ 库上测试，结果可能不泛化到其他语言
- **内部有效性**: ground truth 依赖人工标注，存在主观性
- **构造有效性**: LLM 输出具有随机性（temperature > 0），结果可能因模型/参数不同而变化
- **规则的泛化性**: 13 条规则基于 ASan/MSan/LSan 设计，可能不适用于其他 sanitizer

---

## 6. Related Work (~1 页) ★★

> 【需要的表】**Table 7**: 功能对比表  
> 列：Feature | CrashSage | CKGFuzzer | ClusterFuzz | !exploitable | AFL-tmin  
> 行：Rule-based triage ✓/✗ | Source localization ✓/✗ | Runtime context ✓/✗ | Multi-level dedup ✓/✗ | LLM analysis ✓/✗ | Structured output ✓/✗ | PoC minimization ✓/✗

### 6.1 LLM-assisted Fuzz Testing
- ChatAFL [NDSS'24]: LLM 指导 AFL 变异策略，不涉及 crash 分析
- FuzzGPT [ISSTA'24]: LLM 生成 fuzz driver，crash 分析是手动的
- TitanFuzz [ISSTA'23]: LLM 生成 DL 库 fuzz driver，不分析 crash
- CKGFuzzer: 代码知识图谱 + LLM，有 crash 分析但仅单阶段 LLM
- **本文与上述工作互补**：聚焦 crash 分析质量而非 driver 生成

### 6.2 Crash Triage and Deduplication
- !exploitable [Microsoft]: 基于规则判断 crash 可利用性（仅 Windows/WinDbg）
- ClusterFuzz [Google]: 签名 + 聚类，用于 OSS-Fuzz，但规则不公开
- AFL-tmin: 测试用例最小化，不做 crash 分析
- CREDAL, RETracer, CrashLocator 等学术工作
- **本文的差异**：(1) 专门针对 LLM-assisted fuzzing 场景, (2) 规则 + LLM 混合架构

### 6.3 LLM for Vulnerability Analysis
- LLM 代码审计相关工作
- VulDeePecker, Devign 等深度学习漏洞检测
- **本文不同于独立的 LLM 漏洞分析，而是将 LLM 嵌入 fuzzing 闭环**

---

## 7. Conclusion (~0.3 页) [最后写]

### 写作模板

```
We presented CrashSage, a multi-stage context-enriched crash analysis pipeline
for LLM-assisted fuzz testing. Our key insight is that deterministic
pre-processing (rule-based triage, precise localization, multi-level
deduplication) should precede LLM analysis to reduce false positives,
eliminate redundancy, and enrich context.

[实验结果摘要]
Experiments on N real-world C libraries demonstrate that:
(1) rule-based triage reduces false positives by XX%;
(2) multi-level deduplication achieves XX% crash reduction,
    saving XX% of LLM invocations;
(3) context-enriched LLM analysis produces more precise
    and actionable crash reports.

[未来工作]
In future work, we plan to:
(1) extend CrashSage to support multi-threaded programs and concurrency bugs;
(2) integrate automated patch generation based on crash analysis results;
(3) explore cross-project rule transfer learning.
```

---

## 8. References (~30-40 条)

### 必引文献清单

**LLM-assisted Fuzzing:**
1. ChatAFL (NDSS 2024) — LLM + AFL
2. FuzzGPT (ISSTA 2024) — LLM fuzz driver 生成
3. TitanFuzz (ISSTA 2023) — DL 库 fuzzing
4. CKGFuzzer — 代码知识图谱 + LLM fuzzing
5. Fuzz4All (ICSE 2024) — 通用 LLM fuzzing

**Crash Triage / Dedup:**
6. !exploitable (Microsoft) — 可利用性分析
7. ClusterFuzz (Google OSS-Fuzz)
8. AFL-tmin — 测试用例最小化
9. RETracer (ICSE 2016) — crash 栈分析
10. CrashLocator (ISSTA 2014) — crash 定位

**Sanitizer:**
11. AddressSanitizer (ATC 2012)
12. MemorySanitizer (CGO 2015)
13. libFuzzer 文档

**LLM for SE:**
14. ChatGPT for code analysis 相关综述
15. Copilot / CodeLlama 等代码 LLM

**Fuzzing 基础:**
16. AFL (Zalewski 2013)
17. libFuzzer
18. OSS-Fuzz

**知识图谱:**
19. CodeQL
20. LlamaIndex

---

## =============================================
## 写作顺序建议（优先级排序）
## =============================================

### 第一批（本周内，不依赖更多实验数据）
1. **§3 Approach** (4页) — 核心方法论，最重要
2. **§1 Introduction** (1.5页) — 用已有 c-ares + cJSON 例子
3. **§2 Background** (1页) — 技术背景

### 第二批（边等更多实验边写）
4. **§4 Implementation** (0.7页)
5. **§6 Related Work** (1页) — 文献调研

### 第三批（实验数据就绪后）
6. **§5 Evaluation** (4页) — 分 RQ 逐步填充
7. **§7 Conclusion + Abstract** — 最后写

### 画图任务（可以与写作并行）
- Fig.1 系统架构图 → 用 draw.io 或 TikZ
- Fig.2 Motivating Example → 用 LaTeX box
- Fig.3 CKGFuzzer 流程 → 简化版流程图
- Fig.4 规则决策树 → draw.io
- Fig.5 Prompt 汇聚图 → 信息流图
- Table 1 规则表 → 直接写 LaTeX tabular
