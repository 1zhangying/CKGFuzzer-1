# Context-enriched Crash Analysis for LLM-assisted Fuzz Testing: A Multi-stage Approach
# 面向 LLM 辅助模糊测试的上下文增强 Crash 分析方法

> **目标期刊**: Cybersecurity (Springer Open, CCF-B)  
> **写作策略**: 边实验边写，标注 [可写] / [待数据] / [待补充]

---

## Abstract [待最后写]

提示词模板（等实验全部完成后填充）：
> Fuzz testing assisted by Large Language Models (LLMs) has shown promise in automated vulnerability detection. However, the crash analysis stage in existing LLM-assisted fuzzing frameworks suffers from high false-positive rates, imprecise localization, and redundant analysis. In this paper, we present **XXX**, a multi-stage context-enriched crash analysis pipeline that integrates rule-based triage, precise code localization, GDB-based runtime context collection, and multi-level deduplication to significantly enhance crash analysis quality. We evaluate our approach on N open-source C libraries (c-ares, cJSON, ...) and demonstrate that our method reduces false positives by XX%, saves XX% of LLM invocations, and achieves XX% crash deduplication rate.

---

## 1. Introduction [可写 ★★★] — 建议第一个写

### 写作要点
1. **开场**：模糊测试是发现软件漏洞的重要手段，近年 LLM 辅助 fuzz driver 生成已成为研究热点
2. **问题引出**：自动生成的 fuzz driver 质量参差不齐，会触发大量 crash，其中很多是 driver 本身的 bug 而非目标库漏洞
3. **现有工具不足**（5 个痛点）：
   - 高误判率：LLM 缺乏结构化证据
   - 定位模糊：不知道 crash 在目标库的哪行代码
   - 缺乏可复现性：没有自动 PoC 复现
   - 重复分析浪费：同一 root cause 多次触发
   - 分析内容单薄：缺少结构化输出
4. **我们的方案**：六阶段增强 crash 分析流水线
5. **贡献列表**：
   - (C1) 基于规则的多阶段粗筛机制，有效过滤 fuzz driver 自身 bug
   - (C2) 精确代码定位 + 调用链上下文重建
   - (C3) GDB 集成的运行时上下文收集
   - (C4) 上下文增强的结构化 LLM 深度分析
   - (C5) 多级签名 crash 去重
   - (C6) 在 N 个真实 C 库上的实验评估

### Motivating Example（1-2 个具体例子，来自 c-ares 数据）

**Example 1: deadly signal 误判**
> 原始 CKGFuzzer 将一个仅含 `libFuzzer: deadly signal` 的 crash 判定为 API bug (is_api_bug=True)，
> 但该 crash 无 ASan 栈帧，无法确认出错位置。
> 增强系统的规则 R1 正确将其标记为 noise (confidence=0.9)。

**Example 2: 真实 API bug 保留**
> c-ares 中 `ares_init.c:428 → init_by_options()` 触发 heap-use-after-free，
> 增强系统正确保留并精确定位到源码行。

---

## 2. Background [可写 ★★★]

### 2.1 Sanitizer-based Bug Detection
- AddressSanitizer (ASan): heap-buffer-overflow, use-after-free, double-free, stack-buffer-overflow
- MemorySanitizer (MSan): use-of-uninitialized-value
- LeakSanitizer (LSan): memory leak
- 输出格式：error type + stack trace + SCARINESS score + DEDUP_TOKEN

### 2.2 LLM-assisted Fuzz Testing
- 近年工作：ChatAFL, FuzzGPT, TitanFuzz, CKGFuzzer
- 共同问题：fuzz driver 质量不稳定 → crash 分析成为瓶颈

### 2.3 Code Knowledge Graph
- CodeQL 静态分析 → 函数调用图
- 知识图谱辅助 API 组合与上下文检索

---

## 3. Approach [可写 ★★★] — 核心方法论

### 3.1 System Overview
- 插入 mermaid 流程图（论文中转为 LaTeX tikz 或 PDF 图）
- 六阶段架构：
  Phase 1: Sanitizer Structured Parsing
  Phase 2: Rule-based Multi-stage Triage
  Phase 3: Precise Localization & Context Collection
  Phase 4: Multi-level Deduplication
  Phase 5: Context-enriched LLM Analysis
  Phase 6: Minimization & Report Generation

### 3.2 Sanitizer Output Parsing
- 解析 ASan/MSan/LSan 的结构化输出
- 提取：error_type, stack_frames, signal, registers, SCARINESS, DEDUP_TOKEN
- 栈帧分类：project 帧 vs driver 帧 vs runtime 帧
- 计算 driver_frame_ratio

### 3.3 Rule-based Multi-stage Triage
- 13 条确定性规则（Table 形式展示）
- 规则设计原则：
  - Noise 过滤（R1: 无 ASan 栈帧的 deadly signal）
  - Driver 质量检测（R2: driver_frame_ratio ≥ 0.8; R10-R12）
  - API 漏洞识别（R4: heap-buffer-overflow + API 帧在栈顶）
  - 低价值标记（R6: timeout; R13: leak-only）
- 置信度评估机制
- 只有 likely_api_bug / needs_review 进入 LLM 深度分析

### 3.4 Precise Localization & Call-chain Context
- 从 ASan 栈回溯提取 file:line:column
- 自动读取源文件，提取 crash 点 ± N 行上下文
- 调用链每帧上下文重建（caller → callee → crash point）
- 区分 project 帧与 runtime/driver 帧

### 3.5 GDB-based Runtime Context Collection
- PoC 复现 → GDB 自动化脚本
- 收集：局部变量值、函数参数、寄存器状态、关键指针内存
- 运行时状态与代码上下文融合

### 3.6 Multi-level Signature Deduplication
- Level 1: DEDUP_TOKEN（libFuzzer 原生）
- Level 2: error_type + top-N API 帧 SHA256
- Level 3: error_type + crash 所在函数名（模糊匹配）
- 层级递进：先精确再模糊
- 每个 crash 簇仅做一次完整 LLM 分析

### 3.7 Context-enriched LLM Analysis
- Prompt 构建策略：粗筛结论 + crash 代码上下文 + 调用链 + 运行时状态 + CWE 关联
- 输出结构化 JSON: root_cause, severity, data_flow, fix_suggestion
- 引导策略：根据粗筛标签差异化引导 LLM 分析方向

### 3.8 PoC Reproduction & Minimization
- 多次复现 → repro_rate
- libFuzzer `-minimize_crash=1` + Python delta debugging
- 最小化后验证签名一致性

---

## 4. Implementation [可写 ★★]

### 4.1 System Implementation
- 基于 CKGFuzzer 框架扩展
- Python 实现，~3000+ SLOC
- 使用 LlamaIndex 作为 LLM 调用框架
- CodeQL 用于调用图提取
- Docker 隔离的 fuzzing 执行环境
- 支持 Qwen/DeepSeek/OpenAI 等多种 LLM 后端

### 4.2 Crash Analysis Pipeline Implementation
- sanitizer_parser.py: 结构化解析模块
- triage.py: 13 条规则引擎
- locator.py: 精确定位模块
- debugger.py: GDB 集成模块
- dedup.py: 多级去重模块
- report.py: 结构化报告生成

---

## 5. Evaluation [待数据 — 分步填充]

### 5.0 Experimental Setup
- **被测项目**: c-ares, cJSON, curl, Little-CMS (至少 4 个)
  - c-ares: DNS 解析库, 78 APIs
  - cJSON: JSON 解析库, 78 APIs
  - curl: HTTP 传输库, 大型项目
  - Little-CMS: 色彩管理库
- **Fuzzing 配置**: libFuzzer, ASan+UBSan+MSan, 5min/driver
- **LLM**: Qwen3-Coder-Plus (通义千问)
- **硬件环境**: [填写你的机器配置]
- **对比基线**: 原始 CKGFuzzer crash 分析（直接 LLM 判定）

### 5.1 RQ1: False Positive Reduction [c-ares 数据已有，cJSON 待补充]

> **RQ1: Can the rule-based triage effectively reduce false positives in crash classification?**

**实验方法**：
- 对每个项目的全部 crash，对比原始 LLM is_api_bug 判定 vs 增强系统 triage 判定
- 人工标注 ground truth
- 计算 Precision, Recall, F1

**c-ares 数据（已有）**：

| 指标 | 原始 CKGFuzzer | 增强方法 |
|------|---------------|---------|
| 判定为 API bug | 12/13 (92.3%) | 7/13 (53.8%) |
| 估算旧版 FP 率 | 41.7% | — |

**cJSON 数据**: [待 fuzzing 完成后填充]

**Table X: Triage Label Distribution across Projects**

| Project | Total Crashes | noise | driver_bug | likely_api_bug | needs_review |
|---------|--------------|-------|------------|----------------|--------------|
| c-ares  | 13           | 6     | 0          | 6              | 1            |
| cJSON   | [TBD]        |       |            |                |              |
| curl    | [TBD]        |       |            |                |              |
| lcms    | [TBD]        |       |            |                |              |

### 5.2 RQ2: Localization Precision [待补充]

> **RQ2: How effectively can the enhanced pipeline localize crash sites to specific source locations?**

**实验方法**：
- 统计增强系统能定位到 file:line 的 crash 比例
- 对比：原始系统 0%（仅知道 driver）

**Table X: Localization Success Rate**

| Project | Total Crashes | Located to file:line | Success Rate |
|---------|--------------|---------------------|--------------|
| c-ares  | 13           | [TBD]               |              |
| cJSON   | [TBD]        |                     |              |

### 5.3 RQ3: Deduplication Effectiveness [c-ares 数据已有]

> **RQ3: How effectively does multi-level deduplication reduce redundant crash analysis?**

**c-ares 数据（已有）**：
- 13 crashes → 4 unique clusters (69.2% reduction)
- 节省 LLM 调用: 6/13 (46.2%)

**Table X: Deduplication Results**

| Project | Total Crashes | Unique Clusters | Reduction Rate | LLM Calls Saved |
|---------|--------------|-----------------|----------------|-----------------|
| c-ares  | 13           | 4               | 69.2%          | 46.2%           |
| cJSON   | [TBD]        |                 |                |                 |

### 5.4 RQ4: End-to-end Case Study [可以先写 c-ares 的]

> **RQ4: How does the complete enhanced pipeline improve crash analysis quality compared to the baseline?**

选 3-5 个典型 case，对比原始分析 vs 增强分析的输出质量。

**Case 1: Deadly Signal 误判过滤** (c-ares)
- 原始: is_api_bug=True, category=Segment Violation
- 增强: label=noise, rule=no_asan_stack, confidence=0.9
- 分析: [展示增强系统如何避免误判]

**Case 2: LeakSanitizer 误判过滤** (c-ares)
- 原始: is_api_bug=True, category=Memory Leak
- 增强: label=noise, rule=leak_only, confidence=0.65

**Case 3: 真实 API Bug 保留 + 精确定位** (c-ares)
- 原始: is_api_bug=True（无定位信息）
- 增强: label=likely_api_bug, 定位到 ares_init.c:428, root_cause=heap-use-after-free

**Case 4: cJSON 典型案例** [待 fuzzing 完成]

### 5.5 Threats to Validity [可写]

- 外部有效性：项目选择有限，结果可能不泛化
- 内部有效性：ground truth 人工标注的主观性
- 构造有效性：LLM 输出的随机性（temperature 设置）

---

## 6. Related Work [可写 ★★]

### 6.1 LLM-assisted Fuzz Testing
- ChatAFL (NDSS 2024): LLM 指导 AFL 变异策略
- FuzzGPT (ISSTA 2024): LLM 生成 fuzz driver
- TitanFuzz (ISSTA 2023): LLM 生成 DL 库 fuzz driver
- CKGFuzzer: 代码知识图谱 + LLM 的 fuzz driver 生成
- 本文与上述工作互补，聚焦 crash 分析而非 driver 生成

### 6.2 Crash Triage and Deduplication
- !exploitable: 微软 WinDbg 扩展，基于规则判断可利用性
- ClusterFuzz (Google): crash 签名 + 聚类
- AFL-tmin: 测试用例最小化
- CREDAL, RETracer 等学术工作
- 本文的多级签名优于单一签名

### 6.3 LLM for Vulnerability Analysis
- ChatGPT for code audit 系列工作
- VulDeePecker, Devign 等深度学习漏洞检测
- 本文不同于独立的 LLM 漏洞分析，而是将 LLM 嵌入 fuzzing 闭环中

---

## 7. Conclusion [待最后写]

模板：
> We presented XXX, a multi-stage context-enriched crash analysis pipeline for LLM-assisted fuzz testing. 
> Our approach integrates rule-based triage (reducing false positives by XX%), precise source localization, 
> GDB-based runtime context collection, and multi-level deduplication (achieving XX% reduction). 
> Experiments on N real-world C libraries demonstrate the effectiveness of our approach. 
> In future work, we plan to extend our analysis to more complex multi-threaded programs and 
> integrate automated patch generation.

---

## =============================================
## 📋 写作优先级与时间安排
## =============================================

### Phase 1: 立即开始（本周内，不需要等 cJSON 数据）
- [x] 创新点文档（已完成 paper_innovation.md）
- [ ] **Section 3 (Approach)** — 最核心，篇幅最大，现在就能写完
- [ ] **Section 1 (Introduction)** — 用 c-ares 的例子作为 motivating example
- [ ] **Section 2 (Background)** — 技术背景

### Phase 2: 边等 cJSON fuzzing 边写（本周-下周）
- [ ] **Section 4 (Implementation)** — 系统实现细节
- [ ] **Section 6 (Related Work)** — 文献调研
- [ ] **Section 5.4 (Case Study)** — 先用 c-ares 的 3 个 case

### Phase 3: cJSON + 更多项目数据就绪后（下周-之后）
- [ ] **Section 5.0-5.3** — 补充实验数据表格
- [ ] **Section 5.5** — Threats to Validity
- [ ] **Abstract + Conclusion** — 最后写

### Phase 4: 投稿前
- [ ] 画图（系统架构图、对比表格、实验图表）
- [ ] 格式调整（Springer LaTeX 模板）
- [ ] 英语润色
- [ ] 补充参考文献

---

## =============================================
## 🔧 实验操作 Checklist
## =============================================

### cJSON 实验（当前进行中）
1. [进行中] 编译检查（cjson_check 容器运行中）
2. [ ] 启动 fuzzing 执行
3. [ ] 收集 crash 数据
4. [ ] 运行增强 crash 分析
5. [ ] 运行离线回测: `python -m crash.retroanalyze --crash-dir external_database/cjson/crash`
6. [ ] 收集覆盖率报告
7. [ ] 记录实验数据到论文表格

### 补充项目实验（建议至少再加 1-2 个）
- [ ] curl: 大项目，crash 可能更丰富
- [ ] Little-CMS: 不同领域，增加多样性
- [ ] libpcap/libtiff: 备选

### 消融实验（Ablation Study，可选但加分）
- [ ] 去掉规则粗筛 → 观察误判率变化
- [ ] 去掉 GDB 运行时上下文 → 观察分析质量变化
- [ ] 去掉多级去重 → 观察冗余分析比例
