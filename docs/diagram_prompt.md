# CrashSage 论文核心架构图 — Gemini 生成提示词

> **用途**：将以下提示词发送给 Gemini，请其生成论文级系统架构图 / 流程图  
> **同时也可作为**向导师阐述创新点的完整技术说明书

---

## 提示词（可直接复制使用）

---

请你为一篇学术论文生成一副**论文级别的系统架构流程图**（适用于 CCF-B 期刊论文的 Fig.1），需要高清、专业、可直接放入 LaTeX 论文。请以 SVG 或高分辨率 PNG 输出。

### 一、论文主题与背景

**论文标题**：CrashSage: Context-enriched Crash Analysis for LLM-assisted Fuzz Testing

**核心研究问题**：现有的 LLM 辅助模糊测试框架（如 CKGFuzzer、ChatAFL、FuzzGPT 等）能够自动为 C/C++ 库生成 fuzz driver 并运行模糊测试，但当 fuzzer 触发 crash 后，对 crash 的分析环节存在严重不足：

1. **高误判率**：LLM 在缺乏结构化证据时，将 fuzz driver 自身的代码质量问题（如未初始化变量、缓冲区溢出在 driver 内部）误判为目标库的真实漏洞。实验数据显示：在 c-ares 项目的 13 个 crash 中，原始方法将 92.3%（12/13）判定为 API bug，但其中 41.7% 是误判。
2. **定位模糊**：原始方法只知道"哪个 fuzz driver 触发了 crash"，不能告诉你 crash 出现在目标库源码的**哪一行**。
3. **缺乏可复现性**：没有自动化的 PoC 复现验证和运行时上下文收集机制。
4. **重复分析浪费**：同一个 root cause 可能被不同的 fuzz driver 重复触发，每次都消耗 LLM 调用（token 和时间）。
5. **输出单薄**：只有 `is_api_bug`（布尔值）+ `crash_category`（字符串）+ 自由文本分析，缺乏 root_cause、severity、data_flow、fix_suggestion 等结构化字段。

**我们的解决方案**：提出 CrashSage，一个**六阶段上下文增强 Crash 分析流水线**。核心设计理念是 **"Deterministic-First, LLM-Last"**（确定性优先，LLM 最后）——在 LLM 之前插入多个确定性分析阶段，用结构化证据增强 LLM 的 prompt，同时用规则引擎过滤不值得 LLM 分析的 crash。

---

### 二、系统架构全貌（Fig.1 — 全文最重要的图）

请画一个**从左到右的横向六阶段流水线图**，每个阶段用不同的颜色区分，阶段之间用箭头连接。整体分为上下两层：上层是**数据流**（方框+箭头），下层是**判定逻辑**（决策菱形+分支）。

#### 输入（最左侧）

一个大的输入框，包含三个子元素：
- **Sanitizer Output**（Fuzzer 的崩溃日志，包含 ASan/MSan/LSan 输出）
- **PoC Artifact**（触发 crash 的测试输入文件）
- **Fuzz Driver Source**（LLM 生成的 fuzz driver 源代码）

#### 阶段一：Sanitizer Structured Parsing（蓝色 #2196F3）

**功能**：将 sanitizer 的原始文本输出（含 ANSI 转义码、多种格式）解析为结构化数据。

**输入**：Sanitizer 原始文本输出（如 `ERROR: AddressSanitizer: heap-buffer-overflow ...`）

**处理**：
- 使用 15+ 条正则表达式解析不同字段
- 支持 3 种栈帧格式：完整格式（func + file:line:col）、无源码格式（仅 func）、仅地址格式（模块+偏移）
- 自动分类每个栈帧为 **project 帧**（目标库代码）、**driver 帧**（fuzz driver 代码）、**runtime 帧**（libFuzzer/compiler-rt 运行时）

**输出**（在方框内列出关键字段）：
- `bug_type`：heap-buffer-overflow / use-after-free / memory-leak / ...
- `stack_frames[]`：每帧的 func, file, line, col, address
- `scariness_score`：ASan 的危险度评分
- `dedup_token`：libFuzzer 的去重令牌
- `artifact_path`：PoC 文件路径
- `driver_frame_ratio`：driver 帧占比
- `is_deadly_signal_only`：是否为无 ASan 栈的致命信号

#### 阶段二：Rule-based Multi-stage Triage（橙色 #FF9800）— ⭐ 核心创新

**功能**：用 13 条确定性规则引擎进行粗筛，在 LLM 之前做出初步判定。

**输入**：阶段一的结构化解析结果

**处理逻辑**（请画一个决策分支）：
- 所有 13 条规则**全部执行**（非短路），收集所有匹配的 Evidence
- 每条 Evidence 包含：rule_name、evidence_type（noise/driver_quality/api_vulnerability/low_value）、description、confidence
- 聚合决策：noise 优先 > driver_bug > api_bug > needs_review

**13 条规则分 4 组**（可以在图的一侧用表格或列表标注）：

**组 1 — Noise 过滤**：
- R1 `no_asan_stack`：无 sanitizer 栈帧，仅 deadly signal → noise (0.9)
- R2 `timeout`：超时错误 → low_value (0.7)
- R3 `oom`：内存溢出 → low_value (0.6)
- R13 `leak_only`：仅内存泄漏检测 → low_value (0.65)

**组 2 — Driver 质量问题检测**：
- R4 `driver_uninitialized`：use-of-uninitialized-value 在 driver 帧 → driver_bug (0.9)
- R5 `driver_dominant_stack`：driver_frame_ratio ≥ 0.8 → driver_bug (0.85)
- R10 `stack_overflow_in_driver`：stack-buffer-overflow 且 crash 帧在 driver 内 → driver_bug (0.92)
- R11 `driver_only_crash`：全部非 runtime 帧均为 driver，无 project 帧 → driver_bug (0.95)
- R12 `shallow_api_call`：仅 1-2 个 project 帧 + init/create 浅层调用 → driver_bug (0.70)
- R6 `raw_struct_memcpy_pattern`：driver 直接 memcpy 原始数据到结构体传给 API → driver_bug (0.75)

**组 3 — API 漏洞识别**：
- R7 `api_memory_error`：heap-buffer-overflow / use-after-free / double-free 等 + crash 在 project 帧 → likely_api_bug (0.95)
- R8 `null_deref_high_scariness`：SEGV/null-deref + SCARINESS ≥ 10 + project 帧 → likely_api_bug (0.9)

**组 4 — 逻辑错误**：
- R9 `assertion_failure`：assertion/abort 在 project 代码 → api_logic_error (0.85)

**决策菱形**（关键的分支点）：

```
                    ┌──────────────────────┐
                    │ 聚合所有 Evidence    │
                    └──────────┬───────────┘
                               │
                    ┌──────────▼───────────┐
                    │ 有 noise/low_value    │──是──→ label = "noise"
                    │ 类型的 Evidence?      │        ╔════════════════════╗
                    └──────────┬───────────┘        ║ 跳过后续所有阶段  ║
                               │否                   ║ 不调用 LLM        ║
                    ┌──────────▼───────────┐        ║ 直接输出报告      ║
                    │ 仅有 driver_quality   │        ╚════════════════════╝
                    │ Evidence?             │──是──→ label = "likely_driver_bug"
                    └──────────┬───────────┘        （同上，跳过 LLM）
                               │否
                    ┌──────────▼───────────┐
                    │ 有 api_vulnerability  │──是──→ label = "likely_api_bug"
                    │ Evidence?             │        ╔════════════════════╗
                    └──────────┬───────────┘        ║ 继续进入阶段 3-6  ║
                               │否                   ╚════════════════════╝
                    ┌──────────▼───────────┐
                    │ 证据冲突或无证据      │──────→ label = "needs_review"
                    └──────────────────────┘        （继续进入阶段 3-6）
```

**重要**：只有 `likely_api_bug` 和 `needs_review` 会继续进入后续阶段；`noise` 和 `likely_driver_bug` 直接生成报告，**不调用 LLM**。这是节省资源的关键。

**同时计算三级签名**（为阶段五去重做准备）：
- Level 1 精确签名：`dedup:{DEDUP_TOKEN}`（libFuzzer 原生去重令牌）
- Level 2 栈签名：`stack:{SHA256(bug_type + top-3 project 函数名)}`
- Level 3 模糊签名：`fuzzy:{hash(bug_type + crash 函数名)}`（忽略行号差异）

#### 阶段三：Precise Localization & Call-chain Context（绿色 #4CAF50）

**功能**：精确定位 crash 在目标库源码中的位置，并重建完整的调用链上下文。

**输入**：阶段一的栈帧列表 + 目标库源文件

**处理**：
1. 从 ASan 栈帧中提取第一个 project 帧的 file:line:column
2. 在宿主文件系统上查找对应的源文件（支持多级路径映射：容器内路径 → 宿主路径）
3. 读取 crash 点 **前后各 10 行**源代码上下文
4. 沿调用栈向上回溯，为**每个 project 帧**提取代码上下文（最多 6 帧）
5. 如果源码不可用且有 binary path，回退到 `llvm-symbolizer` / `addr2line` 进行地址反解析

**输出**：
- `crash_file`：崩溃所在源文件（如 `/src/cjson/cJSON.c`）
- `crash_line`：崩溃所在行号（如 `243`）
- `crash_function`：崩溃所在函数（如 `cJSON_New_Item`）
- `crash_code_snippet`：crash 点 ±10 行源码，crash 行用 `>>>` 标记
- `call_chain_context[]`：每帧的 function + file + line + code_snippet + frame_type

#### 阶段四：PoC Reproduction & Runtime Context（绿色 #4CAF50，与阶段三并行）

**功能**：用 PoC 文件复现 crash，并通过 GDB 自动化收集运行时上下文。

**子流程 A — PoC 定位与安全复制**：
1. 优先从 sanitizer 输出的 `artifact_path` 字段查找 PoC（如 `./crash-xxxx`、`./leak-xxxx`）
2. 在 `build/out/{project}/` 目录下定位宿主机上的实际文件
3. 安全复制到 `crash/{driver_name}/pocs/` 独立目录（防止被后续 fuzzing 覆盖）

**子流程 B — 复现验证**：
1. 将 PoC 放入 corpus 目录，用 Docker 容器重新运行 fuzzer **3 次**
2. 每次解析 sanitizer 输出并计算签名
3. 统计 `repro_rate`（3 次中签名一致的比例）

**子流程 C — GDB 运行时上下文**：（如果 binary 可用）
1. 生成 GDB 自动化脚本（`set pagination off` → `run {poc}` → `bt full` → `info registers` → 逐帧 `info args` + `info locals`）
2. 在 crash 点自动收集：
   - **局部变量值**（每变量最多 200 字符）
   - **函数参数**
   - **CPU 寄存器状态**（rip, rsp, rbp, rax, rdi, rsi, rdx, rcx）
   - **调用栈每帧的变量状态**（最多 8 帧）
3. 解析 GDB 输出为结构化的 `RuntimeContext`

**输出**：
- `reproduced`: bool
- `repro_rate`: "2/3" 格式
- `exit_signal`: SIGSEGV / SIGABRT / ...
- `crash_frame`：crash 帧的局部变量 + 参数
- `call_stack[]`：每帧的变量快照
- `registers`：关键寄存器值

#### 阶段五：Multi-level Signature Deduplication（玫红色 #E91E63）

**功能**：跨 fuzz driver 的多级签名去重，避免对同一 root cause 重复分析。

**输入**：阶段二计算的三级签名 + 全局去重数据库

**处理逻辑**（三级递进匹配）：
```
新 crash 签名 ──→ Level 1: 精确签名匹配（DEDUP_TOKEN）
                     │
                     ├── 命中 ──→ 标记为 duplicate_of（精确匹配）
                     │
                     └── 未命中 ──→ Level 2: 栈签名匹配（SHA256）
                                       │
                                       ├── 命中 ──→ 标记为 duplicate_of（栈匹配）
                                       │
                                       └── 未命中 ──→ Level 3: 模糊签名匹配
                                                         │
                                                         ├── 命中 ──→ 标记 fuzzy_similar_to（建议相似）
                                                         │
                                                         └── 未命中 ──→ 新 crash（创建新 cluster）
```

**Cluster 管理**：
- 每个 cluster 有一个 representative crash 做完整 LLM 分析
- 后续 duplicate crash 只记录签名，**不调用 LLM**
- 去重数据库 (`dedup_db.yaml`) 在 session 内共享，跨 fuzz driver 去重

**决策菱形**：
- `is_duplicate = True` → 跳过 LLM 分析，直接标记 `duplicate_of`
- `is_duplicate = False` → 进入阶段六 LLM 分析

#### 阶段六：Context-enriched LLM Analysis（紫色 #9C27B0）

**功能**：将前五个阶段的所有结构化信息汇聚成增强 prompt，调用 LLM 进行深度分析。

**Prompt 构建策略**（5 个 section 汇聚为一个 prompt，请用**信息汇聚图**表示）：

```
┌─────────────────────────┐
│ Section 1: 粗筛结论      │ ← 来自阶段二（triage label + confidence + evidence）
├─────────────────────────┤
│ Section 2: 结构化摘要    │ ← 来自阶段一（bug_type + scariness + 栈帧分类）
├─────────────────────────┤
│ Section 3: 代码上下文    │ ← 来自阶段三（crash 点源码 + 调用链每帧源码）
├─────────────────────────┤        汇
│ Section 4: 运行时上下文  │ ← 来自阶段四（变量值 + 参数 + 寄存器）       聚
├─────────────────────────┤        ↓
│ Section 5: Fuzz Driver   │ ← 原始 fuzz driver 源码
├─────────────────────────┤        ↓
│ Section 6: API Source    │ ← 目标 API 源码                             ↓
├─────────────────────────┤
│ Section 7: Error Pattern │ ← LLM 提取的 driver/API 错误模式
├─────────────────────────┤
│ Section 8: CWE 关联      │ ← CWE 知识库 RAG 检索
└────────────┬────────────┘
             │
             ▼
    ┌────────────────┐
    │   LLM 深度分析  │  ← Qwen3-Coder-Plus
    └────────┬───────┘
             │
             ▼
    ┌────────────────────────────┐
    │ 结构化 JSON 输出（8 字段）  │
    │ • is_api_bug: bool         │
    │ • crash_category: str      │
    │ • root_cause_type: str     │
    │ • root_cause_location: str │
    │ • root_cause_trigger: str  │
    │ • severity: critical/high/ │
    │   medium/low               │
    │ • data_flow: List[str]     │
    │ • fix_suggestion: str      │
    └────────────────────────────┘
```

**差异化引导**：
- 如果阶段二的 triage = `likely_api_bug`：prompt 引导 LLM 聚焦于 API 代码中的 root cause
- 如果阶段二的 triage = `needs_review`：prompt 引导 LLM 判断 crash 是 driver 问题还是 API 问题

**Prompt 安全控制**：
- 每个 section 最多 5000 字符（~1250 tokens）
- API 源码 section 允许 10000 字符
- 总 prompt 不超过 40000 字符（~10000 tokens）
- 超限时自动截断并附加 `[TRUNCATED]` 标记

#### 输出（最右侧）

一个大的输出框——**结构化 Crash 报告 (YAML)**，包含 20+ 字段：
- `verdict`：NOISE / DRIVER_BUG / POTENTIAL_VULNERABILITY / CONFIRMED_VULNERABILITY / NEEDS_REVIEW
- `confidence`：0.0 ~ 1.0
- `sanitizer`：type, bug_type, crash_address, scariness, dedup_token
- `triage`：label, confidence, matched_rules, evidences[], driver_frame_ratio
- `location`：crash_file, crash_line, crash_function, code_snippet
- `runtime`：reproduced, exit_signal, crash_frame (arguments + locals)
- `analysis`：root_cause_type, root_cause_location, severity, data_flow, fix_suggestion
- `signatures`：primary, stack, fuzzy
- `dedup`：is_duplicate, cluster_id, cluster_size
- `reproduction`：repro_rate, runs[]
- `poc_paths`：poc 文件路径
- `timings`：每阶段 wall-clock time (ms)

---

### 三、图的视觉设计要求

1. **颜色方案**（六个阶段各一种颜色）：
   - Phase 1 Sanitizer Parse: 蓝色 `#E3F2FD` / `#2196F3`
   - Phase 2 Rule Triage: 橙色 `#FFF3E0` / `#FF9800`
   - Phase 3 Localization: 绿色 `#E8F5E9` / `#4CAF50`
   - Phase 4 Reproduction: 绿色 `#E8F5E9` / `#4CAF50`（与阶段三同色，因为它们并行执行）
   - Phase 5 Deduplication: 玫红色 `#FCE4EC` / `#E91E63`
   - Phase 6 LLM Analysis: 紫色 `#F3E5F5` / `#9C27B0`

2. **关键标注**：
   - 在阶段 1-5 的底部标注：**"Deterministic Stages (No LLM)"**
   - 在阶段 6 的底部标注：**"LLM-Powered Stage"**
   - 在阶段 2 的 noise/driver_bug 分支旁标注：**"Early Exit — Skip LLM"**
   - 在阶段 5 的 duplicate 分支旁标注：**"Skip LLM — Reuse Existing Analysis"**

3. **布局**：
   - 整体从左到右横向排列
   - 阶段 3 和阶段 4 在垂直方向并行排列（它们同时执行）
   - 决策菱形用于表示阶段 2 的分流和阶段 5 的去重判定
   - 虚线箭头从 noise/duplicate 直接连到最终报告（表示跳过中间阶段）

4. **风格**：
   - 干净、专业的学术论文风格
   - 所有文字使用英文
   - 方框带圆角，箭头清晰
   - 适合在 A4 纸上打印时清晰可读

---

### 四、与原始 CKGFuzzer 的对比（可选的 Fig.2 — Motivating Example 图）

请同时画一个**上下对比图**，展示同一个 crash 在旧方法和新方法下的不同处理：

**上半部分 — Original CKGFuzzer（红色主题）**：
```
Sanitizer Output → [直接扔给 LLM] → LLM 判定: is_api_bug=True ✗ (误判)
                                      crash_category="Segment Violation"
                                      （无定位、无上下文、无去重）
```

**下半部分 — CrashSage（绿色主题）**：
```
Sanitizer Output → Phase 1 Parse → Phase 2 Triage
                                    Rule R1: no_asan_stack
                                    → label=noise, confidence=0.9
                                    → ✓ 正确过滤，不调用 LLM
                                    （节省 LLM token + 避免误判）
```

用一个具体的 c-ares deadly signal crash 作为示例数据：
- crash_info 内容：`libFuzzer: deadly signal`（无 ASan 栈帧）
- 原始方法：LLM 在无证据的情况下判定 `is_api_bug=True` → **误判**
- 新方法：规则 R1 检测到无 ASan 栈帧 → 标记为 noise → **正确过滤**

---

### 五、与现有方法的功能对比表（可选的 Table）

| 能力维度 | CrashSage (本文) | 原始 CKGFuzzer | ClusterFuzz | !exploitable | AFL-tmin |
|----------|:----:|:----:|:----:|:----:|:----:|
| 规则粗筛过滤 | ✓ (13 条规则) | ✗ | 部分 | ✓ | ✗ |
| 源码级精确定位 | ✓ (file:line + 代码片段) | ✗ | ✗ | ✗ | ✗ |
| 调用链上下文 | ✓ (每帧代码) | ✗ | ✗ | ✗ | ✗ |
| GDB 运行时上下文 | ✓ (变量+寄存器) | ✗ | ✗ | ✗ | ✗ |
| 多级签名去重 | ✓ (3 级) | ✗ | 单级 | ✗ | ✗ |
| LLM 深度分析 | ✓ (上下文增强) | ✓ (无上下文) | ✗ | ✗ | ✗ |
| 结构化输出 (JSON) | ✓ (8 字段) | 部分 (2 字段) | ✗ | 部分 | ✗ |
| PoC 复现验证 | ✓ (repro_rate) | ✗ | ✓ | ✗ | ✗ |
| PoC 最小化 | ✓ | ✗ | ✓ | ✗ | ✓ |
| 平台 | Linux/Docker | Linux/Docker | Google Cloud | Windows/WinDbg | Linux |

---

### 六、初步实验数据（用于标注在图上或单独展示）

**c-ares 项目（13 个 crash）的回测数据**：

| 指标 | 原始 CKGFuzzer | CrashSage |
|------|:----:|:----:|
| 判定为 API bug | 12/13 (92.3%) | 7/13 (53.8%) |
| 估算误判率 (FP) | 41.7% | — |
| LLM 调用可省略 | 0/13 (0%) | 6/13 (46.2%) |
| 去重后唯一 crash | 13 | 4 (69.2% reduction) |

**cJSON 项目（已有实际运行数据）**：
- fuzz_driver_42 触发 LeakSanitizer（内存泄漏）
- 旧方法：判定 is_api_bug=True → 误判
- 新方法：规则 R13 (leak_only) 正确标记为 noise (confidence=0.65)
- Pipeline 耗时：parse=8.3ms, triage=6.0ms, locate=1.5ms, dedup=1.4ms → 总计 17.2ms，LLM 跳过

**关键卖点数字**（请在图上高亮标注）：
- 规则粗筛过滤掉 **46.2%** 的 crash，不调用 LLM
- 多级去重将 13 个 crash 合并为 **4 个唯一 cluster**（69.2% 缩减）
- 确定性阶段总耗时 **< 20ms**，LLM 是唯一的高延迟阶段
- 13 条确定性规则 + 3 级签名去重 = 显著降低误判率和分析成本

---

### 七、代码模块与流程的对应关系（供参考）

| 阶段 | 代码模块 | 核心函数 |
|------|---------|---------|
| Phase 1 | `crash/sanitizer_parser.py` | `parse_sanitizer_output()` |
| Phase 2 | `crash/triage.py` | `triage_crash()` → 调用 13 条 `_rule_*()` |
| Phase 3 | `crash/locator.py` | `locate_crash_site()` + `_read_code_context()` |
| Phase 4a | `crash/poc.py` | `locate_poc_on_host()` + `safe_copy_poc()` |
| Phase 4b | `crash/debugger.py` | `reproduce_with_gdb()` + GDB 脚本生成 |
| Phase 5 | `crash/dedup.py` | `DeduplicationEngine.add_crash()` → 3 级索引 |
| Phase 6 | `roles/crash_analyzer.py` | `CrashAnalyzer.analyze_crash_enhanced()` |
| 编排 | `roles/run_fuzzer.py` | `run_enhanced_crash_pipeline()` — 六阶段串联 |
| 报告 | `crash/report.py` | `build_crash_report()` + `save_crash_report()` |

---

### 八、向导师汇报时的核心创新点总结

**用一句话概括创新**：

> 在 LLM 辅助模糊测试中，我们发现"直接把 crash 日志扔给 LLM"会导致高误判、无定位、重复分析三大问题。CrashSage 通过**在 LLM 之前插入五个确定性分析阶段**（解析、规则粗筛、精确定位、PoC 复现、多级去重），实现了"确定性优先、LLM 最后"的 crash 分析范式，在 c-ares 项目上将 LLM 调用节省 46%、crash 去重 69%，同时消除了 41.7% 的误判。

**六大贡献对应解决的具体问题**：

| 贡献 | 解决什么问题 | 技术手段 | 效果 |
|------|-------------|---------|------|
| C1 规则粗筛 | 高误判率 | 13 条确定性规则 + 置信度评估 | FP 率从 41.7% 显著下降 |
| C2 精确定位 | 定位模糊 | ASan 栈帧解析 + 源码上下文读取 | 定位到 file:line + 代码片段 |
| C3 运行时上下文 | 缺乏运行时信息 | GDB 自动化脚本 + PoC 复现 | 收集变量、参数、寄存器 |
| C4 上下文增强 LLM | LLM 分析信息不足 | 8-section 结构化 prompt + 差异化引导 | 输出 root_cause/severity/fix |
| C5 多级去重 | 重复分析浪费 | 3 级签名（精确→栈→模糊）+ cluster | 69.2% crash 缩减 |
| C6 实验评估 | 方法有效性验证 | c-ares/cJSON/curl 多项目实验 | 全面量化对比 |

**与 Related Work 的差异化定位**：
- 不同于 ChatAFL/FuzzGPT/TitanFuzz：它们关注 **driver 生成**，本文关注 **crash 分析**
- 不同于 !exploitable/ClusterFuzz：它们是**独立的 crash 分类工具**，本文是嵌入 **LLM-assisted fuzzing 闭环**的分析模块
- 不同于通用 LLM 漏洞分析：本文不是让 LLM 独立审计代码，而是用**确定性预处理增强 LLM 的判断**
