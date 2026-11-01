# CrashSage 审稿意见逐条评价与回复草稿

稿件编号：CYSE-D-26-01344  
稿件题目：Evidence-Guided Crash Adjudication for LLM-assisted Fuzzing of Third-party Open-source Libraries in Connected Vehicles  
返修截止日期：2026-11-10

> 本文档分为两部分。第一部分是供作者内部使用的中文评价与修改清单；第二部分是可直接改写为英文审稿回复的草稿。方括号中的内容是必须用最终实验结果或章节号补齐的占位符，不应原样提交。

## 一、总体判断

这是一次实质性大修，而不是语言润色。两位审稿人共提出 15 条意见，其中至少以下问题必须在返修稿中补充证据：

1. 明确威胁模型，尤其是“非恶意的 LLM 驱动错误”和“恶意驱动”的边界。
2. 补充人工真值标注协议、标注者盲法与一致性统计。
3. 正确处理 145 个 potential target，不能只用“排除”解释其对 recall 的乐观影响。
4. 将代表选择描述为贪心 leader clustering，而不是等价类，并评估误判传播。
5. 增加独立崩溃归因基线，不能把 CKGFuzzer 的上游生成流程直接称为完整基线。
6. 重复运行云端 LLM 实验，并增加非 Qwen 模型，报告稳定性和置信区间。
7. 补充端到端时延、重放/GDB 细节和规模扩展分析。
8. 重新界定“connected vehicles”的论文范围，避免把通用库方法包装成车规级方法。

### 审稿意见优先级

| 编号 | 意见主题 | 是否成立 | 优先级 | 建议处理 |
|---|---|---:|---:|---|
| R1.1 | malicious 与 incompetent driver 的威胁模型 | 成立 | P1 | 增加独立 Threat Model 小节，明确恶意驱动不在范围 |
| R1.2 | 真值标注协议与 145 个潜在目标 | 成立，且关键 | P0 | 双人盲标/仲裁、报告一致性；补充最坏情形敏感性分析 |
| R1.3 | 签名匹配的传递性与错误传播 | 成立，且关键 | P0 | 改为贪心聚类表述；统计组规模并做代表翻转分析 |
| R1.4 | 运行时间分解与规模扩展 | 成立 | P1 | 增加阶段级、端到端、P50/P95 和规模代理实验 |
| R1.5 | CKGFuzzer 基线与已有方法比较 | 成立，且关键 | P0 | 重命名 V0；增加 raw-LLM、签名去重和定位基线 |
| R1.6 | 模型选择依据与可复现性 | 成立 | P1 | 记录精确模型版本、日期、价格/上下文；增加非 Qwen 模型 |
| R1.7 | 提示词稳定性和过拟合 | 成立，且关键 | P0 | 固定提示词重复运行；多模型稳定性；组件消融和置信区间 |
| R1.8 | Connected vehicles 关联性 | 成立，范围问题 | P0 | 将论文重定位为通用第三方库方法，ICV 作为应用场景 |
| R1.9 | 签名匹配与 CVE 唯一性 | 成立 | P1 | 增加 CVE/公共引用级指标和漏洞多样性损失分析 |
| R2.1 | Connected vehicles 的技术贡献 | 与 R1.8 相同 | P0 | 与 R1.8 合并回复 |
| R2.2 | 实验目标多样性 | 部分成立 | P1 | 补充选择标准、状态型 API 目标及适用边界 |
| R2.3 | 规则过滤造成 V0/V1 差异的原因 | 成立 | P0 | 拆分 filter-only 与 triage-metadata 效果；重复冻结提示词 |
| R2.4 | 模型稳定性与跨模型泛化 | 与 R1.6/R1.7 重叠 | P0 | 与 R1.6/R1.7 合并，但单独引用新增实验 |
| R2.5 | CKGFuzzer 基线问题 | 与 R1.5 相同 | P0 | 与 R1.5 合并回复 |
| R2.6 | 图表可读性 | 成立 | P2 | 使用矢量图、放大字号并简化管线图 |

### 当前数据中需要在返修时正视的三点

这些数据来自当前工作目录中的内部结果，提交前需要与最终论文表格再次核对：

1. 146 个 confirmed target 报告只对应 12 个公共证据族：7 个 CVE 引用和 5 个作者确认的公共 driver+PoC。R1.9 关于“报告级指标可能掩盖 CVE 级重复”的质疑是成立的。
2. 145 个 potential target 全部未进入当前 57 个代表样本，也未计入二分类指标。如果把 145 个全部视为真实目标，仅按现有 TP/FN 计算，V4 recall 的保守下界约为 `139 / (146 + 145) = 47.8%`，而当前报告值是 95.2%。因此只解释“排除策略保守”不足以回应审稿人，必须增加敏感性分析或完成进一步人工判定。
3. 当前 57 个代表映射到 258 个二元可评估报告；组大小中位数为 6，最大为 7，共有 23 个大小为 7 的组。一个代表标签翻转可能影响最多 7 条报告，R1.3 的误判传播风险需要用实验量化。

---

# 二、英文回复草稿

## Response to the Editor

Dear Editor,

We thank you and the reviewers for the constructive and detailed assessment of our manuscript. We have carefully considered every comment. The revision has been reorganized around four issues: a precise threat model and scope statement, an auditable ground-truth annotation and sensitivity protocol, a fair set of crash-adjudication baselines, and a reproducibility analysis of cloud-hosted LLMs and prompt design. We have also improved the presentation of the pipeline figures and supplemented the runtime and vulnerability-diversity analyses.

In the following point-by-point response, reviewer comments are shown in italics and our responses follow immediately. Section, table, and figure references have been updated to the revised manuscript.

---

## Reviewer 1

### R1.1 Threat model: malicious versus incorrect drivers

> *The paper should distinguish malicious drivers from incompetent or unintentionally erroneous drivers and discuss whether rule-guided attribution applies to both.*

**Assessment.** The concern is valid. The manuscript used “untrusted driver” broadly without defining whether the driver is adversarial. The intended setting is a non-adversarial LLM pipeline in which the generated driver may omit initialization, construct invalid arguments, or violate API preconditions unintentionally.

**Draft response.**

We thank the reviewer for identifying this important ambiguity. We agree that “untrusted” must be defined explicitly. In the revised manuscript, we distinguish two settings. The first is a **non-adversarial unreliable driver**, where the LLM produces functionally incorrect or contract-violating code without intentionally targeting the adjudicator. This is the setting evaluated by CrashSage. The second is an **adversarial driver**, in which an attacker deliberately crafts a harness to evade classification, forge evidence, or induce a component-visible failure. CrashSage does not claim robustness against such an adversary, because deterministic stack and sanitizer rules can be deliberately bypassed.

We have added a dedicated threat-model subsection in Section [X.Y]. It defines the privileges, objectives, and assumptions for both settings and explains why the rule-guided stage targets evidence patterns that commonly arise from LLM mistakes rather than from deliberate evasion. We have also added an explicit limitation stating that adversarial-driver robustness requires a separate integrity and provenance mechanism.

### R1.2 Ground-truth annotation protocol and exclusion of potential targets

> *The paper should report annotator number, expertise, blinding, inter-annotator agreement, and the effect of excluding 145 potential targets.*

**Assessment.** Valid and high priority. The current manuscript describes the labels but not how they were produced. Excluding all 145 unresolved candidates can make the headline recall look substantially better than the worst-case outcome.

**Draft response.**

We agree with the reviewer. The previous manuscript did not provide sufficient information about label construction, and the exclusion of the potential-target category requires a more careful treatment.

We have revised the annotation protocol as follows. [N] annotators with backgrounds in systems security and C/C++ memory-safety analysis independently labeled a stratified set containing [N] confirmed targets, [N] confirmed non-targets, and all 145 potential targets. Annotators were blinded to CrashSage outputs, variant names, and representative assignments. Labels were based on the generated driver, sanitizer trace, local reproduction where available, public CVE/advisory/patch evidence, and source-level precondition analysis. Disagreements were resolved by an independent adjudicator. We report Cohen's kappa of [kappa] and the raw agreement matrix in Table [X].

For the 145 potential targets, the revision does not rely on exclusion alone. We now report three results: (i) the confirmed-only binary metrics used in the original submission; (ii) explicit lower- and upper-bound sensitivity bounds obtained by treating all unresolved candidates as true targets and as non-targets; and (iii) a three-way confusion analysis that treats unresolved cases as an abstention class. The worst-case analysis is reported in Table [X]. This makes the uncertainty visible rather than allowing the exclusion rule to inflate the headline recall. We also discuss why a potential target without public confirmation is scientifically different from a confirmed vulnerability.

### R1.3 Transitivity and group-level propagation of duplicate decisions

> *Signature matching may not be transitive, and an incorrect representative decision can propagate to a whole group. The paper should define the grouping construction and quantify this risk.*

**Assessment.** Valid and high priority. The submission describes the process as propagation through “classes,” which suggests an equivalence relation. Exact and stack matching are not jointly guaranteed to be transitive. The implementation is closer to greedy leader clustering with discovery order.

**Draft response.**

We thank the reviewer for this insightful observation. We agree that the previous wording incorrectly suggested equivalence classes. The matching relation is not assumed to be transitive. CrashSage processes retained crashes in discovery order, compares each crash with existing representatives, and joins the first matching leader or becomes a new representative. We now describe the method as **greedy leader clustering** rather than equality-class construction. We explicitly state that transitive closure is not computed because chaining partially similar stacks could merge distinct faults.

We further added a group-level error propagation study. The 57 representatives map to 258 binary-evaluable reports; the group-size distribution is reported in Table [X]. We perturb the label of each representative in turn and recompute TP, FP, TN, and FN at the original-report level. This yields the distribution of metric changes caused by one representative error, including the largest affected group and the aggregate degradation when false-positive or false-negative representatives are sampled. We also manually audited the representative-to-duplicate mappings, including the reported signature fields and sampled stack traces, and summarize the errors in Table [X]. The revised text no longer claims that duplicate propagation is lossless; it reports the observed risk and the safeguards used to reduce false merges.

### R1.4 Runtime and scalability

> *The paper reports rule filtering and representative selection timings but omits replay, GDB, LLM, end-to-end latency, and scalability.*

**Assessment.** Valid. Table 12 is incomplete, and the current manuscript mixes per-stage millisecond measurements with a 2-15 s statement in the conclusion. These values need a single reproducible measurement protocol.

**Draft response.**

We agree and have expanded the runtime evaluation. Table [X] now reports median, P95, and total time separately for sanitizer normalization, rule screening, representative selection, seed recovery, replay, GDB context collection, prompt construction, LLM inference, and post-processing. For each representative we also report end-to-end latency from normalized report to final diagnosis. We distinguish successful runtime reconstruction from replay failures, missing artifacts, and timeouts so that failed cases are not silently omitted from the average.

The measurements in Table [X] were collected on [hardware] with [N] repetitions. Final LLM latency is reported separately from local analysis latency because cloud-service load and network conditions dominate the former. To assess scaling, we model the cost of a workload with `N` reports and a representative rate `r`, and report the measured registration, filtering, and signature-matching throughput on [N] reports. We also discuss the main scaling bottleneck: replay and GDB cost grows with the number of retained representatives, whereas filtering and selection grow approximately linearly before the bounded representative set is formed.

### R1.5 CKGFuzzer and existing-method baselines

> *CKGFuzzer is an upstream fuzz-driver generation workflow, so V0 is not a fair crash-adjudication baseline. Dedicated approaches and a raw-report LLM baseline should be compared.*

**Assessment.** Valid and high priority. V0 is useful as a no-adjudication reference, but the current naming and discussion overstate it as a crash-adjudication baseline.

**Draft response.**

We agree with the reviewer. CKGFuzzer is used in our study as the upstream driver-generation and crash-collection workflow; it is not a dedicated crash-adjudication method. We have renamed V0 as the **raw-report, no-adjudication reference** and now state its role explicitly in Section [X]. We no longer describe it as a complete CKGFuzzer baseline.

We have added the following independent comparisons: B1, direct LLM classification of the raw sanitizer report; B2, exact sanitizer-token matching followed by LLM analysis; and B3, a stack-signature or ReBucket-style call-stack clustering baseline. We also compare against [Igor/CrashLocator or the closest reproducible dedicated baseline] using the same 876 binary-evaluable reports and the same LLM for the final decision where applicable. Table [X] reports precision, recall, F1, LLM submissions, and runtime under matched settings. The ablation variants V1-V4 are retained, but are labeled as component ablations rather than external baselines.

### R1.6 Model selection and reproducibility

> *The paper should justify Qwen, document exact model versions and access dates, and consider open-source models.*

**Assessment.** Valid. Exact commercial model identifiers and access dates are essential for reproducibility, especially for a cloud API. A model-family-only comparison is not sufficient.

**Draft response.**

We have clarified the model-selection criteria: [code-understanding performance, context window, API cost, latency, availability, and data-governance requirements]. We now report the exact model identifiers, provider endpoints, access dates, context limits, decoding settings, retry policy, and pricing used in each run. All frozen prompts and model responses are included in the artifact so that the main comparisons can be replayed.

To avoid relying only on the Qwen family, we additionally evaluate [DeepSeek-Coder / CodeLlama / another open-weight model] under the same V4 evidence package and differential prompt. Table [X] reports the results across model families. Where a hosted model is not byte-for-byte reproducible, we report repeated runs and confidence intervals rather than claiming deterministic behavior. We also state that the method is intended to be model-agnostic and that final deployment should select a model according to the false-positive/false-negative trade-off.

### R1.7 Prompt stability, overfitting, and component ablation

> *The differential prompt has project-dependent effects. Stability, overfitting risk, and key prompt components should be evaluated.*

**Assessment.** Valid and high priority. Temperature zero does not guarantee run-to-run invariance for cloud-hosted models, particularly when prompts are long and structured.

**Draft response.**

We agree that a single temperature-zero run does not establish stability. In the revision, we repeat the V3 and V4 evaluations [N] times with frozen prompts and fixed representative sets. We report mean, standard deviation, and 95% bootstrap confidence intervals for precision, recall, and F1, together with the per-crash decision flip rate between repeated runs. Table [X] separates the effect of the evidence package from the effect of the prompt.

To test overfitting, the prompt template is fixed across all projects and no project name, expected CVE, or ground-truth label is included. We report leave-one-project-out and leave-one-public-reference-out analyses where sample size permits. We also add a prompt-component ablation that compares (i) the clean direct prompt, (ii) the differential hypothesis instruction, (iii) the evidence-rationale requirement, and (iv) the JSON schema requirement. This shows which components contribute to the change rather than attributing the entire effect to one composite prompt. Project-level results with very small denominators are marked as descriptive rather than statistically conclusive.

### R1.8 Connected-vehicle scope and vehicle-specific evidence

> *The title and introduction emphasize connected vehicles, but the experiments use general-purpose libraries and do not involve vehicle protocols, timing constraints, or automotive security mechanisms.*

**Assessment.** Valid and important. The current framing is broader than the evaluation. Either the authors must add vehicle-specific targets or narrow the claim. Narrowing the scope is the more defensible revision unless a substantial automotive experiment can be added.

**Draft response.**

We agree that the previous framing suggested a stronger vehicle-specific contribution than the experiments support. We have repositioned CrashSage as an evidence-guided crash-adjudication method for **third-party C/C++ libraries used in safety- and security-critical software**, with connected vehicles as an important deployment scenario rather than as a vehicle-specific proof of compliance. The title, abstract, introduction, and contributions have been revised accordingly.

Table [X] now maps each evaluated library to a concrete supply-chain or deployment role. Section [X] explicitly states that the study does not cover vehicle buses, real-time control, ISO 26262 certification, or adversarial vehicle-network behavior. These are listed as applicability boundaries and future work. We have removed claims that the results establish automotive-grade assurance. If the journal requires a vehicle-specific empirical component, the scope change can instead be replaced by an additional experiment on [automotive library/protocol]; we have not treated a general-purpose library result as a substitute for such evidence.

### R1.9 Signature matching, CVE uniqueness, and vulnerability diversity

> *Different reports may correspond to different vulnerabilities under the same CVE, or different manifestations of the same vulnerability. Signature deduplication may discard vulnerability diversity.*

**Assessment.** Valid. Report-level metrics alone do not reveal whether the system retains distinct root causes or public vulnerability identities.

**Draft response.**

We agree and have added a vulnerability-identity analysis. Each confirmed target is now linked to a public reference such as a CVE, advisory, or patch and to a root-cause signature defined by the first target-component fault site and precondition. We report precision and recall both at the original-report level and at the CVE/root-cause level, and show the number of distinct public references recovered before and after representative selection.

We also add a diversity-loss analysis that reports which representatives collapse multiple reports, whether the members share the same public reference and root-cause anchor, and whether any merged group contains more than one confirmed vulnerability identity. Cases where signature equality is weaker than vulnerability identity are manually inspected and discussed. The revised method states that representative selection is intended to reduce repeated reports of the same fault, not to establish semantic CVE equivalence. If a group contains evidence of distinct faults, it is split and retained separately in the revised results.

---

## Reviewer 2

### R2.1 Connection between connected vehicles and the technical contribution

> *The scope should be clarified either with representative vehicle stacks or with a general crash-adjudication positioning and explicit applicability limitations.*

**Assessment.** This duplicates R1.8 and should be answered consistently. The general-method positioning is the safer and more honest revision unless a real vehicle-stack experiment is added.

**Draft response.**

We thank the reviewer and agree with this assessment. We have adopted the second option recommended by the reviewer: CrashSage is now positioned as a general evidence-guided crash-adjudication method for third-party libraries, and connected vehicles are presented as one application scenario. The title and abstract no longer imply that the evaluation covers a complete vehicle software stack. Section [X] adds a concrete mapping between the evaluated library functions and vehicle software supply-chain roles, while Section [X] states the limitations regarding vehicle protocols, timing, and certification. This response is aligned with our response to Reviewer 1, comment 8.

### R2.2 Diversity of experimental targets

> *The targets are concentrated in parsing, decoding, networking, and compression. Stateful APIs, resource lifecycles, and invocation-order constraints should be considered.*

**Assessment.** Partially valid. The 12-library set is broad across functionality but not across API interaction types. The current paper should state selection criteria and evaluate at least some stateful API patterns, or explicitly narrow the generalization claim.

**Draft response.**

We agree that the original target set emphasizes data-processing libraries. We have made the target-selection criteria explicit: public availability, relevance to connected-vehicle supply chains, build support under ASan+UBSan, and generation of reproducible crash reports. We also classify the evaluated libraries by API interaction pattern rather than only by file/data function.

To strengthen coverage of stateful behavior, we have added [N] targets involving initialization, handle lifecycles, resource ownership, and ordered API calls: [library names and links]. The corresponding crash counts and API scales are reported in Table [X]. For the existing targets, we additionally report the proportion of multi-call drivers and state-dependent crashes so that the reader can assess how often the method is exercised on stateful interactions. The limitations section now states that the evaluation remains dominated by [parsing/media/compression] libraries and that broader coverage of protocol state machines and resource-lifecycle APIs is needed before claiming general applicability.

### R2.3 Why V0 and V1 produce different per-project LLM decisions

> *All ground-truth positives are retained, yet V0 and V1 differ. The paper should isolate normalization, triage information, and model variation.*

**Assessment.** Valid. The current explanation is too broad. Since filtering retains all positives, recall differences are necessarily caused by the evidence/prompt and model behavior, not by removal of positive reports.

**Draft response.**

We thank the reviewer for this precise observation. We have clarified that V1 differs from V0 not only by removing negative reports, but also by supplying the retained reports with triage labels and matched-rule evidence. Thus, the V0-V1 difference combines the effect of filtering the evaluation set and the effect of changing the LLM input. The previous wording did not make this distinction sufficiently clear.

To isolate the causes, we add three controlled conditions: (i) V1-filter, which evaluates only retained reports but uses the same raw-report prompt as V0; (ii) V1-metadata, which uses the same retained reports plus triage metadata; and (iii) repeated calls with frozen prompts to quantify model variation. Because all 146 confirmed targets are retained, any remaining recall change can be attributed to prompt/evidence effects or run-to-run model variation rather than target removal. Table [X] reports per-project decision flips and the reason categories for those flips. We also separate deterministic filtering statistics from LLM decisions and no longer attribute the full V0-V1 difference to the filtering rules.

### R2.4 Model stability and generalization

> *A single temperature-zero run on a cloud model does not establish stability, and the three Qwen models belong to the same family.*

**Assessment.** Valid. This overlaps with R1.6 and R1.7 but has a distinct emphasis on model-family generalization and repeated execution.

**Draft response.**

We agree with the reviewer. We now repeat the main experiments [N] times with frozen prompts and report means, standard deviations, 95% bootstrap confidence intervals, and per-crash flip rates. We also add [one or more] representative model(s) from a different family, [model names], and keep the evidence package, representative mapping, and differential prompt fixed. Table [X] reports these cross-family results. The revised conclusions distinguish observed robustness on the evaluated models from general model-independent claims. We state that the cloud endpoint version and access date are recorded, and we discuss service-side nondeterminism as a reproducibility limitation.

### R2.5 CKGFuzzer baseline and prior-work comparison

> *The paper should distinguish the CKGFuzzer upstream workflow from its crash-analysis procedure and compare against related crash-attribution methods.*

**Assessment.** Valid. This is the same baseline issue raised by Reviewer 1, comment 5. The response should be identical in substance.

**Draft response.**

We agree. In the revision, CKGFuzzer is explicitly treated as the upstream driver-generation and crash-collection workflow, not as a dedicated crash-adjudication baseline. V0 has been renamed as a no-adjudication raw-report reference. We add raw-report LLM classification, sanitizer-token deduplication, stack-signature/ReBucket-style clustering, and [selected localization/attribution baseline] as independent comparators. The comparison uses the same crash set, evidence availability, and final model where possible. Table [X] reports both attribution metrics and analysis cost. We have also revised the related-work discussion to explain which components CrashSage adds beyond each baseline rather than implying that the upstream fuzzing system is the main competitor.

### R2.6 Figure readability

> *Pipeline diagrams contain small text; use larger fonts, simplified layouts, and vector graphics.*

**Assessment.** Fully valid and straightforward. This should be fixed in the final source rather than defended.

**Draft response.**

We thank the reviewer for this practical suggestion. We have redrawn Figures [1] and [2] as vector graphics with larger fonts, fewer crossing arrows, and a clearer left-to-right flow. Long labels have been moved into the caption or shortened, and the four CrashSage stages are visually aligned with their outputs. We checked the figures at the single-column and full-page scales used in production. The revised figures are supplied separately as vector PDFs and embedded in the LaTeX source.

---

## Closing statement

We believe the revision directly addresses the reviewers' concerns by making the threat model and scope explicit, reporting the ambiguity in ground-truth labels, quantifying representative-level error propagation, adding independent baselines, and evaluating repeated and cross-family LLM behavior. We have also removed claims that the experiments do not support and updated the runtime, vulnerability-diversity, and figure presentations. We hope the revised manuscript is now suitable for publication in Cybersecurity.

---

## 三、提交前必须补齐的占位符

在正式提交前，至少完成并核对以下内容：

1. `[N] annotators`、`[kappa]`、盲标范围和仲裁流程。
2. 145 个 potential target 的最终处理方式，以及 worst-case 表格。
3. 57 个代表的组大小、代表翻转实验和映射人工审计结果。
4. 重放、GDB 和端到端时延的 P50/P95 数据。
5. raw-LLM、签名去重、ReBucket-style 或选定的独立基线结果。
6. 非 Qwen 模型、重复运行次数、均值、标准差和置信区间。
7. 新增状态型 API 目标，或明确不新增时的范围收窄表述。
8. 按 CVE/公共引用统计的去重前后指标。
9. 修改后的 Figure 1、Figure 2 和高分辨率矢量文件。
10. 全文标题、摘要、贡献点和结论中删除未被实验支持的车规级表述。
