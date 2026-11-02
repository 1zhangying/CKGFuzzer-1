<!-- Converted from docs/sn-article-template/sn-article.tex. Original manuscript text is preserved; revision boxes are inserted only below locations that require changes. -->

# Evidence-Guided Crash Adjudication for LLM-assisted Fuzzing of Third-party Open-source Libraries in Connected Vehicles

**Authors:** Qingguan Gao <gaoqingguan@seu.edu.cn>; Ying Zhang <zhangying@seu.edu.cn>; Letian Sha <ltsha@njupt.edu.cn>; Huiran Yang <yanghuiran@zdcst.cn>

**Affiliations:** School of Cyber Science and Engineering, Southeast University, Nanjing, China; School of Computer Science, Nanjing University of Posts and Telecommunications, Nanjing, China; The First Research Institute of the Ministry of Public Security, China

## Abstract

Connected vehicle systems rely heavily on third-party open-source libraries, which necessitates effective fuzz testing to ensure robust security validation. Advances in Large Language Models (LLMs) have increasingly automated fuzz-driver generation. Nevertheless, directly applying LLMs to raw crash reports can produce many false alerts, while case-by-case triage incurs prohibitive labor costs. To tackle this problem, we propose CrashSage, an evidence-guided framework for post-fuzzing crash adjudication in LLM-assisted fuzzing. Before final LLM analysis, CrashSage prepares crash evidence through three key designs: rule-guided crash attribution, representative selection, and crash-context reconstruction. Rule-guided crash attribution filters low-value reports and likely driver-induced crashes to improve false-alert judgment. Representative selection compares exact and stack signatures among retained reports to identify repeated crash instances and submits only selected representatives to the LLM, reducing redundant analysis. Crash-context reconstruction enriches representatives with static and runtime evidence, helping determine whether the faulty state comes from the generated driver or the target component. Experiments on 1021 crash reports collected from 12 third-party open-source libraries, with 876 binary-evaluable reports used in the main evaluation, show that CrashSage achieves 79.89% precision, 95.21% recall, and an 86.88% F1 score, while reducing LLM submissions from 876 to 57 (93.49%). These results demonstrate its effectiveness in improving crash attribution and efficiency for LLM-assisted fuzzing of third-party open-source libraries in connected vehicles.

## Introduction

Intelligent connected vehicle (ICV) systems increasingly depend on third-party open-source libraries [ref1, ref2, ref3, ref4, ref32], causing ICV software to inherit security risks from these libraries. To expose crash-inducing defects in such libraries, fuzz testing is widely adopted [ref16, ref17, ref7]. Yet validating diverse third-party open-source libraries at scale still requires a large number of library-specific fuzz drivers. Recent LLM-assisted fuzzing systems attempt to ease this bottleneck by using LLMs to synthesize fuzz drivers automatically [ref8, ref9, ref10, ref11, ref12].

LLM-assisted fuzzing differs from conventional component fuzzing, where the harness is usually written or reviewed by developers and is therefore treated as trusted during crash inspection. In LLM-assisted fuzzing, the generated driver is not necessarily a trusted harness. It invokes target-component APIs with mutated inputs, but it may omit required initialization, construct invalid arguments, or introduce harness-level memory errors. As a result, a crash report no longer reflects target-component behavior alone, but the interaction between the generated driver and the target component.

This difference leads to three challenges in false-alert judgment, crash localization, and efficiency. First, existing crash adjudication tends to treat crash reports as direct evidence of target-component-attributed crashes, leaving driver-induced false alerts difficult to distinguish from target-component-originated crashes. Second, existing adjudication lacks localization evidence that combines static code context and runtime context, which can lead to inaccurate crash attribution. Third, repeated crash instances triggered during fuzzing may stem from the same underlying failure pattern, but existing workflows still analyze them separately, resulting in redundant triage, localization effort, and LLM submissions.

To address this problem, we propose CrashSage, an evidence-guided crash-adjudication pipeline tailored for LLM-assisted fuzzing with untrusted generated drivers. Rather than reasoning directly over raw crash reports, CrashSage applies rule-guided crash attribution to filter low-value reports and likely driver-induced failures, uses representative selection to reduce repeated crash instances, and performs crash-context reconstruction to localize the origin and propagation of the faulty state for the selected representatives. The resulting evidence is then submitted to LLM analysis for final crash diagnosis. In this way, the LLM reasons over filtered, representative, and localized crash evidence. CrashSage is designed as a post-fuzzing triage aid that reduces the number of reports requiring detailed inspection and prepares attribution evidence for retained representative crashes. The main contributions of this paper are listed as follows.

- **CrashSage pipeline.** We propose an evidence-guided crash-adjudication pipeline for LLM-assisted fuzzing. By preparing structured crash evidence before model reasoning, CrashSage reframes the LLM from a primary classifier over raw crash text into a final analyzer over curated execution evidence.
- **Rule-guided crash attribution.** We introduce rule-guided crash attribution over sanitizer signals and stack-frame roles. This stage filters low-value reports and likely driver-induced crashes before LLM analysis, mitigating over-attribution bias in prompt-based methods and improving false-alert judgment.
- **Representative selection.** We compare exact and stack signatures to identify repeated crash instances and retain representative crashes for subsequent LLM analysis. This selection process reduces redundant analysis while preserving the relationship between each repeated crash and its representative.
- **Crash-context reconstruction.** We reconstruct static code context and runtime context for representative crashes to trace a crash across driver and component code. By combining source locations with execution-state evidence, this stage supports crash attribution by distinguishing the visible crash site from the origin of the faulty state.
- **Experimental evaluation.** We evaluate CrashSage using 1021 crash reports collected from 12 third-party open-source libraries, with 876 used in the main evaluation. Compared with the baseline, the full pipeline achieves 79.89% precision, 95.21% recall, and an 86.88% F1 score, while reducing end-to-end LLM submissions from 876 to 57 (93.49%). Runtime context reconstruction and LLM analysis are the main sources of latency, while rule-guided crash attribution and representative selection each require less than 10 ms per report.

> **【修改框 Q｜论文定位与车联网关联口径】**
>
> **建议标题：** `Evidence-Guided Crash Adjudication for LLM-assisted Fuzzing of Third-party Open-source Libraries`
>
> **修改后的内容：**
>
> "CrashSage is a general method for crash adjudication in LLM-assisted fuzzing of third-party C/C++ libraries. Connected-vehicle software is an application scenario rather than a separate algorithmic assumption. We focus on the third-party-library layer because these libraries mediate networking, diagnostic logging, transport, parsing, compression, and media processing across in-vehicle modules. Defects in this layer can make diagnostic evidence unavailable, interrupt communication-dependent services, or propagate incorrect data through vehicle software."
>
> "The evaluation includes both general-purpose libraries and automotive-oriented components, but it does not reproduce a complete vehicle software stack. Real-time scheduling, bus-level interference, vehicle-wide authentication, and ISO 26262 certification are outside the scope of this work. Accordingly, the results characterize crash-adjudication performance for third-party components used in connected-vehicle software and do not establish automotive-grade assurance."
>
> **对应审稿意见：** R1.8、R2.1（明确车联网是应用场景，并说明实验边界）。

The rest of the paper is organized as follows. Section [ref:sec:related-work] reviews related work. Section [ref:sec:preliminaries] introduces the LLM-assisted fuzzing framework and its crash-adjudication challenges. Section [ref:sec:approach] presents the design of CrashSage, Section [ref:sec:evaluation] reports the evaluation, and Section [ref:sec:conclusion] concludes the paper.

## Related Work

### LLM-Assisted Fuzzing

Fuzz testing remains a standard way to expose memory-safety defects in C/C++ software, especially with sanitizer support and continuous fuzzing infrastructure [ref16, ref17, ref18, ref19, ref7]. In conventional component fuzzing, the driver is usually written or reviewed by developers, so downstream analysis can treat it as part of the trusted harness. However, writing such drivers for diverse libraries and APIs requires substantial manual effort, which limits the scalability of component-level fuzzing.

Recent LLM-assisted fuzzing systems address this scalability problem by using models to infer protocol knowledge, generate inputs, synthesize fuzz drivers, and repair compilation errors. ChatAFL [ref8] guides stateful protocol fuzzing with LLM-derived knowledge; FuzzGPT [ref9] and TitanFuzz [ref10] use LLMs for edge-case or test-input generation; Fuzz4All [ref11] generalizes LLM-based input generation across languages; PromptFuzz [ref13] studies prompt strategies for C/C++ fuzz-driver generation; and CKGFuzzer [ref12] combines code-knowledge-graph construction with LLM-based driver generation and repair. Surveys of LLM-assisted testing likewise emphasize test generation, input synthesis, and repair [ref27]. These systems lower driver-construction cost, but their main optimization target remains the upstream fuzzing workflow. Once a generated driver compiles and produces crashes, crash reports are usually treated as fuzzing outcomes rather than as evidence that must be adjudicated under an untrusted-harness assumption. As a result, existing LLM-assisted fuzzing work does not directly address whether a crash report reflects a driver-induced false alert or a target-component-originated crash.

### Automated Crash Diagnosis and Reasoning

Given the post-fuzzing analysis gap left by LLM-assisted fuzzing, a natural question is whether existing crash diagnosis techniques can resolve the resulting crash reports. Early automated diagnosis methods relied on stack-trace signatures and heuristic rules for clustering, localization, and duplicate detection. Igor [ref21] clusters fuzz crashes by root cause; FuzzerAid [ref22] groups crashes using learned fault signatures; CrashLocator [ref23] localizes crashing faults from crash stacks; FaST [ref24] aligns stack traces efficiently; and ReBucket [ref25] clusters duplicate crash reports using call-stack similarity. Related methods enrich crash reports with source, execution, or explanation-oriented evidence: DeepAnalyze [ref14] localizes crashing faults at scale, CrashTranslator [ref15] reconstructs executable scenarios from stack traces, and Better Debugging [ref20] combines static analysis with LLMs for explainable crash localization.

These techniques provide useful clustering and localization support, but they are most effective when crash evidence is stable and the harness is trusted. This assumption weakens under LLM-generated fuzz drivers. Analyses that do not explicitly localize the failure across driver and component code can mistake a component-visible crash site for a component-originated failure. Localization-oriented methods alleviate part of this ambiguity by recovering static code context, but existing execution enrichment is not designed to bind replay-consistent runtime context to driver/component attribution. Consequently, it may not reveal the runtime values, pointer states, or object states that determine whether the failure originates from driver-side construction or target-component behavior. Likewise, crash clustering can group repeated reports, but it does not by itself decide which representative should receive expensive LLM analysis or how duplicate reports should inherit the representative diagnosis.

LLM-based vulnerability reasoning appears to offer richer semantic judgment for this setting. CVE-LLM enriches vulnerability evaluation with cybersecurity ontologies [ref28], while AutoCVSS studies prompting, few-shot examples, and retrieval-augmented generation for CVSS prediction [ref29]. However, these systems typically reason over curated vulnerability descriptions or structured security context, whereas LLM-assisted fuzzing often yields short crash reports from automatically generated drivers. Direct prompting over such reports lacks the structured semantics assumed by vulnerability-reasoning systems and can amplify over-attribution.

Overall, existing work leaves three gaps for LLM-assisted fuzzing crash adjudication. It does not reliably support false-alert judgment when sanitizer evidence mixes driver behavior with target-component behavior. It lacks attribution-oriented localization that combines static code context and runtime context, making it difficult to determine whether a failure propagates from the generated driver or originates within the target component. It also leaves efficiency concerns when repeated crash instances caused by the same underlying failure pattern are analyzed through separate LLM submissions. This motivates a pipeline that combines rule-guided crash attribution, representative selection, crash-context reconstruction, and LLM-based semantic reasoning before final crash diagnosis.

## LLM-Assisted Fuzzing Framework and Challenges

### Threat Model

We consider a non-adversarial LLM-assisted fuzzing pipeline. The generated driver is untrusted in correctness but is not treated as malicious. It may omit required initialization, construct invalid arguments, violate API contracts, or introduce harness-level memory errors because of limited program understanding or stochastic generation. We assume that the fuzzer, sanitizer, crash artifacts, driver source, and target source are not deliberately modified.

The objectives of CrashSage are to separate target-component failures from driver-induced failures and to prepare auditable evidence for subsequent LLM analysis. A crash report is treated as evidence whose origin must be established, rather than as proof that the target component is faulty. Malicious drivers that intentionally forge sanitizer evidence, conceal their provenance, or evade adjudication are outside the scope of this work. Addressing such drivers requires separate isolation, provenance, and trusted-execution mechanisms.

### LLM-Assisted Fuzzing Framework

Figure [ref:fig:fig1] illustrates the overall workflow of the LLM-assisted fuzzing framework considered in this work. The framework automates the process from modeling component APIs to generating fuzz drivers and collecting crash reports, and consists of three stages: API knowledge modeling, driver generation, and crash-oriented fuzzing [ref12].

**API knowledge modeling.** This stage first extracts the APIs to be tested from open-source components. Static feature extraction then collects key information about the target APIs and identifies their relationships. The extracted information is organized into an API knowledge graph, which provides structured API knowledge for subsequent combination planning and driver generation [ref12].

**Driver generation.** The combination agent summarizes the target APIs and uses the API knowledge graph to plan API combinations. Each planned combination, together with the corresponding API source code and summaries, is provided to the driver generation agent, which synthesizes a fuzz driver that invokes the selected APIs [ref8, ref12, ref13].

**Crash-oriented fuzzing.** For each generated driver, the seed-generation agent produces initial seeds. The fuzzing engine iteratively mutates these seeds and executes the driver in an attempt to trigger crashes. When a crash occurs, the sanitizer records the failure and exports the corresponding crash report for subsequent crash adjudication [ref16, ref17, ref18, ref19].

**Figure:** Overview of the LLM-assisted fuzzing framework. (`fig:fig1`)

![Overview of the LLM-assisted fuzzing framework.](figures/fig1.pdf)

### Challenges Statement

Unlike conventional fuzzing, LLM-assisted fuzzing cannot assume that the generated driver is a trusted harness [ref12, ref13]. A reported crash may result from the target component, the generated driver, or their interaction under a mutated input. Consequently, the crash report alone may not provide sufficient evidence for reliable post-fuzzing analysis. This setting raises three challenges: false-alert judgment, crash localization, and efficiency.

**False-alert judgment.** An LLM-generated driver may violate implicit API contracts by omitting required initialization, constructing inconsistent object states, or passing invalid argument combinations. Such misuse can trigger a failure while execution is inside the target component, causing the sanitizer stack trace to contain component frames even when the underlying fault originates from the driver. The presence of a component frame therefore does not by itself establish target-component attribution. Distinguishing driver-induced failures from target-component-originated crashes is difficult because a raw report records where the failure becomes observable, but does not explicitly identify which side violated the required execution contract.

**Efficiency.** LLM-assisted fuzzing repeatedly mutates related inputs, so many crashing inputs may exercise the same underlying failure pattern. Different generated drivers may also reach that failure pattern through distinct API combinations or call paths. These executions can produce reports that differ in addresses, stack depth, or intermediate frames despite sharing one root cause [ref21, ref22, ref25]. Treating every report as an independent case leads to repeated inspection and redundant LLM submissions, making crash adjudication increasingly expensive as the number of generated drivers and crashing inputs grows.

**Crash localization.** Existing prompt-based analysis commonly reasons over raw crash reports without explicitly localizing the failure across the generated driver and the target component. Because a driver-constructed invalid state may become observable only after entering component code, the visible crash frame can be mistaken for evidence that the open-source supply-chain component caused the failure. Localization information is therefore necessary not only to identify a suspicious statement, but also to determine where the faulty state originates and how it reaches the crash site [ref14, ref15, ref20, ref23]. However, existing localization evidence is dominated by static code context, while runtime context is not systematically incorporated into driver/component attribution. Static code context cannot expose the concrete values, pointer states, or object states involved in the failing execution, leaving the propagation of the faulty state incomplete and crash attribution uncertain.

## Approach

### CrashSage Design Overview

In this section, we present the system design of CrashSage, an evidence-guided crash-adjudication framework for LLM-assisted fuzzing. CrashSage is designed to improve post-fuzzing crash adjudication when automatically generated fuzz drivers cannot be treated as trusted harnesses. Its primary objective is to prepare structured evidence that supports attribution-oriented localization, remove repeated crash instances, and retain auditable inputs before final LLM reasoning. Through this pipeline, CrashSage supports false-alert judgment, crash localization, and efficient analysis of repeatedly triggered crashes.

Figure [ref:fig:three-mechanism-design] illustrates the workflow of CrashSage and aligns the three challenges with the corresponding processing stages. Initially, *rule-guided crash attribution* addresses false-alert judgment by distinguishing noise and likely driver-induced crashes from cases that require further target-component analysis. It normalizes crash reports and applies rule-based preliminary screening over sanitizer signals and stack-frame roles, producing filtered normalized crash reports for the following stages. Next, *representative selection* addresses efficiency by avoiding repeated analysis of crashes that follow the same underlying failure pattern. It constructs exact and stack signatures from the normalized sanitizer evidence, verifies signature matches, maps repeated crashes to an existing representative, and retains unmatched crashes in the selected crash set. CrashSage then performs *crash-context reconstruction* to enrich these selected representatives with static code context and replay-consistent runtime context, helping determine where an invalid state originates and how it propagates to the visible crash site. Finally, *LLM analysis* completes the semantic diagnosis by combining each representative crash's normalized crash report, triage label, and reconstructed context to determine its type, cause, location, triggering condition, and severity.

**Figure:** Multi-stage crash-adjudication pipeline combining rule-guided crash attribution, representative selection, crash-context reconstruction, and LLM analysis. (`fig:three-mechanism-design`)

![Multi-stage crash-adjudication pipeline combining rule-guided crash attribution, representative selection, crash-context reconstruction, and LLM analysis.](figures/fig2.pdf)

### Rule-Guided Crash Attribution

Rule-guided crash attribution is the first stage of CrashSage and addresses the false-alert judgment challenge.
It consists of sanitizer evidence normalization and rule-based preliminary screening.
The former converts raw sanitizer output into a normalized crash report, while the latter assigns a triage label that determines whether the crash is filtered.

#### Sanitizer Evidence Normalization

Crash reports contain substantial redundant information that is not directly useful for subsequent crash adjudication.
CrashSage normalizes each raw crash report into a normalized crash report that retains the information required by subsequent stages.
Table [ref:tab:sanitizer-normalized-fields] summarizes the normalized field groups.

- **Failure identity** describes the crash report type and its failure category.
- **Crash-site metadata** records the immediate low-level crash information, such as the failing address or access behavior, when it is available.
- **Severity and dedup cues** provide sanitizer- or fuzzer-generated hints that help prioritize and compare crash reports.
- **Structured stack trace** converts the raw call stack into ordered frames for later role modeling.
- **Project anchor** identifies the first visible connection between the crash trace and the target-component source code.
- **Reproduction and status hints** preserve crash-input clues and special execution states that may affect filtering or replay.

**Table: Key field groups in the normalized crash report** (`tab:sanitizer-normalized-fields`)

| **Field Group** | **Representative Extracted Fields** |
|---|---|
| Failure identity | `sanitizer_type`, `bug_type`, `summary` |
| Crash-site metadata | `crash_address`, `pc`, `access_type` |
| Severity and dedup cues | `scariness_score`, `scariness_desc`, `dedup_token` |
| Structured stack trace | ordered `frames` with function, file, line, and address |
| Project anchor | `first_in_project_frame`, `first_in_project_function` |
| Reproduction and status hints | `artifact_path_hint`, `base_unit_hash`, special-condition flags |

#### Rule-Based Preliminary Screening

Screening begins by matching the function name, file path, and position of each frame in the `structured stack trace` against predefined project, driver, and runtime patterns.
Frames without sufficient matching evidence remain *unclassified*.

**Table: Stack-frame role classification used by CrashSage** (`tab:stack-frame-roles`)

| **Role** | **Meaning** |
|---|---|
| project | Stack frames in the target-component source code. |
| driver | Stack frames related to the fuzz driver. |
| runtime | Runtime-library frames, including libFuzzer, sanitizers, LLVM runtime, libc, etc. |
| unclassified | Frames that cannot be classified reliably but are not obvious runtime frames. |

Table [ref:tab:stack-frame-roles] summarizes these roles. Frame ownership alone is not sufficient for false-alert judgment.
A crash trace can involve target-component frames, generated-driver frames, and runtime frames at the same time, while the frame where the sanitizer reports the failure may not be the frame that best explains the origin of the crash.
CrashSage therefore applies a set of deterministic rules over the ownership and position of stack frames to infer whether the crash is more consistent with noise, a driver-induced failure, or a target-component crash.

Before listing the rules, we define the following notations.
Let \(S=\langle f_1,\ldots,f_n\rangle\) denote the structured stack trace, ordered from the top crashing frame to lower caller frames.
Let \(F_P\), \(F_D\), and \(F_N\) denote the sets of project frames, driver frames, and non-runtime frames, respectively, where \(F_N=F_P\cup F_D\cup F_U\) and \(F_U\) is the set of unclassified frames.
CrashSage computes the driver-frame ratio

$$R_D=\frac{|F_D|}{\max(|F_N|,1)} ,$$

corresponding to `Driver_Frame_Ratio`.
Runtime frames are excluded from this ratio because they mainly reflect sanitizer and libFuzzer control flow.
Let \(h_D\) denote the top-stack depth inspected for driver evidence, \(\theta_D\) the driver-frame-ratio threshold, \(m_P\) the maximum number of project frames treated as shallow project involvement, and \(\theta_S\) the sanitizer-severity threshold.

CrashSage sets these parameters through an evidence-boundary design strategy that maps each value to an interpretable stack or sanitizer signal.
The parameter \(h_D\) defines the near-crash stack region used for driver-evidence inspection, \(\theta_D\) defines the driver-dominance level in the attribution-relevant non-runtime stack, \(m_P\) defines the amount of project-code involvement treated as shallow API-boundary execution, and \(\theta_S\) defines the sanitizer-severity level used to retain project-frame SEGV/null-dereference reports.

For \(h_D\), CrashSage sets \(h_D=3\) because a three-frame window corresponds to the crash frame, the direct caller, and the caller that usually reflects the immediate driver-side invocation context.
This value keeps the check centered on the local failure path where argument construction, API invocation, and first observable faulty use are most directly represented.
For \(\theta_D\), CrashSage sets \(\theta_D=0.8\), using a four-fifths majority as the driver-dominance criterion over non-runtime frames.
This value requires driver evidence to occupy a clearly dominant share of the attribution-relevant stack before assigning `likely_driver_bug`, making the label depend on stack-level concentration rather than an isolated driver frame.
For \(m_P\), CrashSage sets \(m_P=2\) because shallow API-boundary execution often includes the target entry function and one adjacent helper, initialization, creation, setup, or parsing frame.
This value captures brief project-code contact during driver-constructed calls while distinguishing it from deeper target-component execution paths.
For \(\theta_S\), CrashSage sets \(\theta_S=10\) as the high-severity sanitizer threshold for SEGV/null-dereference reports.
This value retains reports when the sanitizer signal indicates severe invalid memory access and the stack simultaneously provides project-frame evidence for target-component analysis.

These values are fixed before evaluating the crash reports, providing a stable and reproducible configuration for the rule-guided attribution stage. The remaining rule signals also come from the normalized crash report.
Timeout, `ALARM`, out-of-memory, LSan-only, and deadly-signal flags are extracted from sanitizer or libFuzzer status lines, while `SCARINESS` comes from the sanitizer severity line.
Table [ref:tab:triage-rule-groups] summarizes the 13 deterministic rules, their predicates, and their preliminary output labels.
These labels express the direction supported by the available evidence rather than a final vulnerability verdict.

**Table: Rules used for crash attribution** (`tab:triage-rule-groups`)

| **Group** | **Rule** | **Deterministic Predicate** | **Output Label** |
|---|---|---|---|
| NF | R1 | \(F_N=\emptyset \land `deadly_signal`\) | `noise` |
| NF | R2 | Timeout or `ALARM` marker appears | `noise` |
| NF | R3 | Out-of-memory marker appears | `noise` |
| NF | R4 | LSan-only report without crashing execution | `noise` |
| DQ | R5 | \(`use_of_uninitialized_value`\) with a driver frame in the top-\(h_D\) stack frames | `likely_driver_bug` |
| DQ | R6 | \(R_D\ge \theta_D\) | `likely_driver_bug` |
| DQ | R7 | Project init/option/parse function appears near the driver boundary | `likely_driver_bug` |
| DQ | R8 | \(`stack_buffer_overflow`\) with the first non-runtime frame in driver code | `likely_driver_bug` |
| DQ | R9 | \(F_N=F_D \land F_P=\emptyset\) | `likely_driver_bug` |
| DQ | R10 | \(\|F_P\|\le m_P\) and project function matches init/create patterns | `likely_driver_bug` |
| TC | R11 | Memory-safety crash with at least one project frame | `target_crash` |
| TC | R12 | SEGV/null-dereference with \(`SCARINESS`\ge \theta_S\) and project frame evidence | `target_crash` |
| LE | R13 | Assertion, abort, or `ABRT` originates in project code | `needs_review` |

- **R1.** A `deadly_signal` marker confirms abnormal termination, but the absence of non-runtime frames leaves no project or driver location for attribution. The report is therefore labeled `noise` because it provides no inspectable evidence for the subsequent analysis.
- **R2.** Timeout and `ALARM` markers indicate that execution exceeded its time limit, without providing sanitizer evidence for a memory-access crash. Such reports are labeled `noise` because they do not provide crash evidence for component attribution.
- **R3.** An out-of-memory marker records resource exhaustion, which may depend on allocation demand or execution limits and does not identify a specific faulty access. The rule therefore assigns `noise` rather than attributing the condition to either the driver or the target component.
- **R4.** An LSan-only report identifies unreleased allocations at process exit but contains no crashing instruction, signal, or abort. Because the rule-guided stage concerns the origin of crashes, this report is labeled `noise`.
- **R5.** An uninitialized-value report indicates that data was consumed before receiving a valid value. When driver frames occur within the top \(h_D\) frames, the first observable use is close to driver-side execution, so the available evidence supports `likely_driver_bug`.
- **R6.** After runtime frames are removed, \(R_D\ge \theta_D\) means that driver frames account for the specified dominant share of the attribution-relevant stack. Because the observable crash path is concentrated in the generated harness, the rule assigns `likely_driver_bug`.
- **R7.** Initialization, option-processing, and parsing functions near the driver boundary are commonly reached while the generated driver constructs objects and prepares API arguments. When project involvement remains at this boundary, the evidence favors invalid driver-side setup over target-component-originated execution, leading to `likely_driver_bug`.
- **R8.** For a stack-buffer overflow, the first non-runtime frame identifies the function whose active stack object exceeds its boundary. If this frame belongs to the driver, the overflowing object is localized to driver-side execution, so the rule assigns `likely_driver_bug`.
- **R9.** If every non-runtime frame belongs to the driver and no project frame is present, the trace contains no observable evidence that execution reached target-component code. The crash is therefore labeled `likely_driver_bug`.
- **R10.** At most \(m_P\) project frames limited to initialization or creation functions indicate shallow component involvement during API setup rather than an internal target execution path. This pattern is treated as `likely_driver_bug` because the evidence primarily reflects how the generated driver configured the call.
- **R11.** A sanitizer-reported memory-safety crash with at least one project frame establishes that the erroneous execution reached target-component code. The rule labels it `target_crash` so that it is retained as a target-component candidate for subsequent stages, rather than making the final attribution decision in the rule-guided stage.
- **R12.** A severe SEGV or null dereference indicates an invalid memory access, while the presence of project frames anchors that access in target-component execution. Their combination supports the preliminary label `target_crash` and retains the crash for localization.
- **R13.** A project-origin assertion, abort, or `ABRT` identifies the component location that terminates execution, but the report alone cannot distinguish a driver violation of an API precondition from a violated internal invariant. The rule therefore assigns `needs_review` rather than attributing the crash to either side.

Because the rules are evaluated independently, CrashSage resolves their evidence items in the order `noise`, `likely_driver_bug`, `target_crash`, and `needs_review`.
The first matched label in this order becomes the triage label; if no rule matches, the crash is assigned `needs_review` by default.
This procedure removes reports without usable crash evidence and generated-driver crashes before retaining target-component candidates and ambiguous cases for further analysis.

Crashes labeled `noise` or `likely_driver_bug` are filtered, whereas those labeled `target_crash` or `needs_review` are kept as retained normalized crash reports for representative selection.
For a crash \(c\), let \(\mathcal{N}(c)\) denote its normalized crash report and \(y(c)\) denote its triage label.
The output of rule-guided crash attribution is the pair \(\langle\mathcal{N}(c),y(c)\rangle\), which serves as the input to the subsequent stage.

### Representative Selection

Large-scale fuzzing often produces many crash instances that differ in inputs or generated drivers but follow the same underlying failure pattern.
Representative selection reduces this repeated analysis cost by comparing exact and stack signatures and forwarding only non-duplicate representatives to the later LLM stage.

Let \(\mathcal{C}={c_1,\ldots,c_n}\) denote the set of crashes retained after rule-guided crash attribution.
For each crash \(c\), let \(S_c\) denote its structured stack trace following the definition of \(S\) in Section [ref:subsec:rule-guided-attribution], and let \(d(c)\) denote the sanitizer deduplication token.
Let \(b(c)\) denote the sanitizer bug type extracted from \(\mathcal{N}(c)\), and let \(\ell(c)\) denote the crash-site source location derived from the crash-site metadata or resolved frame location when available.
Let \(\bot\) denote an unavailable value.
The sequence \(s(c)\) is the ordered non-runtime key-frame subsequence derived from \(S_c\).
Runtime frames are excluded from \(s(c)\) because they usually describe sanitizer, libFuzzer, or libc control flow rather than the project-driver execution path.

**Exact signature.** The exact signature targets crashes with the same sanitizer-provided identity or the same resolved crash site.
CrashSage computes

$$\sigma_{\mathrm{exact}}(c)=

H(d(c)), & d(c)\neq \bot,\\
H\bigl(b(c),\ell(c),\mathrm{top}(s(c))\bigr), & d(c)=\bot \land \ell(c)\neq \bot \land |s(c)|>0,\\
\bot, & \text{otherwise},
$$

where \(H(\cdot)\) is a stable hash function and \(\mathrm{top}(s(c))\) denotes the first frame in the non-runtime key-frame sequence.
The exact-signature match between two crashes is defined as

$$M_{\mathrm{exact}}(c_i,c_j)=
\mathbb{I}\bigl[
\sigma_{\mathrm{exact}}(c_i)\neq \bot
\land \sigma_{\mathrm{exact}}(c_i)=\sigma_{\mathrm{exact}}(c_j)
\bigr].$$

Here, \(M_{\mathrm{exact}}(c_i,c_j)=1\) represents the strongest duplicate match.
The condition holds either because both crashes expose the same sanitizer deduplication token \(d(c)\), or because the normalized fields \(b(c)\), \(\ell(c)\), and \(\mathrm{top}(s(c))\) agree.
In the latter case, the two reports have the same sanitizer crash class, the same localized crash-site anchor such as file, line, and function, and the same first project/driver frame after runtime frames are removed.

```text
\caption{Representative Selection}
\label{alg:representative-selection}

\Require retained crashes \(\mathcal{C}=\langle c_1,\ldots,c_n\rangle\) in discovery order
\Ensure selected crash set \(\mathcal{R}\) and duplicate mapping \(\mathcal{L}\)
\(\mathcal{R}\gets\varnothing\), \(\mathcal{L}\gets\varnothing\)
\For{\(c_i\in\mathcal{C}\)}
    \(r^\ast\gets\bot\)
    \For{\(r\in\mathcal{R}\)}
        \If{\(M(c_i,r)=1\)}
            \(r^\ast\gets r\)
            \textbf{break}
        \EndIf
    \EndFor
    \If{\(r^\ast\neq\bot\)}
        \(\mathcal{L}\gets\mathcal{L}\cup\{(c_i,r^\ast)\}\)
    \Else
        \(\mathcal{R}\gets\mathcal{R}\cup\{c_i\}\)
    \EndIf
\EndFor
\Return \((\mathcal{R},\mathcal{L})\)
```

**Stack signature.** The stack signature targets crashes whose crash-site anchors differ but whose project-driver call paths are identical.
Let \(p_k(c)\) denote the ordered sequence obtained by taking the first \(\min(k,|s(c)|)\) frames from \(s(c)\), preserving the original stack order from the top crashing frame to lower caller frames.
Here, \(k\) is a fixed prefix length used consistently for all crashes.
CrashSage builds a stack signature from this bounded prefix:

$$\sigma_{\mathrm{stack}}(c)=H\bigl(b(c),p_k(c)\bigr).$$

The bug type is kept in the signature to avoid treating different sanitizer crash classes that happen to pass through similar functions as duplicates.
The bounded prefix of the non-runtime stack captures the driver-to-project execution path that reaches the crash.
The stack-signature match is defined as

$$M_{\mathrm{stack}}(c_i,c_j)=
\mathbb{I}\bigl[
\sigma_{\mathrm{stack}}(c_i)=\sigma_{\mathrm{stack}}(c_j)
\bigr].$$

Here, \(M_{\mathrm{stack}}(c_i,c_j)=1\) represents a duplicate match based on the retained call path rather than on an identical crash-site anchor.
The equality of \(\sigma_{\mathrm{stack}}\) requires the same \(b(c)\) and the same bounded prefix \(p_k(c)\), where \(p_k(c)\) is built from the ordered non-runtime frames in \(s(c)\).
Thus, the two crashes are treated as duplicates when their normalized stack evidence shows the same sanitizer crash class and the same leading project/driver frame sequence, even if the reported line number, resolved crash location, or exact sanitizer token is unavailable or slightly different.

CrashSage evaluates the two match predicates in the order of exact and stack matching, which corresponds to signature verification in Figure [ref:fig:three-mechanism-design].
For a pair of crashes, stack matching is evaluated only when exact matching does not produce a match.
The resulting duplicate decision is

$$M(c_i,c_j)=
M_{\mathrm{exact}}(c_i,c_j)
\lor M_{\mathrm{stack}}(c_i,c_j).$$

CrashSage processes the retained crashes in discovery order and compares each crash with the representatives selected so far.
A matched crash is linked to the corresponding representative, whereas an unmatched crash becomes a new representative.
Algorithm [ref:alg:representative-selection] summarizes this procedure.

The primary output of representative selection is the selected crash set \(\mathcal{R}\).
The accompanying mapping \(\mathcal{L}\) records each duplicate--representative pair \((c_i,r)\), indicating that \(c_i\) matches and reuses the analysis result of representative \(r\).

> **【修改框 I｜签名匹配与代表误判传播口径】**
>
> **怎么改：** 在 Representative Selection 小节末尾补充一段说明，把代表选择写成“报告到代表的确定性签名匹配”，不要暗示它是等价类或会计算传递闭包。结果分析中明确只有代表预测被传播，每条报告保留自己的真值，并用现有冻结映射和 V4 结果完成代表预测翻转分析。回复信单独解释传递性，正文不展开 A、B、C 的传递关系。
>
> **修改后的内容：**
>
> "Exact and stack signatures are deterministic matching keys. For each report, CrashSage compares its keys with those of existing representatives and assigns the report to the first matching representative. If no key matches, the report becomes a new representative. No transitive closure is applied, and each report is mapped to at most one representative."
>
> **结果文件：** 去重映射为 `/home/cc/CKGFuzzer-1/fuzzing_llm_engine/results/dedup_schema2_14projects_20261027/dedup_mapping_14projects.csv`；组级审计为 `/home/cc/CKGFuzzer-1/fuzzing_llm_engine/results/review_gap_completion_20261101/current_dedup_audit/dedup_group_audit.csv`；逐代表翻转结果为 `/home/cc/CKGFuzzer-1/fuzzing_llm_engine/results/review_gap_completion_20261101/current_dedup_audit/dedup_flip_sensitivity.csv`；汇总为 `/home/cc/CKGFuzzer-1/fuzzing_llm_engine/results/review_gap_completion_20261101/current_dedup_audit/dedup_audit_summary.json`。
>
> **回复信口径：**
>
> "We agree that 'equivalence class' was inaccurate. CrashSage does not construct equivalence classes or apply a transitive closure: a report is mapped directly to the first representative with a matching exact or stack signature, or becomes a new representative itself. Therefore, matching between A and B and between B and C does not imply that A and C belong to the same representative. We have clarified this construction in Section 4.3."
>
> "We also corrected the evaluation statement: only representative predictions are propagated, while every report retains its own ground-truth label. We further flip each representative prediction individually and recompute the report-level metrics. The maximum absolute F1 change is 0.0174, confirming that the observed propagation risk is localized. The complete analysis is reported in Section 5.3."
>
> **对应审稿意见：** R1.3（signature matching、transitivity 与代表误判传播）；R1.9（重复报告与根因级去重一致性的分析口径）。

### Crash-Context Reconstruction

After representative selection, the selected crash representatives still require relevant localization evidence to refine the attribution.
A component frame identifies where a failure becomes visible, but it does not establish whether the faulty state originates in the generated driver or the target component.
Crash-context reconstruction addresses this gap through static code context reconstruction and runtime context reconstruction.
Static code context reconstruction maps the driver-to-component call path to source code, while runtime context reconstruction recovers the execution state needed to explain how the failure propagates along that path.
Together, they turn an isolated sanitizer crash label into attribution-oriented execution evidence for LLM adjudication of the selected representatives.

#### Static Code Context Reconstruction

Static code context reconstruction localizes selected project and driver frames in a representative crash report to source files and extracts the surrounding source-code context.
CrashSage first maps each selected frame to a local file, function, and line number using the reported source coordinates.
Based on these locations, it extracts bounded code windows around the crash-site frame and relevant call-chain frames, preserving the local statements before and after each key frame.
These code windows provide source-level evidence for inspecting the crashing operation and tracing how the fuzz input moves from the generated driver into the target API and toward the crash site.
However, static code context alone cannot determine the concrete values and object states present in the failing execution.

#### Runtime Context Reconstruction

Runtime context reconstruction complements static code context reconstruction by recovering execution-state evidence that static code alone cannot provide, including variable values, pointer states, and memory-related conditions at the crash point.
This evidence helps determine whether an invalid state is constructed by the driver and propagated into component code or produced within the component itself.
CrashSage uses `artifact_path_hint` or `base_unit_hash` in the normalized crash report to locate the triggering seed and stage an isolated copy for replay.

Replaying the seed is necessary to observe the execution state at the crash point.
However, environmental differences, timing-dependent behavior, uninitialized state, or external resources may cause the same seed to produce a different crash.
CrashSage therefore parses the replayed crash report into a replay-produced normalized crash record and verifies its consistency before collecting runtime context.
To bind the replay result to the representative crash, CrashSage builds a replay key

$$\kappa(c)=\langle b(c), \ell(c), s(c) \rangle ,$$

where \(b(c)\) corresponds to the `bug_type` field of crash report \(c\), \(\ell(c)\) denotes the crash-site source location derived from the crash-site metadata or resolved frame location when available, and \(s(c)\) denotes the ordered non-runtime key-frame sequence derived from the structured stack trace \(S\).
Let \(c_0\) denote the original normalized crash report and \(c_r\) denote the replay-produced crash record.
CrashSage regards their replay keys as compatible, denoted by \(\kappa(c_r)\simeq\kappa(c_0)\), when

$$b(c_r)=b(c_0) \land s(c_r)=s(c_0) \land
\bigl(\ell(c_0)=\bot \lor \ell(c_r)=\ell(c_0)\bigr),$$

where \(\bot\) denotes an unavailable value in the corresponding field.
Only a replay satisfying this condition is treated as consistent with the representative crash and used for runtime inspection.

For a replay-consistent crash, CrashSage invokes GDB as the runtime inspection tool.
The bounded GDB run records the reproduced backtrace and crash frame, together with selected registers, function arguments, and local variables from the frames nearest to the crash site.
These fields can help reveal state that static code context cannot provide, such as whether a pointer is null, whether a size variable is inconsistent with a buffer, or whether an object has an invalid state before the crashing operation. Algorithm [ref:alg:runtime-context] summarizes this reproduction-gated runtime context reconstruction procedure. The detailed organization of the evidence produced by crash-context reconstruction is presented in Table [ref:tab:reconstruction-output-fields].

\textsc{LocateSeed}, \textsc{StageSeed}, \textsc{ReplayAndParse}, and \textsc{CollectDebugContext} correspond to seed recovery, isolated replay preparation, replay-output parsing, and GDB-based bounded runtime-state collection, respectively.
For each representative crash \(c\in\mathcal{R}\), the output \(C_{\mathrm{recon}}(c)\) contains static code context, optional runtime context, and a status \(\rho\) indicating the outcome of seed recovery, replay matching, and GDB collection.
If runtime evidence is unavailable, \(C_{\mathrm{runtime}}=\bot\), and the static context remains available to subsequent stages.

For each representative crash \(c\in\mathcal{R}\), crash-context reconstruction outputs \(C_{\mathrm{recon}}(c)\). After this stage, the evidence package consumed by the final LLM analysis is defined as

$$\mathbf{x}(c)=
\left\langle
\mathcal{N}(c),\,y(c),\,C_{\mathrm{recon}}(c)
\right\rangle .$$

This package combines the normalized crash report and triage label from rule-guided attribution with the reconstructed context produced in this stage.

```text
\caption{Runtime Context Reconstruction}
\label{alg:runtime-context}

\Require normalized crash report \(c_0\), static code context \(C_{\mathrm{static}}\), fuzz target binary \(B\), corpus or artifact directory \(D\)
\Ensure reconstructed context \(C_{\mathrm{recon}}(c_0)=(C_{\mathrm{static}}, C_{\mathrm{runtime}}, \rho)\)
\(u \gets \Call{LocateSeed}{c_0.\texttt{artifact\_path\_hint}, c_0.\texttt{base\_unit\_hash}, D}\)
\If{\(u\) is unavailable}
    \Return \((C_{\mathrm{static}}, \bot, \textsc{SeedUnavailable})\)
\EndIf
\(u_s \gets \Call{StageSeed}{u}\)
\(c_r \gets \Call{ReplayAndParse}{u_s, B}\)
\If{\(c_r\) is unavailable}
    \Return \((C_{\mathrm{static}}, \bot, \textsc{ReplayFailed})\)
\EndIf
\If{\(\kappa(c_r)\not\simeq\kappa(c_0)\)}
    \Return \((C_{\mathrm{static}}, \bot, \textsc{CrashMismatch})\)
\EndIf
\(C_{\mathrm{runtime}} \gets \Call{CollectDebugContext}{u_s, B}\)
\If{\(C_{\mathrm{runtime}}\) is unavailable}
    \Return \((C_{\mathrm{static}}, \bot, \textsc{RuntimeContextUnavailable})\)
\EndIf
\(\rho \gets \textsc{RuntimeContextAvailable}\)
\Return \((C_{\mathrm{static}}, C_{\mathrm{runtime}}, \rho)\)
```

**Table: Evidence groups produced by crash-context reconstruction** (`tab:reconstruction-output-fields`)

| **Context Type** | **Evidence Group** | **Representative Fields** | **Concrete Role** |
|---|---|---|---|
| \multirow{2}{=}{Static code context | Crash-site anchor | `crash_file`, `crash_line`, `crash_function`, `crash_code_snippet` | Anchors the visible crash site without treating it as the fault origin. |
|  | Call-chain source context | `call_chain_context`, `frame_type`, `code_snippet` | Preserves bounded project/driver frame context for attribution. |
| \multirow{3}{=}{Runtime context | Seed recovery and isolation metadata | `seed_locate`, `seed_copy`, `seed_paths.seed` | Records how the triggering artifact is recovered and staged. |
|  | Replay consistency evidence | `repro.runs`, `signature`, `same_signature`, `repro_rate` | Audits whether replay matches the representative crash. |
|  | Runtime execution context | `reproduced`, `backtrace_text`, `registers`, `crash_frame`, `call_stack` | Supplies runtime state for tracing fault propagation and refining attribution. |

### LLM Analysis

Given the evidence package \(\mathbf{x}(c)\), CrashSage invokes the LLM only for representative crashes \(c\in\mathcal{R}\). The LLM produces a structured diagnosis
through schema-guided, evidence-guided prompting rather than direct classification over raw sanitizer text.

**Table: Prompt design for LLM analysis** (`tab:llm-prompt-design`)

| **Prompt Part** | **Prompt Design** |
|---|---|
| System role | Act as a crash-adjudication assistant and distinguish the visible crash site from the origin of the faulty state. |
| Attribution rule | Do not assign target-component attribution unless target-component evidence is stronger than the driver-misuse hypothesis. |
| Input evidence | Use the triage summary, matched rules, frame-role evidence, normalized sanitizer fields, static context, and runtime context. |
| Final attribution | For every representative crash, compare the target-component-defect and driver-misuse hypotheses before making the final target-component attribution. Attribute the crash to the target component only when the target-component-defect hypothesis is better supported by the supplied evidence. |
| Output schema | Return `is_api_bug`, `root_cause_type`, `root_cause_location`, `triggering_condition`, `severity`, `fix_suggestion`, and `evidence_rationale`. |
| Decoding and retry | Use `temperature=0`; parse the primary response and apply repair only when validation fails. |

Table [ref:tab:llm-prompt-design] summarizes the prompt design sent to the LLM for each representative crash. For each representative, CrashSage serializes \(\mathbf{x}(c)\) into this staged prompt.
Runtime evidence is injected when replay succeeds; otherwise, the prompt records the unavailable runtime status instead of hiding the missing evidence.

Before making the final target-component attribution, the differential prompt asks the model to compare the driver-misuse hypothesis and the target-component-defect hypothesis. The driver-misuse hypothesis considers whether the generated driver caused the observed failure. It is supported when missing required initialization, an inconsistent object state, or an invalid argument combination violates a required API precondition and explains the observed failure. In this case, the visible crash location may be inside the target component. However, the faulty state originates in the generated driver.

The target-component-defect hypothesis considers whether target-component behavior caused the faulty state. It is supported when the generated driver satisfies the relevant API preconditions and the reconstructed evidence indicates that the faulty state originates in target-component behavior. In this case, the target component both contains the visible crash location and produces the faulty state. The model makes the final target-component attribution only when the target-component-defect hypothesis is better supported by the supplied evidence. This differential framing keeps driver misuse in scope and reduces the tendency to over-attribute a component-visible crash to the target component.

The model output is required to follow a structured schema with the fields `is_api_bug`, `root_cause_type`, `root_cause_location`, `triggering_condition`, `severity`, `fix_suggestion`, and `evidence_rationale`.
These fields correspond to the following diagnosis tuple:

$$\mathbf{z}(c)=
\left\langle
a(c),\,\tau(c),\,\lambda(c),\,\gamma(c),\,\nu(c),\,\phi(c)
\right\rangle ,$$

where \(a(c)\) denotes the final target-component attribution judgment, \(\tau(c)\) denotes the root-cause type, \(\lambda(c)\) denotes the root-cause location, \(\gamma(c)\) denotes the triggering condition, \(\nu(c)\) denotes the severity, and \(\phi(c)\) denotes the repair suggestion.
The `evidence_rationale` field records the short evidence chain supporting these schema fields and remains part of the report metadata.
If validation still fails, the deterministic evidence package is preserved and the LLM diagnosis is marked incomplete.
The final structured report is defined as

$$\mathbf{r}(c)=
\left\langle
\mathbf{x}(c),\,\mathbf{z}(c)
\right\rangle .$$

This report preserves the deterministic evidence prepared by CrashSage together with the LLM-generated semantic diagnosis.

## Evaluation

To evaluate the performance of CrashSage, we defined four research questions:

- **RQ1: False-alert judgment**: How effectively does rule-guided crash attribution distinguish driver-induced crashes from confirmed-target crashes?
- **RQ2: Efficiency**: How much redundant analysis does representative selection remove, and what latency do the major pipeline operations introduce?
- **RQ3: Crash localization**: How does crash-context reconstruction improve crash attribution by distinguishing the visible crash location from the origin of the faulty state?
- **RQ4: Final analysis sensitivity**: When the evidence package and representatives are held fixed, how do the final LLM model and final prompt design affect crash attribution?

### Experimental Setup

CrashSage is implemented in Python and uses Qwen3-Coder-Plus, accessed through a cloud API, as the final LLM model. All experiments are conducted on a machine running Ubuntu 22.04 and equipped with an AMD Ryzen 5 5600G with Radeon Graphics processor. We evaluate CrashSage on 12 third-party open-source libraries relevant to connected-vehicle software functions. The selected libraries include c-ares, cJSON, expat, faad2, jansson, json-c, libmad, libmspack, libpcap, libsndfile, tinyxml2, and zlib, covering connected-vehicle software functions such as networking, structured-data parsing, packet capture, compression, media decoding, and archive processing. The evaluation focuses on the third-party-library layer of connected-vehicle software rather than on a complete vehicle software stack.

Table [ref:tab:subjects] summarizes the functions, API scales, and representative deployment roles of the evaluated libraries. We collect crash reports following the fuzz-driver generation and fuzzing workflow of CKGFuzzer [ref12]. The generated drivers are compiled and executed by libFuzzer with ASan+UBSan instrumentation in Docker containers based on the OSS-Fuzz base-runner image. The testing process produces 1021 crash reports in total, of which 876 are used in the main evaluation.

> **【修改框 A｜实验数据范围与车联网目标】**
>
> **怎么改：** 把本段及随后项目表的旧口径改成当前最终的 14 项目、1217 条报告口径；模型统一写成 `qwen3-coder-flash`。在表中加入 dlt-daemon（92 条）和 isotp-c（104 条），分别说明为车载诊断日志组件和 ISO-TP 车载传输协议组件。同步将原 145 条待复核报告的最终结果计入 ground truth，得到正例 215、负例 1002；不再保留单独的 potential 类别。
>
> **修改后的内容：**
>
> "CrashSage is implemented in Python and uses `qwen3-coder-flash`, accessed through a cloud API, as the final LLM model. We evaluate CrashSage on 14 third-party open-source libraries relevant to connected-vehicle software, including the automotive diagnostic-logging component dlt-daemon and the ISO-TP transport-protocol library isotp-c. The generated drivers are compiled and executed with ASan+UBSan under the same CKGFuzzer workflow, producing 1,217 crash reports in total. After completing the final audit of the 145 previously pending reports, the binary ground truth contains 215 target reports and 1,002 non-target reports."
>
> **结果文件：** `/home/cc/CKGFuzzer-1/docs/progress.md`；`/home/cc/CKGFuzzer-1/fuzzing_llm_engine/results/review_gap_completion_20261101/overall_metrics_current_1217.csv`
>
> **对应审稿意见：** R1.8、R2.1、R2.2（车联网关联性与状态型目标多样性）；同时用于统一最终数据口径。

**Table: Third-party open-source libraries used in the evaluation** (`tab:subjects`)

| **Library** | **Function** | **APIs** | **Crash** **Reports** | **Deployment Role** |
|---|---|---|---|---|
| c-ares | Asynchronous DNS resolution | 27 | 103 | Gateway DNS |
| cJSON | JSON parsing and generation | 60 | 78 | Config/telemetry parsing |
| expat | XML parsing | 12 | 36 | Configuration parsing |
| faad2 | AAC audio decoding | 12 | 151 | Media decoding |
| jansson | JSON parsing and generation | 12 | 128 | Config/telemetry parsing |
| json-c | JSON parsing and generation | 12 | 40 | Config/telemetry parsing |
| libmad | MPEG audio decoding | 12 | 112 | Media decoding |
| libmspack | Archive extraction | 12 | 54 | Package/archive processing |
| libpcap | Packet capture and filtering | 30 | 115 | Network monitoring |
| libsndfile | Audio file processing | 12 | 76 | Media/log processing |
| tinyxml2 | XML parsing | 13 | 63 | Configuration parsing |
| zlib | Compression and decompression | 29 | 65 | OTA/log compression |
| **Combined** | -- | **243** | **1021** | -- |

> **【修改框 O｜目标选择标准、状态型覆盖与车联网影响】**
>
> **修改后的内容：**
>
> "We select libraries that are publicly available, have a concrete role in connected-vehicle software supply chains, can be built under ASan+UBSan using the CKGFuzzer workflow, and produce reproducible crash reports. To characterize API-call diversity, a driver is counted as multi-call when it invokes at least two distinct target APIs; a lifecycle/order pattern is counted when initialization, creation, opening, allocation, or receive operations occur together with subsequent use or cleanup operations. The 14 libraries contain 186 drivers, of which 179 invoke multiple target APIs and 168 exhibit lifecycle or ordered-call patterns. The added dlt-daemon and isotp-c targets contribute 196 crash reports and exercise diagnostic filtering and ISO-TP stateful transport, respectively. These statistics characterize API-call diversity and are not presented as complete semantic state-machine coverage."
>
> **Table: Connected-vehicle roles and impact of faulty target behavior.**
>
> | Target | Connected-vehicle role | Potential impact of a target-component defect |
> |---|---|---|
> | dlt-daemon | Diagnostic logging and fault-record storage | Corrupted or terminated logging can make diagnostic evidence unavailable and impede maintenance and incident analysis. |
> | isotp-c | ISO-TP multi-frame transport between ECUs and vehicle modules | Incorrect segmentation or reassembly can interrupt message delivery and affect communication-dependent services. |

**Table: Evaluation configurations.** (`tab:evaluation-configurations`)

| **Variant** | **Rule-guided** **filtering** | **Representative** **selection** | **Reconstruction** **context** | **Final** **prompt** |
|---|---|---|---|---|
| V0 (CKGFuzzer baseline) | No | No | No | Clean direct prompt |
| V1 | Yes | No | No | Clean direct prompt |
| V2 | Yes | Yes | No | Clean direct prompt |
| V3 | Yes | Yes | Yes | Clean direct prompt |
| V4 (CrashSage) | Yes | Yes | Yes | Differential prompt |

Table [ref:tab:evaluation-configurations] summarizes the evaluated variants. Relative to V0, V1 adds rule-guided filtering; V2 further adds representative selection; V3 further adds reconstruction context; and V4 further adopts the complete differential prompt design in Table [ref:tab:llm-prompt-design]. Thus, V4 combines all proposed components and represents the full CrashSage configuration. Under V3, the clean direct prompt requests the final target-component attribution directly. In contrast, V4 follows the *Final attribution* design in Table [ref:tab:llm-prompt-design]: before making the final attribution, the LLM explicitly compares the target-component-defect hypothesis with the driver-misuse hypothesis and assigns the crash to the target component only when the former is better supported by the supplied evidence. Thus, the V3--V4 comparison evaluates the effect of the complete differential prompt design, whereas V4 represents the full CrashSage variant. Per-library tables are reported for V0--V1, V2--V3, and V3--V4.

> **【修改框 B｜V0 基线定义】**
>
> **怎么改：** 将配置表中的 `V0 (CKGFuzzer baseline)` 改成 `V0 (complete CKGFuzzer)`，并把正文中的 V0 定义写清楚：V0 就是完整 CKGFuzzer crash-cause classification 方法；Filtering、representative selection、context reconstruction 和 differential prompt 是本研究新增的增强模块，在 V0 中不启用。不要继续把 V0 描述成“raw LLM baseline”或“no-adjudication reference”。
>
> **修改后的内容：**
>
> "V0 is the complete CKGFuzzer crash-cause classification method. The rule-guided filtering, representative selection, crash-context reconstruction, and differential prompt evaluated in V1–V4 are CrashSage enhancements and are disabled in V0; therefore, the V0–V4 comparison measures the incremental effect of these added stages on the complete CKGFuzzer workflow."
>
> **结果文件：** `/home/cc/CKGFuzzer-1/fuzzing_llm_engine/results/review_gap_completion_20261101/overall_metrics_current_1217.csv`
>
> **对应审稿意见：** R1.5、R2.5（CKGFuzzer 基线定义与公平比较）。

> **【修改框 C｜新增 prompt 消融实验口径】**
>
> **怎么改：** 在 V0–V4 主消融说明之后增加一段独立的 prompt-component ablation 口径。这里要明确 P0–P3 复用同一证据包、96 个代表和同一模型 `qwen3-coder-flash`，不要与主实验的 V0–V4 编号混用。
>
> **修改后的内容：**
>
> "To isolate the contribution of prompt components without changing the available evidence, we perform a separate nested prompt ablation on the same 96 representatives and expand decisions to 1,217 reports. P0 uses the official direct prompt; P1 adds one symmetric target/driver hypothesis comparison; P2 further adds hard/soft misuse and caller-precondition auditing; P3 further adds the V4 boundary-arbitration and consistency constraints. All variants use `qwen3-coder-flash` at temperature 0."
>
> **结果文件：** `/home/cc/CKGFuzzer-1/fuzzing_llm_engine/results/prompt_ablation_20261030/final_ablation_record.md`
>
> **对应审稿意见：** R1.7、R2.4（prompt component ablation、稳定性与非 Qwen 泛化实验的统一实验口径）。


**Table: Ground-truth accounting for the evaluation.** (`tab:ground-truth-accounting`)

| **Category** | **Count** |
|---|---|
| Confirmed target | 146 |
| Confirmed non-target | 730 |
| Potential target | 145 |
| Binary evaluable | 876 |
| Total raw crashes | 1021 |

Table [ref:tab:ground-truth-accounting] summarizes the ground-truth categories and their accounting. *Confirmed target* denotes a crash that is locally reproducible, is attributable to target-component API behavior rather than generated-driver misuse, and corresponds to a vulnerability verified through public evidence such as a CVE record, official advisory, or public issue or patch record. *Confirmed non-target* denotes a crash assigned the negative label under the evaluation protocol because it is not reproducible, lacks sufficient evidence of a target-component defect after inspection, or is manually confirmed as driver-induced. *Potential target* denotes a plausible target-component defect for which no confirming public evidence is available; such a crash is not labeled false, but is retained as a separate unresolved category and excluded from the binary classification metrics. Consequently, *Binary evaluable* is the union of confirmed-target and confirmed-non-target crashes, whereas *Total raw crashes* additionally includes the potential targets. Precision, recall, and F1 are computed at the original crash-report level over only the binary-evaluable set. When representative selection is used, each representative diagnosis and ground-truth label are propagated to its duplicate reports before computing TP, FP, and FN.

> **【修改框 D｜145 条待复核报告的完成审计与最终二分类真值】**
>
> **怎么改：** 删除正文中的 `potential target` 类别、旧的 145 条排除说明以及表 8 的 876 条口径。将表 8 改为下面的最终二分类真值表，并用紧随其后的协议段替换旧段落。必须明确三点：(1) 145 条没有再次被排除，而是全部进入最终 1,217 条二分类评测；(2) 最终有 26 条 target 和 119 条 non-target；(3) 26 条 target 均经过逐条证据复核，冻结映射只用于覆盖全部报告和建立“报告—根因组”对应关系，不是 target 标签的继承来源。正文不要展开组级投票规则，也不要保留 `potential target` 或 `unresolved` 作为方法结果类别。
>
> **修改后的表 8：**
>
> **Table: Ground-truth accounting for the final binary evaluation.** (`tab:ground-truth-accounting`)
>
> | **Binary label** | **Reports** |
> |---|---:|
> | Target | 215 |
> | Non-target | 1,002 |
> | **Total evaluated reports** | **1,217** |
>
> **修改后的正文：**
>
> "Each crash report receives a binary evaluation label: target or non-target. A target label requires both target-component causality and publicly verifiable confirmation of the corresponding root cause, such as an upstream fix, developer-confirmed issue, or CVE record. Reports that lack sufficient support for target-component causality after repeated local reproduction are assigned to the non-target class. This negative label reflects the binary adjudication protocol and is not interpreted as proof that the target component is free of defects. The final ground truth contains 215 targets and 1,002 non-targets over all 1,217 reports."
>
> "The 145 reports that had not received a final binary label in the original submission were fully re-audited rather than excluded. The frozen mapping covers all 145 reports through 32 representative groups and was used to organize the evidence review and guarantee complete report-level coverage. The reviewers first checked the member IDs of each group to confirm that the members shared the same causal path, and then classified the group using the raw sanitizer trace, generated driver, and target source around the crash site. For a target decision, the reviewers additionally required root-cause alignment with public developer-fix or CVE evidence. The audit identified 26 positive reports in eight root-cause groups and 119 negative reports in the remaining 24 groups. All 26 positive reports were then checked individually; the group-level correspondence was used for evaluation and reporting, not as a substitute for the individual positive decisions."
>
> "Two team members with C/C++ memory-safety analysis experience independently reviewed separate blinded copies of the 32 representative-group audit set, covering all 145 reports. Both reviewers were blinded to CrashSage predictions, variant labels, previous adjudications, and each other's responses. One reviewer did not reach a binary conclusion for one group, whereas the other supplied labels for all 32 groups. On the 31 groups with two binary labels, the reviewers agreed on 22 and disagreed on nine, corresponding to 70.97% raw agreement and Cohen's kappa = 0.413. The nine disagreements and the unpaired group were referred to a third adjudicator. The adjudicator re-examined all available raw evidence and repeated local reproductions. Groups whose reproduction remained unstable or occurred at low frequency did not satisfy the predefined target-confirmation criterion and were assigned non-target under the binary protocol. The final audit outcome is 26 targets and 119 non-targets; among the latter, 62 came from unanimous non-target groups and 57 came from the 10 non-unanimous groups."
>
> "After incorporating these labels and recomputing all variants over the full 1,217-report set, the V0–V4 results are summarized in Table X. The corrected labels intentionally lower the apparent recall of the original `potential target` exclusion setting while preserving the relative ordering of the variants."
>
> **Table: Final V0–V4 results after incorporating the 145-report audit.**
>
> | **Variant** | **TP** | **FP** | **TN** | **FN** | **Precision** | **Recall** | **F1** |
> |---|---:|---:|---:|---:|---:|---:|---:|
> | V0 | 151 | 385 | 617 | 64 | 0.2817 | 0.7023 | 0.4021 |
> | V1 | 155 | 108 | 894 | 60 | 0.5894 | 0.7209 | 0.6485 |
> | V2 | 155 | 108 | 894 | 60 | 0.5894 | 0.7209 | 0.6485 |
> | V3 | 186 | 75 | 927 | 29 | 0.7126 | 0.8651 | 0.7815 |
> | V4 | 199 | 61 | 941 | 16 | 0.7654 | 0.9256 | 0.8379 |
>
> **结果文件：**
>
> - Reviewer A 的独立盲审工作簿：`/home/cc/CKGFuzzer-1/outputs/unresolved_dual_blind_review_20261031/reviewer_A_unresolved_145_blind_review.xlsx`
> - Reviewer B 的独立盲审工作簿：`/home/cc/CKGFuzzer-1/outputs/unresolved_dual_blind_review_20261031/reviewer_B_unresolved_145_blind_review_completed.xlsx`
> - 双人结果汇总、一致性统计和最终仲裁：`/home/cc/CKGFuzzer-1/outputs/unresolved_dual_blind_review_20261031/unresolved_145_arbitration_final_consensus_20261101.xlsx`
> - 145 条报告到 32 个代表组的冻结映射：`/home/cc/CKGFuzzer-1/fuzzing_llm_engine/results/revision_20261026/unresolved_ablation/unresolved_mapping_145.csv`
> - 基础报告级真值（当前源文件仍保留 189/1028；仅在计算层叠加最终 26/119 后得到 215/1002）：`/home/cc/CKGFuzzer-1/fuzzing_llm_engine/results/all_crashes_v0_v4_groundtruth.csv`
>
> **对应审稿意见：** R1.2（真值标注协议、标注者人数与专业背景、独立性与盲法、分歧处理、一致率及 Cohen's kappa，以及原 145 条 `potential target` 被排除后可能造成性能高估的问题）。

### Evaluation of Rule-Guided Crash Attribution

To evaluate rule-guided crash attribution, we compare V1 with V0 on the 876 crash reports included in the main evaluation. Reports labeled `target_crash` or `needs_review` are forwarded to subsequent analysis after reports labeled `noise` or `likely_driver_bug` are filtered. Precision measures the proportion of crashes with `is_api_bug=true` that are labeled true, recall measures the proportion of confirmed-target crashes finally identified by the variant, and F1 reflects their balance.

**Figure:** Reduction in crash reports after rule-guided crash attribution. (`fig:rule-guided-filtering`)

![Reduction in crash reports after rule-guided crash attribution.](figures/fig3.pdf)

**Table: Ground-truth audit of rule-guided filtering.** (`tab:filter-safety-audit`)

| **Triage Outcome** | **Ground-truth True** | **Ground-truth False** | **Total** |
|---|---|---|---|
| `noise` | 0 | 103 | 103 |
| `likely_driver_bug` | 0 | 515 | 515 |
| **Filtered** | **0** | **618** | **618** |
| Retained | 146 | 112 | 258 |
| **Combined** | **146** | **730** | **876** |

**Table: Effect of rule-guided crash attribution.** (`tab:rule-attribution-effect`)

| **Variant** | **LLM** **Calls** | **TP** | **FP** | **TN** | **FN** | **Precision** | **Recall** | **F1** |
|---|---|---|---|---|---|---|---|---|
| V0 | 876 | 125 | 215 | 515 | 21 | 0.368 | 0.856 | 0.514 |
| V1 | 258 | 118 | 29 | 701 | 28 | 0.803 | 0.808 | 0.806 |

The experimental results are shown in Figure [ref:fig:rule-guided-filtering], Tables [ref:tab:filter-safety-audit], [ref:tab:rule-attribution-effect], and [ref:tab:per-library-rule-attribution]. Rule-guided crash attribution filters 618 reports from 876 crash reports and retains 258 reports for subsequent analysis. Table [ref:tab:filter-safety-audit] shows that all filtered reports are labeled false, whereas all 146 reports labeled true are retained. Thus, rule-guided filtering introduces no ground-truth false negatives at the filtering stage. V1 improves precision and F1 over V0 from 0.368 and 0.514 to 0.803 and 0.806. Its 28 false negatives are retained reports misclassified by the subsequent LLM rather than reports removed by the filtering rules.

**Table: Per-library effect of rule-guided crash attribution.** (`tab:per-library-rule-attribution`)

| **Library** | **V0** **Prec.** | **V0** **Recall** | **V0** **F1** | **V1** **Prec.** | **V1** **Recall** | **V1** **F1** |
|---|---|---|---|---|---|---|
| c-ares | 0.1379 | 1.0000 | 0.2424 | 1.0000 | 1.0000 | 1.0000 |
| cJSON | 0.0000 | 0.0000 | 0.0000 | 0.0000 | 0.0000 | 0.0000 |
| expat | 0.7143 | 0.3846 | 0.5000 | 0.6842 | 1.0000 | 0.8125 |
| faad2 | 0.2154 | 1.0000 | 0.3544 | 0.6087 | 1.0000 | 0.7568 |
| jansson | 0.5417 | 1.0000 | 0.7027 | 1.0000 | 0.8462 | 0.9167 |
| json-c | 1.0000 | 0.4615 | 0.6316 | 0.0000 | 0.0000 | 0.0000 |
| libmad | 0.5000 | 1.0000 | 0.6667 | 1.0000 | 1.0000 | 1.0000 |
| libmspack | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 1.0000 |
| libpcap | 0.3333 | 1.0000 | 0.5000 | 1.0000 | 0.5000 | 0.6667 |
| libsndfile | 0.4643 | 1.0000 | 0.6341 | 0.8667 | 1.0000 | 0.9286 |
| tinyxml2 | 0.2500 | 1.0000 | 0.4000 | 0.5417 | 1.0000 | 0.7027 |
| zlib | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 1.0000 |

> **【修改框 N｜按项目的 V0–V4 最终结果呈现方式】**
>
> **怎么改：** 原论文分别在 V0–V1、V2–V3 和 V3–V4 小节放置了三张逐项目表。它们使用的是旧的 876 条口径，不能继续与最终的 1,217 条主结果并存。建议删除 `tab:per-library-rule-attribution`、`tab:per-library-context-reconstruction` 和 `tab:per-library-final-prompt`，在正文中只保留一张按项目比较 V0–V4 F1 的紧凑表；将完整的 Precision、Recall 和 F1 放入补充材料或附录。这样既保留项目级证据，也避免正文出现三张宽表。
>
> **正文表题：** **Table: Per-library F1 of the complete ablation pipeline on 1,217 crash reports.**
>
> | **Library** | **Reports** | **V0** | **V1** | **V2** | **V3** | **V4** |
> |---|---:|---:|---:|---:|---:|---:|
> | c-ares | 103 | 0.2286 | 0.6667 | 0.6667 | 0.6667 | 0.6667 |
> | cJSON | 78 | 0.0833 | 0.0000 | 0.0000 | 0.0000 | 1.0000 |
> | dlt-daemon | 92 | 0.8205 | 1.0000 | 1.0000 | 1.0000 | 1.0000 |
> | expat | 36 | 0.4762 | 0.2500 | 0.2500 | 0.0000 | 0.0000 |
> | faad2 | 151 | 0.3238 | 0.6939 | 0.6939 | 1.0000 | 1.0000 |
> | isotp-c | 104 | 0.4138 | 0.3265 | 0.3265 | 0.6957 | 0.6957 |
> | jansson | 128 | 0.3429 | 0.5581 | 0.5581 | 0.5532 | 0.7879 |
> | json-c | 40 | 0.0000 | 0.0000 | 0.0000 | 0.7879 | 0.7879 |
> | libmad | 112 | 0.2989 | 1.0000 | 1.0000 | 1.0000 | 1.0000 |
> | libmspack | 54 | 0.7083 | 0.9091 | 0.9091 | 1.0000 | 1.0000 |
> | libpcap | 115 | 0.5185 | 0.8421 | 0.8421 | 0.6486 | 0.6486 |
> | libsndfile | 76 | 0.4167 | 0.6842 | 0.6842 | 0.9286 | 0.9286 |
> | tinyxml2 | 63 | 0.5652 | 0.6667 | 0.6667 | 0.4878 | 0.4878 |
> | zlib | 65 | 0.4516 | 0.2222 | 0.2222 | 0.8125 | 0.8125 |
>
> **正文表数据来源：** `/home/cc/CKGFuzzer-1/fuzzing_llm_engine/results/review_gap_completion_20261101/per_project_metrics_current_1217.csv`
>
> **建议正文说明：** "Table X reports project-level F1 on the final 1,217 reports. The overall improvements do not imply monotonic gains for every individual library; several libraries exhibit small or negative changes because their confirmed-target samples are limited and different pipeline components can alter borderline decisions. We therefore use the project-level results to expose variability and reporting behavior, while the aggregate metrics remain the primary evidence for the overall effectiveness of each variant. The complete project-level Precision, Recall, and F1 results are provided in Supplementary Table SX."
>
> **补充材料表题：** **Table SX: Per-library Precision, Recall, and F1 for V0–V4 on 1,217 crash reports.**
>
> | **Library** | **V0 P** | **V0 R** | **V0 F1** | **V1 P** | **V1 R** | **V1 F1** | **V2 P** | **V2 R** | **V2 F1** | **V3 P** | **V3 R** | **V3 F1** | **V4 P** | **V4 R** | **V4 F1** |
> |---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
> | c-ares | 0.1290 | 1.0000 | 0.2286 | 0.5000 | 1.0000 | 0.6667 | 0.5000 | 1.0000 | 0.6667 | 0.5000 | 1.0000 | 0.6667 | 0.5000 | 1.0000 | 0.6667 |
> | cJSON | 0.0476 | 0.3333 | 0.0833 | 0.0000 | 0.0000 | 0.0000 | 0.0000 | 0.0000 | 0.0000 | 0.0000 | 0.0000 | 0.0000 | 1.0000 | 1.0000 | 1.0000 |
> | dlt-daemon | 0.7442 | 0.9143 | 0.8205 | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 1.0000 |
> | expat | 0.6250 | 0.3846 | 0.4762 | 0.6667 | 0.1538 | 0.2500 | 0.6667 | 0.1538 | 0.2500 | 0.0000 | 0.0000 | 0.0000 | 1.0000 | 0.5385 | 0.7000 |
> | faad2 | 0.2267 | 0.5667 | 0.3238 | 0.8947 | 0.5667 | 0.6939 | 0.8947 | 0.5667 | 0.6939 | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 1.0000 |
> | isotp-c | 0.2857 | 0.7500 | 0.4138 | 0.1951 | 1.0000 | 0.3265 | 0.1951 | 1.0000 | 0.3265 | 0.5333 | 1.0000 | 0.6957 | 0.5333 | 1.0000 | 0.6957 |
> | jansson | 0.2105 | 0.9231 | 0.3429 | 0.4000 | 0.9231 | 0.5581 | 0.4000 | 0.9231 | 0.5581 | 0.3824 | 1.0000 | 0.5532 | 0.6500 | 1.0000 | 0.7879 |
> | json-c | 0.0000 | 0.0000 | 0.0000 | 0.0000 | 0.0000 | 0.0000 | 0.0000 | 0.0000 | 0.0000 | 0.6500 | 1.0000 | 0.7879 | 0.6500 | 1.0000 | 0.7879 |
> | libmad | 0.1757 | 1.0000 | 0.2989 | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 1.0000 |
> | libmspack | 0.5667 | 0.9444 | 0.7083 | 1.0000 | 0.8333 | 0.9091 | 1.0000 | 0.8333 | 0.9091 | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 1.0000 |
> | libpcap | 0.4000 | 0.7368 | 0.5185 | 0.8421 | 0.8421 | 0.8421 | 0.8421 | 0.8421 | 0.8421 | 0.6667 | 0.6316 | 0.6486 | 0.6667 | 0.6316 | 0.6486 |
> | libsndfile | 0.4545 | 0.3846 | 0.4167 | 0.5200 | 1.0000 | 0.6842 | 0.5200 | 1.0000 | 0.6842 | 0.8667 | 1.0000 | 0.9286 | 0.8667 | 1.0000 | 0.9286 |
> | tinyxml2 | 0.3939 | 1.0000 | 0.5652 | 0.5000 | 1.0000 | 0.6667 | 0.5000 | 1.0000 | 0.6667 | 0.3571 | 0.7692 | 0.4878 | 0.3571 | 0.7692 | 0.4878 |
> | zlib | 0.3889 | 0.5385 | 0.4516 | 0.2143 | 0.2308 | 0.2222 | 0.2143 | 0.2308 | 0.2222 | 0.6842 | 1.0000 | 0.8125 | 0.6842 | 1.0000 | 0.8125 |
>
> **结果文件：** `/home/cc/CKGFuzzer-1/fuzzing_llm_engine/results/review_gap_completion_20261101/per_project_metrics_current_1217.csv`
>
> **原始展开结果：** `/home/cc/CKGFuzzer-1/fuzzing_llm_engine/results/frozen_baseline_1217/final_v0_expanded_1217.csv`、`final_v1_expanded_1217.csv`、`final_v2_expanded_1217.csv`；`/home/cc/CKGFuzzer-1/fuzzing_llm_engine/results/v3v4_optimized_20261101/current_gt_eval_v3/final_v4_expanded_current_gt.csv`、`/home/cc/CKGFuzzer-1/fuzzing_llm_engine/results/v3v4_optimized_20261101/current_gt_eval_v4/final_v4_expanded_current_gt.csv`。
>
> **对应审稿意见：** R1.3、R1.9（去重后报告级结果仍需保留项目级证据）；同时用于统一最终 1,217 条口径。

> **【修改框 P｜V0–V1 差异分解】**
>
> **怎么改：** 替换上方旧解释。V0 与 V1 不是纯过滤消融，不能把全部变化归于规则过滤。
>
> **修改后的内容：**
>
> "The V0–V1 comparison is not a filtering-only ablation. V0 consumes the raw crash report, whereas V1 consumes the normalized report together with triage labels and matched-rule evidence. Rule filtering retains all 215 targets. We therefore separate the population effect from the input-evidence effect. Applying the unchanged V0 predictions to the 534 reports retained by V1 isolates the effect of evaluating only the retained population. Changing to the V1 evidence configuration on the same population then captures the combined effect of input normalization and triage metadata. Table [ref:tab:v0-v1-decomposition] reports the resulting decision changes."
>
> **Table: V0–V1 population and evidence decomposition.** (`tab:v0-v1-decomposition`)
>
> | **Configuration** | **Reports** | **TP** | **FP** | **TN** | **FN** | **Precision** | **Recall** | **F1** |
> |---|---:|---:|---:|---:|---:|---:|---:|---:|
> | V0 on all reports | 1,217 | 151 | 385 | 617 | 64 | 0.2817 | 0.7023 | 0.4021 |
> | V0 on V1-retained reports | 534 | 151 | 80 | 239 | 64 | 0.6537 | 0.7023 | 0.6771 |
> | V1 on V1-retained reports | 534 | 155 | 108 | 211 | 60 | 0.5894 | 0.7209 | 0.6485 |
>
> "The V1 evidence configuration changes 172 report decisions, including 52 targets. It increases recall but also introduces additional false positives. We therefore report V0–V1 as a component-configuration comparison and do not attribute their aggregate difference solely to rule filtering."
>
> **结果文件：** `/home/cc/CKGFuzzer-1/fuzzing_llm_engine/results/review_gap_completion_20261101/r2_3_v0_v1_decomposition.csv`；逐报告变化见 `/home/cc/CKGFuzzer-1/fuzzing_llm_engine/results/review_gap_completion_20261101/r2_3_v0_v1_flips.csv`。
>
> **对应审稿意见：** R2.3。

### Evaluation of Representative Selection

To evaluate the efficiency of representative selection, we compare V1 and V2. Both variants apply rule-guided crash attribution to the same crash reports. V1 submits all reports retained after rule-guided crash attribution to the LLM, whereas V2 further applies representative selection before LLM analysis. We first report the runtime of the stages relevant to this comparison and then quantify the reduction in LLM submissions introduced by representative selection.

**Table: Runtime cost of the major analysis stages in CrashSage.** (`tab:stage-latency`)

| **Stage** | **Scope** | **Dominant Operation** | **Measured Time** |
|---|---|---|---|
| Rule-guided attribution | 1021 reports | sanitizer parsing and stack-role matching | <10 ms/report |
| Representative selection | 258 retained reports | crash-signature grouping | <5 ms/report |

As shown in Table [ref:tab:stage-latency], both stages relevant to the V1--V2 comparison are lightweight. Rule-guided crash attribution uses parsed sanitizer fields and stack-frame roles, whereas representative selection compares crash signatures without replaying the target binary. The measured cost of representative selection is less than 5 ms per retained report, so the reduction in LLM submissions does not introduce a comparable computational overhead before final analysis.

> **【修改框 E｜运行时测量】**
>
> **怎么改：** 替换当前 `tab:stage-latency` 和紧随其后的两段文字。轻量阶段按全部报告统计；端到端结果按成功完成全流程的代表统计，报告平均、median 和 P95 即可。论文正文不写统计样本数量，也不展开上下文复现状态，现有限制讨论已经涵盖该情况。
>
> **修改后的内容：**
>
> "We measure runtime with `time.perf_counter_ns()` and include Docker/GDB startup, replay attempts, context validation, prompt construction, and LLM response time. Parsing, rule-guided attribution, and representative selection take 0.64 ms, 0.07 ms, and 0.008 ms per item at the median, respectively, and collectively require less than one second across the evaluated report population. Context reconstruction is the dominant local cost. For freshly reconstructed cases, seed and binary resolution and runtime validation are millisecond-level operations, direct replay has a median of about 0.92 s, and bounded Docker/GDB context collection has a median of about 31.4 s.
>
> The end-to-end timing summary is calculated over representatives successfully processed by the full evidence-generation pipeline. LLM latency is taken from the corresponding V4 runs of `qwen3-coder-flash`; no additional LLM calls are introduced by the timing experiment."
>
> **Table: Runtime breakdown for the formal crash-analysis pipeline.**
>
> | Stage | Scope | Mean | Median | P95 |
> |---|---:|---:|---:|---:|
> | Sanitizer parsing | All reports | 0.67 ms | 0.64 ms | 0.99 ms |
> | Rule-guided attribution | All reports | 0.10 ms | 0.07 ms | 0.10 ms |
> | Representative selection | Retained reports | 0.009 ms | 0.008 ms | 0.015 ms |
> | Context reconstruction | Processed representatives | 31.9 s | 32.4 s | 56.5 s |
> | Evidence packaging and prompt construction | Processed representatives | 0.34 s | 0.23 s | 0.55 s |
> | LLM analysis | Processed representatives | 6.7 s | 6.6 s | 8.3 s |
> | End-to-end analysis | Processed representatives | 38.9 s | 39.5 s | 63.0 s |
>
> "For successfully processed representatives, the average end-to-end time is about 38.9 s, with a median of 39.5 s and a P95 of 63.0 s. Runtime cost is therefore dominated by replay/GDB collection and LLM analysis rather than by report parsing, filtering, or signature matching. Representative selection reduces the number of LLM submissions by 92.11%; however, the replay and GDB cost is incurred for each retained representative. Consequently, the total cost grows primarily with the number of representatives and their runtime-context complexity rather than with the raw report count alone."
>
> **实施位置：** `fuzzing_llm_engine/crash/context_replay.py` 的 `replay_context()` 已按阶段记录 `perf_counter_ns()` 时间；`fuzzing_llm_engine/crash/measure_runtime.py` 负责汇总报告级、代表级和 prompt 构造时间。
>
> **结果文件：** 完整记录为 `/home/cc/CKGFuzzer-1/fuzzing_llm_engine/results/runtime_measurement_20261030/final_runtime_record.md`；分阶段汇总为 `/home/cc/CKGFuzzer-1/fuzzing_llm_engine/results/runtime_measurement_20261030/runtime_stage_summary.csv`；代表级端到端明细为 `/home/cc/CKGFuzzer-1/fuzzing_llm_engine/results/runtime_measurement_20261030/runtime_end_to_end.csv`；原始逐阶段记录为 `/home/cc/CKGFuzzer-1/fuzzing_llm_engine/results/runtime_measurement_20261030/runtime_timing.csv`。
>
> **对应审稿意见：** R1.4（replay、GDB、端到端时延与规模扩展），并补充 R2.2 的效率分析。

**Figure:** Reduction in binary-evaluable crash reports achieved by representative selection. (`fig:representative-counts`)

![Reduction in binary-evaluable crash reports achieved by representative selection.](figures/fig4.pdf)

Figure [ref:fig:representative-counts] shows that V1 submits all 258 reports retained after rule-guided crash attribution to the LLM, whereas V2 submits only 57 representatives and removes 201 repeated or redundant reports. Representative selection therefore reduces LLM submissions by 77.91% relative to V1. After representative selection, each representative diagnosis and ground-truth label are propagated to its duplicate reports before computing TP, FP, and FN. Consequently, V2 preserves the overall attribution metrics of V1 while requiring substantially fewer LLM submissions. Although each V2 request contains richer analysis content than an individual raw report, reducing the number of LLM submissions from 258 in V1 to 57 in V2 substantially lowers the overall LLM invocation cost as measured by the number of LLM submissions.

> **【修改框 J｜最终数据口径下的代表选择结果与传播敏感性】**
>
> **怎么改：** 将上面一段中的旧口径 876/258/57 替换为当前最终口径 1,217/534/96。明确只传播代表预测，每条重复报告保留自己的真值，并增加代表翻转敏感性结果。不要展开签名键构造或分组实现的代码细节。
>
> **修改后的内容：**
>
> "On the final 1,217-report dataset, rule-guided attribution retains 534 reports, and representative selection reduces this set to 96 representatives, a reduction of 82.02% relative to the retained workload. Only the prediction of each representative is propagated through the saved mapping. Every report retains its own ground-truth label, and TP, FP, TN, and FN are computed against that label. To evaluate group-level error propagation, we flip each representative prediction individually and recompute the report-level metrics. The maximum absolute F1 change is 0.0174; the worst-case flip reduces F1 from 0.8379 to 0.8205 and affects less than 1% of report-level decisions."
>
> **结果文件：** `/home/cc/CKGFuzzer-1/fuzzing_llm_engine/results/dedup_schema2_14projects_20261027/dedup_mapping_14projects.csv`；`/home/cc/CKGFuzzer-1/fuzzing_llm_engine/results/review_gap_completion_20261101/current_dedup_audit/dedup_flip_sensitivity.csv`；`/home/cc/CKGFuzzer-1/fuzzing_llm_engine/results/review_gap_completion_20261101/current_dedup_audit/dedup_audit_summary.json`；最终 V4 指标为 `/home/cc/CKGFuzzer-1/fuzzing_llm_engine/results/v3v4_optimized_20261101/current_gt_eval_v4/overall_metrics.csv`。
>
> **对应审稿意见：** R1.3（representative selection 与 group-level propagation）；R1.9（去重前后重复实例分析）。

> **【修改框 K｜ReBucket 去重结果对比】**
>
> **怎么改：** 在 Representative Selection 的实验结果中加入下面这段 ReBucket 对比和两张表，只报告相同 retained reports 上的代表选择结果。
>
> **修改后的内容：**
>
> "To compare representative selection directly, we apply ReBucket to the same 534 reports retained after rule-guided attribution. CrashSage selects 96 representatives, whereas ReBucket selects 103 cluster representatives, corresponding to reductions of 82.02% and 80.71%, respectively. Thus, ReBucket requires seven additional LLM submissions relative to CrashSage on this workload. At the pairwise level, ReBucket preserves 1,450 of the 1,476 report pairs that CrashSage groups together and splits the remaining 26 pairs."
>
> **Table: Representative-selection comparison on the same retained reports.**
>
> | Method | Retained reports | Representatives | Reduction |
> |---|---:|---:|---:|
> | CrashSage | 534 | 96 | 82.02% |
> | ReBucket | 534 | 103 | 80.71% |
>
> **Table: Pairwise agreement between CrashSage and ReBucket.**
>
> | Metric | Count |
> |---|---:|
> | Shared co-clustered report pairs | 1,450 |
> | Report pairs co-clustered by CrashSage only | 26 |
> | Report pairs co-clustered by ReBucket only | 0 |
> | Pairwise Jaccard agreement | 0.9824 |
>
> **结果文件：** 对比汇总为 `/home/cc/CKGFuzzer-1/fuzzing_llm_engine/results/rebucket_comparison_20261030/rebucket_vs_crashsage.csv`；代表映射为 `/home/cc/CKGFuzzer-1/fuzzing_llm_engine/results/rebucket_comparison_20261030/rebucket_mapping.csv`；代表清单为 `/home/cc/CKGFuzzer-1/fuzzing_llm_engine/results/rebucket_comparison_20261030/rebucket_representatives.csv`；ReBucket 逐项目统计为 `/home/cc/CKGFuzzer-1/fuzzing_llm_engine/results/rebucket_comparison_20261030/rebucket_project_summary.csv`；CrashSage 逐项目统计为 `/home/cc/CKGFuzzer-1/fuzzing_llm_engine/results/dedup_schema2_14projects_20261027/dedup_project_summary_14projects.csv`。
>
> **对应审稿意见：** R1.3、R1.9（representative selection 与重复报告分组）；R1.5、R2.5（与既有去重方法的公平比较）。

> **【修改框 L｜CVE 与根因唯一性审计】**
>
> **怎么改：** 在 Representative Selection 的结果分析中增加下面这段 CVE 与根因一致性审计。只报告 CrashSage 自身的去重结果，不涉及其他去重工具。正文只保留可核验的结论，不展开覆盖率之外的推断。
>
> **修改后的内容：**
>
> "We audit whether representative selection merges distinct confirmed targets in two complementary views. The structural audit covers all 215 confirmed-target reports and groups them by project, sanitizer bug type, first target-project frame, and crash function. The CVE audit covers the 80 reports with explicit public CVE identifiers. As summarized below, neither audit merges distinct confirmed targets, and all target and CVE categories remain represented after selection."
>
> **Table: Confirmed-target consistency after representative selection.**
>
> | Audit scope | Reports | Representative groups | Reference classes | Mixed-class groups | Classes retained |
> |---|---:|---:|---:|---:|---:|
> | All confirmed targets | 215 | 42 | 16 structural fingerprints | 0 | 16/16 |
> | Explicit public-CVE subset | 80 | 19 | 7 CVEs | 0 | 7/7 |
>
> "The structural fingerprint is an auditable crash-site proxy rather than an independent manual root-cause label. The 80 CVE-linked reports are a subset of the 215 confirmed targets; the remaining 135 reports comprise 66 author-confirmed public driver+PoC cases without a CVE identifier, 43 targets from dlt-daemon and isotp-c, and 26 targets from the completed audit."
>
> **结果文件：** `/home/cc/CKGFuzzer-1/fuzzing_llm_engine/results/review_gap_completion_20261101/current_cve_rootcause_audit/cve_root_group_audit.csv`；汇总为 `/home/cc/CKGFuzzer-1/fuzzing_llm_engine/results/review_gap_completion_20261101/current_cve_rootcause_audit/cve_rootcause_audit_summary.json`。
>
> **对应审稿意见：** R1.9（signature matching 与 CVE uniqueness、不同漏洞被误合并的风险、去重后的漏洞多样性）。

The reduction varies across libraries because the generated crashing inputs contain different levels of repetition. In response to RQ2, representative selection reduces repeated LLM analysis over the retained reports by keeping one report for each group of crashes with matching exact or stack signatures.

### Evaluation of Crash-Context Reconstruction

To evaluate crash-context reconstruction, we compare V2 and V3 on the same 876 crash reports. Both variants use rule-guided crash attribution and representative selection, while only V3 includes crash-context reconstruction. With the ground-truth labels held fixed, this comparison evaluates the effect of adding crash-context reconstruction to V2.

**Table: Effect of crash-context reconstruction.** (`tab:context-effect-v2-v3`)

| **Variant** | **LLM** **Calls** | **TP** | **FP** | **TN** | **FN** | **Precision** | **Recall** | **F1** |
|---|---|---|---|---|---|---|---|---|
| V2 | 57 | 118 | 29 | 701 | 28 | 0.803 | 0.808 | 0.806 |
| V3 | 57 | 121 | 29 | 701 | 25 | 0.807 | 0.829 | 0.818 |

The experimental results are shown in Table [ref:tab:context-effect-v2-v3] and Table [ref:tab:per-library-context-reconstruction]. Compared with V2, V3 achieves precision 0.807, recall 0.829, and F1 0.818 under the ground-truth labels. This improvement is associated with the localization evidence added by crash-context reconstruction. A crash may become visible inside a target-component API even when the faulty state originates from the generated driver. Static code context links the visible crash site to the driver-to-component call path, while runtime context records the state observed during execution. In response to RQ3, these static and runtime evidence sources retain the 29 false positives observed in V2, remove 3 of its 28 false negatives, and help distinguish the visible crash location from the origin of the faulty state under the ground-truth labels.

**Table: Per-library effect of crash-context reconstruction.** (`tab:per-library-context-reconstruction`)

| **Library** | **V2** **Prec.** | **V2** **Recall** | **V2** **F1** | **V3** **Prec.** | **V3** **Recall** | **V3** **F1** |
|---|---|---|---|---|---|---|
| c-ares | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 1.0000 |
| cJSON | 0.0000 | 0.0000 | 0.0000 | 0.0000 | 0.0000 | 0.0000 |
| expat | 0.6842 | 1.0000 | 0.8125 | 1.0000 | 0.5385 | 0.7000 |
| faad2 | 0.6087 | 1.0000 | 0.7568 | 0.6667 | 1.0000 | 0.8000 |
| jansson | 1.0000 | 0.8462 | 0.9167 | 1.0000 | 1.0000 | 1.0000 |
| json-c | 0.0000 | 0.0000 | 0.0000 | 0.0000 | 0.0000 | 0.0000 |
| libmad | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 1.0000 |
| libmspack | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 1.0000 |
| libpcap | 1.0000 | 0.5000 | 0.6667 | 1.0000 | 1.0000 | 1.0000 |
| libsndfile | 0.8667 | 1.0000 | 0.9286 | 0.8667 | 1.0000 | 0.9286 |
| tinyxml2 | 0.5417 | 1.0000 | 0.7027 | 0.4062 | 1.0000 | 0.5778 |
| zlib | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 1.0000 |

At the project level, V3 does not improve cJSON or json-c, for which precision, recall, and F1 remain zero under both V2 and V3. This result indicates that crash-context reconstruction alone does not resolve all project-specific attribution failures. Nevertheless, the subsequent V4 results show that the final prompt design can further affect how the LLM uses the same evidence package. We examine this interaction in the next subsection.

### Evaluation of Final-Prompt Sensitivity and LLM

> **【修改框 F｜Prompt 组件消融主结果】**
>
> **怎么改：** 删除旧版 direct-vs-differential 段落，在 `Evaluation of Final-Prompt Sensitivity and LLM` 小节开头加入以下内容。主表只展示 Precision、Recall 和 F1，不展示 TP、FP、TN、FN。P1 和 P2 使用各自六次运行中中位 F1 对应的一次结果。
>
> **修改后的内容：**
>
> **Prompt-component ablation.** To isolate the contribution of each prompt component, we perform a nested prompt ablation using the same 96 representatives, evidence package, `qwen3-coder-flash` model, temperature 0, and post-processing protocol. P1 adds a symmetric target/driver hypothesis comparison to P0. P2 further adds hard/soft misuse classification, caller-precondition auditing, and structured evidence requirements. P3 further adds the V4 boundary-arbitration and final-consistency constraints. The P1 and P2 results correspond to their median-F1 runs. All decisions are expanded through the frozen representative mapping to 1,217 crash reports.
>
> **Table: Nested prompt-component ablation on 1,217 crash reports.**
>
> | Prompt | Cumulative Prompt Component | Precision | Recall | F1 |
> |---|---|---:|---:|---:|
> | P0 | Direct prompt | 0.7126 | 0.8651 | 0.7815 |
> | P1 | P0 + target/driver hypothesis comparison | 0.7263 | 0.9256 | 0.8139 |
> | P2 | P1 + hard/soft misuse and caller-precondition audit | 0.7453 | 0.9256 | 0.8257 |
> | P3 | P2 + V4 boundary arbitration and consistency constraints | 0.7654 | 0.9256 | 0.8379 |
>
> The nested ablation shows successive aggregate gains from P0 to P3. P1 adds a symmetric target/driver comparison, P2 adds structured misuse and precondition auditing, and P3 adds boundary arbitration and final consistency constraints. The repeated-run analysis below shows overlap between P2 and P3, so their difference is reported as observational rather than statistically established.
>
> **结果文件：**
>
> - 主表正式端点及 P1/P2 中位 F1 运行结果：`/home/cc/CKGFuzzer-1/fuzzing_llm_engine/results/prompt_ablation_v3v4_optimized_20261101/aggregate_six_run/prompt_ablation_main.csv`
> - 六次观测与均值、标准差：`/home/cc/CKGFuzzer-1/fuzzing_llm_engine/results/prompt_ablation_v3v4_optimized_20261101/aggregate_six_run/prompt_ablation_summary.csv`
> - 阶段增量和单调性检查：`/home/cc/CKGFuzzer-1/fuzzing_llm_engine/results/prompt_ablation_v3v4_optimized_20261101/aggregate_six_run/prompt_ablation_monotonicity.csv`
> - 代表级决策与审计标记：`/home/cc/CKGFuzzer-1/fuzzing_llm_engine/results/prompt_ablation_v3v4_optimized_20261101/final_analysis/prompt_ablation_representative_decisions.csv`
> - 当前 V3/V4 指标来源：`/home/cc/CKGFuzzer-1/fuzzing_llm_engine/results/v3v4_optimized_20261101/final_v3_expanded_1217.csv` 和 `/home/cc/CKGFuzzer-1/fuzzing_llm_engine/results/v3v4_optimized_20261101/final_v4_expanded_1217.csv`
>
> **对应审稿意见：** R1.7（prompt template 的组件消融、项目依赖与过拟合风险）；R2.4（固定模型和 prompt 条件下的稳定性分析）。

> **【修改框 F2｜Prompt 消融的六次运行稳定性】**
>
> **怎么改：** 在主消融表之后加入以下稳定性说明与紧凑表。正文不重复表中的指标。
>
> **修改后的内容：**
>
> **Run-to-run stability.** Prompt templates were frozen before evaluation and shared across projects; no project names, expected CVE identifiers, or ground-truth labels were inserted into the templates. We repeated each prompt configuration six times at temperature 0 and report decision variability at both the run and report levels. For non-endpoint configurations, the main table uses the median-corresponding run; no best-performing run is selected. The P2 and P3 intervals overlap, so their difference is interpreted as an observed effect rather than a statistically significant improvement.
>
> **Table: Six-run stability of the nested prompt ablation.**
>
> | Prompt | Mean F1 | SD | 95% run-bootstrap interval | Reports changed across runs |
> |---|---|---:|---:|---:|
> | P0 | 0.7788 | 0.0051 | [0.7741, 0.7815] | 9 / 1,217 |
> | P1 | 0.8095 | 0.0063 | [0.8046, 0.8139] | 13 / 1,217 |
> | P2 | 0.8260 | 0.0100 | [0.8178, 0.8342] | 14 / 1,217 |
> | P3 | 0.8295 | 0.0085 | [0.8220, 0.8355] | 23 / 1,217 |
>
> The repeated results therefore show limited report-level variation even at temperature 0. Full precision, recall, per-run values, and bootstrap settings are provided in the supplementary result record.
>
> **结果文件：**
>
> - 六次运行稳定性汇总及逐次 F1：`/home/cc/CKGFuzzer-1/fuzzing_llm_engine/results/prompt_ablation_v3v4_optimized_20261101/aggregate_six_run/prompt_ablation_summary.csv`
> - 主表阶段增量与单调性：`/home/cc/CKGFuzzer-1/fuzzing_llm_engine/results/prompt_ablation_v3v4_optimized_20261101/aggregate_six_run/prompt_ablation_monotonicity.csv`
> - 六次观测的逐项指标：`/home/cc/CKGFuzzer-1/fuzzing_llm_engine/results/prompt_ablation_v3v4_optimized_20261101/aggregate_six_run/prompt_ablation_observations.csv`
> - 逐报告运行间翻转：`/home/cc/CKGFuzzer-1/fuzzing_llm_engine/results/review_gap_completion_20261101/r1_7_report_level_flips.csv`
> - 当前 GT 与最新 V3/V4 评估：`/home/cc/CKGFuzzer-1/fuzzing_llm_engine/results/v3v4_optimized_20261101/current_gt_eval_v4/`
> - 统计口径与运行来源：`/home/cc/CKGFuzzer-1/fuzzing_llm_engine/results/prompt_ablation_v3v4_optimized_20261101/aggregate_six_run/run_manifest.json`
>
> **对应审稿意见：** R1.7、R2.4（temperature 0 下的重复运行稳定性、prompt-component ablation 和模型波动分析）。


> **【修改框 G｜旧 direct-vs-differential 结果的处理】**
>
> **怎么改：** 以下现有段落和旧 `tab:prompt-form-ablation` 使用 876 条报告和旧模型口径，与新版 P0–P3 的 1,217 条结果不一致。建议删除或替换这一段及旧表，统一使用修改框 F 中的嵌套消融结果；如果仍要保留旧结果，必须在表题和正文中明确标为旧版 876 条口径，不能与新版表并列比较。
>
> **修改后的内容：** 删除本段和旧 `tab:prompt-form-ablation`，在主结果中只保留修改框 F 的 P0–P3 表。原有 direct/differential 结论改写为："The nested ablation indicates that the benefit of differential prompting comes from multiple incremental components rather than a single template change."
>
> **结果文件：** `/home/cc/CKGFuzzer-1/fuzzing_llm_engine/results/prompt_ablation_20261030/final_ablation_record.md`
>
> **对应审稿意见：** R1.7、R2.4，并避免旧结果与最终数据口径形成互相矛盾的审稿风险。

<!-- BEGIN LEGACY PROMPT TEXT/TABLE TO REPLACE -->

To evaluate the effect of prompt design, we compare the clean direct prompt with the differential prompt under the same evidence package. Table [ref:tab:prompt-form-ablation] shows that the differential prompt slightly lowers precision from 0.807 to 0.799, but improves recall from 0.829 to 0.952 and F1 from 0.818 to 0.869. The direct prompt yields more conservative positive decisions because it requests a final attribution without requiring the model to compare target-component-defect and driver-misuse hypotheses. The differential prompt makes this comparison explicit, preserving target-component attributions when the visible crash location is ambiguous but the evidence supports a target-component defect. Accordingly, CrashSage uses the differential prompt as the default final prompt.

The project-level results in Table [ref:tab:per-library-final-prompt] provide a concrete example of this prompt sensitivity. Under V3, cJSON and json-c both obtain zero precision, recall, and F1. Under V4, cJSON reaches 1.0000 precision, 1.0000 recall, and 1.0000 F1, while json-c reaches 0.8571 precision, 0.4615 recall, and 0.6000 F1. These results indicate that the differential prompt can recover target-component attributions that the clean direct prompt fails to identify, although the improvement is project-dependent. By explicitly requiring a comparison between the target-component-defect and driver-misuse hypotheses, the differential prompt provides a more structured decision process for evidence that does not lead to a positive attribution under the direct prompt.

**Table: Effect of final prompt design under Qwen3-Coder-Plus.** (`tab:prompt-form-ablation`)

| **Variant** | **TP** | **FP** | **TN** | **FN** | **Precision** | **Recall** | **F1** |
|---|---|---|---|---|---|---|---|
| V3 (clean direct prompt) | 121 | 29 | 701 | 25 | 0.807 | 0.829 | 0.818 |
| V4 (differential prompt) | 139 | 35 | 695 | 7 | 0.799 | 0.952 | 0.869 |

<!-- END LEGACY PROMPT TEXT/TABLE TO REPLACE -->

**Table: Per-library effect of final prompt design under Qwen3-Coder-Plus.** (`tab:per-library-final-prompt`)

| **Library** | **V3** **Prec.** | **V3** **Recall** | **V3** **F1** | **V4** **Prec.** | **V4** **Recall** | **V4** **F1** |
|---|---|---|---|---|---|---|
| c-ares | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 1.0000 |
| cJSON | 0.0000 | 0.0000 | 0.0000 | 1.0000 | 1.0000 | 1.0000 |
| expat | 1.0000 | 0.5385 | 0.7000 | 0.6842 | 1.0000 | 0.8125 |
| faad2 | 0.6667 | 1.0000 | 0.8000 | 0.6667 | 1.0000 | 0.8000 |
| jansson | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 1.0000 |
| json-c | 0.0000 | 0.0000 | 0.0000 | 0.8571 | 0.4615 | 0.6000 |
| libmad | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 1.0000 |
| libmspack | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 1.0000 |
| libpcap | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 1.0000 |
| libsndfile | 0.8667 | 1.0000 | 0.9286 | 0.8667 | 1.0000 | 0.9286 |
| tinyxml2 | 0.4062 | 1.0000 | 0.5778 | 0.4062 | 1.0000 | 0.5778 |
| zlib | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 1.0000 |

> **【修改框 H｜RQ4 不同 LLM 后端的完整 V4 实验】**
>
> **怎么改：** 用以下内容替换旧版跨模型实验。所有行均固定当前 1,217 条报告对应的 96 个代表、上下文、differential prompt、映射关系和 ground truth，只替换最终 LLM 后端。将 Qwen3-Coder-Flash 写为 CrashSage V4 的默认配置行。
>
> **修改后的内容：**
>
> CrashSage-V4 outperforms V3 on the same 1,217 crash reports; the quantitative comparison is reported in the main ablation table.
>
> Furthermore, to evaluate whether the effectiveness of CrashSage-V4 depends on the final LLM backend, we repeat the V4 experiment with five additional LLMs. The representative crashes, reconstructed contexts, V4 prompt configuration, representative mapping, and ground-truth labels are held fixed; only the final LLM is replaced. All models are evaluated at temperature 0 on the same 96 representatives, and the decisions are expanded to the same 1,217 crash reports.
>
> The primary CrashSage-V4 model is `qwen3-coder-flash`, accessed on 1 November 2026 through the OpenAI-compatible endpoint `https://llm-1aqn2a1i6uz9t6gu.cn-beijing.maas.aliyuncs.com/compatible-mode/v1`. At the time of the experiments, this model was selected as a balanced choice considering its overall general and code-analysis performance, long-context capability, service stability, response latency, and API cost. The model choice was made independently of the evaluation results and was not tuned using the ground-truth labels.
>
> The alternative backends are `qwen-flash`, `qwen3.8-flash`, `deepseek-flash`, `gpt-5.6-sol`, and `glm-5.3-flash`, accessed between 30 October and 1 November 2026. Each backend was accessed through the OpenAI-compatible endpoint documented by its API provider for the corresponding model identifier; the provider-documented access endpoints are therefore not repeated here. Because these hosted services expose provider-managed model aliases rather than immutable weight revision identifiers, we report the exact API model identifiers and access dates and retain the corresponding model responses in the experiment archive to characterize the evaluated systems reproducibly. All calls used `temperature=0`. No explicit `top_p`, random seed, `max_tokens`, or forced JSON response format was specified. The request timeout was 300 seconds, except for the official DeepSeek client, which used 60 seconds. Automatic application-level re-sampling was disabled. Requests that failed or returned no processable response were recorded as failed attempts and explicitly resubmitted; these attempts were excluded from all model judgments. When structured-output extraction was required, it was performed on the original model response rather than by requesting an alternative decision.
>
> **Table: Effect of the final LLM backend under V4.** All configurations use the same V4 setting and are evaluated on 1,217 crash reports; only the final LLM is changed.
>
> | **LLM Backend** | **Precision** | **Recall** | **F1** |
> |---|---:|---:|---:|
> | Qwen3-Coder-Flash (default V4) | 0.7654 | 0.9256 | 0.8379 |
> | Qwen-Flash | 0.7425 | 0.9256 | 0.8240 |
> | Qwen3.8-Flash | 0.7636 | 0.9163 | 0.8330 |
> | DeepSeek-Flash | 0.7645 | 0.9209 | 0.8354 |
> | GPT-5.6-Sol | 0.7645 | 0.9209 | 0.8354 |
> | GLM-5.3-Flash | 0.7606 | 0.9163 | 0.8312 |
>
> The evaluated backends achieve closely matched overall performance. Model choice shifts individual attribution decisions and the precision--recall balance, but does not change the main conclusion that CrashSage-V4 remains effective when the final LLM backend is replaced.
>
> The results do not imply a strict monotonic relationship between model capability and aggregate performance. The backend should therefore be selected according to deployment constraints and the acceptable balance between missed target crashes and false alerts.
>
> **结果文件：**
>
> - 当前 V3/V4 汇总：`/home/cc/CKGFuzzer-1/fuzzing_llm_engine/results/v3v4_optimized_20261101/summary.csv`
> - Qwen-Flash：`/home/cc/CKGFuzzer-1/fuzzing_llm_engine/results/frozen_prompt_rerun_20261101/qwen-flash_current_gt_215/final/metrics.csv`
> - Qwen3.8-Flash、DeepSeek-Flash、GPT-5.6-Sol：`/home/cc/CKGFuzzer-1/fuzzing_llm_engine/results/frozen_prompt_rerun_20261101/current_v4_calibrated_20261101_final_v3/overall_metrics.csv`
> - GLM-5.3-Flash：`/home/cc/CKGFuzzer-1/fuzzing_llm_engine/results/frozen_prompt_rerun_20261101/glm-5.3-flash_current_v4_code/overall_metrics.csv`
>
> **对应审稿意见：** R1.6（模型版本、访问日期、调用参数与复现信息）；R2.4（固定 prompt 设置下的跨模型泛化）；同时关联 R1.7（prompt-component ablation 与 LLM-backend sensitivity）。

> **【修改框 M｜Raw-only LLM 端到端基线】**
>
> **怎么改：** 在 `Case Studies` 之前新增一个独立小节 **Comparison with a Raw-Report LLM Baseline**。该实验应放在所有 V0–V4 组件实验和 P0–P3 prompt 消融之后，但不并入任何现有编号体系，也不称为 V5。正文按“完整朴素基线 vs 完整 CrashSage”解释；各模块和 prompt 的独立贡献仍由前面的消融实验说明，不要把 raw-only 与 CrashSage 的全部差距单独归因于某一个模块。
>
> **修改后的内容：**
>
> **Comparison with a Raw-Report LLM Baseline.**
> To evaluate whether direct reasoning over raw crash reports is sufficient, we introduce a raw-only LLM baseline. Each of the 1,217 original reports is passed directly to `qwen3-coder-flash` at temperature 0 with a minimal direct instruction to decide whether the crash is attributable to a target-library defect. This condition does not apply rule-guided filtering or representative selection, does not provide static or runtime context, and does not use the differential prompt. Ground-truth labels and the final pass/fail decision protocol are otherwise identical to those used for CrashSage. This baseline is therefore an end-to-end naive reference rather than another step in the V0–V4 component ablation.
>
> **Table: Comparison with a raw-report LLM baseline.** Both methods are evaluated on the same 1,217 reports and ground-truth labels.
>
> | Method | Evidence input | LLM submissions | Precision | Recall | F1 |
> |---|---|---:|---:|---:|---:|
> | Raw-only LLM | Original sanitizer report only | 1,217 | 0.2010 | 0.5488 | 0.2943 |
> | CrashSage | Filtered and reconstructed representative evidence | 96 | 0.7654 | 0.9256 | 0.8379 |
>
> The raw-only baseline produces substantially lower precision and F1 than CrashSage, indicating that exposing the LLM to the complete raw report does not by itself provide reliable target/driver attribution. In particular, raw sanitizer traces often reveal where a failure becomes visible, but do not identify whether the driver violated an API contract or whether a target-side invariant failed. CrashSage raises precision and recall while reducing the number of LLM submissions from 1,217 to 96. The improvement of the complete method is therefore observed both in attribution quality and in the number of reports that require detailed LLM analysis. The component-level sources of this improvement are separately established by the V0–V4 and P0–P3 ablations.
>
> **结果文件：**
>
> - 汇总指标：`/home/cc/CKGFuzzer-1/fuzzing_llm_engine/results/review_gap_completion_20261101/raw_only_current_gt_metrics.csv`
> - 与 CrashSage 的直接对比：`/home/cc/CKGFuzzer-1/fuzzing_llm_engine/results/review_gap_completion_20261101/raw_only_vs_crashsage_current.csv`
> - 完整判定结果：`/home/cc/CKGFuzzer-1/fuzzing_llm_engine/results/raw_only_baseline_20261030/run/llm_bool_results.csv`
> - 原始模型响应：`/home/cc/CKGFuzzer-1/fuzzing_llm_engine/results/raw_only_baseline_20261030/run/llm_bool_results.jsonl`
> - 冻结 raw-only prompts：`/home/cc/CKGFuzzer-1/fuzzing_llm_engine/results/raw_only_baseline_20261030/prepared/prompts.jsonl`
>
> **对应审稿意见：** R1.5、R2.5（直接使用 raw report 的 LLM baseline、CKGFuzzer 基线边界与完整 CrashSage 的有效性比较）。

### Case Studies

To complement the quantitative results above, we present three case studies that illustrate how CrashSage prepares structured crash evidence before final LLM analysis. They are selected to match the three evaluation concerns studied above: false-alert judgment, efficiency, and crash localization.

Table [ref:tab:case-study-evidence] summarizes three case studies corresponding to the three evaluation concerns. In Case 1, the sanitizer reports a `heap-buffer-overflow`, but the top crashing frame and heap-boundary evidence are both confined to the generated driver.
The driver allocates a 20-byte `second_str` buffer and then writes the terminator after copying fuzz input into that buffer, so the faulty state is created before any target-component behavior needs to be considered.
CrashSage therefore treats this report as `likely_driver_bug` and filters it before LLM analysis, illustrating how rule-guided attribution prevents a driver memory error from being counted as a target-component crash candidate.

In Case 2, the libpcap reports form a repeated SEGV group rather than independent failures. The raw reports share similar crash-site evidence and stack signatures, and CrashSage records repeated reports in the `driver_30` group as duplicates of selected representative reports.
Representative selection therefore skips duplicate LLM submissions and reuses the representative mapping, providing a concrete instance of the RQ2 result: redundant SEGV reports are collapsed by signature evidence before final analysis.

**Table: Case studies for CrashSage evaluation** (`tab:case-study-evidence`)

| **Evidence** | **Case 1: False-alert judgment** | **Case 2: Efficiency** | **Case 3: Crash localization** |
|---|---|---|---|
| **Crash report** | cJSON `driver_4_crash_1` | libpcap `driver_30` group | json-c `driver_13_crash_1` |
| **Failure identity** | `heap-buffer-overflow` | repeated `SEGV` | `SEGV` wild write |
| **Attribution evidence** | top crashing frame: driver | shared crash-site / stack signature | project frame in `printbuf_memappend` |
| **Context or mapping** | 20-byte driver heap region | duplicate--representative pair; 10+ reports | state-sensitive `printbuf` context; replay confirmed |
| **Pipeline output** | `likely_driver_bug`; filtered | duplicate skipped; representative reused | context-supported `is_api_bug=true` result |

In Case 3, the raw prompt-based analysis does not return `is_api_bug=true` for the json-c crash, although the crash is labeled true under the ground-truth labels.
CrashSage changes this decision after reconstructing the state-sensitive context around `printbuf_memappend`.
The context records that the driver-created `printbuf` reaches the library with boundary-sensitive position and size fields.
Replay confirms that this state consistently reaches the same failing library path.
The reconstructed data flow shows that the generated driver directly sets `pb->bpos` near `INT_MAX` while keeping `pb->size` small before invoking `printbuf_memappend`.
The additional static and runtime context changes the raw-report-level negative result into an `is_api_bug=true` result consistent with the confirmed-target ground-truth label.

## Limitations

The current implementation follows one LLM-assisted fuzz-driver generation workflow and uses ASan+UBSan instrumentation. This setting is consistent across all evaluated variants, which keeps the comparison controlled, but other driver generators, prompt strategies, fuzzing engines, or sanitizer configurations may change the proportion of driver-induced crashes, duplicate reports, and target-component candidates. Extending CrashSage to additional driver-generation workflows and sanitizer combinations is left as future work.

Rule-guided crash attribution is based on a predefined set of deterministic rules over sanitizer signals and stack-frame roles. These rules are designed to conservatively remove reports with insufficient crash evidence or evidence more consistent with driver-induced failures, but their coverage is still bounded by the sanitizer information and stack structure available in each report. Crash-context reconstruction depends on replaying the crashing input and collecting runtime state in a stable execution environment. When replay fails or the reproduced crash does not match the original signature, CrashSage falls back to the normalized crash report and static context, which may reduce localization confidence. Different LLM capabilities or false-alert ratios may change the observed gains. CrashSage is therefore most appropriate as an evidence-preparation and attribution aid: it preserves reports that warrant further analysis and records the evidence used for each filtering or retention decision.

## Conclusion

CrashSage introduces an evidence-guided crash-adjudication pipeline for LLM-assisted fuzzing workloads. By applying rule-guided crash attribution, representative selection, and crash-context reconstruction before final LLM analysis, it replaces direct reasoning over raw crash reports with analysis over filtered, representative, and reconstructed crash evidence. In particular, representative selection reduces repeated crash instances before LLM analysis, and crash-context reconstruction combines static code context with replay-consistent runtime context for the selected representatives to distinguish the visible crash site from the origin and propagation of the faulty state. Evaluation on 1021 crash reports collected from 12 third-party open-source libraries, with 876 binary-evaluable reports used in the main evaluation, shows that CrashSage achieves 79.89% precision, 95.21% recall, and an 86.88% F1 score under ground-truth labels. The full pipeline also reduces end-to-end LLM submissions from 876 to 57 (93.49%). Rule-guided crash attribution and representative selection each require less than 10 ms per report, whereas crash-context reconstruction requires approximately 2--15 s and final LLM analysis uses 57 API calls. These results demonstrate that CrashSage improves attribution quality while substantially reducing redundant LLM submissions. Future work will extend the evaluation to additional driver-generation workflows and sanitizer configurations.

### Acknowledgements

Not applicable.

### Authors' contributions

Gaoqing Guan contributed to conceptualization, methodology, implementation, evaluation, and writing of the original draft. Ying Zhang, Letian Sha, and Huiran Yang contributed to experimental design, validation, result analysis and interpretation, and manuscript review and editing. All authors read and approved the final manuscript.

### Funding

Not applicable.

### Availability of data and materials

The data supporting the findings of this study are available from the corresponding author upon reasonable request.

## Declarations

### Competing interests

The authors declare that they have no known competing financial interests or personal relationships that could have appeared to influence the work reported in this paper.

## References

Bibliography source: `sn-bibliography.bib`
