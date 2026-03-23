# 需求文档：增强型Crash分析系统

## 简介

本需求文档定义了增强型Crash分析系统的功能需求。该系统旨在改进现有模糊测试crash分析模块，通过引入粗筛机制、精确代码定位、动态调试器集成、上下文关联分析、crash去重和测试用例最小化功能，显著减少误判率，提高分析质量，降低人工分析工作量。

系统将处理模糊测试产生的crash，通过多阶段分析流程识别真实漏洞，精确定位代码位置，收集运行时上下文，生成详细分析报告，并对crash进行去重和测试用例最小化。

## 术语表

- **Crash_Analysis_System**: 增强型crash分析系统，本文档描述的主要系统
- **Triage_Engine**: 粗筛引擎，负责快速过滤非真实漏洞的crash
- **Locator**: 精确定位引擎，负责将crash定位到具体代码位置
- **Debugger**: 动态调试器集成组件，负责复现crash并收集运行时信息
- **Analyzer**: 增强型分析器，负责整合所有信息进行深度分析
- **Dedup_Engine**: 去重引擎，负责识别和合并重复的crash
- **Minimizer**: 测试用例最小化引擎，负责最小化触发crash的输入
- **CrashInfo**: 包含crash原始信息的数据结构
- **TriageResult**: 粗筛结果数据结构
- **LocationResult**: 精确定位结果数据结构
- **RuntimeContext**: 运行时上下文数据结构
- **EnhancedAnalysis**: 增强分析结果数据结构
- **CrashSignature**: crash签名，用于去重
- **POC**: Proof of Concept，触发crash的测试输入
- **Sanitizer**: 内存错误检测工具（如ASan、MSan、UBSan）

## 需求

### 需求1：Crash粗筛

**用户故事**：作为安全研究人员，我希望系统能够快速过滤掉非真实漏洞的crash，以便我可以专注于分析真正的安全问题。

#### 验收标准

1. WHEN接收到包含sanitizer输出和栈信息的CrashInfo时，THE Triage_Engine SHALL在100毫秒内返回TriageResult
2. WHEN粗筛判断crash为非真实漏洞时，THE Triage_Engine SHALL提供至少一条支持证据
3. THE TriageResult SHALL包含置信度值，且该值在0.0到1.0范围内
4. WHEN粗筛完成时，THE Triage_Engine SHALL记录所有匹配的规则名称
5. WHEN检测到模糊驱动本身的未初始化变量时，THE Triage_Engine SHALL将crash标记为非真实漏洞
6. WHEN检测到模糊驱动引起的栈溢出（驱动帧占比超过80%）时，THE Triage_Engine SHALL将crash标记为非真实漏洞
7. WHEN检测到已知的sanitizer误报模式时，THE Triage_Engine SHALL将crash标记为非真实漏洞
8. WHEN检测到API代码中的内存错误时，THE Triage_Engine SHALL将crash标记为真实漏洞并设置高置信度（≥0.9）

### 需求2：精确代码定位

**用户故事**：作为开发人员，我希望系统能够精确定位crash发生的代码位置，以便我可以快速定位和修复问题。

#### 验收标准

1. WHEN接收到CrashInfo和二进制文件路径时，THE Locator SHALL返回包含文件路径、行号和函数名的LocationResult
2. THE LocationResult SHALL包含至少一个有效的栈帧，且每个栈帧的行号为正整数
3. WHEN二进制文件包含调试符号时，THE Locator SHALL使用llvm-symbolizer或addr2line进行符号化
4. WHEN符号化成功时，THE Locator SHALL提取crash位置周围的代码片段（默认前后10行）
5. WHEN符号化失败时，THE Locator SHALL返回地址信息并在code_snippet中说明"符号信息不可用"
6. THE Locator SHALL解析完整的调用栈并为每个关键帧提供代码上下文
7. WHEN处理栈回溯时，THE Locator SHALL优先处理前10个栈帧以优化性能
8. THE Locator SHALL在500毫秒内完成单个crash的定位

### 需求3：动态Crash复现

**用户故事**：作为安全分析师，我希望系统能够自动复现crash并收集运行时信息，以便我可以深入理解crash的根本原因。

#### 验收标准

1. WHEN接收到POC文件路径和二进制文件路径时，THE Debugger SHALL使用GDB或LLDB尝试复现crash
2. WHEN复现成功时，THE Debugger SHALL返回包含运行时上下文的ReproductionResult
3. THE RuntimeContext SHALL包含crash点的局部变量、寄存器状态和内存区域信息
4. THE RuntimeContext SHALL包含完整的调用栈，每个调用帧包含函数名、参数和局部变量
5. WHEN复现失败时，THE Debugger SHALL在error_message中记录失败原因
6. THE Debugger SHALL设置5秒的默认超时时间，防止无限等待
7. WHEN超时发生时，THE Debugger SHALL终止调试会话并返回失败结果
8. THE Debugger SHALL在10秒内完成单个crash的复现尝试
9. WHEN复现失败时，THE Debugger SHALL最多重试3次

### 需求4：增强型Crash分析

**用户故事**：作为安全团队负责人，我希望系统能够整合所有信息进行深度分析，以便我可以获得全面的crash分析报告和修复建议。

#### 验收标准

1. WHEN接收到CrashInfo、LocationResult、RuntimeContext和TriageResult时，THE Analyzer SHALL生成EnhancedAnalysis
2. THE EnhancedAnalysis SHALL包含crash类别、根本原因、严重程度和可利用性评估
3. THE EnhancedAnalysis SHALL包含严重程度字段，且该值必须为"critical"、"high"、"medium"或"low"之一
4. WHEN分析判断为API bug时，THE Analyzer SHALL提供至少一条修复建议
5. THE Analyzer SHALL生成包含所有上下文信息的LLM提示
6. WHEN LLM分析成功时，THE Analyzer SHALL提取根本原因和修复建议
7. WHEN LLM API调用失败时，THE Analyzer SHALL使用基于规则的备用分析
8. WHEN LLM API调用超时时，THE Analyzer SHALL使用指数退避重试最多3次
9. THE Analyzer SHALL在30秒内完成单个crash的LLM分析
10. THE RootCause SHALL包含漏洞类型、触发位置和触发条件

### 需求5：Crash去重

**用户故事**：作为测试工程师，我希望系统能够识别重复的crash，以便我可以避免重复分析相同的问题。

#### 验收标准

1. WHEN接收到CrashInfo和LocationResult时，THE Dedup_Engine SHALL计算唯一的crash签名
2. THE CrashSignature SHALL基于栈哈希、crash类型、crash位置和函数调用序列计算
3. WHEN使用相同输入计算签名时，THE Dedup_Engine SHALL总是返回相同的签名（确定性）
4. THE Dedup_Engine SHALL使用SHA256算法生成64字符的十六进制签名
5. WHEN计算签名时，THE Dedup_Engine SHALL过滤掉模糊驱动帧和库函数帧
6. WHEN查找相似crash时，THE Dedup_Engine SHALL使用可配置的相似度阈值（默认0.85）
7. WHEN发现相似crash时，THE Dedup_Engine SHALL将它们合并到同一个crash簇中
8. THE Dedup_Engine SHALL在200毫秒内完成单个crash的去重处理
9. WHEN crash A与crash B相似且crash B与crash C相似时，THE Dedup_Engine SHALL确保crash A和crash C在同一簇中（传递性）

### 需求6：测试用例最小化

**用户故事**：作为漏洞修复人员，我希望系统能够最小化触发crash的输入，以便我可以更容易地理解和修复问题。

#### 验收标准

1. WHEN接收到POC文件路径和二进制文件路径时，THE Minimizer SHALL使用delta debugging算法最小化输入
2. THE MinimizationResult SHALL包含原始大小、最小化后大小和减少比例
3. WHEN最小化完成时，THE Minimizer SHALL验证最小化后的输入仍能触发相同的crash
4. WHEN验证失败时，THE Minimizer SHALL设置verification_passed为False并使用原始POC
5. THE Minimizer SHALL确保最小化后的大小不大于原始大小
6. THE Minimizer SHALL正确计算减少比例：reduction_ratio = 1 - (minimized_size / original_size)
7. THE Minimizer SHALL设置最大迭代次数限制为100次
8. WHEN最小化过程中crash行为改变时，THE Minimizer SHALL停止最小化并标记为"不可最小化"
9. THE Minimizer SHALL在60秒内完成单个crash的最小化
10. WHEN处理大文件（>10MB）时，THE Minimizer SHALL先进行粗粒度最小化

### 需求7：数据验证

**用户故事**：作为系统架构师，我希望系统能够验证所有输入和输出数据的完整性，以便我可以确保系统的可靠性和安全性。

#### 验收标准

1. WHEN创建CrashInfo时，THE Crash_Analysis_System SHALL验证crash_id的唯一性
2. WHEN创建CrashInfo时，THE Crash_Analysis_System SHALL验证timestamp为有效的ISO格式
3. WHEN创建CrashInfo时，THE Crash_Analysis_System SHALL验证sanitizer_output非空
4. WHEN创建CrashInfo时，THE Crash_Analysis_System SHALL验证signal_type在预定义列表中
5. WHEN创建TriageResult时，THE Crash_Analysis_System SHALL验证confidence在0.0到1.0范围内
6. WHEN创建LocationResult时，THE Crash_Analysis_System SHALL验证line_number为正整数
7. WHEN创建LocationResult时，THE Crash_Analysis_System SHALL验证stack_frames至少包含一个帧
8. WHEN创建RuntimeContext时，THE Crash_Analysis_System SHALL验证registers包含常见寄存器（rip/eip, rsp/esp）
9. WHEN创建EnhancedAnalysis时，THE Crash_Analysis_System SHALL验证severity在预定义列表中
10. WHEN创建MinimizationResult时，THE Crash_Analysis_System SHALL验证minimized_size不大于original_size

### 需求8：错误处理和恢复

**用户故事**：作为系统运维人员，我希望系统能够优雅地处理各种错误情况，以便系统可以持续稳定运行。

#### 验收标准

1. WHEN粗筛引擎无法判断crash时，THE Triage_Engine SHALL返回默认结果（is_real_bug=True, confidence=0.5）
2. WHEN符号化失败时，THE Locator SHALL返回只包含地址信息的LocationResult并继续分析
3. WHEN动态调试器复现失败时，THE Debugger SHALL记录失败原因并继续后续分析
4. WHEN LLM分析失败时，THE Analyzer SHALL使用基于规则的备用分析
5. WHEN去重数据库损坏时，THE Dedup_Engine SHALL尝试从备份恢复，如失败则重建空数据库
6. WHEN文件系统权限错误时，THE Crash_Analysis_System SHALL记录详细错误信息并将crash标记为"处理失败"
7. WHEN任何组件发生错误时，THE Crash_Analysis_System SHALL记录错误日志并继续处理下一个crash
8. WHEN检测到资源耗尽时，THE Crash_Analysis_System SHALL限制并发处理数量

### 需求9：性能要求

**用户故事**：作为系统管理员，我希望系统能够高效处理大量crash，以便我可以及时发现和修复安全问题。

#### 验收标准

1. THE Crash_Analysis_System SHALL达到每小时处理100个以上crash的吞吐量
2. THE Triage_Engine SHALL在100毫秒内完成单个crash的粗筛
3. THE Locator SHALL在500毫秒内完成单个crash的精确定位
4. THE Debugger SHALL在10秒内完成单个crash的复现尝试
5. THE Analyzer SHALL在30秒内完成单个crash的LLM分析
6. THE Dedup_Engine SHALL在200毫秒内完成单个crash的去重处理
7. THE Minimizer SHALL在60秒内完成单个crash的测试用例最小化
8. WHEN系统负载较高时，THE Crash_Analysis_System SHALL使用多进程并行处理crash
9. THE Crash_Analysis_System SHALL限制每个分析进程的最大内存使用为2GB
10. THE Crash_Analysis_System SHALL支持最多CPU核心数的并发分析任务

### 需求10：安全要求

**用户故事**：作为安全官，我希望系统能够安全地处理潜在恶意的输入，以便我可以保护分析环境不受攻击。

#### 验收标准

1. THE Crash_Analysis_System SHALL在沙箱环境（Docker容器）中执行所有POC
2. THE Crash_Analysis_System SHALL限制POC文件大小不超过100MB
3. THE Crash_Analysis_System SHALL为所有外部程序执行设置严格的超时时间
4. THE Crash_Analysis_System SHALL使用非特权用户运行所有分析进程
5. THE Crash_Analysis_System SHALL限制分析进程的文件系统访问权限
6. THE Crash_Analysis_System SHALL过滤运行时上下文中的敏感数据（密钥、凭证等）
7. THE Crash_Analysis_System SHALL使用AES-256加密存储敏感的crash数据
8. THE Crash_Analysis_System SHALL使用HTTPS与LLM API通信
9. WHEN检测到恶意模式时，THE Crash_Analysis_System SHALL拒绝处理并记录安全事件
10. THE Crash_Analysis_System SHALL定期清理临时文件和容器

### 需求11：可扩展性

**用户故事**：作为系统开发者，我希望系统具有良好的可扩展性，以便我可以添加新的分析规则和功能。

#### 验收标准

1. THE Triage_Engine SHALL支持通过add_rule方法动态添加新的粗筛规则
2. THE Crash_Analysis_System SHALL支持插件式的分析器扩展
3. THE Dedup_Engine SHALL支持多种去重策略（精确匹配、模糊匹配）
4. THE Minimizer SHALL支持多种最小化策略配置
5. THE Crash_Analysis_System SHALL提供配置文件支持所有关键参数的自定义
6. THE Crash_Analysis_System SHALL支持自定义LLM提示模板
7. THE Crash_Analysis_System SHALL提供API接口供外部系统集成

### 需求12：可观测性

**用户故事**：作为运维工程师，我希望系统能够提供详细的日志和监控指标，以便我可以了解系统运行状态和性能瓶颈。

#### 验收标准

1. THE Crash_Analysis_System SHALL记录所有关键操作的详细日志
2. THE Crash_Analysis_System SHALL为每个处理阶段记录耗时指标
3. THE Crash_Analysis_System SHALL记录资源使用情况（CPU、内存、磁盘）
4. THE Crash_Analysis_System SHALL提供Prometheus兼容的指标接口
5. WHEN发生错误时，THE Crash_Analysis_System SHALL记录完整的错误堆栈和上下文
6. THE Crash_Analysis_System SHALL支持可配置的日志级别（DEBUG、INFO、WARNING、ERROR）
7. THE Crash_Analysis_System SHALL定期输出处理统计信息（成功率、平均耗时等）
