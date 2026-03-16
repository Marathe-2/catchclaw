# LobsterGuard v4.0 Architecture Plan

> 版本: v4.0.0-draft | 日期: 2026-03-16
> 基于: v3.0.0 (49 chains, 48 exploit modules, 13 packages)

---

## 一、总体架构变更概览

### 版本对比

| 维度 | v3.0.0 (当前) | v4.0.0 (规划) |
|------|--------------|--------------|
| 攻击链 | 49 (DAG) | 65+ (扩展 DAG + AI 推荐) |
| Exploit 模块 | 48 | 62+ |
| 包数量 | 13 | 18 (+fuzzer, cve, concurrent, ws, prompt) |
| MCP Tools | 8 (3 未实现) | 14 (全部实现) |
| MCP Resources | 0 | 6 |
| MCP Prompts | 0 | 4 |
| AI 模式 | 3 (triage/attack-path/remediation) | 8+ |
| 最大并发 | 20 (aggressive) | 200 (ultra-aggressive, 可配置池) |
| 报告格式 | JSON | JSON / Markdown / HTML / SARIF |
| 实时推送 | 无 | WebSocket + SSE |

### 新增包结构

```
lobster-guard/
├── pkg/
│   ├── ai/                    # [扩展] AI 增强模块
│   │   ├── analyzer.go        # [改造] 结构化输出 + 多模型
│   │   ├── fuzzer.go          # [新增] AI Fuzzing 引擎
│   │   ├── prompt_detector.go # [新增] LLM Prompt Injection 检测
│   │   ├── chain_recommender.go # [新增] 攻击链推荐引擎
│   │   ├── report_gen.go      # [新增] AI 报告生成器
│   │   └── provider.go        # [新增] 多模型 Provider 抽象
│   ├── concurrent/            # [新包] 高并发扫描引擎
│   │   ├── pool.go            # Worker pool
│   │   ├── scheduler.go       # 渐进式调度器
│   │   └── limiter.go         # 自适应速率限制
│   ├── cve/                   # [新包] CVE 数据库
│   │   ├── lookup.go          # CVE 查询
│   │   ├── mapper.go          # Finding -> CVE 映射
│   │   └── db.go              # 本地 CVE 缓存
│   ├── ws/                    # [新包] WebSocket/SSE 实时推送
│   │   ├── server.go          # WS/SSE Server
│   │   ├── hub.go             # 连接管理
│   │   └── events.go          # 事件定义
│   ├── mcp/                   # [扩展] MCP 深度集成
│   │   ├── server.go          # [改造] MCP 2.0 完整实现
│   │   ├── resources.go       # [新增] MCP Resources
│   │   ├── prompts.go         # [新增] MCP Prompts
│   │   └── store.go           # [新增] 结果存储
│   └── ... (现有包保持不变)
```

---

## 二、AI 增强模块 (`pkg/ai/`)

### 2.1 Provider 抽象层 (`pkg/ai/provider.go`)

**动机**: 当前 `analyzer.go` 直接硬编码 Anthropic/OpenAI 两个 HTTP client (L185-256)，
新增模型需要逐个方法修改。抽象出 Provider 接口实现多模型对比。

```go
// Provider 抽象 LLM API 调用
type Provider interface {
    // Name 返回 provider 标识 (如 "anthropic", "openai", "ollama")
    Name() string
    // Complete 发送 prompt 并返回结构化结果
    Complete(ctx context.Context, req CompletionRequest) (*CompletionResponse, error)
    // Available 检查 API key 是否配置
    Available() bool
}

// CompletionRequest LLM 请求
type CompletionRequest struct {
    SystemPrompt string            `json:"system_prompt"`
    UserPrompt   string            `json:"user_prompt"`
    MaxTokens    int               `json:"max_tokens"`
    Temperature  float64           `json:"temperature"`
    JSONMode     bool              `json:"json_mode"` // 强制 JSON 输出
    Model        string            `json:"model,omitempty"` // 覆盖默认模型
}

// CompletionResponse LLM 响应
type CompletionResponse struct {
    Content    string        `json:"content"`
    TokensUsed int           `json:"tokens_used"`
    Latency    time.Duration `json:"latency"`
    Provider   string        `json:"provider"`
    Model      string        `json:"model"`
}

// AnthropicProvider Anthropic Claude 实现
type AnthropicProvider struct {
    APIKey  string
    BaseURL string
    Model   string
    Timeout time.Duration
}

func NewAnthropicProvider() *AnthropicProvider
func (p *AnthropicProvider) Name() string
func (p *AnthropicProvider) Complete(ctx context.Context, req CompletionRequest) (*CompletionResponse, error)
func (p *AnthropicProvider) Available() bool

// OpenAIProvider OpenAI/兼容 API 实现
type OpenAIProvider struct {
    APIKey  string
    BaseURL string
    Model   string
    Timeout time.Duration
}

func NewOpenAIProvider() *OpenAIProvider
func (p *OpenAIProvider) Name() string
func (p *OpenAIProvider) Complete(ctx context.Context, req CompletionRequest) (*CompletionResponse, error)
func (p *OpenAIProvider) Available() bool

// OllamaProvider 本地 Ollama 实现 (新增)
type OllamaProvider struct {
    BaseURL string // 默认 http://localhost:11434
    Model   string // 默认 llama3
    Timeout time.Duration
}

func NewOllamaProvider() *OllamaProvider
func (p *OllamaProvider) Name() string
func (p *OllamaProvider) Complete(ctx context.Context, req CompletionRequest) (*CompletionResponse, error)
func (p *OllamaProvider) Available() bool

// MultiProvider 多模型对比 (自动选择最优)
type MultiProvider struct {
    Providers []Provider
    Strategy  SelectionStrategy // "first-available" | "fastest" | "consensus"
}

func NewMultiProvider(providers ...Provider) *MultiProvider
func (p *MultiProvider) Name() string
func (p *MultiProvider) Complete(ctx context.Context, req CompletionRequest) (*CompletionResponse, error)
func (p *MultiProvider) CompareAll(ctx context.Context, req CompletionRequest) ([]*CompletionResponse, error)
func (p *MultiProvider) Available() bool
```

### 2.2 Analyzer 增强 (`pkg/ai/analyzer.go` 改造)

**改造点**: 替换当前 `callAnthropic`/`callOpenAI` 直接调用为 Provider 接口，
增加结构化输出模式和多模型对比。

```go
// Analyzer v4 — 基于 Provider 抽象的 AI 分析器
type Analyzer struct {
    provider Provider          // 替换原有 Provider/Model/APIKey/BaseURL
    Timeout  time.Duration
    store    *ResultStore      // 结果持久化
}

// AnalysisResult v4 结构化输出 (扩展现有)
type AnalysisResult struct {
    Summary          string              `json:"summary"`
    CriticalPaths    []AttackPath        `json:"critical_paths"`     // 改为结构化
    AttackChains     []ChainRecommend    `json:"attack_chains"`      // 改为结构化
    Recommendations  []Recommendation    `json:"recommendations"`    // 改为结构化
    RiskScore        int                 `json:"risk_score"`
    FalsePositives   []FalsePositive     `json:"false_positives,omitempty"`
    CVEMappings      []CVEMapping        `json:"cve_mappings,omitempty"`     // 新增
    ComplianceIssues []ComplianceIssue   `json:"compliance_issues,omitempty"` // 新增
    ProviderMeta     CompletionResponse  `json:"provider_meta,omitempty"`     // 新增
}

// AttackPath 结构化攻击路径
type AttackPath struct {
    ID          string   `json:"id"`
    Name        string   `json:"name"`
    Steps       []string `json:"steps"`        // 攻击步骤序列
    ChainIDs    []int    `json:"chain_ids"`     // 对应 DAG 节点 ID
    Probability float64  `json:"probability"`   // 成功概率 0-1
    Impact      string   `json:"impact"`        // 影响描述
    Severity    string   `json:"severity"`
}

// ChainRecommend AI 推荐的攻击链
type ChainRecommend struct {
    ChainID    int      `json:"chain_id"`
    Priority   int      `json:"priority"`    // 1=最高
    Reason     string   `json:"reason"`
    PreReqs    []int    `json:"prereqs"`     // 前置链 ID
    EstTime    string   `json:"est_time"`    // 预估耗时
}

// Recommendation 修复建议
type Recommendation struct {
    Finding     string `json:"finding"`
    Priority    int    `json:"priority"`
    Action      string `json:"action"`
    Effort      string `json:"effort"`      // "low" | "medium" | "high"
    Reference   string `json:"reference"`   // URL/文档引用
}

// FalsePositive 误报标记
type FalsePositive struct {
    FindingIdx int    `json:"finding_idx"`
    Reason     string `json:"reason"`
    Confidence float64 `json:"confidence"` // 0-1
}

// CVEMapping Finding 到 CVE 的映射
type CVEMapping struct {
    FindingIdx int    `json:"finding_idx"`
    CVEID      string `json:"cve_id"`
    CVSS       float64 `json:"cvss"`
    Confidence float64 `json:"confidence"`
}

func NewAnalyzer() *Analyzer
func (a *Analyzer) AnalyzeFindings(ctx context.Context, findings []utils.Finding, mode string) (*AnalysisResult, error)
func (a *Analyzer) CompareAnalysis(ctx context.Context, findings []utils.Finding) (map[string]*AnalysisResult, error)
func (a *Analyzer) localAnalysis(findings []utils.Finding, mode string) *AnalysisResult
```

**新增分析模式**:

| 模式 | 说明 | System Prompt 关键指令 |
|------|------|----------------------|
| `triage` | 分级分类 (保留) | Triage by severity and urgency |
| `attack-path` | 攻击路径 (保留) | Link findings into exploitation paths |
| `remediation` | 修复建议 (保留) | Prioritized remediation recommendations |
| `compare` | 多模型对比 (新增) | 同时调多模型，比较结果差异 |
| `compliance` | 合规检查 (新增) | Map to OWASP/CWE/NIST frameworks |
| `executive` | 管理层摘要 (新增) | Non-technical executive summary |
| `exploit-dev` | 利用开发辅助 (新增) | Generate PoC skeleton from findings |
| `threat-model` | 威胁建模 (新增) | STRIDE-based threat modeling |

### 2.3 AI Fuzzing 引擎 (`pkg/ai/fuzzer.go`)

**动机**: 用 LLM 生成智能 fuzzing payload，特别针对 OpenClaw 的 MCP 消息格式和 prompt 处理。

```go
// AIFuzzer 用 LLM 生成和变异 fuzzing payload
type AIFuzzer struct {
    provider  Provider
    templates []FuzzTemplate
    store     *ResultStore
}

// FuzzTemplate 定义 fuzzing 目标模板
type FuzzTemplate struct {
    Name        string            `json:"name"`
    Target      string            `json:"target"`      // "mcp_message" | "ws_frame" | "http_param" | "prompt"
    BasePayload string            `json:"base_payload"` // 基础 payload 模板
    Mutations   []string          `json:"mutations"`    // 变异类型
    Constraints map[string]string `json:"constraints"`  // 约束条件
}

// FuzzResult 单次 fuzzing 结果
type FuzzResult struct {
    Payload    string        `json:"payload"`
    Response   string        `json:"response"`
    StatusCode int           `json:"status_code"`
    Latency    time.Duration `json:"latency"`
    Anomaly    bool          `json:"anomaly"`      // 异常检测
    AnomalyType string      `json:"anomaly_type"` // "crash" | "timeout" | "error_leak" | "behavior_change"
    Finding    *utils.Finding `json:"finding,omitempty"`
}

// FuzzCampaign 完整 fuzzing 活动
type FuzzCampaign struct {
    ID        string        `json:"id"`
    Template  FuzzTemplate  `json:"template"`
    Target    utils.Target  `json:"target"`
    Results   []FuzzResult  `json:"results"`
    StartTime time.Time     `json:"start_time"`
    EndTime   time.Time     `json:"end_time"`
    Stats     FuzzStats     `json:"stats"`
}

// FuzzStats fuzzing 统计
type FuzzStats struct {
    TotalPayloads   int `json:"total_payloads"`
    Anomalies       int `json:"anomalies"`
    UniqueFindings  int `json:"unique_findings"`
    CoveragePercent int `json:"coverage_percent"`
}

func NewAIFuzzer(provider Provider) *AIFuzzer

// GeneratePayloads 用 LLM 生成特定目标的 fuzzing payloads
func (f *AIFuzzer) GeneratePayloads(ctx context.Context, template FuzzTemplate, count int) ([]string, error)

// MutatePayload 用 LLM 对已知有效 payload 做智能变异
func (f *AIFuzzer) MutatePayload(ctx context.Context, payload string, mutationType string) ([]string, error)

// RunCampaign 执行完整 fuzzing 活动
func (f *AIFuzzer) RunCampaign(ctx context.Context, target utils.Target, template FuzzTemplate, cfg FuzzConfig) (*FuzzCampaign, error)

// AnalyzeAnomalies 用 AI 分析异常响应是否构成安全漏洞
func (f *AIFuzzer) AnalyzeAnomalies(ctx context.Context, results []FuzzResult) ([]utils.Finding, error)

// FuzzConfig fuzzing 配置
type FuzzConfig struct {
    MaxPayloads    int           `json:"max_payloads"`
    Concurrency    int           `json:"concurrency"`
    Timeout        time.Duration `json:"timeout"`
    StopOnCrash    bool          `json:"stop_on_crash"`
    TokenForAuth   string        `json:"token"`
}
```

**内置 FuzzTemplate 集**:

1. `mcp_json_rpc` — MCP JSON-RPC 消息格式 fuzzing
2. `ws_chat_message` — WebSocket 聊天消息 fuzzing
3. `http_api_params` — HTTP API 参数 fuzzing
4. `prompt_injection` — Prompt injection payload 生成
5. `unicode_edge_cases` — Unicode 边界情况
6. `json_structure` — JSON 结构变异

### 2.4 LLM Prompt Injection 检测 (`pkg/ai/prompt_detector.go`)

**动机**: OpenClaw 是 AI 平台，prompt injection 是核心攻击面。
当前 `prompt_inject.go` (pkg/exploit/) 用硬编码 payload，需要 AI 增强。

```go
// PromptInjectionDetector 检测 OpenClaw 的 prompt injection 防护
type PromptInjectionDetector struct {
    provider Provider
    payloads []PromptPayload
}

// PromptPayload prompt injection 测试用例
type PromptPayload struct {
    ID          string `json:"id"`
    Category    string `json:"category"`    // "direct" | "indirect" | "jailbreak" | "encoding" | "context_switch"
    Payload     string `json:"payload"`
    Description string `json:"description"`
    Expected    string `json:"expected"`    // 预期行为
}

// PromptTestResult 单次测试结果
type PromptTestResult struct {
    Payload     PromptPayload `json:"payload"`
    Response    string        `json:"response"`
    Injected    bool          `json:"injected"`     // 是否注入成功
    Confidence  float64       `json:"confidence"`   // 0-1
    Technique   string        `json:"technique"`    // 使用的注入技术
    AIAnalysis  string        `json:"ai_analysis"`  // AI 对结果的分析
}

func NewPromptInjectionDetector(provider Provider) *PromptInjectionDetector

// GeneratePayloads 用 AI 生成针对目标系统的 prompt injection payloads
func (d *PromptInjectionDetector) GeneratePayloads(ctx context.Context, systemPromptHints string, count int) ([]PromptPayload, error)

// TestInjection 对目标执行 prompt injection 测试
func (d *PromptInjectionDetector) TestInjection(ctx context.Context, target utils.Target, token string, payload PromptPayload) (*PromptTestResult, error)

// RunSuite 执行完整 prompt injection 测试套件
func (d *PromptInjectionDetector) RunSuite(ctx context.Context, target utils.Target, token string, cfg PromptTestConfig) ([]PromptTestResult, error)

// AnalyzeDefenses 分析目标的 prompt injection 防御机制
func (d *PromptInjectionDetector) AnalyzeDefenses(ctx context.Context, results []PromptTestResult) (*DefenseAnalysis, error)

// DefenseAnalysis prompt injection 防御分析
type DefenseAnalysis struct {
    HasInputFilter    bool     `json:"has_input_filter"`
    HasOutputFilter   bool     `json:"has_output_filter"`
    HasSystemGuard    bool     `json:"has_system_guard"`
    BypassTechniques  []string `json:"bypass_techniques"`
    DefenseScore      int      `json:"defense_score"`     // 0-100
    Recommendations   []string `json:"recommendations"`
}

// PromptTestConfig 测试配置
type PromptTestConfig struct {
    Categories   []string      // 测试类别过滤
    MaxPayloads  int
    Concurrency  int
    Timeout      time.Duration
    UseAIGen     bool          // 是否用 AI 生成额外 payload
    AdaptPayload bool          // 根据前序结果自适应调整
}
```

**内置 Prompt Injection 类别**:

| 类别 | 技术 | 示例 |
|------|------|------|
| `direct` | 直接覆盖 system prompt | "Ignore previous instructions..." |
| `indirect` | 通过数据投毒间接注入 | 在 MCP resource 中嵌入指令 |
| `jailbreak` | 绕过安全限制 | DAN/AIM 变体 |
| `encoding` | 编码绕过 | Base64/Unicode/HTML entity |
| `context_switch` | 上下文切换 | 模拟工具输出/系统消息 |
| `multi_turn` | 多轮对话积累 | 渐进式权限升级 |
| `tool_abuse` | 利用工具调用注入 | MCP tool 参数注入 |

### 2.5 攻击链推荐引擎 (`pkg/ai/chain_recommender.go`)

**动机**: 当前 DAG 按拓扑序全量执行。v4 可基于指纹结果智能推荐最有效的攻击子集。

```go
// ChainRecommender 基于扫描结果推荐最佳攻击路径
type ChainRecommender struct {
    provider Provider
    dagInfo  DAGInfo // 预计算的 DAG 元信息
}

// DAGInfo DAG 静态分析信息
type DAGInfo struct {
    TotalNodes  int                    `json:"total_nodes"`
    Categories  map[string][]int       `json:"categories"`   // category -> chain IDs
    DepGraph    map[int][]int          `json:"dep_graph"`    // chain ID -> depends on
    SevMap      map[int]string         `json:"sev_map"`      // chain ID -> expected severity
}

// RecommendRequest 推荐请求
type RecommendRequest struct {
    FingerprintData  map[string]interface{} `json:"fingerprint"`  // 指纹结果
    KnownFindings    []utils.Finding        `json:"known_findings"`
    TimeLimit        time.Duration          `json:"time_limit"`   // 可用时间
    AggressiveLevel  int                    `json:"aggressive"`   // 1-5
    ExcludeChains    []int                  `json:"exclude"`      // 已尝试/排除的链
}

// RecommendResult 推荐结果
type RecommendResult struct {
    RecommendedChains []ChainRecommend    `json:"recommended_chains"`
    ExecutionOrder    []int               `json:"execution_order"` // 推荐执行顺序
    EstimatedTime     time.Duration       `json:"estimated_time"`
    Rationale         string              `json:"rationale"`       // 推荐理由
    SkipReasons       map[int]string      `json:"skip_reasons"`   // 跳过的链及原因
}

func NewChainRecommender(provider Provider) *ChainRecommender

// Recommend 基于当前状态推荐攻击链
func (r *ChainRecommender) Recommend(ctx context.Context, req RecommendRequest) (*RecommendResult, error)

// AdaptiveRecommend 在扫描过程中动态调整推荐
func (r *ChainRecommender) AdaptiveRecommend(ctx context.Context, req RecommendRequest, onNewFinding func(utils.Finding)) (*RecommendResult, error)

// BuildDAGInfo 从 BuildFullDAG 提取静态 DAG 信息
func BuildDAGInfo() DAGInfo
```

### 2.6 AI 报告生成 (`pkg/ai/report_gen.go`)

```go
// ReportGenerator 用 AI 生成自然语言安全报告
type ReportGenerator struct {
    provider Provider
}

// ReportConfig 报告配置
type ReportConfig struct {
    Format    string // "markdown" | "html" | "sarif" | "pdf"
    Audience  string // "technical" | "executive" | "compliance"
    Language  string // "en" | "zh"
    Template  string // 自定义模板路径 (可选)
    IncludeAI bool   // 是否包含 AI 分析
}

// GeneratedReport 生成的报告
type GeneratedReport struct {
    Title     string `json:"title"`
    Content   string `json:"content"`
    Format    string `json:"format"`
    Metadata  ReportMeta `json:"metadata"`
}

type ReportMeta struct {
    Target       string    `json:"target"`
    ScanTime     time.Time `json:"scan_time"`
    TotalFindings int      `json:"total_findings"`
    RiskScore    int       `json:"risk_score"`
    ToolVersion  string    `json:"tool_version"`
}

func NewReportGenerator(provider Provider) *ReportGenerator

// Generate 生成完整安全报告
func (g *ReportGenerator) Generate(ctx context.Context, scanResult *utils.ScanResult, analysis *AnalysisResult, cfg ReportConfig) (*GeneratedReport, error)

// GenerateExecutiveSummary 生成管理层摘要
func (g *ReportGenerator) GenerateExecutiveSummary(ctx context.Context, findings []utils.Finding) (string, error)

// GenerateSARIF 生成 SARIF 格式报告 (CI/CD 集成)
func (g *ReportGenerator) GenerateSARIF(findings []utils.Finding) ([]byte, error)
```

---

## 三、MCP 深度集成 (`pkg/mcp/`)

### 3.1 Server 改造 (`pkg/mcp/server.go`)

**当前问题**:
- 3 个 handler 返回 `not_implemented` (`handleRecon`, `handleDiscover`, `handleReport`)
- `handleAIAnalyze` 返回 `not_implemented`
- 不支持 MCP Resources / Prompts
- `version` 硬编码 "2.0.0" (应跟随工具版本)
- `protocolVersion` 使用 "2024-11-05" (需升级至 "2025-03-26" 支持 resources/prompts)

```go
// Server v4 — 完整 MCP 实现
type Server struct {
    tools     map[string]ToolHandler
    resources map[string]ResourceHandler  // 新增
    prompts   map[string]PromptHandler    // 新增
    store     *ResultStore                // 新增: 结果存储
    version   string
}

// ResourceHandler MCP Resource 处理器
type ResourceHandler func(uri string) (interface{}, error)

// PromptHandler MCP Prompt 处理器
type PromptHandler func(params json.RawMessage) (*PromptResult, error)

// PromptResult MCP Prompt 返回结构
type PromptResult struct {
    Description string                   `json:"description"`
    Messages    []map[string]interface{} `json:"messages"`
}

func NewServer() *Server  // 改造: 注册 resources/prompts

// dispatch 扩展 (新增 method 处理)
// 新增 case:
//   "resources/list"     -> 列出所有 resources
//   "resources/read"     -> 读取指定 resource
//   "prompts/list"       -> 列出所有 prompts
//   "prompts/get"        -> 获取指定 prompt
//   "resources/subscribe" -> 订阅 resource 变更 (可选)
```

### 3.2 MCP Tools 完整实现

#### 新增 Tool: `lobster_cve_lookup`
```go
// 查询 CVE 信息
func (s *Server) handleCVELookup(params json.RawMessage) (interface{}, error)

// InputSchema:
// {
//   "cve_id": "string (CVE-YYYY-NNNNN)",      // 直接查 CVE
//   "keyword": "string",                        // 关键词搜索
//   "finding_id": "string"                      // 从 finding 自动匹配
// }
```

#### 新增 Tool: `lobster_chain_list`
```go
// 列出所有攻击链及其依赖关系
func (s *Server) handleChainList(params json.RawMessage) (interface{}, error)

// InputSchema:
// {
//   "category": "string (可选, 按类别过滤)",
//   "severity": "string (可选, 按严重度过滤)",
//   "include_deps": "boolean (包含依赖图, 默认 true)"
// }

// 返回: { chains: [{id, name, category, severity, depends_on, description}...], dag_levels: [...] }
```

#### 新增 Tool: `lobster_nuclei_run`
```go
// 运行 Nuclei 模板扫描
func (s *Server) handleNucleiRun(params json.RawMessage) (interface{}, error)

// InputSchema:
// {
//   "target": "string (必填)",
//   "templates": "string[] (模板 ID 列表, 为空=全部)",
//   "severity": "string (过滤严重度, 如 'critical,high')",
//   "version": "string ('v1' | 'v2' | 'v3' | 'all', 默认 'all')"
// }
```

#### 新增 Tool: `lobster_fuzzer`
```go
// AI Fuzzing 引擎
func (s *Server) handleFuzzer(params json.RawMessage) (interface{}, error)

// InputSchema:
// {
//   "target": "string (必填)",
//   "token": "string",
//   "template": "string ('mcp_json_rpc' | 'ws_chat_message' | 'prompt_injection' | ...)",
//   "max_payloads": "integer (默认 100)",
//   "concurrency": "integer (默认 5)"
// }
```

#### 新增 Tool: `lobster_prompt_test`
```go
// Prompt Injection 测试
func (s *Server) handlePromptTest(params json.RawMessage) (interface{}, error)

// InputSchema:
// {
//   "target": "string (必填)",
//   "token": "string",
//   "categories": "string[] ('direct', 'indirect', 'jailbreak', 'encoding', 'context_switch', 'multi_turn', 'tool_abuse')",
//   "use_ai_gen": "boolean (用 AI 生成额外 payload)",
//   "max_payloads": "integer (默认 50)"
// }
```

#### 新增 Tool: `lobster_chain_recommend`
```go
// AI 攻击链推荐
func (s *Server) handleChainRecommend(params json.RawMessage) (interface{}, error)

// InputSchema:
// {
//   "target": "string (必填)",
//   "token": "string",
//   "time_limit": "integer (可用时间秒数)",
//   "aggressive_level": "integer (1-5)",
//   "exclude_chains": "integer[] (排除的链 ID)"
// }
```

#### 已有 Tool 实现补全

| Tool | 当前状态 | v4 改造 |
|------|---------|---------|
| `lobster_scan` | 已实现 | 增加 `mode` 参数 (normal/aggressive/ultra), 结果写入 store |
| `lobster_fingerprint` | 已实现 | 不变 |
| `lobster_recon` | not_implemented | 实现: 调用 `recon.EnumEndpoints` + `recon.EnumWSMethods` |
| `lobster_exploit` | 已实现 | 增加 `category` 过滤, 支持 `chain_ids` 数组 |
| `lobster_audit` | 已实现 | 不变 |
| `lobster_discover` | not_implemented | 实现: 调用 `discovery.Discover` |
| `lobster_report` | not_implemented | 实现: 调用 `ReportGenerator.Generate` |
| `lobster_ai_analyze` | not_implemented | 实现: 调用 `Analyzer.AnalyzeFindings` |

### 3.3 MCP Resources (`pkg/mcp/resources.go`)

```go
// registerResources 注册所有 MCP Resources
func (s *Server) registerResources() {
    s.resources["scan://results/{id}"]   = s.resourceScanResult
    s.resources["scan://results/latest"] = s.resourceLatestResult
    s.resources["vuln://database"]       = s.resourceVulnDB
    s.resources["vuln://cve/{id}"]       = s.resourceCVE
    s.resources["chain://dag"]           = s.resourceDAG
    s.resources["chain://dag/{id}"]      = s.resourceChainNode
}

// ResourceDef MCP Resource 定义
type ResourceDef struct {
    URI         string `json:"uri"`
    Name        string `json:"name"`
    Description string `json:"description"`
    MimeType    string `json:"mimeType"`
}

func (s *Server) resourceDefinitions() []ResourceDef

// --- Resource Handlers ---

// scan://results/{id} — 获取指定扫描结果
func (s *Server) resourceScanResult(uri string) (interface{}, error)
// 返回: ScanResult JSON

// scan://results/latest — 获取最新扫描结果
func (s *Server) resourceLatestResult(uri string) (interface{}, error)

// vuln://database — 完整漏洞数据库 (30 个已知 OpenClaw 漏洞)
func (s *Server) resourceVulnDB(uri string) (interface{}, error)
// 返回: [{vuln_id, title, severity, cve, description, affected_version, exploit_chain_id}...]

// vuln://cve/{id} — 单个 CVE 详情
func (s *Server) resourceCVE(uri string) (interface{}, error)

// chain://dag — 完整 DAG 攻击链图
func (s *Server) resourceDAG(uri string) (interface{}, error)
// 返回: {nodes: [{id, name, category, severity, depends_on}...], edges: [...], levels: [...]}

// chain://dag/{id} — 单个攻击链节点详情
func (s *Server) resourceChainNode(uri string) (interface{}, error)
```

### 3.4 MCP Prompts (`pkg/mcp/prompts.go`)

```go
// registerPrompts 注册所有 MCP Prompts
func (s *Server) registerPrompts() {
    s.prompts["analyze_target"]   = s.promptAnalyzeTarget
    s.prompts["suggest_attacks"]  = s.promptSuggestAttacks
    s.prompts["write_report"]     = s.promptWriteReport
    s.prompts["explain_finding"]  = s.promptExplainFinding
}

// PromptDef MCP Prompt 定义
type PromptDef struct {
    Name        string      `json:"name"`
    Description string      `json:"description"`
    Arguments   []PromptArg `json:"arguments,omitempty"`
}

type PromptArg struct {
    Name        string `json:"name"`
    Description string `json:"description"`
    Required    bool   `json:"required"`
}

func (s *Server) promptDefinitions() []PromptDef

// --- Prompt Handlers ---

// analyze_target — 分析目标安全状况
// 参数: target (必填), scan_id (可选, 引用已有扫描)
func (s *Server) promptAnalyzeTarget(params json.RawMessage) (*PromptResult, error)
// 生成系统消息 + 用户消息，包含目标信息、指纹、已知漏洞

// suggest_attacks — 推荐攻击策略
// 参数: target (必填), findings (可选 JSON), time_limit (可选)
func (s *Server) promptSuggestAttacks(params json.RawMessage) (*PromptResult, error)
// 基于当前发现推荐下一步攻击策略

// write_report — 生成安全报告
// 参数: scan_id (必填), audience ("technical" | "executive"), language ("en" | "zh")
func (s *Server) promptWriteReport(params json.RawMessage) (*PromptResult, error)

// explain_finding — 解释具体漏洞
// 参数: finding_id (必填) 或 vuln_id (必填)
func (s *Server) promptExplainFinding(params json.RawMessage) (*PromptResult, error)
// 返回漏洞的详细解释、影响、PoC、修复建议
```

### 3.5 结果存储 (`pkg/mcp/store.go`)

```go
// ResultStore 扫描结果内存存储 (MCP session 生命周期)
type ResultStore struct {
    mu      sync.RWMutex
    scans   map[string]*utils.ScanResult     // scan_id -> result
    latest  string                           // 最新 scan_id
    counter int
}

func NewResultStore() *ResultStore

func (s *ResultStore) SaveScan(result *utils.ScanResult) string  // 返回 scan_id
func (s *ResultStore) GetScan(id string) (*utils.ScanResult, bool)
func (s *ResultStore) GetLatest() (*utils.ScanResult, bool)
func (s *ResultStore) ListScans() []ScanSummary

type ScanSummary struct {
    ID        string    `json:"id"`
    Target    string    `json:"target"`
    Findings  int       `json:"findings"`
    Time      time.Time `json:"time"`
}
```

---

## 四、激进扫描模式

### 4.1 高并发引擎 (`pkg/concurrent/`)

#### Worker Pool (`pkg/concurrent/pool.go`)

```go
// WorkerPool 可配置的 goroutine 工作池
type WorkerPool struct {
    maxWorkers int
    taskQueue  chan Task
    results    chan TaskResult
    wg         sync.WaitGroup
    ctx        context.Context
    cancel     context.CancelFunc
    metrics    *PoolMetrics
}

// Task 工作池任务
type Task struct {
    ID       string
    Execute  func(ctx context.Context) (interface{}, error)
    Priority int  // 0=最高
}

// TaskResult 任务结果
type TaskResult struct {
    TaskID   string
    Result   interface{}
    Error    error
    Duration time.Duration
}

// PoolMetrics 池运行指标
type PoolMetrics struct {
    ActiveWorkers  int64
    CompletedTasks int64
    FailedTasks    int64
    QueueDepth     int64
    AvgLatency     time.Duration
}

func NewWorkerPool(maxWorkers int, queueSize int) *WorkerPool

func (p *WorkerPool) Start(ctx context.Context)
func (p *WorkerPool) Submit(task Task) error
func (p *WorkerPool) SubmitBatch(tasks []Task) error
func (p *WorkerPool) Results() <-chan TaskResult
func (p *WorkerPool) Metrics() *PoolMetrics
func (p *WorkerPool) Shutdown()
func (p *WorkerPool) Resize(newMax int)  // 动态调整池大小
```

#### 渐进式调度器 (`pkg/concurrent/scheduler.go`)

```go
// ProgressiveScheduler 从保守到激进的渐进式扫描调度
type ProgressiveScheduler struct {
    pool    *WorkerPool
    levels  []ScanLevel
    current int
}

// ScanLevel 扫描级别
type ScanLevel struct {
    Name        string        // "stealth" | "normal" | "aggressive" | "ultra"
    Concurrency int           // 并发数
    Delay       time.Duration // 请求间延迟
    Timeout     time.Duration // 单请求超时
    Chains      []int         // 此级别执行的链 ID
}

// 预定义扫描级别
var (
    LevelStealth    = ScanLevel{Name: "stealth", Concurrency: 1, Delay: 2 * time.Second, Timeout: 30 * time.Second}
    LevelNormal     = ScanLevel{Name: "normal", Concurrency: 5, Delay: 500 * time.Millisecond, Timeout: 15 * time.Second}
    LevelAggressive = ScanLevel{Name: "aggressive", Concurrency: 20, Delay: 100 * time.Millisecond, Timeout: 10 * time.Second}
    LevelUltra      = ScanLevel{Name: "ultra", Concurrency: 50, Delay: 0, Timeout: 5 * time.Second}
    LevelMaximum    = ScanLevel{Name: "maximum", Concurrency: 200, Delay: 0, Timeout: 3 * time.Second}
)

func NewProgressiveScheduler(pool *WorkerPool) *ProgressiveScheduler

// RunProgressive 渐进式扫描 (自动从 stealth 升级到 aggressive)
func (s *ProgressiveScheduler) RunProgressive(ctx context.Context, target utils.Target, cfg chain.ChainConfig) []utils.Finding

// Escalate 手动升级到下一级别
func (s *ProgressiveScheduler) Escalate() error

// CurrentLevel 获取当前级别
func (s *ProgressiveScheduler) CurrentLevel() ScanLevel
```

#### 自适应速率限制 (`pkg/concurrent/limiter.go`)

```go
// AdaptiveLimiter 根据目标响应自适应调整速率
type AdaptiveLimiter struct {
    baseRate     float64   // 基础 RPS
    currentRate  float64   // 当前 RPS
    maxRate      float64   // 最大 RPS
    errorWindow  []time.Time // 错误窗口
    mu           sync.Mutex
}

func NewAdaptiveLimiter(baseRate, maxRate float64) *AdaptiveLimiter

// Wait 等待直到可以发送下一个请求
func (l *AdaptiveLimiter) Wait(ctx context.Context) error

// RecordSuccess 记录成功请求
func (l *AdaptiveLimiter) RecordSuccess()

// RecordError 记录失败请求 (自动降速)
func (l *AdaptiveLimiter) RecordError()

// CurrentRate 当前 RPS
func (l *AdaptiveLimiter) CurrentRate() float64
```

### 4.2 实时推送 (`pkg/ws/`)

```go
// EventServer WebSocket/SSE 实时事件推送服务
type EventServer struct {
    hub      *Hub
    addr     string
    upgrader websocket.Upgrader
}

// Hub 连接管理器
type Hub struct {
    clients    map[*Client]bool
    broadcast  chan Event
    register   chan *Client
    unregister chan *Client
}

// Event 实时事件
type Event struct {
    Type      string      `json:"type"`      // "finding" | "progress" | "level_change" | "complete" | "error"
    Timestamp time.Time   `json:"timestamp"`
    Data      interface{} `json:"data"`
}

// ScanProgressEvent 扫描进度事件
type ScanProgressEvent struct {
    ChainID    int    `json:"chain_id"`
    ChainName  string `json:"chain_name"`
    Status     string `json:"status"` // "running" | "done" | "skipped"
    Level      int    `json:"level"`
    Progress   float64 `json:"progress"` // 0-1
    Findings   int    `json:"findings_so_far"`
}

func NewEventServer(addr string) *EventServer

func (s *EventServer) Start() error
func (s *EventServer) Stop()
func (s *EventServer) Publish(event Event)  // 广播事件

// 集成到 DAGChain:
// dag.OnNodeStart(func(node *ChainNode) { eventServer.Publish(...) })
// dag.OnNodeComplete(func(node *ChainNode, findings []Finding) { eventServer.Publish(...) })
// dag.OnFinding(func(finding Finding) { eventServer.Publish(...) })
```

### 4.3 CLI 新增标志

```go
// 新增 CLI flags
var (
    flagUltraAggressive bool    // --ultra-aggressive
    flagProgressiveMode bool    // --progressive (渐进式)
    flagMaxConcurrency  int     // --max-concurrency (最大并发, 默认 50)
    flagWSPort          int     // --ws-port (实时推送端口, 默认 0=禁用)
    flagAIFuzz          bool    // --ai-fuzz (AI Fuzzing)
    flagPromptTest      bool    // --prompt-test (Prompt Injection 测试)
    flagAIRecommend     bool    // --ai-recommend (AI 攻击链推荐)
    flagReportFormat    string  // --report-format (json|markdown|html|sarif)
    flagCVELookup       bool    // --cve-lookup (自动 CVE 映射)
    flagOllamaURL       string  // --ollama-url (本地 Ollama 地址)
)

// exploit 子命令新增:
// lobster-guard exploit -t host:port --ultra-aggressive --ai-fuzz --prompt-test --ws-port 9090
// lobster-guard exploit -t host:port --progressive --ai-recommend --report-format sarif
```

---

## 五、CVE 数据库 (`pkg/cve/`)

### 5.1 CVE 查询 (`pkg/cve/lookup.go`)

```go
// CVELookup CVE 查询服务
type CVELookup struct {
    cache   *CVECache
    timeout time.Duration
}

// CVEInfo CVE 详情
type CVEInfo struct {
    ID          string    `json:"id"`          // CVE-YYYY-NNNNN
    Description string    `json:"description"`
    CVSS        float64   `json:"cvss"`
    Severity    string    `json:"severity"`
    Published   time.Time `json:"published"`
    References  []string  `json:"references"`
    CWE         []string  `json:"cwe"`
    AffectedVer string    `json:"affected_versions"`
}

func NewCVELookup() *CVELookup

// LookupByID 按 CVE ID 查询
func (l *CVELookup) LookupByID(ctx context.Context, cveID string) (*CVEInfo, error)

// SearchByKeyword 关键词搜索
func (l *CVELookup) SearchByKeyword(ctx context.Context, keyword string, limit int) ([]CVEInfo, error)

// SearchByProduct 按产品搜索 (针对 OpenClaw)
func (l *CVELookup) SearchByProduct(ctx context.Context, product string) ([]CVEInfo, error)
```

### 5.2 Finding -> CVE 映射 (`pkg/cve/mapper.go`)

```go
// CVEMapper 将 Finding 映射到已知 CVE
type CVEMapper struct {
    lookup    *CVELookup
    mappings  map[string][]string // module -> CVE IDs (静态映射)
}

func NewCVEMapper(lookup *CVELookup) *CVEMapper

// MapFindings 批量映射
func (m *CVEMapper) MapFindings(ctx context.Context, findings []utils.Finding) ([]CVEMapping, error)

// CVEMapping 映射结果
type CVEMapping struct {
    FindingModule string  `json:"finding_module"`
    FindingTitle  string  `json:"finding_title"`
    CVEID         string  `json:"cve_id"`
    CVSS          float64 `json:"cvss"`
    Confidence    float64 `json:"confidence"` // 0-1
}
```

### 5.3 本地缓存 (`pkg/cve/db.go`)

```go
// CVECache 本地 CVE 缓存 (SQLite 或 JSON 文件)
type CVECache struct {
    path    string // 缓存文件路径
    entries map[string]*CVEInfo
    mu      sync.RWMutex
}

func NewCVECache(path string) *CVECache

func (c *CVECache) Get(cveID string) (*CVEInfo, bool)
func (c *CVECache) Put(info *CVEInfo)
func (c *CVECache) Load() error     // 从文件加载
func (c *CVECache) Save() error     // 持久化到文件
func (c *CVECache) Size() int
```

---

## 六、DAG 扩展计划

### 新增攻击链节点 (v4)

基于 v4 新模块，DAG 从 49 节点扩展到 65+ 节点:

| 链 ID | 名称 | 类别 | 依赖 | 说明 |
|--------|------|------|------|------|
| 50 | AI Prompt Extraction | injection | [6] | 提取 system prompt |
| 51 | AI Jailbreak Suite | injection | [50] | 多技术 jailbreak |
| 52 | Indirect Prompt Inject | injection | [31] | MCP resource 间接注入 |
| 53 | Multi-turn Escalation | injection | [6] | 多轮对话权限升级 |
| 54 | AI Tool Abuse | rce | [11, 6] | 利用 AI 调用危险工具 |
| 55 | MCP Fuzz Campaign | fuzz | [0] | MCP 协议 fuzzing |
| 56 | WS Fuzz Enhanced | fuzz | [21] | AI 增强 WS fuzzing |
| 57 | HTTP Param Fuzz | fuzz | [0] | HTTP API 参数 fuzzing |
| 58 | Context Window Poison | injection | [6] | 上下文窗口投毒 |
| 59 | System Message Spoof | injection | [18] | 伪造系统消息 |
| 60 | AI Memory Extraction | disclosure | [6, 12] | 提取 AI 记忆/上下文 |
| 61 | Resource Injection | injection | [31] | MCP Resource 注入 |
| 62 | Model Switching Abuse | auth | [35] | 滥用模型切换功能 |
| 63 | RAG Poisoning | injection | [6] | RAG 数据源投毒 |
| 64 | Agent Loop Exploit | rce | [18, 11] | 利用 Agent 循环执行 |
| 65 | Full AI Chain | rce | [50, 51, 54] | AI 全链路攻击 |

### DAG 依赖图变化

```
Level 0: [0, 13, 17, 35]                          (不变)
Level 1: [1,2,3,4,6,15,19,20,21,31,32,33,36,38,39,42,43, 55,57]  (+2 fuzz)
Level 2: [5,7,8,9,10,11,12,14,16,18,22,23,40,41,44,45, 50,56,58,59,61,62]  (+7)
Level 3: [24,25,26,27,28,29,34,46,47,48,49, 51,52,53,54,60,63]  (+6)
Level 4: [30, 64,65]  (+2)
```

---

## 七、实现优先级与阶段划分

### Phase 1: 基础设施 (优先级: P0)

1. `pkg/ai/provider.go` — Provider 抽象层
2. `pkg/concurrent/pool.go` — Worker Pool
3. `pkg/concurrent/limiter.go` — 自适应速率限制
4. `pkg/mcp/store.go` — 结果存储
5. 改造 `pkg/ai/analyzer.go` — 迁移到 Provider 接口

**预估代码量**: ~1200 行

### Phase 2: AI 核心能力 (优先级: P0)

1. `pkg/ai/fuzzer.go` — AI Fuzzing 引擎
2. `pkg/ai/prompt_detector.go` — Prompt Injection 检测
3. `pkg/ai/chain_recommender.go` — 攻击链推荐
4. `pkg/ai/report_gen.go` — AI 报告生成

**预估代码量**: ~2000 行

### Phase 3: MCP 完整实现 (优先级: P1)

1. 改造 `pkg/mcp/server.go` — 支持 Resources/Prompts
2. `pkg/mcp/resources.go` — 6 个 Resource
3. `pkg/mcp/prompts.go` — 4 个 Prompt
4. 实现所有 not_implemented handler
5. 新增 6 个 MCP Tool handler

**预估代码量**: ~1500 行

### Phase 4: 激进扫描 (优先级: P1)

1. `pkg/concurrent/scheduler.go` — 渐进式调度
2. `pkg/ws/server.go` + `pkg/ws/hub.go` — 实时推送
3. CLI 新增标志
4. DAG 扩展 (16+ 新节点)

**预估代码量**: ~1800 行

### Phase 5: CVE 与报告 (优先级: P2)

1. `pkg/cve/lookup.go` — CVE 查询
2. `pkg/cve/mapper.go` — Finding 映射
3. `pkg/cve/db.go` — 本地缓存
4. SARIF 输出支持

**预估代码量**: ~800 行

### 总计

| 阶段 | 新代码量 | 修改代码量 | 新文件数 |
|------|---------|-----------|---------|
| Phase 1 | ~1200 行 | ~400 行 | 4 |
| Phase 2 | ~2000 行 | ~200 行 | 4 |
| Phase 3 | ~1500 行 | ~300 行 | 3 |
| Phase 4 | ~1800 行 | ~500 行 | 5 |
| Phase 5 | ~800 行 | ~100 行 | 3 |
| **合计** | **~7300 行** | **~1500 行** | **19** |

v4.0.0 总计: ~21500 行 (14200 现有 + 7300 新增)

---

## 八、依赖变更

### 新增 Go 依赖

```go
// go.mod 新增
require (
    github.com/gorilla/websocket v1.5.3    // WebSocket 实时推送
    github.com/mattn/go-sqlite3 v1.14.24   // CVE 本地缓存 (可选, 或用 JSON)
)
```

### 环境变量新增

| 变量 | 说明 | 默认值 |
|------|------|--------|
| `OLLAMA_URL` | Ollama API 地址 | `http://localhost:11434` |
| `LOBSTER_AI_PROVIDER` | 首选 AI Provider | (auto-detect) |
| `LOBSTER_CVE_CACHE` | CVE 缓存路径 | `~/.lobster-guard/cve-cache.json` |
| `LOBSTER_WS_PORT` | 实时推送端口 | (disabled) |
| `LOBSTER_MAX_CONCURRENCY` | 最大并发 | `50` |

---

## 九、向后兼容性

- 所有 v3 CLI 命令和标志保持不变
- MCP Tool name 保持不变，新增 tool 不影响旧客户端
- `--aggressive` 行为不变，`--ultra-aggressive` 是新标志
- `pkg/exploit/` 下 48 个现有模块不修改
- `chain.BuildFullDAG()` 返回的 DAG 仍包含全部 v1/v2/v3 节点

---

## 十、MCP Server JSON-RPC 2.0 协议升级 Checklist

- [ ] `protocolVersion`: "2024-11-05" -> "2025-03-26"
- [ ] `capabilities.tools.listChanged`: false -> true (支持动态 tool 注册)
- [ ] `capabilities.resources`: 新增，`{ subscribe: true, listChanged: true }`
- [ ] `capabilities.prompts`: 新增，`{ listChanged: false }`
- [ ] `resources/list` method handler
- [ ] `resources/read` method handler
- [ ] `resources/subscribe` method handler (可选)
- [ ] `resources/unsubscribe` method handler (可选)
- [ ] `prompts/list` method handler
- [ ] `prompts/get` method handler
- [ ] `notifications/resources/updated` 通知 (扫描完成时)
- [ ] Error code 规范: -32600 (Invalid Request), -32601 (Method not found), -32602 (Invalid params), -32603 (Internal error), -32700 (Parse error)
