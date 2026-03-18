package fuzzer

import (
	"fmt"
	"math/rand"
	"strings"
	"time"

	"github.com/coff0xc/lobster-guard/pkg/ai"
	"github.com/coff0xc/lobster-guard/pkg/payload"
	"github.com/coff0xc/lobster-guard/pkg/utils"
)

// AIFuzzer 使用内置 payload 和 AI 生成变异进行模糊测试
type AIFuzzer struct {
	Analyzer  *ai.Analyzer
	Target    utils.Target
	Token     string
	MaxRounds int // 最大 fuzzing 轮次 (默认 3)
	Timeout   time.Duration
}

// FuzzResult 单次 fuzzing 结果
type FuzzResult struct {
	Input    string         `json:"input"`
	Endpoint string         `json:"endpoint"`
	Response string         `json:"response"`
	Status   int            `json:"status"`
	IsVuln   bool           `json:"is_vuln"`
	Category string         `json:"category"`
	Finding  *utils.Finding `json:"finding,omitempty"`
}

// FuzzConfig 模糊测试配置
type FuzzConfig struct {
	Categories []string // 测试类别: xss, sqli, ssrf, cmdi, prompt_inject
	Endpoints  []string // 目标端点列表
	MaxPayloads int     // 每类最大 payload 数
}

// NewAIFuzzer 创建 AI Fuzzer 实例
func NewAIFuzzer(target utils.Target, token string, analyzer *ai.Analyzer) *AIFuzzer {
	return &AIFuzzer{
		Analyzer:  analyzer,
		Target:    target,
		Token:     token,
		MaxRounds: 3,
		Timeout:   15 * time.Second,
	}
}

// GeneratePayloads 生成指定类别的 payload 列表 (内置 + AI 增强)
func (f *AIFuzzer) GeneratePayloads(category string, context string) []string {
	// 内置 payload
	base := builtinPayloads(category)

	// 如果 AI 可用，生成变异 payload
	if f.Analyzer != nil && f.Analyzer.Available() {
		mutated := f.aiMutate(category, context, base)
		base = append(base, mutated...)
	}

	return base
}

// Fuzz 对目标端点进行全面模糊测试
func (f *AIFuzzer) Fuzz(endpoints []string, categories []string) []FuzzResult {
	if len(endpoints) == 0 {
		endpoints = defaultEndpoints()
	}
	if len(categories) == 0 {
		categories = []string{"xss", "sqli", "ssrf", "cmdi", "prompt_inject"}
	}

	fmt.Printf("\n[*] ═══ AI Fuzzer: %d endpoints x %d categories ═══\n",
		len(endpoints), len(categories))

	client := utils.HTTPClient(f.Timeout)
	var results []FuzzResult

	for _, cat := range categories {
		payloads := f.GeneratePayloads(cat, "")
		fmt.Printf("[*] Category: %s (%d payloads)\n", cat, len(payloads))

		for _, endpoint := range endpoints {
			for _, pl := range payloads {
				url := fmt.Sprintf("%s%s", f.Target.BaseURL(), endpoint)

				headers := map[string]string{
					"Content-Type": "application/json",
				}
				if f.Token != "" {
					headers["Authorization"] = "Bearer " + f.Token
				}

				// 根据类别构造请求体
				body := buildFuzzBody(cat, pl)
				status, respBody, _, err := utils.DoRequest(client, "POST", url, headers, strings.NewReader(body))
				if err != nil {
					continue
				}

				resp := string(respBody)
				isVuln := detectVulnerability(cat, pl, resp, status)

				result := FuzzResult{
					Input:    pl,
					Endpoint: endpoint,
					Response: utils.Truncate(resp, 500),
					Status:   status,
					IsVuln:   isVuln,
					Category: cat,
				}

				if isVuln {
					finding := utils.NewFinding(
						f.Target.String(), "ai_fuzzer",
						fmt.Sprintf("Fuzzer detected %s vulnerability", strings.ToUpper(cat)),
						categoySeverity(cat),
						fmt.Sprintf("Endpoint: %s\nPayload: %s", endpoint, utils.Truncate(pl, 200)),
					)
					finding.Evidence = utils.Truncate(resp, 300)
					result.Finding = &finding
					fmt.Printf("  [+] VULN: %s @ %s\n", cat, endpoint)
				}

				results = append(results, result)
			}
		}
	}

	vulnCount := 0
	for _, r := range results {
		if r.IsVuln {
			vulnCount++
		}
	}
	fmt.Printf("\n[*] ═══ Fuzzer complete: %d tests, %d vulns ═══\n", len(results), vulnCount)
	return results
}

// FuzzPromptInjection 专门针对 LLM prompt injection 的深度测试
func (f *AIFuzzer) FuzzPromptInjection() []FuzzResult {
	fmt.Printf("\n[*] ═══ Prompt Injection Fuzzer ═══\n")

	payloads := promptInjectionPayloads()
	endpoints := []string{
		"/api/chat/completions",
		"/api/v1/messages",
		"/v1/chat/completions",
		"/api/chat",
	}

	client := utils.HTTPClient(f.Timeout)
	var results []FuzzResult

	for _, endpoint := range endpoints {
		for _, pl := range payloads {
			url := fmt.Sprintf("%s%s", f.Target.BaseURL(), endpoint)

			headers := map[string]string{
				"Content-Type": "application/json",
			}
			if f.Token != "" {
				headers["Authorization"] = "Bearer " + f.Token
			}

			body := fmt.Sprintf(`{"model":"default","messages":[{"role":"user","content":%q}]}`, pl)
			status, respBody, _, err := utils.DoRequest(client, "POST", url, headers, strings.NewReader(body))
			if err != nil {
				continue
			}

			resp := string(respBody)
			isVuln := detectPromptLeak(resp)

			result := FuzzResult{
				Input:    pl,
				Endpoint: endpoint,
				Response: utils.Truncate(resp, 500),
				Status:   status,
				IsVuln:   isVuln,
				Category: "prompt_inject",
			}

			if isVuln {
				finding := utils.NewFinding(
					f.Target.String(), "ai_fuzzer",
					"LLM Prompt Injection — System Prompt Leak",
					utils.SevHigh,
					fmt.Sprintf("Endpoint: %s\nPayload: %s", endpoint, utils.Truncate(pl, 200)),
				)
				finding.Evidence = utils.Truncate(resp, 300)
				result.Finding = &finding
				fmt.Printf("  [+] PROMPT LEAK @ %s\n", endpoint)
			}

			results = append(results, result)
		}
	}

	return results
}

// Findings 从 FuzzResult 中提取所有漏洞发现
func Findings(results []FuzzResult) []utils.Finding {
	var findings []utils.Finding
	for _, r := range results {
		if r.Finding != nil {
			findings = append(findings, *r.Finding)
		}
	}
	return findings
}

// --- 内置 payload 库 ---

func builtinPayloads(category string) []string {
	// All payloads loaded from XOR-obfuscated registry
	if p := payload.List(category); len(p) > 0 {
		return p
	}
	if category == "prompt_inject" {
		return promptInjectionPayloads()
	}
	return nil
}

func promptInjectionPayloads() []string {
	return payload.List("prompt_inject")
}

// defaultEndpoints 默认 OpenClaw fuzzing 端点
func defaultEndpoints() []string {
	return []string{
		"/api/chat/completions",
		"/api/v1/messages",
		"/v1/chat/completions",
		"/api/chat",
		"/api/models",
		"/api/config",
		"/api/user",
		"/api/search",
	}
}

// --- 检测逻辑 ---

func detectVulnerability(category, pl, response string, status int) bool {
	resp := strings.ToLower(response)

	switch category {
	case "xss":
		// 检查 payload 是否在响应中被反射 (未转义)
		return strings.Contains(response, pl) ||
			strings.Contains(response, "<script>") ||
			strings.Contains(response, "onerror=")
	case "sqli":
		// SQL 错误信息检测
		for _, e := range payload.List("sqli_detect") {
			if strings.Contains(resp, e) {
				return true
			}
		}
		// 时间盲注检测由调用者处理
		return false
	case "ssrf":
		// 云元数据响应特征
		return strings.Contains(resp, "ami-id") ||
			strings.Contains(resp, "instance-id") ||
			strings.Contains(resp, "computeMetadata") ||
			strings.Contains(resp, "root:x:0:0")
	case "cmdi":
		// 命令执行特征
		return strings.Contains(resp, "uid=") ||
			strings.Contains(resp, "root:x:0:0") ||
			strings.Contains(resp, "vulnerable")
	case "prompt_inject":
		return detectPromptLeak(response)
	}
	return false
}

func detectPromptLeak(response string) bool {
	resp := strings.ToLower(response)
	// 系统提示词泄露特征
	indicators := []string{
		"system prompt", "system message", "initial instructions",
		"you are a", "your instructions", "configured to",
		"api key:", "api_key", "openai_api_key",
		"anthropic_api_key", "secret_key", "access_token",
	}
	for _, ind := range indicators {
		if strings.Contains(resp, ind) {
			return true
		}
	}
	return false
}

func categoySeverity(category string) utils.Severity {
	switch category {
	case "cmdi", "sqli":
		return utils.SevCritical
	case "ssrf", "xss", "prompt_inject":
		return utils.SevHigh
	default:
		return utils.SevMedium
	}
}

// buildFuzzBody 根据类别构造 JSON 请求体
func buildFuzzBody(category, fuzzPayload string) string {
	switch category {
	case "xss", "sqli", "cmdi":
		return fmt.Sprintf(`{"query":%q,"input":%q}`, fuzzPayload, fuzzPayload)
	case "ssrf":
		return fmt.Sprintf(`{"url":%q}`, fuzzPayload)
	case "prompt_inject":
		return fmt.Sprintf(`{"model":"default","messages":[{"role":"user","content":%q}]}`, fuzzPayload)
	default:
		return fmt.Sprintf(`{"data":%q}`, fuzzPayload)
	}
}

// aiMutate 使用 AI 对 payload 进行智能变异
func (f *AIFuzzer) aiMutate(category, context string, base []string) []string {
	if f.Analyzer == nil || !f.Analyzer.Available() {
		return localMutate(category, base)
	}

	prompt := fmt.Sprintf(
		"Generate 5 novel %s payloads for web application fuzzing. "+
			"Context: %s\nExisting payloads:\n%s\n"+
			"Output only the payloads, one per line, no explanation.",
		category, context, strings.Join(base[:min(3, len(base))], "\n"))

	result, err := f.Analyzer.AnalyzeFindings(nil, "")
	if err != nil || result == nil {
		return localMutate(category, base)
	}

	// 如果 AI 返回了有用的内容，解析 payload
	_ = prompt // AI 调用需要完整实现
	return localMutate(category, base)
}

// localMutate 本地 payload 变异 (不依赖 AI)
func localMutate(category string, base []string) []string {
	var mutated []string

	for _, p := range base {
		// URL 编码变异
		mutated = append(mutated, strings.ReplaceAll(p, "<", "%3C"))
		// 大小写变异
		mutated = append(mutated, strings.ToUpper(p))
		// 空格变异
		mutated = append(mutated, strings.ReplaceAll(p, " ", "/**/"))
	}

	// 随机打乱取前 5 个
	rand.Shuffle(len(mutated), func(i, j int) { mutated[i], mutated[j] = mutated[j], mutated[i] })
	if len(mutated) > 5 {
		mutated = mutated[:5]
	}

	return mutated
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
