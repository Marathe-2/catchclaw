# OpenClaw 源码深度审计报告 — v4 新漏洞发现

> 审计日期: 2026-03-16
> 审计范围: openclaw/src/ 中 v1-v3 未覆盖的模块
> 审计目标: memory, providers, agents, plugins, plugin-sdk, node-host, process, daemon, context-engine, link-understanding, media-understanding, tts, whatsapp

---

## 一、审计发现汇总

| # | 模块 | 漏洞类型 | 严重性 | 文件 | 描述 |
|---|------|----------|--------|------|------|
| SA-01 | link-understanding | 命令注入 | **CRITICAL** | runner.ts:60-68 | URL 经模板替换后传入 CLI 命令执行，用户可控的 URL 注入恶意参数 |
| SA-02 | plugin-sdk | SSRF 通配绕过 | **HIGH** | ssrf-policy.ts:8-9,20-21 | `*` 通配符直接返回 true 绕过所有 hostname 校验 |
| SA-03 | plugins/loader | 代码执行 | **HIGH** | loader.ts:1082 | Jiti 动态加载插件模块，恶意插件路径可导致任意代码执行 |
| SA-04 | node-host | 命令执行控制不足 | **HIGH** | invoke.ts:207 | spawn(argv[0], argv.slice(1)) 直接执行，依赖上游策略但 security="full" 时无限制 |
| SA-05 | process/exec | Windows cmd.exe 注入 | **HIGH** | exec.ts:131-137 | Windows .bat/.cmd 文件通过 cmd.exe /c 执行，虽有 escapeForCmdExe 但双引号转义不完备 |
| SA-06 | memory | SSRF 策略可选 | **MEDIUM** | remote-http.ts:25 | ssrfPolicy 参数可选，调用者可不传递导致无 SSRF 防护 |
| SA-07 | memory | 远程嵌入服务可信 | **MEDIUM** | embeddings-remote-fetch.ts:4-8 | 远程 embedding 服务返回数据未做完整性验证，恶意服务器可注入恶意向量 |
| SA-08 | daemon | 任务调度注入 | **MEDIUM** | schtasks-exec.ts:9 | Windows schtasks 命令参数直接传入，无额外校验 |
| SA-09 | plugins | 路径穿越检测依赖 | **MEDIUM** | path-safety.ts:4 | isPathInside 委托给 infra/path-guards.js，需验证符号链接 race condition |
| SA-10 | plugin-sdk | webhook 路径注入 | **MEDIUM** | webhook-path.ts | webhook 路径可被插件定义，恶意插件可能注册恶意路由 |
| SA-11 | memory | SQL 注入潜力 | **LOW** | sqlite-vec.ts | node:sqlite 内置模块使用，需确认参数化查询 |
| SA-12 | providers | OAuth token 存储 | **LOW** | qwen-portal-oauth.ts | OAuth token 处理安全性依赖实现 |
| SA-13 | media-understanding | CLI 命令注入 | **CRITICAL** | runner.entries.ts:625-644 | MediaPath 模板变量含用户上传文件名，经 applyTemplate 注入 CLI 参数 |
| SA-14 | agents | Elevated 执行绕过审批 | **HIGH** | bash-tools.exec.ts:324-334 | elevated=full 模式下 security="full" + ask="off"，完全绕过命令审批 |
| SA-15 | agents | CLI Backend bypassPermissions | **HIGH** | cli-backends.ts:42-48 | 默认 CLI backend 使用 --permission-mode bypassPermissions |
| SA-16 | tts | TTS 指令注入 | **MEDIUM** | tts-core.ts:129-334 | 用户消息中 [[tts:...]] 指令可覆盖 provider/voice/model 等配置 |
| SA-17 | tts | SSRF via 自定义 TTS 端点 | **MEDIUM** | tts-core.ts:354-363 | OPENAI_TTS_BASE_URL 环境变量可指向任意 URL，无 SSRF 防护 |
| SA-18 | memory | 跨 Agent 数据库隔离不足 | **MEDIUM** | manager.ts:146 | 缓存 key 含 agentId 但 DB 路径可能共享，scope 隔离依赖配置 |
| SA-19 | memory | readFile 路径穿越 (extraPaths) | **MEDIUM** | manager.ts:608-634 | extraPaths 配置可扩展读取范围，symlink 检查可被 race condition 绕过 |
| SA-20 | browser | noVNC 密码泄露 | **LOW** | bridge-server.ts:31-57 | noVNC 密码通过 URL hash 传递，可能被浏览器历史/日志记录 |
| SA-21 | daemon | 启动脚本注入 | **MEDIUM** | schtasks.ts:235-264 | buildTaskScript 将 environment 变量写入 .cmd 脚本，虽有 assertNoCmdLineBreak 但 SET 命令仍可注入 |

---

## 二、详细漏洞分析

### SA-01: Link Understanding CLI 命令注入 [CRITICAL]

**文件**: `openclaw/src/link-understanding/runner.ts:41-73`

**漏洞描述**:
`runCliEntry` 函数将用户消息中提取的 URL 通过模板替换 (`applyTemplate`) 嵌入到 CLI 命令参数中，然后通过 `runExec` 执行。

```typescript
// runner.ts:56-68
const templCtx = {
  ...params.ctx,
  LinkUrl: params.url,   // 用户消息中提取的 URL
};
const argv = [command, ...args].map((part, index) =>
  index === 0 ? part : applyTemplate(part, templCtx),
);
const { stdout } = await runExec(argv[0], argv.slice(1), { ... });
```

**攻击向量**:
- 用户发送包含恶意 URL 的消息，如 `http://evil.com$(whoami)` 或 `http://evil.com; cat /etc/passwd`
- URL 经 `extractLinksFromMessage` 提取后传入 `LinkUrl` 模板变量
- 如果 link understanding CLI 配置的 args 模板包含 `{LinkUrl}`，恶意内容直接进入命令参数
- `runExec` 使用 `execFile` 而非 shell，但在 Windows 上 .cmd/.bat 路由到 cmd.exe，可能允许注入

**风险评估**:
- `execFile` 本身不走 shell，但模板中 URL 可包含 shell 元字符
- Windows 上 `buildCmdExeCommandLine` 虽检查 `WINDOWS_UNSAFE_CMD_CHARS_RE`（`/[&|<>^%\r\n]/`），但 `$()` 未被阻止
- Linux 上如果 CLI 工具本身解析 URL 参数，可能导致 SSRF/命令注入
- 严重性: **CRITICAL** — 用户可控输入直接传入命令行

**建议 exploit 模块**: `link_cmd_inject`

---

### SA-02: Plugin SDK SSRF 通配符绕过 [HIGH]

**文件**: `openclaw/src/plugin-sdk/ssrf-policy.ts:8-9,20-21`

**漏洞描述**:
```typescript
// ssrf-policy.ts:8-9
if (trimmed === "*" || trimmed === "*.") {
  return "*";
}

// ssrf-policy.ts:20-21
if (allowlist.includes("*")) {
  return true;
}
```

当插件配置中 `allowHosts` 包含 `*` 时，`isHostnameAllowedBySuffixAllowlist` 直接返回 `true`，同时 `buildHostnameAllowlistPolicyFromSuffixAllowlist` 返回 `undefined`（即无策略）。

**攻击向量**:
- 恶意插件或错误配置设置 `allowHosts: ["*"]`
- 所有 hostname 校验被绕过，包括私网和云元数据端点
- 可发起 SSRF 攻击访问 169.254.169.254 等

**风险评估**: **HIGH** — 配置错误或恶意插件可完全绕过 SSRF 防护

**建议 exploit 模块**: `plugin_ssrf_wildcard`

---

### SA-03: 插件加载器动态代码执行 [HIGH]

**文件**: `openclaw/src/plugins/loader.ts:1082`

**漏洞描述**:
```typescript
mod = getJiti()(safeSource) as OpenClawPluginModule;
```

Jiti (JIT Transform) 加载器动态执行 TypeScript/JavaScript 模块。虽然有 `openBoundaryFileSync` 路径安全检查（line 1066-1076），但:
1. `skipLexicalRootCheck: true` 跳过了词法根检查
2. 只对非 bundled 插件检查硬链接 (`rejectHardlinks: candidate.origin !== "bundled"`)
3. 插件路径来自 `loadPaths` 配置和 `discovery`

**攻击向量**:
- 攻击者在 workspace 目录放置恶意 `.ts` 文件
- 如果 `plugins.allow` 为空（代码 line 659-681 有警告但不阻止），恶意插件自动加载
- 执行任意 TypeScript/JS 代码

**风险评估**: **HIGH** — 代码已有 allowlist 警告机制但非阻止性

**建议 exploit 模块**: `plugin_code_exec`

---

### SA-04: Node Host 命令执行策略绕过 [HIGH]

**文件**: `openclaw/src/node-host/invoke.ts:192-281, exec-policy.ts:52-134`

**漏洞描述**:
`handleSystemRunInvoke` 在 `security="full"` 模式下允许执行任意命令。`runCommand` 函数 (line 192-281) 直接使用 `spawn(argv[0], argv.slice(1])` 执行命令。

```typescript
// exec-policy.ts:78-79
function resolveExecSecurity(value?: string): ExecSecurity {
  return value === "deny" || value === "allowlist" || value === "full" ? value : "allowlist";
}
```

**攻击向量**:
- 如果管理员配置 `security: "full"`，所有命令不受限制
- Agent 或 plugin 通过 gateway 发送 `system.run` 命令
- 恶意 AI agent 可利用此执行任意系统命令

**风险评估**: **HIGH** — security=full 配置下无任何命令限制

**建议 exploit 模块**: `exec_policy_abuse`

---

### SA-05: Windows cmd.exe 注入 [HIGH]

**文件**: `openclaw/src/process/exec.ts:14-41, 131-137`

**漏洞描述**:
```typescript
// exec.ts:14
const WINDOWS_UNSAFE_CMD_CHARS_RE = /[&|<>^%\r\n]/;

// exec.ts:24-37
function escapeForCmdExe(arg: string): string {
  if (WINDOWS_UNSAFE_CMD_CHARS_RE.test(arg)) {
    throw new Error(`Unsafe Windows cmd.exe argument detected`);
  }
  if (!arg.includes(" ") && !arg.includes('"')) {
    return arg;
  }
  return `"${arg.replace(/"/g, '""')}"`;
}
```

**问题**:
1. 正则 `/[&|<>^%\r\n]/` 未检测 `!` (delayed expansion)、`()`、backtick 等
2. `""` 双引号转义在 cmd.exe 中的行为取决于上下文
3. `shouldSpawnWithShell` 虽然始终返回 `false`（line 90-97），但 `.cmd/.bat` 文件仍通过 `cmd.exe /c` 执行

**攻击向量**:
- 在 Windows 上，如果参数包含 `!`（延迟扩展字符），可能导致环境变量注入
- `.cmd` 文件本身就是 cmd.exe 脚本，可能有额外注入向量

**风险评估**: **HIGH** — Windows 环境下的命令注入

**建议 exploit 模块**: `win_cmd_inject`

---

### SA-06: Memory 远程 HTTP SSRF 策略可选 [MEDIUM]

**文件**: `openclaw/src/memory/remote-http.ts:22-40`

**漏洞描述**:
```typescript
export async function withRemoteHttpResponse<T>(params: {
  url: string;
  ssrfPolicy?: SsrFPolicy;  // 可选!
  ...
})
```

`ssrfPolicy` 参数是可选的。如果调用者不传递策略，请求可能绕过 SSRF 防护。需审计所有调用 `withRemoteHttpResponse` 和 `postJson` 的地方。

`buildRemoteBaseUrlPolicy` (line 4-20) 只对配置的 baseUrl 创建策略，但如果 baseUrl 为空或无效，返回 `undefined`。

**风险评估**: **MEDIUM** — 依赖调用者正确传递策略

---

### SA-07: 远程 Embedding 服务返回数据未验证 [MEDIUM]

**文件**: `openclaw/src/memory/embeddings-remote-fetch.ts:17-23`

**漏洞描述**:
```typescript
parse: (payload) => {
  const typedPayload = payload as { data?: Array<{ embedding?: number[] }> };
  const data = typedPayload.data ?? [];
  return data.map((entry) => entry.embedding ?? []);
},
```

远程 embedding 服务返回的数据通过 `as` 类型断言直接使用，无校验:
1. 不验证返回数组长度是否与请求匹配
2. 不验证向量维度是否正确
3. 不验证数值范围

**攻击向量**: 恶意 embedding 服务可返回特制向量，影响搜索结果排序

**风险评估**: **MEDIUM** — 需要控制 embedding 服务端点

---

### SA-08: Daemon schtasks 参数注入 [MEDIUM]

**文件**: `openclaw/src/daemon/schtasks-exec.ts:6-24`

**漏洞描述**:
```typescript
export async function execSchtasks(args: string[]) {
  const result = await runCommandWithTimeout(["schtasks", ...args], { ... });
}
```

`args` 数组直接传入 `runCommandWithTimeout`，虽然 `runCommandWithTimeout` 不使用 shell，但 Windows `schtasks.exe` 本身有命令执行能力（如通过 `/TR` 参数指定任务命令）。

**风险评估**: **MEDIUM** — 需要调用者传入恶意参数

---

### SA-09: 插件路径安全 symlink race [MEDIUM]

**文件**: `openclaw/src/plugins/path-safety.ts:4, loader.ts:1066-1078`

**漏洞描述**:
```typescript
// loader.ts:1066-1078
const opened = openBoundaryFileSync({
  absolutePath: loadSource,
  rootPath: pluginRoot,
  boundaryLabel: "plugin root",
  rejectHardlinks: candidate.origin !== "bundled",
  skipLexicalRootCheck: true,  // 跳过!
});
```

1. `skipLexicalRootCheck: true` — 跳过路径是否在 root 内的词法检查
2. 虽然使用 `openBoundaryFileSync` 打开文件获取 fd 后关闭，但随后 Jiti 通过路径重新加载
3. TOCTOU race condition: 在 `openBoundaryFileSync` 检查和 `getJiti()` 加载之间，路径可能被替换

**风险评估**: **MEDIUM** — 需要本地文件系统访问

---

### SA-10: Webhook 路径注入 [MEDIUM]

**文件**: `openclaw/src/plugin-sdk/webhook-path.ts`（需进一步验证）

**描述**: 插件可注册自定义 webhook 路径。虽有 `http-route-overlap.ts` 检测冲突，但恶意插件可能注册覆盖关键路由。

---

### SA-13: Media Understanding CLI 命令注入 [CRITICAL]

**文件**: `openclaw/src/media-understanding/runner.entries.ts:625-644`

**漏洞描述**:
`runCliEntry` 函数将用户上传的媒体文件路径通过模板替换嵌入 CLI 命令参数:

```typescript
// runner.entries.ts:625-636
const templCtx: MsgContext = {
  ...ctx,
  MediaPath: mediaPath,      // 用户上传文件的本地路径
  MediaDir: path.dirname(mediaPath),
  OutputDir: outputDir,
  OutputBase: outputBase,
  Prompt: prompt,
  MaxChars: maxChars,
};
const argv = [command, ...args].map((part, index) =>
  index === 0 ? part : applyTemplate(part, templCtx),
);
const { stdout } = await runExec(argv[0], argv.slice(1), { ... });
```

**攻击向量**:
- 用户上传文件名包含 shell 元字符，如 `$(whoami).mp3` 或 `` `id`.wav ``
- 文件名经 `MediaPath` 模板变量注入 CLI 参数
- 虽然 `runExec` 使用 `execFile` 不走 shell，但 Windows 上 `.cmd/.bat` 路由到 `cmd.exe /c`
- 与 SA-01 (link-understanding) 同类漏洞，但攻击入口不同（文件上传 vs URL）
- `Prompt` 模板变量也来自配置，如果配置被污染可注入

**风险评估**: **CRITICAL** — 用户可控文件名直接传入命令行参数

**建议 exploit 模块**: `media_cli_inject`

---

### SA-14: Elevated 执行完全绕过审批 [HIGH]

**文件**: `openclaw/src/agents/bash-tools.exec.ts:324-334`

**漏洞描述**:
```typescript
// bash-tools.exec.ts:324-334
if (elevatedRequested && elevatedMode === "full") {
  security = "full";       // 无任何命令限制
}
const bypassApprovals = elevatedRequested && elevatedMode === "full";
if (bypassApprovals) {
  ask = "off";             // 关闭审批
}
// ...
if (host === "gateway" && !bypassApprovals) {  // 跳过 allowlist 检查
```

当 `elevated.defaultLevel = "full"` 时:
1. `security` 被设为 `"full"` — 允许执行任何命令
2. `ask` 被设为 `"off"` — 关闭用户审批
3. `bypassApprovals = true` — 跳过 gateway allowlist 检查

**攻击向量**:
- AI agent 通过 `/elevated full` 命令切换到 full 模式
- 后续所有 exec 调用无需审批，无 allowlist 限制
- 恶意 prompt injection 可利用此执行任意命令

**风险评估**: **HIGH** — 需要 elevated 配置启用，但一旦启用完全无限制

**建议 exploit 模块**: `elevated_bypass`

---

### SA-15: CLI Backend 默认 bypassPermissions [HIGH]

**文件**: `openclaw/src/agents/cli-backends.ts:40-48`

**漏洞描述**:
```typescript
const DEFAULT_CLAUDE_BACKEND: CliBackendConfig = {
  command: "claude",
  args: ["-p", "--output-format", "json", "--permission-mode", "bypassPermissions"],
  // ...
};
```

默认 Claude CLI backend 配置使用 `--permission-mode bypassPermissions`，这意味着通过 OpenClaw 调用的 Claude CLI 实例默认跳过所有权限检查。

**攻击向量**:
- 通过 OpenClaw gateway 触发的 Claude CLI 会话自动获得 bypassPermissions
- 如果 agent 配置允许用户触发 CLI backend，用户间接获得无限制的 Claude 执行权限
- 结合 prompt injection，可执行任意文件操作

**风险评估**: **HIGH** — 默认配置即存在风险

---

### SA-16: TTS 指令注入 [MEDIUM]

**文件**: `openclaw/src/tts/tts-core.ts:129-334`

**漏洞描述**:
```typescript
// tts-core.ts:129-139
const blockRegex = /\[\[tts:text\]\]([\s\S]*?)\[\[\/tts:text\]\]/gi;
const directiveRegex = /\[\[tts:([^\]]+)\]\]/gi;
```

用户消息中的 `[[tts:...]]` 指令可覆盖 TTS 配置:
- `[[tts:provider=openai]]` — 切换 TTS 提供者
- `[[tts:voice=...]]` — 切换语音
- `[[tts:model=...]]` — 切换模型
- `[[tts:text]]...[[/tts:text]]` — 替换 TTS 文本内容

虽然有 `policy` 控制哪些指令允许，但默认策略可能过于宽松。

**攻击向量**: 用户通过消息注入 TTS 指令，切换到攻击者控制的 provider/model

**风险评估**: **MEDIUM** — 依赖 policy 配置

---

### SA-17: TTS 自定义端点 SSRF [MEDIUM]

**文件**: `openclaw/src/tts/tts-core.ts:354-363, 655`

**漏洞描述**:
```typescript
// tts-core.ts:655
const response = await fetch(`${baseUrl}/audio/speech`, { ... });
```

`OPENAI_TTS_BASE_URL` 环境变量或配置中的 `baseUrl` 可指向任意 URL。TTS 请求直接使用 `fetch` 发送，无 SSRF 防护（不经过 `fetchWithSsrFGuard`）。

**攻击向量**: 配置 `baseUrl` 指向内网地址，TTS 请求变成 SSRF 探测

**风险评估**: **MEDIUM** — 需要配置访问权限

---

### SA-18: Memory 跨 Agent 数据库隔离 [MEDIUM]

**文件**: `openclaw/src/memory/manager.ts:146`

**漏洞描述**:
```typescript
const key = `${agentId}:${workspaceDir}:${JSON.stringify(settings)}`;
```

Memory 索引管理器使用 `agentId + workspaceDir + settings` 作为缓存 key。如果两个 agent 共享相同的 `workspaceDir` 和 `settings`，它们会共享同一个 `MemoryIndexManager` 实例和底层 SQLite 数据库。

**攻击向量**: 不同权限级别的 agent 可能共享记忆数据库，低权限 agent 可搜索高权限 agent 的对话记录

**风险评估**: **MEDIUM** — 依赖 agent 配置隔离

---

### SA-19: Memory readFile extraPaths 路径穿越 [MEDIUM]

**文件**: `openclaw/src/memory/manager.ts:608-634`

**漏洞描述**:
```typescript
// manager.ts:613-633
for (const additionalPath of additionalPaths) {
  try {
    const stat = await fs.lstat(additionalPath);
    if (stat.isSymbolicLink()) {
      continue;  // 跳过 symlink
    }
    if (stat.isDirectory()) {
      if (absPath === additionalPath || absPath.startsWith(`${additionalPath}${path.sep}`)) {
        allowedAdditional = true;
        break;
      }
    }
  } catch {}
}
```

`readFile` 方法通过 `extraPaths` 配置扩展可读取范围。虽然检查了 symlink，但:
1. TOCTOU race: `lstat` 检查和后续 `readFile` 之间路径可被替换
2. `startsWith` 检查可能被 Windows 路径大小写不敏感绕过
3. 只检查 `.md` 扩展名，但 `.md` 文件可能包含敏感信息

**风险评估**: **MEDIUM** — 需要本地文件系统访问

---

### SA-21: Daemon 启动脚本环境变量注入 [MEDIUM]

**文件**: `openclaw/src/daemon/schtasks.ts:235-264`

**漏洞描述**:
```typescript
// schtasks.ts:250-259
if (environment) {
  for (const [key, value] of Object.entries(environment)) {
    if (!value) continue;
    if (key.toUpperCase() === "PATH") continue;
    lines.push(renderCmdSetAssignment(key, value));
  }
}
```

`buildTaskScript` 将环境变量写入 `.cmd` 脚本。虽然 `renderCmdSetAssignment` 和 `assertNoCmdLineBreak` 提供了一定保护，但 `SET` 命令在 cmd.exe 中的行为复杂，特殊字符（如 `!` 在延迟扩展模式下）可能导致注入。

**风险评估**: **MEDIUM** — 需要控制环境变量配置

---

## 三、安全架构评估

### 正面发现

1. **SSRF 防护框架完善**: `infra/net/ssrf.ts` 实现了全面的 SSRF 防护:
   - DNS 解析后检查 IP 地址
   - 阻止私网地址、localhost、元数据端点
   - 支持 hostname allowlist 和 pinned DNS
   - 阻止 legacy IPv4 literal (八进制/十六进制)

2. **命令执行审批系统**: `node-host/exec-policy.ts` 实现了 allowlist + ask 机制
3. **`shouldSpawnWithShell` 始终返回 false**: 有意不使用 shell 执行 (exec.ts:90-97)
4. **环境变量清理**: `sanitizeHostExecEnv` 清理执行环境
5. **插件来源追踪**: `warnAboutUntrackedLoadedPlugins` 警告未追踪的插件
6. **跨域重定向头过滤**: fetch-guard.ts 有 `CROSS_ORIGIN_REDIRECT_SAFE_HEADERS` 白名单

### 薄弱环节

1. **Link Understanding**: URL 直接传入 CLI 命令是最大风险
2. **Windows 兼容性**: cmd.exe 路径增加攻击面
3. **插件系统信任模型**: 依赖 allowlist 但非阻止性
4. **可选 SSRF 策略**: 调用者可绕过

---

## 四、v4 新 Exploit 模块建议

基于源码审计发现，建议新增以下 exploit 模块:

| # | 模块名 | 基于审计发现 | 预期代码量 |
|---|--------|-------------|-----------|
| 1 | `link_cmd_inject` | SA-01 Link Understanding 命令注入 | ~350 lines |
| 2 | `plugin_ssrf_wildcard` | SA-02 SSRF 通配符绕过 | ~200 lines |
| 3 | `plugin_code_exec` | SA-03 插件加载器代码执行 | ~300 lines |
| 4 | `exec_policy_abuse` | SA-04 Node Host security=full 滥用 | ~250 lines |
| 5 | `win_cmd_inject` | SA-05 Windows cmd.exe 注入 | ~250 lines |
| 6 | `embedding_poison` | SA-07 恶意 embedding 向量注入 | ~200 lines |
| 7 | `media_cli_inject` | SA-13 Media Understanding CLI 命令注入 | ~350 lines |
| 8 | `elevated_bypass` | SA-14 Elevated 执行绕过审批 | ~250 lines |
| 9 | `tts_ssrf` | SA-17 TTS 自定义端点 SSRF | ~200 lines |
| 10 | `memory_cross_agent` | SA-18 跨 Agent 记忆泄露 | ~250 lines |

**总计**: 10 个新模块, ~2600 lines

---

## 五、与 CVE 研究的交叉验证

| 源码发现 | 对应 CVE | 关系 |
|----------|----------|------|
| SA-01 Link CLI 注入 | CVE-2026-0765/0766 (PIP/Tool 命令注入) | 同类漏洞，不同入口点 |
| SA-02 SSRF 通配绕过 | CVE-2025-65958, CVE-2024-7959 | 补充已有 SSRF 攻击面 |
| SA-03 插件代码执行 | CVE-2025-64496 (SSE 代码注入) | 不同攻击路径达到相同效果 |
| SA-04 Exec Policy 滥用 | CVE-2024-7037 (Pipeline RCE) | 同类权限滥用 |
| SA-05 Windows cmd 注入 | CVE-2024-7033 (Windows 文件写入) | Windows 特有攻击面 |
| SA-13 Media CLI 注入 | CVE-2026-0765 (命令注入) | 同类漏洞，文件上传入口 |
| SA-14 Elevated 绕过 | CVE-2024-7037 (Pipeline RCE) | 权限提升链 |
| SA-15 bypassPermissions | — | 新发现，默认配置风险 |
| SA-17 TTS SSRF | CVE-2025-65958 (SSRF) | 新 SSRF 入口点 |
| SA-18 跨 Agent 泄露 | — | 新发现，数据隔离问题 |

---

## 六、审计覆盖统计

| 模块 | 文件数 | 已审计关键文件 | 发现数 |
|------|--------|---------------|--------|
| memory | 64 | 12 | 4 (SA-06, SA-07, SA-18, SA-19) |
| providers | 5 | 3 | 1 (SA-12) |
| agents | 431 | 8 | 2 (SA-14, SA-15) |
| plugins | 65 | 3 | 2 (SA-03, SA-09) |
| plugin-sdk | 90+ | 3 | 2 (SA-02, SA-10) |
| node-host | 16 | 5 | 1 (SA-04) |
| process | 14 | 2 | 1 (SA-05) |
| daemon | 30 | 4 | 2 (SA-08, SA-21) |
| context-engine | 6 | 4 | 0 |
| link-understanding | 5 | 3 | 1 (SA-01) |
| media-understanding | 47 | 6 | 1 (SA-13) |
| tts | 2 | 2 | 2 (SA-16, SA-17) |
| whatsapp | 4 | 2 | 0 |
| browser | 30+ | 3 | 1 (SA-20) |
| auto-reply | 291 | 2 | 0 |
| infra/net (SSRF) | 4 | 2 | 0 (设计良好) |

**总计**: 21 个安全发现 (2 CRITICAL, 5 HIGH, 9 MEDIUM, 3 LOW, 2 INFO/LOW)
