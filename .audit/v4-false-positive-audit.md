# LobsterGuard Exploit Module False Positive Audit

> Auditor: code-reviewer agent | Date: 2026-03-16
> Scope: v3 modules (12) + v4 modules (6) — challenge gate & determination logic review

## Executive Summary

Reviewed 18 exploit modules for false positive risks, specifically focusing on:
1. WS connection success + any response → misidentified as vulnerability
2. Regex matching `connect.challenge` nonce UUID → misidentified as secret leak
3. WS method call returning non-error → misidentified as successful exploitation (when it may just be a challenge requiring authentication)

**Critical finding**: The `GatewayWSClient.Call()` method in `pkg/utils/gateway_ws.go:68-109` does **NOT** handle the `connect.challenge` handshake protocol. It reads JSON-RPC responses by matching `resp.ID == id`, but a `connect.challenge` message is a server-push with a different ID (or no matching ID). This means:
- If the server sends `connect.challenge` as a push message, `Call()` silently skips it (line 107: "Skip push messages / events with different IDs") and waits for the actual RPC response.
- If the server sends `connect.challenge` AS the response with the matching ID, `Call()` returns it as a successful result (no error field), and the caller treats it as a valid RPC response.

The second scenario is the root cause of false positives: **a `connect.challenge` response with the caller's request ID will be returned as `json.RawMessage` with no error, and every module that checks `callErr == nil` will treat it as a confirmed vulnerability.**

---

## Per-Module Analysis

---

### 1. `silent_pair_abuse.go` (VULN-18)

**Challenge gate false positive risk: YES**

| Line(s) | Logic | Problem |
|---------|-------|---------|
| 68-69 | Sends `{"id":1,"method":"health","params":{}}` via raw `WriteMessage` | Bypasses `Call()` entirely — reads raw response |
| 74 | `conn.ReadMessage()` reads first response | If server sends `connect.challenge` as first message, this captures it |
| 83-86 | `!Contains("unauthorized") && !Contains("auth") && !Contains("forbidden") && len > 2` → finding | A `connect.challenge` JSON like `{"method":"connect.challenge","params":{"nonce":"abc-123..."}}` passes ALL these negative checks — no "unauthorized"/"auth"/"forbidden" substring, and len > 2 |

**Severity**: HIGH — Phase 1 (lines 41-99) will almost certainly false-positive on any server that sends `connect.challenge` as the first WS message. The nonce UUID in the challenge response will be captured as "evidence" of auto-pairing.

**Fix**: After `ReadMessage()`, check if the response contains `"connect.challenge"` or `"method":"connect.challenge"`. Only treat as auto-paired if the response is a valid RPC result for the `health` method (check for `"id":1` and `"result"` field).

---

### 2. `flood_guard_reset.go` (VULN-17)

**Challenge gate false positive risk: YES (moderate)**

| Line(s) | Logic | Problem |
|---------|-------|---------|
| 69 | `ws.Call(method, params)` — uses `Call()` | If `connect.challenge` is returned with matching ID, `callErr == nil` and the loop counts it as a successful message |
| 98 | `messagesBeforeGuard = i + 1` increments on every non-error call | Challenge responses counted as successful flood messages |
| 117-118 | Reconnect verification: `ws.Call("health", nil)` — `callErr == nil && len(result) > 0` | A challenge response satisfies both conditions |

**Severity**: MEDIUM — The flood guard logic depends on counting successful messages. If the first `Call()` returns a challenge instead of a real response, the count is inflated by 1 per connection cycle. For the "no flood guard" finding (line 176-188), this is unlikely to cause a false positive alone (needs 100+ messages). But for the reconnect-reset finding (line 158-173), a challenge response on reconnect would falsely confirm "counter reset."

**Fix**: In the reconnect verification (line 117), validate that `result` contains expected health response fields (e.g., `"status"` or `"ok"`), not just `len > 0`.

---

### 3. `auth_disable_leak.go` (VULN-19)

**Challenge gate false positive risk: YES**

| Line(s) | Logic | Problem |
|---------|-------|---------|
| 40-41 | `ws.Call("config.get", ...)` — checks `callErr != nil` to skip | If challenge returned as result, `callErr == nil` and `result` contains challenge JSON |
| 46 | `strings.Contains(resultStr, "dangerouslyDisableDeviceAuth")` | Challenge JSON won't contain this string — **safe for Phase 1** |
| 108-109 | Phase 2: `wsNoAuth.Call(op.method, op.params)` — `callErr == nil && len(result) > 2` | A `connect.challenge` response on the no-auth WS connection satisfies both conditions. The module would report "Unauthenticated config.get succeeded" when it actually just received a challenge nonce |

**Severity**: HIGH — Phase 2 (lines 91-123) is the critical path. An unauthenticated WS connection that receives `connect.challenge` (which is the normal handshake first step) will be misinterpreted as "unauthenticated privileged operation succeeded."

**Fix**: After `wsNoAuth.Call()`, validate that `result` is a valid config response (try `json.Unmarshal` into expected structure). A challenge response won't have the expected config fields.

---

### 4. `origin_wildcard.go` (VULN-20)

**Challenge gate false positive risk: YES**

| Line(s) | Logic | Problem |
|---------|-------|---------|
| 105 | `wsClient.Call("config.get", ...)` — `callErr` checked | If challenge returned, `callErr != nil` path taken (line 108) — **partially safe** |
| 108-116 | `callErr != nil` → SevMedium finding "connected but call failed" | This is actually correct behavior — but the finding text says "partial bypass" which is misleading. A challenge is not a bypass, it's normal handshake |
| 98-99 | `NewGatewayWSClientWithOrigin` — connection success alone | WS handshake success with crafted Origin is a valid test — but if the server accepts all WS upgrades and then challenges, connection success alone is not meaningful |

**Severity**: MEDIUM — The `callErr != nil` path (line 108-116) correctly downgrades to SevMedium, but still creates a finding for "WS connection accepted with Origin 'X' (call failed)". If the call failed because of a challenge (not an auth rejection), this is a false positive — the server may simply challenge all connections regardless of origin.

**Fix**: In the `callErr != nil` branch, check if the error message contains "challenge" or if the connection was simply in handshake state. Only report if the error indicates the connection was functional but the specific call was rejected.

---

### 5. `csrf_no_origin.go` (VULN-21)

**Challenge gate false positive risk: NO**

This module uses exclusively HTTP requests (`utils.DoRequest`), not WebSocket. All determination logic is based on HTTP status codes (200-399 = success, else failure). No WS `connect.challenge` interaction.

---

### 6. `ratelimit_scope_bypass.go` (VULN-16)

**Challenge gate false positive risk: YES (minor)**

| Line(s) | Logic | Problem |
|---------|-------|---------|
| 189-218 | WS method calls: `ws.Call(method, nil)` — `callErr != nil` checks for rate limit keywords | If challenge returned as result, `callErr == nil` and `wsSuccess++` increments |
| 208 | `wsSuccess > singleScopeLimit` → finding | Only triggers if WS successes exceed HTTP rate limit, which requires many successful calls. A single challenge response adds +1 but unlikely to cross threshold alone |

**Severity**: LOW — The WS section (lines 189-218) is supplementary. The main rate limit test is HTTP-based (phases 1-3) and unaffected. The WS false positive would only add a minor inflation to `wsSuccess` count.

**Fix**: Validate `Call()` results contain expected response structure before counting as success.

---
### 7. `ssrf_rebind.go` (VULN-22)

**Challenge gate false positive risk: NO**

This module uses exclusively HTTP requests via `utils.DoRequest`. All SSRF detection is based on HTTP status codes (200, 500 with ECONNREFUSED/timeout indicators) and response body content. No WS `Call()` usage in determination logic. The timing test (Phase 2) compares HTTP request durations. Phase 4 OOB callback is also HTTP-only.

---

### 8. `ssrf_proxy_bypass.go` (VULN-23)

**Challenge gate false positive risk: YES (moderate)**

| Line(s) | Logic | Problem |
|---------|-------|---------|
| 43-44 | `ws.Call("config.get", ...)` — `err != nil` to skip | If challenge returned as result, `err == nil` and `resultStr` contains challenge JSON |
| 50-51 | `strings.Contains(resultStr, indicator)` for proxy indicators | Challenge JSON is unlikely to contain "TRUSTED_ENV_PROXY", "HTTP_PROXY" etc. — **safe for string matching** |
| 76-89 | Deep parse: `json.Unmarshal` into `configMap`, check `configMap["TRUSTED_ENV_PROXY"]` | Challenge JSON won't have this key — **safe for structured parse** |

**Severity**: LOW — Although `Call()` may return a challenge, the subsequent string/JSON checks for specific proxy indicators effectively filter it out. The SSRF tests in Phase 2-4 are all HTTP-based and unaffected.

**Fix**: No immediate fix needed for false positives, but adding a generic challenge filter in `Call()` would be cleaner.

---

### 9. `obfuscation_bypass.go` (VULN-24)

**Challenge gate false positive risk: YES (moderate)**

| Line(s) | Logic | Problem |
|---------|-------|---------|
| 113 | `ws.Call("exec.run", ...)` — `err != nil` branch | If challenge returned as result, `err == nil` and falls through to line 132 |
| 132-141 | `unicodeResults[p.name+"_ws"] = true` + creates CRITICAL finding | A challenge response would be treated as "exec.run accepted obfuscated command without detection" — direct false positive |
| 125-127 | `err != nil` but not obfuscation-blocked → also sets `unicodeResults[p.name+"_ws"] = true` | Non-obfuscation errors (including challenge-related errors) are counted as "not blocked" |

**Severity**: HIGH — If `exec.run` is not a recognized method and the server returns a challenge instead, the module will report CRITICAL "Unicode obfuscation bypass via WS exec.run" for every payload. The differential analysis in Phase 4 (lines 180-226) amplifies this: if ASCII payloads are blocked by HTTP but Unicode payloads "succeed" via WS challenge responses, the module reports confirmed bypass.

**Fix**: After `ws.Call("exec.run", ...)` succeeds, validate that `result` contains execution output (e.g., stdout/stderr fields). A challenge response won't have these fields.

---

### 10. `exec_socket_leak.go` (VULN-25/26)

**Challenge gate false positive risk: YES**

| Line(s) | Logic | Problem |
|---------|-------|---------|
| 162 | `ws.Call("config.get", ...)` for env config paths | If challenge returned, `resultStr` contains challenge JSON |
| 170 | `len(resultStr) > 2 && resultStr != "null"` → finding | Challenge JSON passes this check — false positive "Host environment config exposed" |
| 223-224 | `ws.Call("exec.setEnv", ...)` — `err == nil` → bypass confirmed | If challenge returned as result for `exec.setEnv`, `err == nil` triggers CRITICAL "Env var case bypass" finding |
| 249 | Same pattern: `err == nil` after `exec.setEnv` variant → SevHigh finding | Same false positive risk |
| 280-286 | `ws.Call("config.get", ...)` for `env.` + variant — `len(resultStr) > 4` | Challenge JSON passes length check → false positive "Env var value leaked" |

**Severity**: HIGH — Multiple determination points are vulnerable. Phase 3 env case bypass (lines 220-275) is especially dangerous: if `exec.setEnv` for the canonical form returns an error (unknown method) but the variant also returns a challenge-as-result, the module reports a confirmed case sensitivity bypass.

**Fix**: For `exec.setEnv` calls, validate that the response indicates the operation was actually performed (e.g., `"ok":true` or `"set":true`). For `config.get` calls, validate the response structure matches expected config format.

---

### 11. `marker_spoof.go` (VULN-27/28/29)

**Challenge gate false positive risk: YES (Phase 2 & 3 only)**

| Line(s) | Logic | Problem |
|---------|-------|---------|
| 169 | Phase 2 `ws.Call("skills.list", nil)` — `err` checked | If challenge returned, `err == nil` and `result` contains challenge JSON |
| 180 | `json.Unmarshal(result, &skillsList)` | Challenge JSON will unmarshal into `interface{}` successfully — proceeds to scanner tests |
| 231-232 | `ws.Call("skills.scan", ...)` — indirect payload | If challenge returned, `indirectErr == nil` and `indirectResult` contains challenge |
| 254-258 | `indirectResult != nil` → check for "blocked"/"dangerous"/"violation" | Challenge JSON won't contain these → `indirectBlocked = false` |
| 270 | `directBlocked && !indirectBlocked` → CONFIRMED finding | If direct payload errors (unknown method) but indirect returns challenge → false positive |
| 353-363 | Phase 3: `ws.Call("config.get", ...)` — `len(resultStr) > 2 && resultStr != "null"` | Challenge JSON passes → false positive for dangerous flag detection |
| 373 | `resultStr == "true" || Contains(resultStr, "true")` | Challenge JSON unlikely to contain bare "true" — **partially safe** |

**Severity**: HIGH for Phase 2 (scanner evasion). If `skills.scan` is not a real method and the server returns challenges, the differential test (direct blocked vs indirect not-blocked) will produce false positives for every evasion payload. Phase 3 (dangerous flags) has moderate risk — the `config.get` length check is vulnerable but the `"true"` content check provides some protection.

**Fix**: For `skills.scan`, check if the response contains scan-specific fields ("blocked", "passed", "violations"). For `config.get`, validate response is a valid config value, not a protocol message.

---

### 12. `redact_bypass.go` (VULN-30)

**Challenge gate false positive risk: YES (Phase 3 only)**

| Line(s) | Logic | Problem |
|---------|-------|---------|
| 184-185 | `ws.Call(method, ...)` for log methods — `err` checked | If challenge returned, `err == nil` |
| 196-206 | Check `resultStr` for sensitive patterns like "sk_live_", "AKIA", "token" | The word "token" appears in challenge responses (nonce token) — false positive for "Unredacted credentials found in logs" |
| 280 | `len(resultStr) > 10` → finding for cross-session memory read | Challenge JSON passes length check |

**Severity**: MEDIUM — Phase 3 WS log search (lines 178-221) is the risk area. The sensitive pattern "token" (line 199) will match against challenge JSON that contains a token/nonce field. Other patterns like "sk_live_", "AKIA" are unlikely to match challenge content.

**Fix**: Filter out the generic "token" pattern from log search results, or validate that the matched context is actually a credential (e.g., check for `sk_live_` prefix, not bare "token").

---

## v4 Modules

---

### 13. `link_template_inject.go` (VULN-31)

**Challenge gate false positive risk: YES (Phase 2 & 3)**

| Line(s) | Logic | Problem |
|---------|-------|---------|
| 105-106 | `ws.Call("message.send", params)` — `err` checked | If challenge returned as result, `err == nil` |
| 121 | `!strings.Contains(resultStr, marker) && strings.Contains(resultStr, "probe.invalid/ws/")` | Challenge JSON won't contain `probe.invalid/ws/` — **safe**, the probe URL won't appear in a challenge response |
| 109 | Fallback: `ws.Call("chat.send", params)` — same pattern | Same analysis applies |
| 159-160 | Phase 3 nested: `!Contains(resultStr, "{{")` | Challenge JSON won't contain `{{` — but also won't contain `probe.invalid/` so the AND condition protects |

**Severity**: LOW — The determination logic requires the probe URL domain (`probe.invalid/`) to appear in the response, which a challenge response won't contain. The template injection detection is well-guarded by checking for the specific probe URL structure in the response.

**Fix**: No immediate fix needed — the probe URL check acts as an effective canary.

---

### 14. `qmd_cmd_inject.go` (VULN-32)

**Challenge gate false positive risk: YES (moderate)**

| Line(s) | Logic | Problem |
|---------|-------|---------|
| 142-165 | `ws.Call("config.get", ...)` for qmd paths — `len(resultStr) > 2 && resultStr != "null"` | Challenge JSON passes length check → false positive "QMD config readable via WS" |
| 153 | `strings.Contains(strings.ToLower(resultStr), "command")` → SevHigh | Challenge JSON unlikely to contain "command" — **partially safe** |
| 172-173 | `ws.Call("config.set", writePayload)` — `err == nil` → CRITICAL finding | If challenge returned as result for `config.set`, `err == nil` triggers "QMD command writable via WS config.set → RCE" — **severe false positive** |

**Severity**: HIGH — The `config.set` success check (line 173) is the critical risk. If the server returns a challenge response with the matching request ID instead of an error, the module reports confirmed RCE. The `config.get` checks (lines 142-165) have moderate risk — the length check passes but the "command" content check provides partial protection.

**Fix**: For `config.set`, send a follow-up `config.get` to verify the value was actually written. For `config.get`, validate the response structure matches expected config format (key-value pairs, not protocol messages).

---

### 15. `oauth_token_theft.go` (VULN-33)

**Challenge gate false positive risk: YES (Phase 3)**

| Line(s) | Logic | Problem |
|---------|-------|---------|
| 197 | `ws.Call("config.get", ...)` for auth paths — `len(resultStr) > 2` | Challenge JSON passes → false positive |
| 207-210 | `Contains(ToLower(resultStr), "token")` → SevHigh | Challenge JSON containing a nonce/token field will match "token" — false positive "Auth profile store exposed" with elevated severity |
| 233 | `ws.Call(method, ...)` for adopt methods — `err` checked | If challenge returned, `err == nil` |
| 235-236 | `err != nil` but not "unknown method" → check for "blocked"/"denied" | If error is challenge-related, it won't contain "blocked"/"denied" → falls through to SevMedium finding (line 240-248) |
| 251-252 | `err == nil` after adopt method → CRITICAL finding | If challenge returned as result, reports "Credential adoption via WS succeeded" — **severe false positive** |

**Severity**: HIGH — The adopt method success check (line 251) is critical. A challenge response misinterpreted as successful credential adoption would be a CRITICAL false positive. The `config.get` "token" string match (line 207) is also problematic since challenge responses naturally contain token-like fields.

**Fix**: For adopt methods, validate the response contains expected credential fields (`access_token`, `refresh_token`). For `config.get`, validate response is structured config data, not a protocol message.

---

### 16. `exec_race_toctou.go` (VULN-34)

**Challenge gate false positive risk: YES (moderate)**

| Line(s) | Logic | Problem |
|---------|-------|---------|
| 99-100 | `ws.Call("config.get", ...)` for approval paths — `len(resultStr) > 2` | Challenge JSON passes → false positive "Exec approval state readable" |
| 185 | Race test: `c.Call(method, params)` — `err == nil` → `raceSuccess++` | If challenge returned as result, counted as successful race |
| 210-211 | `successes > 1` → TOCTOU confirmed | Multiple WS connections each receiving a challenge would all count as successes, falsely confirming TOCTOU race |

**Severity**: HIGH — The race condition test (Phase 2, lines 134-242) opens multiple WS connections and fires concurrent requests. If each connection receives a `connect.challenge` as the response, ALL of them count as successes (`raceSuccess` incremented for each). With 10 concurrent connections, `successes > 1` is trivially satisfied → false CRITICAL "TOCTOU race confirmed" finding.

**Fix**: After each `Call()` in the race test, validate the response contains expected approval/hash fields. A challenge response won't have `baseHash`, `approved`, or `command` fields.

---

### 17. `memory_data_leak.go` (VULN-36)

**Challenge gate false positive risk: YES (Phase 4)**

| Line(s) | Logic | Problem |
|---------|-------|---------|
| 248-249 | `ws.Call("config.get", ...)` for memory paths — `len(resultStr) > 2` | Challenge JSON passes → false positive "Memory config exposed via WS" |
| 271-272 | `ws.Call(method, ...)` for memory search — `err` checked | If challenge returned, `err == nil` |
| 280 | `len(resultStr) > 10` → finding "Cross-session memory read" | Challenge JSON easily exceeds 10 chars → false positive |

**Severity**: MEDIUM — Phase 4 WS tests (lines 234-292) are supplementary to the HTTP-based phases 1-3. The `config.get` length check and `memory.search` length check are both vulnerable to challenge responses, but the HTTP phases provide the primary detection and are unaffected.

**Fix**: Validate `config.get` responses contain memory-specific fields. For `memory.search`/`memory.query`, validate the response is an array of search results, not a protocol message.

---

### 18. `media_ssrf.go` (VULN-40)

**Challenge gate false positive risk: NO**

This module uses exclusively HTTP requests via `utils.DoRequest`. All SSRF detection is based on HTTP status codes and response body content analysis (ECONNREFUSED, timeout, connect indicators). No WS `Call()` usage in any determination logic.

---

## Summary Matrix

| # | Module | File | Challenge FP Risk | Severity | Root Cause |
|---|--------|------|-------------------|----------|------------|
| 1 | silent_pair_abuse | silent_pair_abuse.go:83-86 | **YES** | HIGH | Raw `ReadMessage()` treats any non-auth-error response as auto-pair confirmation |
| 2 | flood_guard_reset | flood_guard_reset.go:117-118 | **YES** | MEDIUM | `Call()` result length check on reconnect verification |
| 3 | auth_disable_leak | auth_disable_leak.go:108-109 | **YES** | HIGH | No-auth `Call()` success = "privileged op succeeded" |
| 4 | origin_wildcard | origin_wildcard.go:108-116 | **YES** | MEDIUM | `callErr != nil` path still creates finding for "partial bypass" |
| 5 | csrf_no_origin | csrf_no_origin.go | **NO** | — | HTTP-only module |
| 6 | ratelimit_scope_bypass | ratelimit_scope_bypass.go:196-204 | **YES** | LOW | WS success counter inflated by +1 per challenge |
| 7 | ssrf_rebind | ssrf_rebind.go | **NO** | — | HTTP-only module |
| 8 | ssrf_proxy_bypass | ssrf_proxy_bypass.go:43-51 | **YES** | LOW | `config.get` string matching filters out challenge content |
| 9 | obfuscation_bypass | obfuscation_bypass.go:132-141 | **YES** | HIGH | `exec.run` challenge response → CRITICAL "bypass confirmed" |
| 10 | exec_socket_leak | exec_socket_leak.go:223-249 | **YES** | HIGH | `exec.setEnv` challenge response → "case bypass confirmed" |
| 11 | marker_spoof | marker_spoof.go:231-270 | **YES** | HIGH | `skills.scan` challenge → differential evasion false positive |
| 12 | redact_bypass | redact_bypass.go:196-206 | **YES** | MEDIUM | "token" pattern matches challenge nonce field |
| 13 | link_template_inject | link_template_inject.go:121 | **YES** | LOW | Probe URL canary in response check protects against FP |
| 14 | qmd_cmd_inject | qmd_cmd_inject.go:172-173 | **YES** | HIGH | `config.set` challenge response → CRITICAL "RCE confirmed" |
| 15 | oauth_token_theft | oauth_token_theft.go:251-252 | **YES** | HIGH | Adopt method challenge response → CRITICAL "token theft" |
| 16 | exec_race_toctou | exec_race_toctou.go:185-211 | **YES** | HIGH | N concurrent challenges all counted as race successes |
| 17 | memory_data_leak | memory_data_leak.go:271-280 | **YES** | MEDIUM | `len > 10` on challenge JSON → "cross-session leak" |
| 18 | media_ssrf | media_ssrf.go | **NO** | — | HTTP-only module |

**Totals**: 15/18 modules affected, 7 HIGH, 4 MEDIUM, 4 LOW, 3 clean (HTTP-only)

---

## Root Cause Analysis

The systemic root cause is in `pkg/utils/gateway_ws.go:96-108`:

```go
// Read responses until we get our ID back
c.conn.SetReadDeadline(time.Now().Add(c.timeout))
for {
    var resp WSMessage
    if err := c.conn.ReadJSON(&resp); err != nil {
        return nil, fmt.Errorf("ws read: %w", err)
    }
    if resp.ID == id {
        if resp.Error != nil {
            return nil, fmt.Errorf("rpc error %d: %s", resp.Error.Code, resp.Error.Message)
        }
        return resp.Result, nil  // ← returns challenge as valid result
    }
    // Skip push messages / events with different IDs
}
```

**Problem**: `Call()` has no awareness of the `connect.challenge` protocol. Two failure modes:

1. **Challenge as push message (different ID)**: Silently skipped. The real RPC response (if any) is returned correctly. This is the benign case.

2. **Challenge as response (matching ID)**: Returned as `json.RawMessage` with `nil` error. Every caller that checks `err == nil` treats this as a successful RPC call. This is the false positive case.

Additionally, `silent_pair_abuse.go` bypasses `Call()` entirely and uses raw `WriteMessage`/`ReadMessage`, making it vulnerable to any first-message-is-challenge protocol.

---

## Recommended Fixes

### Fix 1: Challenge-aware `Call()` (systemic fix)

Add challenge detection to `GatewayWSClient.Call()` in `gateway_ws.go`:

```go
func (c *GatewayWSClient) Call(method string, params interface{}) (json.RawMessage, error) {
    // ... existing send logic ...

    c.conn.SetReadDeadline(time.Now().Add(c.timeout))
    for {
        var resp WSMessage
        if err := c.conn.ReadJSON(&resp); err != nil {
            return nil, fmt.Errorf("ws read: %w", err)
        }

        // Skip connect.challenge messages — they are handshake protocol,
        // not RPC responses. Treat as server push regardless of ID.
        if resp.Method == "connect.challenge" {
            continue
        }

        if resp.ID == id {
            if resp.Error != nil {
                return nil, fmt.Errorf("rpc error %d: %s", resp.Error.Code, resp.Error.Message)
            }
            return resp.Result, nil
        }
    }
}
```

This single fix eliminates the false positive risk for all 12 modules that use `Call()`.

### Fix 2: Challenge-aware raw read (for silent_pair_abuse.go)

In `silent_pair_abuse.go`, after `conn.ReadMessage()` at line 74:

```go
respStr := string(respMsg)
// Skip connect.challenge — it's the handshake first step, not auto-pair confirmation
if strings.Contains(respStr, "connect.challenge") {
    // Read next message — the actual response to our health call
    _, respMsg, readErr = conn.ReadMessage()
    if readErr != nil {
        conn.Close()
        continue
    }
    respStr = string(respMsg)
}
```

### Fix 3: Response structure validation (defense-in-depth)

For HIGH-severity modules, add response structure validation as a second layer:

```go
// Example for exec_socket_leak.go exec.setEnv check
result, err := ws.Call("exec.setEnv", params)
if err == nil {
    // Validate response is an actual setEnv confirmation, not a protocol message
    var setResult map[string]interface{}
    if json.Unmarshal(result, &setResult) != nil {
        continue // not valid JSON object — skip
    }
    if _, hasOK := setResult["ok"]; !hasOK {
        if _, hasSet := setResult["set"]; !hasSet {
            continue // no confirmation field — likely protocol message
        }
    }
    // ... proceed with finding creation ...
}
```

### Fix Priority

| Priority | Fix | Impact | Effort |
|----------|-----|--------|--------|
| P0 | Fix 1: Challenge-aware `Call()` | Eliminates 12/15 affected modules | 1 file, ~5 lines |
| P0 | Fix 2: Challenge-aware raw read | Eliminates silent_pair_abuse FP | 1 file, ~8 lines |
| P1 | Fix 3: Response validation | Defense-in-depth for 7 HIGH modules | 7 files, ~5-10 lines each |

---

## Additional Non-Challenge False Positive Patterns

Beyond the `connect.challenge` issue, the following determination logic patterns also carry false positive risk:

### Pattern A: HTTP 500 + error string matching as SSRF confirmation

**Affected**: `ssrf_rebind.go:98-105`, `ssrf_proxy_bypass.go:170-178`, `media_ssrf.go:106-113`

These modules treat HTTP 500 responses containing "ECONNREFUSED", "timeout", or "connect" as SSRF confirmation. However, a 500 error with "connect" in the body could be any backend connection failure (e.g., the AI provider is down), not necessarily SSRF. The word "timeout" is especially generic.

**Recommendation**: Require the error message to also contain the target IP/hostname (e.g., "169.254.169.254", "127.0.0.1") to confirm the server actually attempted to reach the internal target.

### Pattern B: HTTP 200 + response body keyword matching

**Affected**: `exec_socket_leak.go:48-58`, `qmd_cmd_inject.go:50-57`

These modules check for generic keywords like "socket", "token", "path", "command" in HTTP 200 responses. These words are common in many API responses and don't necessarily indicate vulnerability. The `hitCount >= 1` threshold (exec_socket_leak.go:58) is too low.

**Recommendation**: Raise `hitCount` threshold to >= 2 and require more specific indicators (e.g., actual file paths like `/tmp/*.sock`, not just the word "socket").

### Pattern C: `len(result) > N` as success indicator

**Affected**: Multiple modules using `len(resultStr) > 2`, `len(resultStr) > 4`, `len(resultStr) > 10`

Any non-empty JSON response passes these checks. Error messages, protocol messages, and even `{"error":"not found"}` would pass `len > 2`.

**Recommendation**: Replace length checks with structural validation — parse as expected type and check for expected fields.

---

*End of audit report.*
