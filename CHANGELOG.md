# Changelog

All notable changes to CatchClaw will be documented in this file.

Format based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [5.0.0] - 2026-03-19

### Changed
- **Complete rewrite from Go to Rust** (Edition 2024, Tokio async runtime)
- CLI framework: Cobra (Go) → clap derive (Rust)
- HTTP client: net/http (Go) → reqwest with rustls-tls (Rust)
- WebSocket client: gorilla/websocket (Go) → tokio-tungstenite (Rust)
- Concurrency: goroutines (Go) → tokio::task::JoinSet + Semaphore (Rust)
- Exploit registration: manual registry (Go) → inventory crate auto-collection (Rust)

### Added
- 59 exploit modules (up from 30 in v4.0.0)
- 59-node DAG attack chain with Kahn's topological sort
- ATT&CK 9-phase mapping (Recon → Impact)
- Condition-based and fallback node execution
- AttackGraph with Mermaid diagram export
- False-positive filters: challenge page, SPA fallback, LLM refusal detection
- 38 unit tests for core modules (http, types, DAG)
- New modules: C2 exfil, skill poison, MCP inject, DNS rebind, TOCTOU race, QMD inject, keychain inject, browser upload traversal, and more

### Removed
- Go codebase (all `cmd/`, `pkg/` directories)
- Interactive shell (msfconsole-style REPL)
- Shodan/FOFA asset discovery
- AI-powered fuzzing module
- Built-in CVE database
- HTML report generation (JSON only for now)
- MCP stdio server

## [4.0.0] - 2026-03-17

### Added
- 55 DAG attack chains
- 30 exploit modules
- Nuclei templates (23 main + 7 v3 + 15 v4)
- Interactive shell
- Shodan/FOFA discovery
- AI-powered fuzzing (Anthropic/OpenAI)

## [1.0.0] - 2026-03-15

### Added
- Initial release
- 31 attack chains, 30 exploit modules
- Go 1.22 implementation
