# Contributing to CatchClaw

Thank you for your interest in contributing to CatchClaw.

## License Agreement

By contributing to this project, you agree that your contributions will be licensed under the [CatchClaw Strict Non-Commercial License v2.0](LICENSE). **All commercial use is strictly prohibited.**

## Development Setup

```bash
# Clone
git clone https://github.com/Coff0xc/catchclaw.git
cd catchclaw/rust

# Build
cargo build

# Run tests
cargo test

# Lint
cargo clippy -- -D warnings

# Format
cargo fmt
```

## Adding a New Exploit Module

1. Create `rust/src/exploit/your_module.rs`:

```rust
use crate::config::AppConfig;
use crate::exploit::base::ExploitCtx;
use crate::exploit::{Category, Phase};
use crate::utils::{Finding, Severity, Target};
use crate::register_exploit;

register_exploit!("your_module", "Module Name", Category::Xxx, Phase::Xxx, check);

pub async fn check(target: Target, cfg: AppConfig) -> Vec<Finding> {
    let ctx = ExploitCtx::setup(&target, "Module Name", &cfg);
    let mut findings = Vec::new();
    // ... exploit logic ...
    findings
}
```

2. Add `pub mod your_module;` to `rust/src/exploit/mod.rs`
3. Add a chain node in `rust/src/chain/chains.rs`
4. Run `cargo test` to verify

## Code Style

- Follow existing patterns — read `exploit/ssrf.rs` as a reference
- Use `ExploitCtx::setup()` for HTTP client initialization
- Return `Vec<Finding>` with proper severity, evidence, and remediation
- Use `is_challenge_response()` / `is_non_api_response()` for false-positive filtering
- Prefer `tracing` macros over `println!` for logging

## Commit Messages

Follow conventional commits:

```
feat: add new exploit module for XYZ
fix: resolve false positive in SSRF detection
docs: update README with new module
test: add unit tests for DAG topological sort
refactor: simplify HTTP client configuration
```

## Pull Requests

- One feature/fix per PR
- Include tests for new functionality
- Update CHANGELOG.md
- Ensure `cargo clippy -- -D warnings` passes
- Ensure `cargo test` passes
