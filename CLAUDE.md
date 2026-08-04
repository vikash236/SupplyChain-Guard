# CLAUDE.md — Agent Briefing for SupplyChain-Guard

## Build & Test Commands
- **Build project:** `cargo build`
- **Release build:** `cargo build --release`
- **Run tests:** `cargo test`
- **Lint check:** `cargo clippy -- -D warnings`
- **Format code:** `cargo fmt`

## Architecture Standards
- **Core language:** Rust (2021 edition)
- **OS Sandboxing:** `winapi` / `windows-sys` for Windows Job Objects, `nix` / `libc` for Linux namespaces.
- **AST Parsing:** `syn` for Rust `build.rs` parsing, `serde_json` for Node `package.json` hook inspection.

## Handoff & State Tracking
- Check `.agent/specs/active/current.md` for active tasks.
- Log completed features in `.agent/memory/execution.log`.
