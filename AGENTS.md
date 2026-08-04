# SupplyChain-Guard — Agent Instructions

> **Project Goal:** Build-time sandbox and static analyzer that detects and contains malicious supply chain build scripts (`build.rs`, `postinstall`) before they compromise developer machines — combining AST-level code inspection with OS-native process isolation.

## 🤖 Unified Multi-AI Workflow

Whether you are Gemini, Claude, Codex, or any other LLM assistant, you are participating in a continuous, unified multi-agent development session.

### Rules for All AI Assistants:
1. **Seamless Handoff:** Pick up execution exactly where the previous AI assistant left off by inspecting `.agent/memory/execution.log` and `.agent/memory/handoff.md`.
2. **Single Blueprint:** Follow the active specs in `.agent/specs/active/` and update status when completing tasks.
3. **OS Sandboxing Standards:** Leverage Windows Job Objects + AppContainer on Windows and Linux `unshare` + `seccomp-bpf` on Linux. Keep platform-specific code isolated under `crates/sandbox/src/win/` and `crates/sandbox/src/linux/`.
4. **Security Guardrails:** Follow all rules in `.agent/rules/security-guardrails.md` — especially: no code execution in the scanner, network deny-by-default in the sandbox, credential env-var stripping before process launch.

## Quick Start for Agents

1. **Active specs & tasks?** → Read `.agent/specs/active/current.md`
2. **Execution history?** → Read `.agent/memory/execution.log`
3. **Architecture catalog?** → Read `.agent/specs/active/catalog.md`
4. **Security rules?** → Read `.agent/rules/security-guardrails.md`

## Architecture Overview

| Module | Location | Purpose |
|--------|----------|---------|
| `scanner` | `crates/scanner/` | Static AST scanner — `syn` for Rust `build.rs` analysis, `serde_json` for Node.js `package.json` lifecycle hook inspection |
| `sandbox` | `crates/sandbox/` | OS-native process sandbox — Windows: Job Objects + AppContainer; Linux: `unshare` namespaces + `seccomp-bpf` syscall filtering |
| `cli` | `src/` | CLI entry point — `clap`-based with `scan` (static analysis) and `exec` (sandboxed execution) subcommands |

## Key Dependencies

| Crate | Purpose |
|-------|---------|
| `syn` (full features) | Rust AST parsing for `build.rs` |
| `serde_json` | `package.json` parsing |
| `clap` | CLI argument parsing |
| `windows-sys` | Windows Job Objects and AppContainer API bindings |
| `nix` / `libc` | Linux namespace and seccomp API bindings |
| `walkdir` | Recursive directory traversal for finding build scripts |

## Rules & Policies

| Policy | Path |
|--------|------|
| Security Guardrails | `.agent/rules/security-guardrails.md` |
