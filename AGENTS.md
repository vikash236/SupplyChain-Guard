# SupplyChain-Guard — Agent Instructions

> **Project Goal:** High-performance build-time script sandbox and AST security analyzer for Rust (`build.rs`) and Node.js (`postinstall`).

## 🤖 Unified Multi-AI Workflow

Whether you are Gemini, Claude, Codex, or any other LLM assistant, you are participating in a continuous, unified multi-agent development session.

### Rules for All AI Assistants:
1. **Seamless Handoff:** Pick up execution exactly where the previous AI assistant left off by inspecting `.agent/memory/execution.log` and `.agent/memory/handoff.md`.
2. **Single Blueprint:** Follow the active specs in `.agent/specs/active/` and update status when completing tasks.
3. **OS Sandboxing Standards:** Leverage Windows Job Objects / AppContainers on Windows and Linux namespaces (`unshare`/seccomp) on Linux.

## Quick Start for Agents

1. **Active specs & tasks?** → Read `.agent/specs/active/current.md`
2. **Execution history?** → Read `.agent/memory/execution.log`
3. **Architecture catalog?** → Read `.agent/specs/active/catalog.md`

## Architecture Overview

| Module | Location | Purpose |
|--------|----------|---------|
| `scanner` | `crates/scanner/` | Static AST scanner for `build.rs` and `package.json` scripts |
| `sandbox` | `crates/sandbox/` | OS-native process sandbox and privilege isolation enforcer |
| `cli` | `src/` | CLI runner wrapping build command invocations |

## Rules & Policies

| Policy | Path |
|--------|------|
| Token Efficiency | `.agent/rules/token-efficiency.md` |
| Security Guardrails | `.agent/rules/security-guardrails.md` |
| Project Structure | `.agent/rules/project-structure.md` |
| Context Hygiene | `.agent/rules/context-hygiene.md` |
