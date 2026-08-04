# SupplyChain-Guard Agent Board

> Build-time sandbox & static analyzer for supply chain build scripts. This board manages multi-AI workstreams and specs.

## Board Structure

| Path | Purpose |
|------|---------|
| `specs/active/current.md` | Active workstreams and current phase checklist |
| `specs/active/catalog.md` | Master phase blueprint catalog (P0–P4) |
| `memory/execution.log` | Timestamped log of execution milestones |
| `memory/handoff.md` | Multi-agent context handoff document |
| `rules/security-guardrails.md` | Sandbox threat model and enforcement rules |

## Architecture Summary

| Module | Location | Purpose |
|--------|----------|---------|
| `scanner` | `crates/scanner/` | Static AST scanner — `syn` for `build.rs`, `serde_json` for `package.json` lifecycle hooks |
| `sandbox` | `crates/sandbox/` | OS-native process sandbox — Windows Job Objects + AppContainer, Linux `unshare` + `seccomp-bpf` |
| `cli` | `src/` | CLI entry point — `scan` (static analysis) and `exec` (sandboxed execution) subcommands |

## Priority Phases
- **Phase 0 (Static AST Scanner):** AST parser for `build.rs` detecting command spawning, network calls, credential access, and suspicious filesystem reads. `package.json` script analyzer for lifecycle hook inspection.
- **Phase 1 (Process Isolation Enforcer):** Windows Job Objects + AppContainer / Linux `unshare` + `seccomp-bpf` sandbox wrapper with filesystem write isolation.
- **Phase 2 (Network & Env Sanitizer):** Network deny-by-default enforcement and credential environment variable stripping.
- **Phase 3 (Package Manager Integration):** `cargo-guard` and `npm-guard` transparent wrappers for build workflow integration.
- **Phase 4 (CI/CD Pipeline Mode):** SARIF output, severity thresholds, and CI gating support.
