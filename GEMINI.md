# GEMINI.md — Agent Guidelines for SupplyChain-Guard

## Overview
You are working on **SupplyChain-Guard**, a Rust-based build-time sandbox and static AST analyzer that detects and contains malicious supply chain build scripts (`build.rs` and Node `postinstall`) before they compromise developer machines.

## Rules of Engagement
- Always read `.agent/specs/active/current.md` before making code changes.
- Follow all rules in `.agent/rules/security-guardrails.md` — especially: no code execution in the scanner, network deny-by-default in the sandbox, credential env-var stripping.
- Cross-platform sandbox handling: keep platform-specific sandbox code isolated under `crates/sandbox/src/win/` (Windows Job Objects + AppContainer) and `crates/sandbox/src/linux/` (`unshare` + `seccomp-bpf`). Use `#[cfg(target_os)]` gates.
- Scanner uses `syn` (full features) for Rust AST analysis and `serde_json` for `package.json` parsing. Scanner must never execute analyzed code.
- CLI uses `clap` with `scan` and `exec` subcommands. Support both JSON and human-readable output.
- Update `.agent/memory/execution.log` after completing tasks.
