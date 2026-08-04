# GEMINI.md — Agent Guidelines for SupplyChain-Guard

## Overview
You are working on **SupplyChain-Guard**, a Rust-based build script sandbox and static AST scanner for `build.rs` and Node `postinstall` scripts.

## Rules of Engagement
- Always read `.agent/specs/active/current.md` before making code changes.
- Cross-platform sandbox handling: keep platform-specific sandbox code isolated under `crates/sandbox/src/win/` and `crates/sandbox/src/linux/`.
- Update `.agent/memory/execution.log` after completing tasks.
