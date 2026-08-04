# CLAUDE.md — Agent Briefing for SupplyChain-Guard

## Build & Test Commands
- **Build project:** `cargo build`
- **Release build:** `cargo build --release`
- **Run tests:** `cargo test`
- **Lint check:** `cargo clippy -- -D warnings`
- **Format code:** `cargo fmt`

## Architecture Standards
- **Core language:** Rust (2021 edition)
- **AST Parsing:** `syn` (full features) for Rust `build.rs` static analysis, `serde_json` for Node `package.json` lifecycle hook inspection.
- **OS Sandboxing (Windows):** `windows-sys` for Job Objects (`CreateJobObjectW`, `SetInformationJobObject`) and AppContainer (`CreateAppContainerProfile`). Platform code under `crates/sandbox/src/win/`.
- **OS Sandboxing (Linux):** `nix` / `libc` for `unshare` namespaces (PID/NET/MNT) and `seccomp-bpf` syscall filtering. Platform code under `crates/sandbox/src/linux/`.
- **CLI:** `clap` with `scan` and `exec` subcommands. JSON and human-readable output formats.
- **Cross-platform isolation:** Platform-specific sandbox code must be isolated behind `#[cfg(target_os = "...")]` gates. Shared abstractions in `crates/sandbox/src/lib.rs`.

## Security Rules
- Scanner must NEVER execute or compile analyzed code — AST parsing only.
- Sandbox must strip credential env vars before launching any process.
- Sandbox must enforce network deny-by-default — zero outbound connectivity.
- Filesystem writes restricted to `./target/` or `./node_modules/` only.

## Handoff & State Tracking
- Check `.agent/specs/active/current.md` for active tasks.
- Log completed features in `.agent/memory/execution.log`.
- Follow security guardrails in `.agent/rules/security-guardrails.md`.
