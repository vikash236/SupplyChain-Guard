# Master Phase Blueprint Catalog — SupplyChain-Guard

> Authoritative roadmap for all development phases. Each phase maps to a specific layer in the defense-in-depth pipeline.

| Phase | Title | Description | Key Deliverables | Status |
|-------|-------|-------------|-----------------|--------|
| **P0** | Static AST Script Scanner | `syn`-based Rust AST visitor for `build.rs` and `serde_json` parser for `package.json` lifecycle hooks. Detects command execution (`Command::new`), network calls (`TcpStream::connect`), credential access (`env::var` for sensitive keys), and suspicious filesystem reads (`~/.ssh/`, `~/.aws/`, `.env`) | `crates/scanner/`, `supplychain-guard scan` CLI subcommand, JSON + human-readable output | 🔄 Active |
| **P1** | Process Isolation Enforcer | OS-native sandbox wrapper. **Windows:** Job Objects (`CreateJobObjectW`, `SetInformationJobObject`) + AppContainer (`CreateAppContainerProfile`) for capability-based isolation. **Linux:** `unshare` namespaces (PID/NET/MNT) + `seccomp-bpf` syscall filtering | `crates/sandbox/`, platform-specific modules under `src/win/` and `src/linux/`, `supplychain-guard exec` CLI subcommand | ⏳ Pending |
| **P2** | Network & Env Sanitizer | Network deny-by-default enforcement inside the sandbox. Environment variable stripping for known credential patterns (`AWS_*`, `GITHUB_TOKEN`, `NPM_TOKEN`, `SSH_AUTH_SOCK`). Configurable allowlists for legitimate env vars | Integrated into `crates/sandbox/`, env sanitization module, network policy config | ⏳ Pending |
| **P3** | Package Manager Integration | Transparent wrappers: `cargo-guard` Cargo subcommand (intercepting `cargo build` to inject scan + sandbox) and `npm-guard` npm wrapper (intercepting `npm install` lifecycle hooks) | `crates/cargo-guard/`, `crates/npm-guard/`, integration tests with real package builds | ⏳ Pending |
| **P4** | CI/CD Pipeline Mode | Structured JSON output, configurable severity thresholds, non-zero exit codes for CI gating, SARIF report generation for GitHub Security tab integration | SARIF output module, CI config examples (GitHub Actions, GitLab CI), threshold configuration | ⏳ Pending |
