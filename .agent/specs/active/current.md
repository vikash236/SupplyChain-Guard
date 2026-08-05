# Active Workstreams — SupplyChain-Guard

## Active Phase: Phase 1 — Process Isolation Enforcer

### Scaffold & Workspace (Phase 0 Completed ✓)
- [x] Initialize Cargo workspace (`Cargo.toml` with members: `crates/scanner`, `crates/sandbox`, root `src/`).
- [x] Set up `crates/scanner/Cargo.toml` with dependencies (`syn`, `serde_json`, `walkdir`).
- [x] Set up `crates/sandbox/Cargo.toml` with platform-conditional dependencies (`windows-sys`, `nix`/`libc`).
- [x] Create CLI entry point in `src/main.rs` using `clap` with `scan` and `exec` subcommands.

### Rust `build.rs` Scanner (Phase 0 Completed ✓)
- [x] Implement `syn` AST visitor that walks Rust source files.
- [x] Detect `std::process::Command::new()` and `.spawn()` / `.output()` call chains.
- [x] Detect `std::net::TcpStream::connect()` and `std::net::UdpSocket::bind()`.
- [x] Detect `std::env::var()` / `std::env::vars()` accessing sensitive key patterns.
- [x] Detect `std::fs::read()` / `std::fs::read_to_string()` targeting sensitive paths.
- [x] Assign severity levels: `INFO`, `WARN`, `CRITICAL`.

### Node.js `package.json` Scanner (Phase 0 Completed ✓)
- [x] Parse `package.json` `scripts` field via `serde_json`.
- [x] Detect shell metacharacters in lifecycle hooks (`preinstall`, `install`, `postinstall`, `prepare`).
- [x] Detect `curl`, `wget`, `nc`, `bash -c`, `eval`, `base64` patterns in script values.
- [x] Flag encoded/obfuscated payloads.

### Output & CLI (Phase 0 Completed ✓)
- [x] Implement structured findings output (JSON format).
- [x] Implement human-readable terminal output with color-coded severity.
- [x] Return non-zero exit code when CRITICAL findings are present.
- [x] Write integration tests with sample malicious and benign `build.rs` / `package.json` fixtures.

---

### Process Isolation Enforcer (Phase 1 Completed ✓)
- [x] Implement Windows Job Objects isolation in `crates/sandbox/src/win.rs` using `windows-sys` (`CreateJobObjectW`, `SetInformationJobObject` with `JOBOBJECT_EXTENDED_LIMIT_INFORMATION` & `JOBOBJECT_BASIC_UI_RESTRICTIONS`).
- [x] Implement UI restrictions and process handle isolation on Windows.
- [x] Implement Linux namespace isolation in `crates/sandbox/src/linux.rs` using `nix` (`unshare` for `CLONE_NEWPID`, `CLONE_NEWNET`, `CLONE_NEWNS`).
- [x] Implement environment variable credential stripping prior to process launch (`AWS_*`, `GITHUB_*`, `SLACK_*`, `DATABASE_*`, `ID_RSA`, etc. stripped by default).
- [x] Implement CLI command string parsing (`parse_command_str`) and connect `supplychain-guard exec` subcommand to active sandbox enforcer.
- [x] Write comprehensive unit and integration tests for sandbox configurations and sandboxed process execution (30 passing workspace tests).

---

### Dynamic Behavioral Interceptor & Policy Engine (Phase 2 Completed ✓)
- [x] Implement declarative build policy engine crate (`crates/policy`) for `guard.toml` configuration parsing (`GuardPolicy`, `ScannerPolicy`, `SandboxPolicy`, `RulePolicy`).
- [x] Implement policy-driven scanner finding suppressions, ignored paths, and severity overrides in `crates/scanner/src/lib.rs` (`apply_policy_to_report`).
- [x] Implement policy-driven sandbox configuration construction, environment denylisting, and process memory limits (`memory_limit_mb`) via Windows Job Objects `JOBOBJECT_EXTENDED_LIMIT_INFORMATION` (`ProcessMemoryLimit`).
- [x] Add `--config` / `-c` CLI option to `supplychain-guard scan` and `exec` subcommands with auto-detection of `./guard.toml`.
- [x] Provide annotated example policy configuration (`guard.toml.example`).
- [x] Write complete unit test suite for policy parsing and enforcement (32 passing workspace tests).

---

### Next Tasks: Phase 3 — Continuous CI/CD Integration & Enterprise Governance
- [ ] Implement GitHub Actions reusable action runner (`action.yml`).
- [ ] Implement SARIF (Static Analysis Results Interchange Format) report output for GitHub Security / Code Scanning integration.
- [ ] Implement build script hash caching / signature verification to skip unchanged benign build scripts.
- [ ] Add pre-commit hook installer command (`supplychain-guard init-hook`).


