# Active Workstreams — SupplyChain-Guard

## Active Phase: Phase 8 — Software Bill of Materials (SBOM) Security Attestation Engine

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

### Continuous CI/CD Integration & Enterprise Governance (Phase 3 Completed ✓)
- [x] Implement SARIF v2.1.0 report exporter in `crates/scanner/src/sarif.rs` (`report_to_sarif`) with `--format sarif` CLI option.
- [x] Implement GitHub Actions reusable workflow (`action.yml`) for automated static AST security scans and SARIF uploads to GitHub Security Code Scanning.
- [x] Implement SHA-256 build script hash caching engine (`crates/scanner/src/cache.rs`) with `--use-cache` / `-u` CLI option.
- [x] Implement pre-commit hook installer command (`supplychain-guard init-hook`) creating `.git/hooks/pre-commit`.
- [x] Complete workspace unit and integration test suite (34 passing tests).
---

### Advanced AST Heuristics & Enterprise Hardening (Phase 4 Completed ✓)
- [x] Implement dynamic FFI call AST inspection (`dlsym`, `dlopen`, `LoadLibrary`, `GetProcAddress`, `memfd_create`) in `crates/scanner/src/rust_scanner.rs`.
- [x] Implement raw socket / HTTP client crate import inspection (`socket2`, `reqwest`, `ureq`, `hyper`, `curl`).
- [x] Implement obfuscated hex/byte-array literal sequence detection (`[0x68, 0x65, 0x6c, ...]`).
- [x] Implement policy template generator command (`supplychain-guard init-config`).
- [x] Add scan execution duration performance telemetry to report output.
- [x] Complete comprehensive unit test suite (37 passing workspace tests).
- [x] Commit and push all changes to GitHub repository (`main` branch commit `1cffd59`).

---

### Package Manager Interceptor & Ecosystem Integration (Phase 5 Completed ✓)
- [x] Create `crates/cargo-guard` workspace member crate.
- [x] Implement `cargo-guard` binary subcommand plugin supporting `cargo guard scan` and `cargo guard build` transparent security gate interception.
- [x] Implement `supplychain-guard npm-install` subcommand for Node.js package lifecycle script pre-install scanning and sandboxed installation.
- [x] Implement `cargo-guard` integration unit test suite (`cargo_guard_tests.rs`).

---

### Security Audit Telemetry Engine & Policy Auto-Tuning (Phase 6 Completed ✓)
- [x] Create `crates/audit` workspace member crate.
- [x] Implement append-only JSONL event audit logger (`.guard-audit.jsonl`).
- [x] Implement scan event and sandboxed process execution record logging in `AuditLogger`.
- [x] Implement telemetry metrics analysis and policy recommendation engine in `crates/audit/src/lib.rs`.
- [x] Add `supplychain-guard audit` subcommand to analyze historical audit trails.
- [x] Integrate `AuditLogger` into `supplychain-guard` and `cargo-guard` execution pipelines.
- [x] Complete comprehensive unit test suite (`crates/audit/tests/audit_tests.rs`).

---

### Workspace Integrity & Build Mutation Gating (Phase 7 Completed ✓)
- [x] Create `crates/integrity` workspace member crate.
- [x] Implement `WorkspaceSnapshot` SHA-256 workspace file hashing engine.
- [x] Implement pre/post execution snapshot diff verification algorithm.
- [x] Integrate pre/post integrity checks into `supplychain-guard exec` and `cargo-guard`.
- [x] Add `supplychain-guard verify-integrity` CLI subcommand.
- [x] Complete comprehensive unit and integration test suite (`crates/integrity/tests/integrity_tests.rs`).

---

### Software Bill of Materials (SBOM) Security Attestation Engine (Phase 8 Completed ✓)
- [x] Create `crates/sbom` workspace member crate.
- [x] Implement `SbomGenerator` with CycloneDX v1.4 and SPDX v2.3 compliant JSON output engines.
- [x] Annotate build script component hashes, AST security findings, and sandbox policy settings in SBOM manifests.
- [x] Add `supplychain-guard sbom` CLI subcommand with `--format cyclonedx` / `--format spdx`.
- [x] Complete comprehensive unit and integration test suite (`crates/sbom/tests/sbom_tests.rs`).








