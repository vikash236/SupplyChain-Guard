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

### Next Tasks: Phase 1 — Process Isolation Enforcer
- [ ] Implement Windows Job Objects isolation in `crates/sandbox/src/win.rs` using `windows-sys` (`CreateJobObjectW`, `SetInformationJobObject`).
- [ ] Implement AppContainer capability-based filesystem and network restriction on Windows.
- [ ] Implement Linux namespace isolation in `crates/sandbox/src/linux.rs` using `nix` (`unshare` for `CLONE_NEWPID`, `CLONE_NEWNET`, `CLONE_NEWNS`).
- [ ] Implement environment variable credential stripping prior to process launch.
