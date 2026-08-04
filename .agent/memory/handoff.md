# Context Handoff Contract — SupplyChain-Guard

## Current Status
- **Phase 0 (Static AST Script Scanner & Scaffold): COMPLETE.**
  - Initialized Cargo workspace with `crates/scanner`, `crates/sandbox`, and root CLI crate.
  - Implemented `syn` AST visitor in `crates/scanner/src/rust_scanner.rs` to parse `build.rs` files and detect `Command::new()`, `TcpStream::connect()`, sensitive `env::var()` access, and sensitive `fs::read()` operations.
  - Implemented `package.json` lifecycle hook scanner in `crates/scanner/src/node_scanner.rs` to detect shell metacharacters, `curl`/`wget`/`eval` suspicious commands, and base64/hex obfuscated payloads.
  - Implemented `crates/scanner/src/project_scanner.rs` for recursive project directory walking with skip rules (`.git`, `target`, `node_modules`).
  - Created `src/main.rs` CLI entry point with `clap` implementing `scan` (with text & JSON formats) and `exec` subcommands.
  - Created test fixtures and complete unit + integration test suite (26 passing tests).

## Next Phase: Phase 1 — Process Isolation Enforcer
- Implement OS-native process sandboxing in `crates/sandbox/src/win.rs` (Windows Job Objects via `windows-sys` + AppContainer capability profiles) and `crates/sandbox/src/linux.rs` (Linux `unshare` namespaces + `seccomp-bpf`).
- Connect `supplychain-guard exec` subcommand to active process sandbox enforcer.
- Implement target directory write isolation (`./target/` or `./node_modules/`).
