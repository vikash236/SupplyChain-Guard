# Context Handoff Contract — SupplyChain-Guard

## Current Status
- **Phase 0 (Static AST Script Scanner & Scaffold): COMPLETE.**
  - Initialized Cargo workspace with `crates/scanner`, `crates/sandbox`, and root CLI crate.
  - Implemented `syn` AST visitor in `crates/scanner/src/rust_scanner.rs` to parse `build.rs` files and detect `Command::new()`, `TcpStream::connect()`, sensitive `env::var()` access, and sensitive `fs::read()` operations.
  - Implemented `package.json` lifecycle hook scanner in `crates/scanner/src/node_scanner.rs` to detect shell metacharacters, `curl`/`wget`/`eval` suspicious commands, and base64/hex obfuscated payloads.
  - Implemented `crates/scanner/src/project_scanner.rs` for recursive project directory walking with skip rules (`.git`, `target`, `node_modules`).
  - Created `src/main.rs` CLI entry point with `clap` implementing `scan` (with text & JSON formats) and `exec` subcommands.
  - Created test fixtures and complete unit + integration test suite (26 passing tests).

- **Phase 1 (Process Isolation Enforcer): COMPLETE.**
  - Implemented Windows Job Objects process isolation in `crates/sandbox/src/win.rs` using `windows-sys` (`CreateJobObjectW`, `SetInformationJobObject` with `JOBOBJECT_EXTENDED_LIMIT_INFORMATION` and `JOBOBJECT_BASIC_UI_RESTRICTIONS`).
  - Implemented Linux namespace process isolation in `crates/sandbox/src/linux.rs` using `nix` (`unshare` for `CLONE_NEWNS`, `CLONE_NEWNET`, `CLONE_NEWPID`).
  - Implemented credential environment variable stripping engine (`sanitize_env`) in `crates/sandbox/src/lib.rs` stripping `AWS_*`, `GITHUB_*`, `SLACK_*`, `DATABASE_*`, `ID_RSA`, and sensitive suffixes/exact names.
  - Implemented shell command parser (`parse_command_str`) for tokenizing multi-word execution strings.
  - Integrated `supplychain-guard exec` CLI command to launch sandboxed subprocesses with network deny-by-default and environment sanitization.
  - Created sandbox unit/integration test suite (`crates/sandbox/tests/sandbox_tests.rs`) with 30 passing workspace tests across scanner and sandbox crates.

- **Phase 2 (Dynamic Behavioral Interceptor & Policy Engine): COMPLETE.**
  - Implemented declarative policy crate `crates/policy` for `guard.toml` configuration parsing (`GuardPolicy`, `ScannerPolicy`, `SandboxPolicy`, `RulePolicy`).
  - Integrated policy-aware finding suppressions, ignored paths, and severity overrides in `crates/scanner/src/lib.rs` (`apply_policy_to_report`).
  - Integrated policy-driven sandbox configuration, environment denylisting, and process memory limits (`memory_limit_mb`) via Windows Job Objects `JOBOBJECT_EXTENDED_LIMIT_INFORMATION` (`ProcessMemoryLimit`).
  - Added `--config` / `-c` CLI option to `supplychain-guard scan` and `exec` subcommands with auto-detection of `./guard.toml`.
  - Created annotated example policy configuration (`guard.toml.example`) and unit tests (`crates/policy/tests/policy_tests.rs`) with 32 passing workspace tests.

- **Phase 3 (Continuous CI/CD Integration & Enterprise Governance): COMPLETE.**
  - Implemented SARIF v2.1.0 output serializer (`crates/scanner/src/sarif.rs`) with `--format sarif` CLI option.
  - Implemented composite GitHub Actions runner (`action.yml`) for automated static AST security scanning and SARIF uploads to GitHub Security Code Scanning.
  - Implemented SHA-256 build script hash caching engine (`crates/scanner/src/cache.rs`) with `--use-cache` / `-u` CLI option.
  - Implemented pre-commit hook installer command (`supplychain-guard init-hook`) setting up `.git/hooks/pre-commit`.
  - Staged, committed, and pushed all code to GitHub repository (`main` branch).
  - All 34 workspace unit and integration tests passing.



