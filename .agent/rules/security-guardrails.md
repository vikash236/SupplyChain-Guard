# Security Guardrails — SupplyChain-Guard

## Process Isolation
1. **Strict Process Boundaries:** Processes executed inside the sandbox must be restricted from inheriting host environment tokens (`AWS_SECRET_ACCESS_KEY`, `GITHUB_TOKEN`, `NPM_TOKEN`, `SSH_AUTH_SOCK`, `DOCKER_AUTH_CONFIG`).
2. **No Process Spawning:** Sandboxed build scripts must not be able to spawn child processes beyond the immediate build command. On Windows, enforce via `JOB_OBJECT_LIMIT_ACTIVE_PROCESS`. On Linux, enforce via `seccomp-bpf` restricting `clone`/`fork`/`execve`.
3. **No Direct System Shell Invocations:** Sandbox logic must not invoke `cmd.exe` or `bash` without explicit path sanitization.

## Filesystem Restrictions
4. **Write Isolation:** Build script execution must only write to specified build target directories (`./target/` or `./node_modules/`). All other filesystem paths must be read-only or inaccessible.
5. **Sensitive Path Deny-List:** Filesystem reads to `~/.ssh/`, `~/.aws/`, `~/.gnupg/`, `~/.config/`, `.env`, `.npmrc`, and `.cargo/credentials.toml` must be blocked or flagged as CRITICAL.
6. **Symlink Resolution:** All filesystem paths must be canonicalized before access checks to prevent symlink-based sandbox escapes.

## Network Restrictions
7. **Network Deny-by-Default:** Sandboxed processes must have zero network access — no DNS resolution, no TCP/UDP connections, no raw sockets. On Windows, enforce via AppContainer network capability denial. On Linux, enforce via `CLONE_NEWNET` with no network interfaces configured.
8. **No Exfiltration Channels:** Block alternative exfiltration vectors including named pipes, shared memory, and UNIX domain sockets where possible.

## Environment Sanitization
9. **Credential Stripping:** Before launching any sandboxed process, strip all environment variables matching known credential patterns: `*TOKEN*`, `*SECRET*`, `*KEY*`, `*PASSWORD*`, `*CREDENTIAL*`, `AWS_*`, `AZURE_*`, `GCP_*`, `GITHUB_*`, `NPM_*`, `DOCKER_*`.
10. **Allowlist Override:** Provide a configurable allowlist for environment variables that legitimate build scripts require (e.g., `PATH`, `HOME`, `CARGO_HOME`, `RUSTUP_HOME`, `NODE_PATH`).

## Scanner Integrity
11. **No Code Execution in Scanner:** The static scanner must never execute, compile, or evaluate the code it analyzes. AST parsing only.
12. **Bounded Resource Usage:** Scanner must enforce timeouts and memory limits when parsing adversarial inputs to prevent denial-of-service via pathological ASTs.
