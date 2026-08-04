# Security Guardrails — SupplyChain-Guard

1. **Strict Process Boundaries:** Processes executed inside the sandbox must be restricted from inheriting host environment tokens (`AWS_SECRET_ACCESS_KEY`, `GITHUB_TOKEN`).
2. **Filesystem Write Restrictions:** Build script execution must only write to specified build target directories (`./target/` or `./node_modules/`).
3. **No Direct System Shell Invocations:** Sandbox logic must not invoke `cmd.exe` or `bash` without explicit path sanitization.
