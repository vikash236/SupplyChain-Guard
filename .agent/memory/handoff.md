# Context Handoff Contract — SupplyChain-Guard

## Current Status
- Initial repository setup and `.agent` infrastructure completed.
- Core specification for Phase 0 (Static Script Scanner) and Phase 1 (Process Isolation Enforcer) created.

## Next Steps
- Initialize Cargo Workspace (`Cargo.toml`).
- Implement `crates/scanner` using `syn` for `build.rs` AST analysis.
- Implement `crates/sandbox` for Windows Job Object isolation.
