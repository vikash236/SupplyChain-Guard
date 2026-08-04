# Active Workstreams — SupplyChain-Guard

## Active Phase: Phase 0 — Static Script Scanner & Project Scaffold

- [ ] Initialize Cargo workspace (`Cargo.toml` with `crates/scanner`, `crates/sandbox`).
- [ ] Implement `syn` AST visitor for `build.rs` parsing.
- [ ] Detect suspicious calls (`std::process::Command`, `std::net::TcpStream`, env variable access).
- [ ] Implement `supplychain-guard scan <path>` CLI subcommand.
