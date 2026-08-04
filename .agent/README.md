# SupplyChain-Guard Agent Board

> Core sandbox & scanner → `README.md`. This board manages multi-AI workstreams and specs.

## Board Structure

| Path | Purpose |
|------|---------|
| `specs/active/current.md` | Active workstreams and current phase checklist |
| `specs/active/next.md` | Execution priority order |
| `specs/active/catalog.md` | Master phase blueprint catalog |
| `specs/active/details/` | Detailed technical specifications per phase |
| `memory/execution.log` | Timestamped log of execution milestones |
| `memory/handoff.md` | Multi-agent context handoff document |
| `policy/` | Sandboxing threat models and security rules |
| `rules/` | Token efficiency, security guardrails, context hygiene |
| `skills/` | Custom agent skills |
| `wiki/` | Architecture deep-dives & OS sandbox API references |

## Priority Phases
- **Phase 0 (Static AST Scanner):** AST parser for `build.rs` to detect command spawning and network calls.
- **Phase 1 (Process Isolation Enforcer):** Windows Job Objects / Linux cgroups sandbox wrapper.
- **Phase 2 (Network Socket Blocker):** Intercept and deny network socket creation during build time.
