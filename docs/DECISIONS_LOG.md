# fplogin Decisions Log

This index records accepted architecture decisions. The detailed ADRs are the normative records; `docs/IMPLEMENTATION_PLAN.md`, `docs/architecture/CORE_ADAPTER_ANALYSIS.md`, and `docs/architecture/OPEN_POINTS_RESOLUTION.md` provide the governing product and contract context.

| ADR | Decision | Status | Detailed record |
|---|---|---|---|
| 0001 | Use Go for the authoritative core; restrict Bash to thin launch/recovery wrappers; avoid in-process plugins. | Accepted | [0001-core-language.md](architecture/decisions/0001-core-language.md) |
| 0002 | Use trusted static descriptors and bounded, versioned JSON-over-stdin/stdout processes for adapters and platform providers. | Accepted | [0002-adapter-process-protocol.md](architecture/decisions/0002-adapter-process-protocol.md) |
| 0003 | Write and fsync a transaction journal before mutation; journal every operation; publish the final manifest atomically only after verification. | Accepted | [0003-transaction-journal.md](architecture/decisions/0003-transaction-journal.md) |

## Consistency rule

New implementation work must satisfy all accepted ADRs and the architecture addendum. If a later decision changes one of these boundaries, add a new numbered ADR or an explicit superseding record; do not silently rewrite the historical decision.
