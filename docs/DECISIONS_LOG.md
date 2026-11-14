# fplogin Decisions Log

This index records accepted architecture decisions. The detailed ADRs are the normative records; `docs/IMPLEMENTATION_PLAN.md`, `docs/architecture/CORE_ADAPTER_ANALYSIS.md`, and `docs/architecture/OPEN_POINTS_RESOLUTION.md` provide the governing product and contract context.

| ADR | Decision | Status | Detailed record |
|---|---|---|---|
| 0001 | Use Go for the authoritative core; restrict Bash to thin launch/recovery wrappers; avoid in-process plugins. | Accepted | [0001-core-language.md](architecture/decisions/0001-core-language.md) |
| 0002 | Use trusted static descriptors and bounded, versioned JSON-over-stdin/stdout processes for adapters and platform providers. | Accepted | [0002-adapter-process-protocol.md](architecture/decisions/0002-adapter-process-protocol.md) |
| 0003 | Write and fsync a transaction journal before mutation; journal every operation; publish the final manifest atomically only after verification. | Accepted | [0003-transaction-journal.md](architecture/decisions/0003-transaction-journal.md) |

## Consistency rule

New implementation work must satisfy all accepted ADRs and the architecture addendum. If a later decision changes one of these boundaries, add a new numbered ADR or an explicit superseding record; do not silently rewrite the historical decision.

## Owner gate exceptions

| Date | Decision | Scope and limits |
|---|---|---|
| 2026-11-12 | The owner authorized **preparatory Sprint 3 work in parallel** while Sprint 2 is not accepted. | Covers the PAM service, the reproducible PKGBUILD, package layout, clean-environment builds and container-only verification. Everything produced is labelled **unaccepted**. It does not accept Sprint 2, does not open the Sprint 3 gate, and does not authorize Sprint 4–6 implementation, host installation or release. Sprint 3 acceptance still requires Sprint 2 acceptance first, then the Sprint 3 review. Plan: [SPRINT_3_EXECUTION_PLAN.md](SPRINT_3_EXECUTION_PLAN.md). |
| 2026-11-12 | The owner **accepted and closed Sprint 2 and authorized transition to Sprint 3**. | Supersedes the preparatory-only gate restriction above, not its historical evidence limits. Sprint 3 is in progress and remains unaccepted; no host installation, release or Sprint 4–6 authorization follows. See [Sprint 2 closure](reviews/sprint-2.md#13-2026-11-12-sprint-2-final-acceptance-and-closure-by-the-project-owner). |

## Sprint 3 compatibility decision

On 2026-11-14 the owner chose to **extend compatibility to Qt5 themes while retaining Qt6**, rather than declare v1 Qt6-only. Preserve accepted `0001`/`0002` and their series; plan a separate packaging supplement, dual builds and an allowlisted merge of the Qt5 greeter/components/translations. The daemon/helpers and PAM policy remain canonical Qt6 artifacts. Legacy themes are not promised new biometric controls. The [implementation plan](SPRINT_3_EXECUTION_PLAN.md#qt5-compatibility-extension--implementation-plan-2026-11-14) defines tests, persistence and acceptance gates. This is an approved compatibility direction and a reviewed plan, not implemented or verified Qt5 support.

