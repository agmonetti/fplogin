# ADR 0003: Durable Transaction Journal and Manifest Publication

- **Status:** Accepted
- **Date:** 2026-09-10
- **Decision owners:** fplogin maintainers

## Context

Installation and removal can mutate packages, files, and services in several ordered steps. A process crash or power loss can occur after any individual mutation. A final-state manifest written only after success cannot explain or reverse changes made before the interruption. Uninstallation must also remain possible when the adapter that originally planned an installation is unavailable or has been upgraded.

The core owns transaction sequencing, journaling, rollback, and final manifest publication. Adapters provide declarative plans; the platform provider performs only approved typed operations and returns receipts.

## Decision

1. Store the active journal at `/var/lib/fplogin/transactions/<transaction-id>.json` and the successful installed-state manifest at `/var/lib/fplogin/manifest.json`.
2. Create the journal, containing the transaction identity, selected provider/adapter/target metadata, accepted plan identity/digest, operation order, preconditions, and compensation data, and fsync it before the first live-host mutation.
3. Publish and update JSON files through a temporary file in the same directory, restrictive creation mode, complete write, file fsync, and atomic rename followed by directory fsync. The implementation must not expose a partially written journal or manifest.
4. Journal every operation attempt and its result, including failures, and atomically update and fsync the journal after each provider receipt. A receipt records the operation ID, before-state, after-state, result, artifact/package/file evidence where relevant, and compensation data.
5. Execute only the dependency-ordered operations in the core-validated plan. Reject unknown operation kinds, missing preconditions, non-canonical or policy-violating paths, symlink traversal, missing hashes, and insufficient rollback data before mutation.
6. On failure or interruption, recover from the durable journal rather than relying on the current adapter version. Roll back completed operations in reverse dependency order using recorded generic compensation data. Journal each rollback attempt and result, and run read-only post-rollback verification. An unresolved rollback result remains visible and must preserve the documented recovery path.
7. Keep transaction state explicit and recoverable. The journal must distinguish planning/approval, prepared, applying, rollback-required, rolling-back, rolled-back, verification-failed, completed, and other schema-defined terminal/intermediate states rather than inferring state from file presence.
8. Publish `/var/lib/fplogin/manifest.json` atomically only after all planned operations and post-install verification succeed. The manifest contains operational metadata, descriptor digests, accepted plan digest, artifact/file checksums, ownership/modes, operation receipts, compensation data, previous DM state, service changes, timestamps, and verification evidence; it never contains passwords, PAM responses, fingerprint templates, wallet contents, or other secrets.
9. Retain enough generic receipts and compensation data in the final manifest for checksum-aware uninstall and recovery if the original adapter is missing or upgraded. The adapter may assist with a new uninstall plan, but it is not the sole source of rollback knowledge.
10. Uninstallation verifies the manifest and installed-file checksums first. Files that no longer match fplogin-owned content are preserved or explicitly escalated according to user policy. Only recorded fplogin-owned assets and recorded prior state may be removed or restored.
11. Package and service semantics remain provider-owned; the core journal stores provider-preserved receipts and evidence without interpreting distro-specific package versions or service-manager internals.

## Consequences

- Power loss and process interruption leave an auditable recovery record before any mutation.
- Atomic publication prevents readers from observing truncated JSON.
- Reverse-order compensation and explicit receipts make rollback deterministic and adapter-independent.
- Journal and manifest data require careful secret exclusion, permission checks, checksum handling, and schema compatibility tests.
- A journal may remain after a failed transaction and must be handled by recovery tooling; deleting it to hide an incomplete operation is prohibited.
- The final manifest is a completed installation record, not a substitute for the active journal.

## References

- `docs/architecture/CORE_ADAPTER_ANALYSIS.md`, sections 2.4, 3.2, and 4.1.
- `docs/architecture/OPEN_POINTS_RESOLUTION.md`, sections 1.1, 4.1, and 4.2.
- `docs/IMPLEMENTATION_PLAN.md`, sections 8 and 10 Foundation Gate items 8 and 11.
