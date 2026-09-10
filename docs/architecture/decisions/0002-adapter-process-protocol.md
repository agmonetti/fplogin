# ADR 0002: Adapter and Platform Provider Process Protocol

- **Status:** Accepted
- **Date:** 2026-09-10
- **Decision owners:** fplogin maintainers

## Context

The core must discover display-manager adapters and platform providers without hardcoded display-manager or distribution branches. Discovered code must not be loaded into the privileged core process. Adapters need to inspect host facts and prepare declarative plans, while the core and selected platform provider retain ownership of privileged mutation.

The protocol must support independent implementations in Go, C++, Python, or another language, remain versionable, bound resource use, and fail closed on malformed or untrusted input.

## Decision

1. Adapters and platform providers are **separate executables**, never shared libraries or in-process plugins.
2. Each executable is discovered through a trusted, root-owned static descriptor:
   - adapters under fixed directories such as `/usr/lib/fplogin/adapters/*.json` and `/usr/local/lib/fplogin/adapters/*.json`;
   - providers under fixed directories such as `/usr/lib/fplogin/platforms/*.json` and `/usr/local/lib/fplogin/platforms/*.json`.
3. Discovery is deterministic and security-checked. The core validates the descriptor schema before semantic use, rejects duplicate opaque IDs, and rejects descriptors, executables, or asset roots that are non-regular, non-canonical, symlink-crossing, or writable by non-root users/groups. Absolute executable paths and `PATH` lookup are forbidden.
4. The core invokes each executable directly, without a shell, using a minimal allowlisted environment, fixed `C` locale, bounded input/output, a deadline, and process-group cancellation. Diagnostics go to stderr. Stdout is reserved for the protocol response.
5. Every invocation uses one versioned JSON request on stdin and one versioned JSON response on stdout. The shared envelope contains `protocol_version`, `request_id`, `operation`, `core_version`, `context`, and an operation-specific `payload`.
6. Every response contains `protocol_version`, `request_id`, `ok`, `result`, and `error`. The response request ID must equal the request ID. A missing prerequisite is a successful typed report, not a protocol failure.
7. Protocol compatibility uses major/minor versions. Major mismatches are incompatible; minor revisions are additive only. Runtime identity, version, executable metadata, and protocol support returned by `Describe` must match the trusted static descriptor; a mismatch disables that executable.
8. Stable protocol errors include `invalid_request`, `protocol_mismatch`, `unsupported_target`/`unsupported_platform`, `timeout`, `host_read_failed`, `artifact_failed`, `mutation_failed` where applicable, and `internal_error`. Error objects contain `code`, `message`, `retryable`, `evidence`, and optional `details`.
9. Exit status is deterministic: invalid input exits 64, protocol mismatch exits 65, and a failure without a valid response exits 70. Signal termination remains distinguishable to the core. A valid response exits zero even if it reports an unsatisfied prerequisite.
10. Adapters run without elevated privileges. They inspect supplied facts, prepare artifacts in restricted unprivileged workspaces, and return declarative plans. They never write live `/etc`, `/usr`, or `/var`, invoke a package manager as root, enable/stop services, or provide an arbitrary privileged hook.
11. The platform provider uses the same transport and envelope implementation rules but has a separate protocol namespace and schema family. Its only mutating operation is the typed `ApplyOperation` vocabulary defined by the platform contract; it has no shell-command parameter or arbitrary hook.
12. Core selection uses opaque IDs and capability predicates. It never branches on adapter IDs, provider IDs, distribution names, or display-manager names. A development-only adapter directory is permitted only while unprivileged and must be rejected after elevation.

## Required adapter method vocabulary

Every adapter implements the eight methods below, even when a method returns an empty result for its integration strategy:

- `Describe`
- `Detect`
- `CheckPrerequisites`
- `InspectState`
- `PlanInstall`
- `PrepareArtifacts`
- `PlanUninstall`
- `Verify`

There is deliberately no `ApplyInstall`, `ApplyUninstall`, or arbitrary `run_as_root` adapter method. The core validates and executes closed plans through the selected platform provider.

## Consequences

- A compromised or malformed discovered adapter does not inherit the core process address space or privileged mutation primitives.
- Future adapters/providers can be written in another language without changing the core ABI.
- Descriptor validation, bounded execution, schema validation, and conformance tests become mandatory foundation infrastructure.
- Adapter/provider upgrades must preserve descriptor identity and protocol compatibility; otherwise the executable is disabled rather than guessed compatible.
- Process startup and JSON serialization add implementation and test cost, accepted in exchange for isolation and recoverability.

## References

- `docs/architecture/CORE_ADAPTER_ANALYSIS.md`, sections 2.1 through 2.7.
- `docs/architecture/OPEN_POINTS_RESOLUTION.md`, sections 1.1 through 1.3 and 4.1.
- `docs/IMPLEMENTATION_PLAN.md`, Foundation Gate items 7, 10, 11, and 12.
