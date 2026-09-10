# ADR 0001: Core Language and Build Policy

- **Status:** Accepted
- **Date:** 2026-09-10
- **Decision owners:** fplogin maintainers

## Context

fplogin needs a privileged transaction executor, a read-only system analyzer, durable JSON manifests, bounded subprocess execution, trusted adapter/provider discovery, and portable package artifacts. The installer must remain recoverable even when an adapter or language runtime is unavailable. The core must also maintain a narrow privilege boundary: adapters and platform providers are separate processes and must not be loaded into the privileged core address space.

The target for v1 is Arch Linux, but the core contracts must not encode Arch or SDDM behavior. The project is maintained by contributors who are more likely to know Go, shell, Python, or C++ than advanced systems-language techniques.

## Decision

1. Implement the authoritative core in **Go**.
2. Use Go's standard library for JSON, filesystem operations, hashing, atomic file publication, subprocess execution, deadlines, signals, and reporting wherever practical.
3. Keep the core free of cgo unless a later decision explicitly approves it. Release verification must inspect the produced binary and its runtime dependencies; it must not assume that a Go build is static without evidence.
4. Build the core, the SDDM adapter, and the platform provider as separate executables. The installed package requires no Go runtime or compiler.
5. Pin the supported Go language/toolchain floor in `go.mod` and package metadata. The exact toolchain used for a release is part of reproducible-build evidence.
6. Restrict Bash to thin `install.sh`/`uninstall.sh` launchers and documented emergency-recovery commands. Bash must not implement discovery, selection, manifest serialization, mutation, or rollback.
7. Do not use Go's native `plugin` package or any other in-process dynamic adapter mechanism. The supported extension boundary is the versioned JSON process protocol defined by ADR 0002.

## Consequences

### Positive

- The installed product has no interpreter dependency beyond the compiled binaries.
- Go provides explicit structs, interfaces, errors, and state modeling without introducing a language-level ABI for adapters.
- The standard library supports the bounded, sequential installer and analyzer without a mandatory third-party dependency closure.
- Separate binaries make accidental imports of SDDM or Arch implementation packages visible in the build graph.
- The protocol remains language-neutral for future adapters and providers.

### Costs and constraints

- Go does not enforce all exhaustive state or operation handling at compile time; validators and conformance tests are required.
- Ownership, modes, symlink resistance, fsync ordering, process-group cancellation, and artifact inspection require explicit implementation and review.
- Binary size is accepted as operationally insignificant for this product.
- Any future cgo dependency requires a new review of portability, runtime dependencies, and release policy.

## Rejected alternatives

- **Python for the authoritative core:** in-process entry-point discovery would execute adapter code inside the privileged process, and interpreter/package resolution would become part of recovery.
- **Bash for the core:** untyped transaction state and unsafe hand-built JSON would weaken rollback and manifest correctness.
- **Rust:** technically suitable, but its added implementation and contributor complexity does not improve the required out-of-process boundary.
- **Shared-object plugins:** toolchain, dependency, platform, and privilege coupling are unacceptable; IPC provides the required isolation.

## Scope

This decision governs the core and its build/runtime policy. It does not select an SDDM source baseline, define the adapter wire objects, or authorize privileged operations. Those concerns are covered by the implementation plan, ADR 0002, and ADR 0003.

## References

- `docs/architecture/CORE_ADAPTER_ANALYSIS.md`, sections 1 and 3.2.
- `docs/architecture/OPEN_POINTS_RESOLUTION.md`, sections 1 and 4.
- `docs/IMPLEMENTATION_PLAN.md`, Foundation Gate items 2, 5, 10, and 11.
