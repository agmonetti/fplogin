# Core Language and Core–Adapter Architecture Analysis

**Status:** Accepted architecture decision; no implementation has started.  
**Decision:** Adopted as the governing architecture before the Foundation Gate. The decisions are recorded in ADRs `0001`–`0003`; this document remains the detailed analysis and contract source.

## Scope and constraints

fplogin v1 targets Arch Linux, systemd, SDDM 0.21, PAM/fprintd, and Hyprland. The architecture must nevertheless keep the core independent of any display manager from the first commit. The core must not import an SDDM package, inspect an SDDM path, compare a DM name with `"sddm"`, or encode SDDM version rules. Those responsibilities belong to an adapter.

The core has four operational responsibilities:

1. Inspect the host and produce evidence-based findings.
2. Select a compatible display-manager adapter.
3. Execute an approved, transactional change plan and persist enough state for crash recovery and uninstall.
4. Render human-readable and machine-readable results.

The display-manager adapter has four different responsibilities:

1. Identify compatible DM installations from generic host facts.
2. Interpret DM-specific versions, configuration, and prerequisites.
3. Produce DM-specific install, upgrade, repair, and uninstall plans using core-defined operations.
4. Verify the result and report DM-specific capabilities.

The distinction is important: adapters decide **what changes are required**; the core transaction engine decides **whether and how approved changes are applied, journaled, rolled back, and recorded**.

---

## 1. Core language

### 1.1 Evaluation criteria

The language must be evaluated against the actual workload, not against general language popularity:

- Transactional privileged installation with explicit preconditions, durable journaling, rollback, checksums, ownership and mode handling, and interruption recovery.
- A versioned JSON manifest that must remain readable across upgrades.
- A read-only analyzer that runs commands with bounded timeouts, reads Linux configuration safely, preserves evidence, and emits text and JSON.
- Runtime discovery of adapters without hardcoded DM names.
- Reliable distribution as an Arch package today and as packages or standalone artifacts on other Linux distributions later.
- A narrow privilege boundary. Adapter discovery and adapter logic must not become arbitrary code loaded into a privileged core process.
- Long-term maintenance by contributors who are more likely to know shell, Python, Go, or C++ than advanced systems-language techniques.

### 1.2 Python

#### Concrete advantages

- The standard library already provides mature JSON handling, filesystem APIs, subprocess timeouts, hashing, temporary files, dataclasses, enums, and import metadata.
- Analyzer development would be fast. Parsing structured command output and building evidence-rich findings is substantially safer in Python than in Bash.
- Python supports package entry points through `importlib.metadata`, so in-process adapter discovery is straightforward.
- Exceptions and context managers make multi-step cleanup clearer than shell traps.
- Test fixtures and fake host roots are easy to construct.

#### Concrete disadvantages

- Python is not part of Arch's `base` package set. The `python` package is available in Arch `core`, but installing fplogin on a minimal Arch system would add an interpreter runtime solely for the product.
- In-process Python entry points are the wrong security boundary for this project. Loading an adapter imports and executes its module inside the core process. If the core is privileged, an adapter receives the same privilege and memory access. If Python packaging paths or environment variables are not sanitized, discovery can load unintended code.
- Interpreter and dependency resolution become part of the recovery path. A broken Python environment must not prevent uninstalling a display-manager modification.
- System Python packaging differs across distributions. Debian-family externally managed environments, Arch packages, virtual environments, and user `site-packages` create deployment and discovery differences that are unrelated to fplogin's product behavior.
- Python's runtime type checks do not enforce exhaustive handling of manifest states or operation kinds. This can be mitigated with typing and validation, but the safety comes from discipline rather than the runtime.
- Shipping a self-contained Python artifact is possible, but it adds a bundler and larger opaque runtime instead of removing deployment complexity.

#### Availability

- **Arch v1:** available as an explicit `python` package, but not guaranteed by `base`.
- **Future Linux distributions:** commonly available on workstation installations, not guaranteed on minimal, immutable, or appliance-style systems. Exact interpreter versions and packaging policy vary.
- **Runtime implication:** the interpreter must be installed and functional both at install and uninstall time.

#### Verdict

Python is a viable analyzer language but a weaker choice for the authoritative privileged transaction engine. Its easiest plugin mechanism violates the desired privilege boundary, and its runtime becomes a recovery dependency.

### 1.3 Bash

#### Concrete advantages

- Bash is a dependency of Arch's `base` package and is therefore available on the v1 target before fplogin installs anything.
- `pacman`, `systemctl`, `install`, and other system tools are easy to invoke.
- A small bootstrap script can inspect the environment, locate the packaged binary, and request privilege without introducing another runtime.
- Recovery commands remain easy for an administrator to inspect from a TTY.

#### Concrete disadvantages

- Bash has no native JSON parser or serializer. A correct manifest implementation therefore requires another dependency such as `jq`, Python, or a purpose-built helper. Hand-built JSON escaping is not acceptable for a security-sensitive manifest.
- Transaction state becomes untyped strings and global shell state. Nested error propagation, partial success, rollback ordering, idempotency, and crash recovery are difficult to make auditable.
- `set -e`, traps, pipelines, and subshells have context-dependent behavior. They are not a substitute for an explicit transaction state machine.
- Safe dynamic adapters are awkward. Sourcing adapter scripts executes arbitrary code in the core shell and allows adapters to overwrite core functions and variables. Executing adapters as subprocesses is safer, but then Bash still needs a robust versioned serialization protocol.
- Parsing localized human-readable command output is brittle. The analyzer needs structured facts and evidence, not regular expressions over whatever a host command printed in the current locale.
- Unit-testing rollback transitions and schema compatibility is expensive compared with a typed language.
- Bash-specific scripts are not POSIX shell scripts. Bash is common on Linux, but a future target still needs to declare it as a dependency.

#### Availability

- **Arch v1:** guaranteed by the `base` metapackage.
- **Future Linux distributions:** widely packaged and usually present on general-purpose systems, but not a universal guarantee for minimal or immutable images.
- **Runtime implication:** no new v1 dependency, but robust JSON would add another required tool.

#### Verdict

Bash is appropriate only for thin `install.sh` and `uninstall.sh` launchers and documented emergency recovery commands. It is not appropriate for the core transaction engine, manifest writer, or adapter protocol implementation.

### 1.4 Rust

#### Concrete advantages

- Strong enums, pattern matching, ownership, and `Result` types are an excellent fit for transaction states, closed operation kinds, tri-state host facts, and explicit error propagation.
- Memory safety is valuable in a privileged installer.
- `serde` and JSON Schema tooling can keep wire objects and persisted state strongly typed.
- A compiled binary requires no Rust runtime package on the target.
- Rust supports GNU Linux Tier 1 targets and musl targets, enabling controlled portable artifacts.
- Filesystem and process behavior can be implemented without invoking a shell.

#### Concrete disadvantages

- Rust's benefits are partly offset by implementation complexity for this project. Lifetimes, trait object boundaries, error types, and async choices create more design surface than the mostly sequential installer/analyzer requires.
- Compile times and build dependency size are high. Arch's Rust toolchain package is optional and materially larger than the finished program.
- Rust does not provide a stable language-level ABI for arbitrary third-party dynamic libraries. A safe runtime adapter model still needs an out-of-process protocol, so Rust does not simplify dynamic adapter discovery relative to Go.
- The project already requires C++ expertise for the SDDM patch. Requiring advanced Rust expertise for the installer creates a second high-barrier implementation language.
- Static musl builds and GNU-linked distribution packages need separate release policies. Native library dependencies would complicate static builds if introduced later.

#### Availability

- **Arch v1:** `rust`/`cargo` are available build dependencies in `extra`, not base runtime dependencies.
- **Future Linux distributions:** official Rust targets cover common Linux architectures, but distro compiler versions differ.
- **Runtime implication:** packaged or released binaries need no Rust interpreter/runtime; the build system must produce an artifact for each supported architecture/libc policy.

#### Verdict

Rust is technically sound and would be the second choice. It provides stronger type modeling than Go, but the additional implementation and contributor complexity does not buy a better adapter boundary because adapters must still be out of process.

### 1.5 Go

#### Concrete advantages

- A Go binary includes the Go runtime and requires no separately installed language runtime. The v1 package can install one core executable and separate adapter/provider executables.
- The standard library covers JSON, SHA-256, filesystem traversal, atomic rename, subprocess execution without a shell, timeouts through contexts, signals, and text/template-style reporting. The core can remain dependency-light.
- Structs, interfaces, explicit errors, and small packages are sufficient for manifest records, transaction states, evidence, and protocol envelopes without the implementation overhead of Rust.
- Compilation and tests are fast enough for repeated package/VM work.
- Linux amd64 and arm64 artifacts are straightforward to build. A pure-Go build can avoid a target Go installation and most libc coupling; release verification must still inspect the actual produced binary rather than assume it is static.
- Out-of-process adapters are natural to implement with `os/exec`, stdin/stdout, context cancellation, and process groups.
- The same versioned JSON protocol can be implemented by future adapters in any language. The SDDM adapter may initially be Go, but the core contract is not a Go ABI.

#### Concrete disadvantages

- Go binaries are larger than equivalent C or optimized Rust binaries. For this project the expected size is operationally irrelevant compared with SDDM/Qt and package build dependencies.
- Go has fewer type-level guarantees than Rust. Closed operation kinds, state transitions, and version handling require validators and exhaustive tests.
- Unix ownership, permissions, fsync ordering, symlink resistance, and process-group cancellation are not automatic. They need explicit implementation and review.
- Go's native `plugin` package is unsuitable. The official package warns about limited platform support, poor race-detector support, security risks, and runtime crashes unless the host and plugins use the exact same toolchain, flags, and dependency sources.
- Fully static builds require a deliberate policy (`CGO_ENABLED=0`, dependency review, and artifact inspection). Introducing cgo later would change portability.

#### Availability

- **Arch v1:** the `go` compiler is available in `extra` as a build dependency but is not installed by `base`. The installed fplogin package does not need the compiler.
- **Future Linux distributions:** common architectures are supported by upstream Go and distribution toolchains. Binary packaging avoids relying on a target-side Go version.
- **Runtime implication:** no separate runtime package. Build tooling is required only in a clean package build environment.

#### Verdict

Go is the best fit for the core.

### 1.6 Recommendation

**Use Go for the core and for the first adapter executable. Use Bash only as a thin launcher/recovery surface. Do not use Go shared-object plugins.**

The decisive reasons are:

1. A single packaged core binary does not add a Python runtime to a minimal Arch install and remains available during recovery.
2. Go provides enough type structure for explicit transaction and manifest models without Rust's higher contributor and implementation cost.
3. Its standard library directly supports the analyzer and a bounded subprocess protocol.
4. Dynamic discovery is solved more safely by versioned JSON over stdin/stdout than by importing Python modules, sourcing Bash, or loading Go/Rust shared objects.
5. The adapter protocol becomes language-neutral. Choosing Go for v1 does not force a future LightDM or greetd adapter to use Go.

Build policy must pin an exact Go toolchain in `go.mod` and package metadata, keep the core free of cgo unless explicitly approved, and verify runtime dependencies on every release artifact.

Primary evidence:

- Arch's [`base` package](https://archlinux.org/packages/core/any/base/) includes Bash but not Python, Go, or Rust.
- Arch packages [Python](https://archlinux.org/packages/core/x86_64/python/), [Go](https://archlinux.org/packages/extra/x86_64/go/), and [Rust](https://archlinux.org/packages/extra/x86_64/rust/) separately.
- Python supports installed entry-point discovery through [`importlib.metadata`](https://docs.python.org/3/library/importlib.metadata.html#entry-points), but that is an in-process import mechanism.
- Go documents the concrete failure and deployment constraints of native [plugins](https://raw.githubusercontent.com/golang/go/master/src/plugin/plugin.go) and recommends considering IPC instead.
- Rust documents its [platform support tiers](https://doc.rust-lang.org/rustc/platform-support.html), including GNU and musl Linux targets.

---

## 2. Core–adapter contract

### 2.1 Boundary decision

Adapters must be separate executables discovered through trusted descriptor files. They must not be linked into the core binary and must not be loaded as shared libraries.

Communication uses one versioned JSON request on stdin and one versioned JSON response on stdout per process invocation. Diagnostic logs go to stderr. The core starts adapters directly without a shell, sets a minimal environment, enforces a deadline, captures bounded output, and terminates the adapter process group on cancellation.

Adapters run without elevated privileges. They inspect supplied host facts, read permitted host paths, prepare unprivileged build artifacts, and return declarative plans. They never write `/etc`, `/usr`, or `/var`, never invoke a package manager as root, and never enable or stop services. The privileged core executor is the sole owner of mutation primitives.

This process boundary is not an optimization detail. It prevents a discovered adapter from sharing the core's address space or implicitly acquiring installer privileges.

### 2.2 Common protocol envelope

Every request contains:

| Field | Type | Meaning |
|---|---|---|
| `protocol_version` | `{major, minor}` | Adapter protocol requested by the core. Major changes are incompatible; minor changes are additive only. |
| `request_id` | UUID string | Correlates one invocation and its logs. |
| `operation` | stable operation name | One of the methods defined below. |
| `core_version` | version string | Diagnostic compatibility evidence; adapters must use `protocol_version` for behavior. |
| `context` | `HostContext` | Root, platform facts, architecture, invoking UID/GID, dry-run state, and deadline. |
| `payload` | operation-specific object | Validated against the operation's JSON Schema. |

Every response contains:

| Field | Type | Meaning |
|---|---|---|
| `protocol_version` | `{major, minor}` | Protocol actually used. |
| `request_id` | UUID string | Must equal the request. |
| `ok` | boolean | Whether the adapter successfully handled the operation. A missing prerequisite is a successful report, not a protocol failure. |
| `result` | operation-specific object or null | Present when `ok` is true. |
| `error` | `AdapterError` or null | Present when `ok` is false. |

`AdapterError` contains exact fields: `code`, `message`, `retryable`, `evidence`, and optional `details`. Stable codes include `invalid_request`, `protocol_mismatch`, `unsupported_target`, `timeout`, `host_read_failed`, `artifact_failed`, and `internal_error`.

Stdout must contain exactly one JSON object and no log text. A valid response exits zero even when it reports missing/incompatible prerequisites. Invalid input exits 64, protocol mismatch exits 65, and an adapter failure without a valid response exits 70. Termination by signal remains distinguishable to the core.

### 2.3 Required adapter methods

The following signatures are language-neutral IDL, not implementation code. Every adapter must implement every method. A method may return an empty result where the integration strategy does not require work.

#### `Describe(DescribeRequest) -> Result<AdapterDescriptor, AdapterError>`

- **Input:** requested protocol range.
- **Output:** the runtime descriptor.
- **Rules:** no host inspection and no mutation. The result identity, version, protocol, and executable metadata must match the static discovery descriptor. A mismatch disables the adapter.

#### `Detect(DetectRequest) -> Result<DetectionReport, AdapterError>`

- **Input:** `HostContext` and generic `DisplayManagerCandidate[]` produced by the platform provider.
- **Output:** zero or more `DetectedTarget` records.
- **Rules:** the adapter, not the core, decides whether a candidate is one of its supported DMs and whether its upstream/package version is compatible. Detection is read-only and must include evidence.

`DetectedTarget` contains: `instance_id`, opaque `dm_id`, display name, upstream version if known, package references, service references, compatibility (`compatible`, `incompatible`, `unknown`), confidence (`confirmed`, `likely`, `unknown`), and evidence.

#### `CheckPrerequisites(PrerequisiteRequest) -> Result<PrerequisiteReport, AdapterError>`

- **Input:** selected `DetectedTarget`, requested capability IDs, operation mode (`fresh_install`, `upgrade`, `repair`, or `uninstall`), and host facts.
- **Output:** ordered prerequisite findings.
- **Rules:** no package installation and no configuration changes. Each finding has a stable prerequisite ID, status (`satisfied`, `missing`, `incompatible`, `unknown`), required/optional severity, evidence, and a structured remediation proposal.

#### `InspectState(StateRequest) -> Result<DisplayManagerState, AdapterError>`

- **Input:** selected target and host facts.
- **Output:** current DM state.
- **Rules:** `active`, `enabled`, and `configurable` are tri-state values (`yes`, `no`, `unknown`), not booleans. The response also includes configuration evidence, conflicting active/enabled instances, installed fplogin assets recognized by the adapter, and capabilities currently effective.

#### `PlanInstall(InstallRequest) -> Result<ChangePlan, AdapterError>`

- **Input:** target, requested capabilities, approved remediation policy, current state, prerequisite report, existing install record if any, and mode (`fresh_install`, `upgrade`, `repair`, `reinstall`).
- **Output:** complete declarative `ChangePlan`.
- **Rules:** no mutation. Repeating the same request against the same state must produce the same semantic plan. The plan must declare all required approvals, preconditions, artifacts, ordered operations, postconditions, and rollback information. It must preserve existing configuration unless a specific approved operation says otherwise.

#### `PrepareArtifacts(PrepareArtifactsRequest) -> Result<ArtifactSet, AdapterError>`

- **Input:** accepted plan ID/digest, an unprivileged empty workspace, a source-cache location, and explicit network policy.
- **Output:** artifacts with canonical paths, media types, sizes, SHA-256 digests, provenance, and the plan operation IDs that consume them.
- **Rules:** no privileged mutation. For SDDM this is where the pinned source and patch series can produce an Arch package. An adapter that only installs static configuration returns the packaged assets without a build.

#### `PlanUninstall(UninstallRequest) -> Result<ChangePlan, AdapterError>`

- **Input:** the exact `AdapterInstallRecord` from the manifest, current inspected state, checksum drift findings, and the user's policy for modified files.
- **Output:** declarative uninstall/restore plan.
- **Rules:** the install record is authoritative; redetection alone is insufficient. Locally modified files must be preserved or explicitly escalated. The plan may remove only assets owned by the recorded installation and may restore only recorded prior state.

#### `Verify(VerifyRequest) -> Result<VerificationReport, AdapterError>`

- **Input:** target, verification phase (`pre_apply`, `post_install`, `post_rollback`, `post_uninstall`), expected capabilities/postconditions, and optional install record.
- **Output:** ordered checks with status (`passed`, `failed`, `unknown`), evidence, and severity.
- **Rules:** read-only. `unknown` never counts as `passed`. Post-install verification failure triggers core rollback before any DM replacement is considered complete.

There is deliberately no `ApplyInstall`, `ApplyUninstall`, or arbitrary privileged hook. The core executes plans through closed, reviewed mutation primitives. Adding an unrestricted `run_as_root` operation would erase the transactional and security guarantees of this contract.

### 2.4 Shared data types

#### `HostContext`

Contains:

- Read root (`/` on the live host or a fixture root in tests).
- OS/distribution identity as opaque platform facts.
- Architecture.
- Package-manager and service-manager capabilities supplied by a platform provider.
- Generic display-manager candidates.
- Effective invoking UID/GID and whether the request is elevated.
- Locale fixed to `C` for adapter subprocesses.
- Dry-run flag and deadline.

It never contains passwords, PAM responses, fingerprint templates, wallet contents, or environment variables not explicitly allowlisted.

#### `ChangePlan`

Contains:

- `plan_id`, adapter ID/version/protocol, target instance ID, mode, and creation time.
- Hash of all planning inputs relevant to correctness.
- Required user approvals and risk statements.
- Preconditions and postconditions.
- Required artifact references.
- A dependency-ordered operation DAG.
- Expected capabilities after success.
- Canonical plan digest.

Allowed privileged operation kinds are a closed union:

- `create_directory`
- `write_file_atomic`
- `remove_owned_file`
- `install_package_artifact`
- `remove_owned_package`
- `set_service_enabled`
- `set_service_active`
- `restore_service_state`

Each operation contains a stable operation ID, dependencies, typed parameters, preconditions, expected before-state, expected after-state, and compensation data. The privileged executor rejects unknown operation kinds, paths outside policy, symlink traversal, missing hashes, non-canonical paths, and operations without sufficient rollback data.

There is no generic shell-command operation. Unprivileged artifact builds are isolated under `PrepareArtifacts`; privileged package and service changes go through the selected platform provider.

#### `AdapterInstallRecord`

The successful manifest section for an adapter contains:

- Adapter ID, version, protocol version, and descriptor SHA-256.
- Selected target instance, opaque DM ID, detected version, and evidence.
- Integration strategy and capabilities actually installed.
- Platform-provider ID/version.
- Accepted plan ID/digest.
- Artifact provenance and hashes.
- Every applied operation receipt, before-state, after-state, and compensation record.
- Checksums/modes/owners of installed files.
- Previous active/enabled DM state.
- Verification report IDs and timestamps.

Uninstall and interrupted-transaction recovery must not depend exclusively on the currently installed adapter version. The journal and manifest must contain enough generic compensation data for the core to restore prior state if the adapter is missing or upgraded.

### 2.5 Static adapter descriptor

Each adapter is discovered through an `adapter.json` file with these required fields:

| Field | Required content |
|---|---|
| `descriptor_schema_version` | Version of the descriptor JSON Schema. |
| `adapter_id` | Stable globally unique opaque ID, e.g. `org.fplogin.adapter.sddm`; never reused or renamed after release. |
| `adapter_version` | Adapter implementation version. |
| `protocol_versions` | Supported core–adapter protocol major/minor ranges. |
| `minimum_core_version` | Diagnostic/package compatibility floor; protocol still controls wire behavior. |
| `name` and `vendor` | Human-readable identity only; never used for control flow. |
| `executable` | Path relative to the descriptor directory. Absolute paths and PATH lookup are forbidden. |
| `supported_display_managers` | Entries containing opaque `dm_id`, human name, version-policy description, and target aliases understood by the adapter. Version evaluation remains adapter-owned. |
| `integration_strategies` | Values from `native`, `source_patch`, `configuration`, and `plugin`, with optional adapter-defined detail. |
| `capabilities` | Structured capability offers described below. |
| `prerequisites` | Stable prerequisite declarations: ID, kind, required/optional, reason, and remediation policy. |
| `supported_platforms` | Declared platform constraints or `any`; compatibility is confirmed dynamically. |
| `operation_modes` | Supported install/upgrade/repair/uninstall modes. |
| `asset_root` | Path relative to the descriptor containing immutable adapter assets. |

Capabilities use stable IDs rather than an expanding struct of loosely defined booleans. The v1 vocabulary must define at least:

- `auth.concurrent_methods`
- `auth.password_fallback`
- `auth.biometric_auto_start`
- `auth.request_identity_binding`
- `auth.cancellable_attempts`
- `auth.password_only_degradation`
- `auth.observable_method_state`

Each capability has `status` (`native`, `provided`, `unsupported`), a semantic level/version, constraints, and evidence requirements. The core may filter on capability IDs but never on adapter or DM IDs.

### 2.6 Dynamic discovery and selection

Production discovery follows this exact sequence:

1. Scan fixed root-owned descriptor directories such as `/usr/lib/fplogin/adapters/*.json` and `/usr/local/lib/fplogin/adapters/*.json` in deterministic lexical order.
2. Reject descriptors, executables, or asset roots that are not regular/canonical files, are symlinks crossing the package root, or are writable by non-root users/groups.
3. Validate descriptors against the pinned JSON Schema before reading semantic fields.
4. Reject duplicate adapter IDs. Never resolve duplicates by search order.
5. Invoke `Describe` with a clean environment and compare runtime identity/protocol metadata with the static descriptor.
6. Obtain generic DM candidates from the platform provider. On systemd, `display-manager.service` is useful evidence because systemd defines it as the display-manager service alias, but it is not sufficient to detect every installed inactive DM.
7. Invoke `Detect` on every compatible adapter. The core does not compare candidate names with known DMs.
8. Discard incompatible matches but retain their evidence for diagnostics.
9. If exactly one compatible target/adapter pair exists, present it for approval. If several exist, present all options; do not silently choose by priority.
10. Record the selected adapter ID, version, descriptor digest, target instance, and platform provider in the transaction journal and final manifest.

A development-only `--adapter-dir` may be supported while the process is unprivileged. It must be rejected after elevation and must never be inherited implicitly from an environment variable such as `PATH`, `PYTHONPATH`, or a Go plugin path.

### 2.7 Contract failures that must be prevented before SDDM work

The SDDM adapter will accidentally become the contract if any of the following remains unspecified:

- **No stable IDs:** manifests become impossible to route after adapters are renamed.
- **No protocol major/minor policy:** core and adapter upgrades can silently reinterpret fields.
- **In-process plugins:** a Go toolchain change or Python import-path change becomes an installer failure and a privilege escalation surface.
- **Adapter-owned privileged writes:** rollback semantics differ per adapter and the core cannot guarantee recovery.
- **An arbitrary root command operation:** every adapter bypasses path validation, journaling, and compensation.
- **Boolean host state:** `unknown` is misreported as `false`, causing unsafe install or uninstall decisions.
- **One-DM assumption:** detection returns a single global DM and loses installed-but-disabled alternatives.
- **Core-owned version parsing:** SDDM, distro package epochs/releases, and future DMs force DM-specific branches into core.
- **Platform logic under the DM contract:** the SDDM adapter becomes an Arch-only adapter even where its source integration could work elsewhere.
- **Manifest written only after success:** an interrupted installation has no durable record of already-applied mutations.
- **Uninstall delegated to the latest adapter:** an adapter upgrade can make an old installation impossible to reverse.
- **Capabilities without semantic definitions:** two adapters can both claim `concurrent=true` while providing materially different cancellation or identity guarantees.
- **No idempotency/input digest:** retrying after interruption can duplicate package or service mutations.

---

## 3. Concrete repository structure

### 3.1 Proposed complete tree

```text
fplogin/
├── cmd/
│   ├── fplogin/
│   │   └── main.go
│   ├── fplogin-adapter-sddm/
│   │   └── main.go
│   └── fplogin-platform-arch/
│       └── main.go
├── internal/
│   ├── core/
│   │   ├── app/
│   │   ├── discovery/
│   │   ├── selection/
│   │   ├── analyze/
│   │   ├── install/
│   │   ├── transaction/
│   │   ├── manifest/
│   │   └── report/
│   ├── protocol/
│   │   ├── adapter/v1/
│   │   ├── platform/v1/
│   │   └── manifest/v1/
│   ├── adapterclient/
│   ├── platformclient/
│   └── executor/
├── contracts/
│   ├── adapter/v1/
│   │   ├── descriptor.schema.json
│   │   ├── request.schema.json
│   │   ├── response.schema.json
│   │   ├── change-plan.schema.json
│   │   └── examples/
│   ├── platform/v1/
│   │   ├── descriptor.schema.json
│   │   ├── request.schema.json
│   │   ├── response.schema.json
│   │   └── examples/
│   └── manifest/v1/
│       ├── transaction-journal.schema.json
│       ├── install-manifest.schema.json
│       └── examples/
├── adapters/
│   └── sddm/
│       ├── adapter.json
│       ├── adapter/
│       ├── patches/
│       ├── assets/
│       │   ├── pam/
│       │   └── theme/
│       ├── packaging/
│       │   └── arch/
│       └── testdata/
├── platforms/
│   └── arch/
│       ├── platform.json
│       ├── provider/
│       └── testdata/
├── tests/
│   ├── contract/
│   ├── fixtures/
│   │   ├── hosts/
│   │   ├── adapters/
│   │   └── manifests/
│   ├── integration/
│   └── vm/
├── docs/
│   ├── architecture/
│   │   ├── CORE_ADAPTER_ANALYSIS.md
│   │   └── decisions/
│   ├── reviews/
│   ├── IMPLEMENTATION_PLAN.md
│   └── LESSONS.md
├── install.sh
├── uninstall.sh
├── go.mod
├── go.sum
├── Makefile
├── LICENSE
├── .gitignore
└── README.md
```

Directories must be created only with real files; no `.gitkeep` placeholders.

### 3.2 Non-obvious decisions

#### Three executables under `cmd/`

The core, SDDM adapter, and Arch platform provider are separate process boundaries. `cmd/fplogin` may import core packages but must not import `adapters/sddm` or `platforms/arch`. Each adapter/provider command imports only its own implementation and shared protocol representation. Separate binaries make an accidental in-process dependency visible in the build graph.

#### `internal/core/` instead of a public Go plugin API

The core implementation is not an SDK. Keeping it under Go's `internal/` rule prevents external modules from treating unstable implementation packages as a supported adapter API. The supported API is the versioned JSON contract under `contracts/`.

#### `contracts/` as the wire-format source of truth

Go structs are not sufficient documentation for adapters written in other languages and do not validate persisted old manifests. JSON Schemas and examples define the external contract. Go protocol types mirror those schemas and must pass schema conformance tests.

#### `platforms/arch/` outside `internal/core/`

The current plan places Arch under `core/platform/arch`. That would make pacman and Arch package semantics part of the core. Moving it to a platform provider keeps both DM-specific and distro-specific decisions outside the orchestration core. v1 has one platform provider and one DM adapter; neither is a special case in core.

A platform provider supplies generic package, service-manager, filesystem, and host-candidate operations. The DM adapter interprets those facts. For example, the Arch provider can expose packages that provide `display-manager`; the SDDM adapter decides which candidate is SDDM.

#### Adapter assets live with the adapter

PAM service files, themes, SDDM patches, and SDDM packaging metadata are inseparable from the SDDM integration and therefore remain under `adapters/sddm/`. The core sees immutable artifact references and hashes, not SDDM paths.

#### Platform-specific SDDM packaging remains at the intersection

`adapters/sddm/packaging/arch/` is intentionally inside the adapter because it packages a patched SDDM build. Generic pacman installation belongs to `platforms/arch`; the exact PKGBUILD and patch inputs belong to the SDDM adapter.

#### Transaction journal and installed manifest are separate schemas

`/var/lib/fplogin/transactions/<transaction-id>.json` must be created and fsynced before the first mutation and updated atomically after every operation receipt. Only after verification succeeds is an installed-state manifest atomically published at `/var/lib/fplogin/manifest.json`.

The current implementation plan says to write the manifest after installation. That is insufficient for interruption recovery: a power loss before the final write would leave changed files/services with no rollback record.

#### Thin shell launchers

`install.sh` and `uninstall.sh` locate and invoke the packaged Go core. They may perform bootstrap/version checks and display recovery instructions. They must not implement detection, adapter selection, manifest editing, mutation, or rollback.

### 3.3 Files required before Sprint 0

A short **Foundation Gate** must precede Sprint 0. This is not product feature work; it prevents the SDDM experiment from defining core interfaces accidentally.

The following files must exist and be reviewed before any SDDM adapter implementation:

1. `docs/architecture/CORE_ADAPTER_ANALYSIS.md` — this decision analysis, accepted or amended.
2. `docs/architecture/decisions/0001-core-language.md` — accepted language/toolchain/build policy.
3. `docs/architecture/decisions/0002-adapter-process-protocol.md` — accepted process, privilege, discovery, and compatibility rules.
4. `docs/architecture/decisions/0003-transaction-journal.md` — accepted journaling, fsync, rollback, and manifest publication rules.
5. `go.mod` and `go.sum` — exact Go language/toolchain floor and initial dependency closure.
6. `contracts/adapter/v1/*.schema.json` — descriptor, envelopes, methods, change plan, and closed operation kinds.
7. `contracts/platform/v1/*.schema.json` — generic platform provider contract; no pacman fields in the core-facing schema.
8. `contracts/manifest/v1/*.schema.json` — interrupted transaction and successful installation formats.
9. `contracts/**/examples/` — at least one valid and one invalid fixture per schema family.
10. `internal/protocol/{adapter,platform,manifest}/v1/` — Go representations and validation boundaries matching the schemas.
11. `internal/adapterclient/` — bounded process runner and descriptor validation; no SDDM imports.
12. `tests/contract/` — a fake adapter/provider executable and conformance tests for discovery, protocol mismatch, duplicate IDs, timeouts, malformed stdout, and unknown operation rejection.
13. `adapters/sddm/adapter.json` — metadata and declared contract only; its implementation may still return `not_implemented` until Sprint 0.
14. An architecture-boundary check proving that `internal/core/...` does not depend on `adapters/...` or `platforms/...`.
15. `LICENSE` and `.gitignore` entries for build/worktree artifacts.

Foundation Gate acceptance criteria:

- A fake adapter is discovered without any DM-name branch in core.
- Two compatible fake adapters produce a user-selection set rather than an implicit winner.
- Invalid/untrusted descriptors are rejected before execution.
- Protocol major mismatch is reported deterministically.
- A fixture manifest validates and includes adapter identity plus generic rollback receipts.
- Dependency inspection proves the core does not import the SDDM adapter or Arch provider.

Only after this gate should Sprint 0 add real SDDM detection, baseline build preparation, or SDDM-specific evidence.

---

## 4. Early architectural risks

### 4.1 Decisions that become expensive or impossible to reverse

#### Adapter identity and manifest routing

Once an installation manifest contains an adapter ID, changing that ID requires migration logic forever. IDs must be opaque, globally unique, and stable before the first installable package.

#### In-process versus out-of-process adapters

Starting with in-process adapters exposes language types and privilege to adapters. Moving to a process protocol later changes every adapter, test, package layout, and failure mode. The process boundary must be fixed before the SDDM adapter.

#### Privilege ownership

If the first adapter writes system files directly, later centralization cannot reconstruct reliable rollback records for old installations. The core executor must own all privileged mutations from the first mutable prototype.

#### Manifest and journal semantics

A final-state-only manifest cannot recover an interrupted transaction. Adding a journal later does not repair installations made before journaling. Transaction ID, operation ID, before-state, compensation, and fsync ordering are v1 schema concerns.

#### Operation vocabulary

An early arbitrary `run_command` escape hatch becomes permanent because adapters depend on it. A closed typed operation set is harder initially but preserves auditability and rollback. New operation kinds can be added only with a protocol-major or carefully additive protocol-minor rule.

#### Capability semantics

A boolean called `concurrent_authentication` is too weak unless it defines identity binding, cancellation, winner gating, fallback, and session-creation guarantees. Once manifests and user decisions consume ambiguous booleans, correcting their meaning breaks compatibility.

#### Version representation

Distro package versions are not universally SemVer. Arch pkgver/pkgrel, Debian epochs/revisions, RPM EVR, and upstream versions must not be normalized into one lossy core string comparison. Platform providers preserve package version structure; adapters own compatibility decisions.

#### Uninstall dependency on adapter availability

If uninstall requires executing the exact adapter that installed the system, removing/upgrading a package can strand the host. Generic operation receipts and compensation data must be sufficient for core recovery. The adapter improves planning and verification but is not the sole copy of rollback knowledge.

#### Filesystem ownership and conflict policy

Whether fplogin writes files directly or installs package-owned files affects upgrades, checksum checks, and package-manager conflict handling. v1 should prefer package-owned immutable assets; direct core writes should be limited to fplogin-owned state and dedicated drop-ins.

#### Platform abstraction placement

Keeping `arch` beneath `core/` turns pacman/systemd behavior into core behavior and forces a later repository/API migration. The platform provider boundary should exist now even though only Arch is implemented.

### 4.2 Current-plan assumptions that may not survive v2

#### One active DM is not the same as one installed DM

`display-manager.service` identifies the usual active systemd alias, but multiple DMs may be installed and disabled. Detection must return a set of instances with independent installed/enabled/active state. Selection and conflict handling cannot use one global `dm` variable.

#### systemd is a v1 platform choice, not a universal core fact

Future distributions may use another service manager or immutable image activation. Generic state uses service references and tri-state results. `systemctl` and `display-manager.service` belong to a platform provider.

#### Package discovery is package-manager-specific

Arch's `provides=(display-manager)` is useful, but Debian/RPM metadata and locally compiled installations differ. The core cannot equate package presence with DM presence or compatibility.

#### Filesystem paths differ

PAM service directories, theme roots, libexec directories, configuration precedence, and package-owned drop-in locations vary by distribution and build configuration. These paths belong to adapter/platform facts and must be recorded in plan operations, not constants in core.

#### PAM is not necessarily the generic adapter mechanism

The SDDM adapter uses PAM/fprintd, but a future DM could expose a plugin, broker, or native multi-method authentication API. The core capability model must describe observable guarantees rather than require PAM service names or PAM transaction phases.

#### Authentication capabilities are not all-or-nothing

A DM may support multiple methods but not concurrent attempts, cancellation, automatic start, or request-bound status. Capabilities need independent semantic IDs and levels. The installer must reject an adapter that cannot satisfy mandatory v1 safety capabilities even if it claims generic biometric support.

#### Local users are only the v1 certified account source

LDAP, SSSD, systemd-homed, network homes, and smartcard-backed accounts change username resolution, enrollment visibility, and account policy. Adapter requests carry opaque selected-user identity; the core analyzer must report uncertainty instead of assuming `/etc/passwd` is complete.

#### A writable traditional root filesystem is not universal

Immutable systems, image-based updates, read-only `/usr`, transactional package managers, and containerized greeters require different operation providers. Core operations must be capabilities of the platform provider, not unconditional POSIX writes.

#### x86_64 is not a durable packaging assumption

The current development host is x86_64, but reader hardware and Linux desktops also use arm64. Artifact metadata and adapter descriptors must include architecture; manifests must record it.

#### Security policy is distro-specific

SELinux/AppArmor labels, polkit policy, PAM module locations, package signatures, and service sandboxing differ. File mode/owner checks alone are not complete verification on future platforms.

#### Adapter upgrades can cross source baselines

The SDDM 0.21 patch series may not apply to a later SDDM baseline. Adapter version, upstream source commit, distro patch baseline, and produced artifact digest must be independently recorded. `adapter_version == fplogin_version` must not be assumed.

#### Analyzer probes are partly platform-specific

The analyzer's questions are core policy, but package queries, PAM include resolution, systemd-homed detection, crypttab paths, and wallet startup integration vary. Core owns finding semantics and confidence; platform providers and DM adapters supply evidence through contracts.

### 4.3 Required corrections to the current implementation plan before code

The plan already states the DM-independent goal, but several concrete steps still encode SDDM inside the core flow. They should be rewritten after this architecture is accepted:

- Installer phase “Detect SDDM” becomes “obtain generic DM candidates, discover adapters, and select a compatible target.”
- “Build or install the pinned fplogin SDDM package” becomes an adapter plan/artifact step followed by a platform-provider package operation.
- Manifest field “previous SDDM theme/configuration state” becomes adapter-scoped opaque evidence plus generic operation receipts.
- Analyzer item “active display manager and SDDM package/version” becomes generic DM inventory with adapter-attributed details.
- `core/platform/arch/` moves to `platforms/arch/`.
- The manifest is not first written after installation; a durable transaction journal is written before the first mutation and promoted to the final manifest after verification.
- Sprint 0 is preceded by the Foundation Gate in section 3.3.

These corrections do not broaden v1 product scope. They prevent v1's only adapter from defining irreversible core behavior.

---

## Final decision

Adopt the following before implementation:

1. **Go core**, with Bash restricted to launch/recovery wrappers.
2. **Out-of-process, language-neutral adapters** using versioned JSON over stdin/stdout.
3. **Trusted static descriptors plus runtime handshake** for discovery; no hardcoded DM-name branches.
4. **Core-owned privileged transaction executor**; adapters return declarative plans and never mutate privileged paths.
5. **Separate platform-provider contract** from the first commit; Arch is an implementation, not a core namespace.
6. **Durable transaction journal before mutation**, then atomic final-manifest publication after verification.
7. **Foundation Gate before Sprint 0** so the SDDM adapter is written against real contracts and conformance tests.

This architecture is more work than a Bash installer that calls SDDM-specific functions directly. That extra work is not speculative abstraction: each boundary directly protects rollback correctness, privileged execution, dynamic adapter discovery, or the stated multi-DM requirement.
