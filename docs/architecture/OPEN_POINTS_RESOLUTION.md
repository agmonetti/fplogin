# Open Points Resolution

**Status:** Architecture addendum to `docs/architecture/CORE_ADAPTER_ANALYSIS.md`  
**Scope:** Contract clarification only. This document introduces no implementation language exception, no new privileged escape hatch, and no display-manager-specific branch in core.

## 1. Platform provider contract

### Decision

A platform provider is a separate executable, discovered through a trusted static `platform.json` descriptor and contacted over the same versioned JSON-over-stdin/stdout envelope used by adapters. The provider exposes generic host, package, service, artifact, and mutation operations. It never exposes distro-specific concepts to core; distro-specific behavior is encoded behind the provider implementation and represented only through generic contract types.

The Arch provider is the only v1 implementation. `org.fplogin.platform.arch` is an implementation identity, not a value the core compares in control flow.

### 1.1 Operations

The platform protocol uses these operations. Every provider implements every operation; an operation may return an empty result when the provider has no applicable evidence or capability.

#### `Describe(DescribeRequest) -> Result<PlatformDescriptor, PlatformError>`

- **Input:** the core's supported platform-protocol major and minor range.
- **Output:** runtime provider identity, version, protocol actually supported, and capability summary.
- **Rules:** no host inspection and no mutation. Runtime identity, executable metadata, and protocol support must match `platform.json`; a mismatch disables the provider. The provider must not use `Describe` to infer the host platform.

#### `InspectHost(InspectHostRequest) -> Result<PlatformHostReport, PlatformError>`

- **Input:** `HostContext` read root, architecture, invoking identity, deadline, and requested generic fact classes.
- **Output:** opaque platform identity facts, architecture, package-manager and service-manager capabilities, filesystem-policy capabilities, and bounded evidence; plus generic installed package and service references where available.
- **Rules:** read-only. Distribution names, package epochs/revisions, service-manager identifiers, and paths remain provider-owned facts. Unknown facts are represented as `unknown`, never guessed from a missing command or package.

#### `ListPackageCandidates(ListPackageCandidatesRequest) -> Result<PackageCandidateReport, PlatformError>`

- **Input:** generic candidate predicates such as `provides: display-manager`, package name hints supplied by an adapter, architecture, and host context.
- **Output:** zero or more `PackageCandidate` records containing opaque package reference, display name, provider-preserved version structure, installed state, provided capabilities, and evidence.
- **Rules:** read-only. The provider may interpret its package database, but must not decide that a candidate is a particular display manager. Package presence alone is not compatibility. Package-version structure must not be lossy-normalized into a core SemVer.

#### `ListServiceCandidates(ListServiceCandidatesRequest) -> Result<ServiceCandidateReport, PlatformError>`

- **Input:** generic service aliases/capability queries and host context.
- **Output:** zero or more `ServiceCandidate` records containing opaque service reference, active/enabled/configurable tri-state values, package associations if known, and evidence.
- **Rules:** read-only. The provider may use its service manager and generic aliases such as a display-manager alias, but the core must not infer a DM identity from an alias. All three state values are `yes`, `no`, or `unknown`.

#### `CollectAnalyzerFacts(AnalyzerFactsRequest) -> Result<PlatformAnalyzerFacts, PlatformError>`

- **Input:** analyzer scope, selected target/provider context if present, read root, requested probe IDs, and deadline.
- **Output:** bounded, read-only evidence for platform-dependent analyzer probes: effective package metadata, service state, PAM/include resolution, filesystem locations, crypttab/systemd-homed facts, session-start integration facts, and probe errors. Facts are evidence, not findings.
- **Rules:** no secrets, wallet contents, passwords, fingerprint templates, arbitrary process memory, configuration mutation, or claims based solely on package presence. The provider must preserve command/path provenance and report `unknown` when evidence is insufficient.

#### `PrepareArtifactInstall(PrepareArtifactInstallRequest) -> Result<ArtifactInstallPreparation, PlatformError>`

- **Input:** selected provider capabilities, approved plan digest, artifact references produced by the adapter, operation IDs that consume them, and a restricted staging handoff.
- **Output:** provider-owned installation references: canonical staged artifact identity, expected media type, digest, package/file ownership expectations, and the typed operation parameters that the core executor may apply.
- **Rules:** no mutation of the live host. The provider validates that each artifact is within the approved handoff, matches its declared digest/media type, and is installable under the selected provider. It must not reinterpret an artifact into an unapproved operation or add operations to the plan.

#### `ApplyOperation(ApplyOperationRequest) -> Result<OperationReceipt, PlatformError>`

- **Input:** one already core-validated operation from the closed vocabulary in section 2.4 of the analysis, its dependencies/preconditions, approved plan digest, and any prepared artifact reference.
- **Output:** a receipt with operation ID, provider-preserved before-state and after-state, result, artifact/package receipts, ownership/checksum/mode evidence where relevant, and compensation data.
- **Rules:** this is the only mutating provider operation. It may execute only the known typed operation kinds (`create_directory`, `write_file_atomic`, `remove_owned_file`, `install_package_artifact`, `remove_owned_package`, `set_service_enabled`, `set_service_active`, `restore_service_state`). It must reject unknown kinds, path-policy violations, missing digests, failed preconditions, and artifact mismatches. It has no shell-command parameter and no arbitrary hook. The core journals the receipt after every successful or failed attempt.

#### `VerifyOperation(VerifyOperationRequest) -> Result<PlatformVerificationReport, PlatformError>`

- **Input:** operation or completed plan ID/digest, expected postcondition, provider state scope, and verification phase.
- **Output:** ordered read-only checks with `passed`, `failed`, or `unknown`, evidence, severity, and any provider-specific diagnostic details.
- **Rules:** read-only; `unknown` never counts as `passed`. It verifies generic package, file, and service effects only. Adapter-specific authentication and capability verification remains the adapter's `Verify` responsibility.

`PlatformError` has exact fields `code`, `message`, `retryable`, `evidence`, and optional `details`, matching `AdapterError`. Stable codes are `invalid_request`, `protocol_mismatch`, `unsupported_platform`, `unsupported_operation`, `timeout`, `host_read_failed`, `artifact_failed`, `mutation_failed`, and `internal_error`. A missing package/service capability is a successful report with an unsatisfied or unknown result, not a protocol failure.

### 1.2 `platform.json` descriptor

Each provider is discovered through a root-owned `platform.json`, structurally parallel to `adapter.json`:

| Field | Type/meaning |
|---|---|
| `descriptor_schema_version` | Descriptor JSON-Schema version. |
| `platform_id` | Stable globally unique opaque ID; never reused or renamed. |
| `platform_version` | Provider implementation version. |
| `protocol_versions` | Supported platform-protocol major/minor ranges. |
| `minimum_core_version` | Diagnostic/package compatibility floor; protocol controls wire behavior. |
| `name`, `vendor` | Human-readable identity only; never control flow. |
| `executable` | Path relative to descriptor directory; absolute paths and `PATH` lookup forbidden. |
| `supported_platforms` | Opaque platform predicates (distribution, architecture, service/package manager); compatibility is confirmed dynamically. |
| `capabilities` | Stable IDs for host inspection, package queries, service queries, analyzer facts, artifact staging, and each supported closed operation. Each has status, semantic level, constraints, and evidence requirements. |
| `operation_kinds` | Exact subset of the closed operation vocabulary the provider can execute; unknown kinds are rejected. |
| `package_formats` | Provider-recognized artifact media types and architecture constraints. No adapter or core package-manager fields. |
| `service_manager` | Generic service-manager capability declaration, not a hardcoded core branch. |
| `asset_root` | Path relative to the descriptor containing immutable provider assets, if any. |

The descriptor schema forbids executable paths, asset roots, or descriptor files that are non-canonical, symlink-crossing, or writable by non-root users/groups. Duplicate `platform_id` values are a discovery error, never resolved by search order.

### 1.3 Discovery and protocol

The core scans fixed root-owned provider directories such as `/usr/lib/fplogin/platforms/*.json` and `/usr/local/lib/fplogin/platforms/*.json` in deterministic lexical order, validates each descriptor against the pinned schema, rejects untrusted/duplicate descriptors, and invokes `Describe` with a clean environment. Runtime identity and protocol metadata must equal the descriptor.

The core then requests `InspectHost` from every usable provider. A provider is eligible only when its descriptor and dynamic report satisfy the requested platform and architecture constraints. The core selects the provider that can supply the required generic capabilities and records its ID, version, protocol, and descriptor digest in the journal and manifest. If zero or multiple providers remain, selection fails explicitly; the core never chooses by a hardcoded distro name or descriptor priority. A development-only provider directory is allowed only while unprivileged and is rejected after elevation.

The provider reuses the adapter envelope because both are one-request/one-response, version-negotiated, bounded subprocess protocols with identical trust, stdout, stderr, timeout, and exit-status rules. Only the operation vocabulary and error type name differ. Reuse prevents two subtly different process-security implementations while preserving separate schemas and namespaces (`contracts/adapter/v1` and `contracts/platform/v1`).

## 2. Analyzer contract

### Decision

The analyzer is core-owned and produces findings. Adapters do **not** contribute findings through a new adapter method. This preserves the closed eight-method adapter vocabulary and keeps the analyzer's policy and confidence semantics independent of any DM implementation. Adapters contribute evidence through their existing read-only `Detect`, `InspectState`, `CheckPrerequisites`, and `Verify` responses; the core tags that evidence with its source and normalizes it into findings when relevant. Platform providers contribute platform-dependent raw evidence only through `CollectAnalyzerFacts`.

No adapter or provider may inject a preclassified `confirmed` finding. Classification belongs to `internal/core/analyze/`.

### 2.1 Finding schema

A `Finding` contains exactly:

| Field | Type/meaning |
|---|---|
| `finding_id` | Stable analyzer rule identifier plus occurrence key. |
| `component` | Structured opaque component ID and human label, for example a PAM module, wallet, keyring, mount facility, homed configuration, or session integration. |
| `evidence` | Non-empty ordered evidence records: `source` (`core`, `adapter`, or `platform`), `kind` (`path`, `command`, `package`, `service`, `adapter_report`, or `derived`), canonical subject, bounded observed value/redacted summary, timestamp, and optional error. Secrets and raw credential material are forbidden. |
| `fingerprint_login_impact` | Observable or cautiously stated effect after fingerprint login. |
| `password_login_comparison` | Corresponding password-login behavior, including `not_comparable` where evidence does not support a comparison. |
| `impact` | Enum `none`, `informational`, `degraded`, or `blocked`, plus a required human explanation. `blocked` means a stated facility cannot proceed, not that the login session itself is blocked. |
| `confidence` | Exactly one of `confirmed`, `likely`, or `unknown`. `confirmed` requires direct configuration/runtime evidence; `likely` requires multiple consistent indicators or a documented reliable inference; `unknown` means evidence is insufficient or conflicting. |
| `suggested_action` | Structured `action_id`, human text, and optional safe next step; null when no action is justified. Suggestions never authorize mutation. |

Package presence alone cannot yield `confirmed`. Findings must identify evidence and limitations, and the analyzer may emit a separate `unknown` finding for a probe that cannot be safely resolved.

### 2.2 Forbidden analyzer behavior

Consistent with Implementation Plan section 7, analyzer code is read-only and must not scan arbitrary process memory, read wallets/passwords/fingerprint templates, alter PAM or application settings, unlock or attempt to unlock wallets, install packages, enable/stop services, or claim complete discovery of every secret-service consumer. It must not turn an adapter/provider assertion into fact without evidence, infer behavior solely from package presence, or make authentication/installation decisions. Bounded commands and reads use the provider-supplied facts and fixed `C` locale; failures become evidence and confidence degradation, not guessed success.

### 2.3 Analyzer outputs

Terminal output is deterministic text: a header, host/provider context, one block per finding ordered by `component`, `impact` severity, then `finding_id`, and a limitations block. Each block prints `Component`, `Impact`, `Confidence`, `Fingerprint login`, `Password comparison`, `Evidence`, and `Suggested action` (or `None`). It never prints secret contents. No terminal wording is used as a machine contract.

Machine output is one JSON object:

```json
{
  "schema_version": "1.0",
  "analyzer_version": "...",
  "generated_at": "RFC3339 timestamp",
  "platform_provider": {"id": "opaque", "version": "...", "descriptor_sha256": "hex"},
  "target": {"adapter_id": "opaque or null", "instance_id": "opaque or null"},
  "findings": [/* Finding objects above */],
  "limitations": [{"code": "stable", "message": "...", "evidence": []}]
}
```

The JSON Schema requires `schema_version`, `analyzer_version`, `generated_at`, `platform_provider`, `target`, `findings`, and `limitations`; rejects unknown required-contract omissions, requires every finding's `evidence`, `impact`, `confidence`, and `suggested_action`, and permits additive diagnostic fields only under the protocol's minor-version rules. An analyzer execution with probe failures can still succeed and returns those failures in evidence/limitations.

## 3. User-facing selection flow

### Decision

Selection remains entirely in core and operates on opaque target/adapter records and capability predicates. There are no DM-name branches, distro-name branches, or adapter-priority defaults.

The exact sequence is:

1. Discover and validate trusted platform descriptors; select one eligible provider and obtain `InspectHost` facts.
2. Ask the provider for generic package/service/display-manager candidates.
3. Discover and validate all trusted adapter descriptors; invoke `Describe` for each.
4. Invoke `Detect` on every usable adapter with the generic candidate set. Retain incompatible/unknown evidence for diagnostics but do not make it selectable.
5. Form selectable records only for compatible target/adapter pairs that satisfy mandatory capability predicates and have no unresolved hard prerequisite. Each record shows an opaque target/adapter identity, human names from descriptors/reports, detected version evidence, compatibility/confidence, offered capabilities, prerequisite summary, and platform-provider identity.
6. If one record remains, show it as the proposed target and require explicit confirmation before inspection/planning. Core never silently installs.
7. If multiple records remain, show all records in deterministic order with the same fields and require the user to select exactly one and then confirm the selected plan/risk. No priority or “first discovered” winner exists.
8. After selection, call adapter `InspectState` and `CheckPrerequisites`, display required remediation, approvals, package/DM replacement risks, and analyzer limitations, then require the explicit approval required by the plan before mutation.
9. Record provider, adapter, target, descriptor digests, selected-user decision, and accepted plan digest in the journal before the first mutation.

The displayed list is pre-filtered to compatible target/adapter pairs, not to installed DMs alone. Incompatible detections remain available in diagnostic output so absence is explainable.

If a user requests a DM/target for which no compatible adapter exists, core rejects the request before planning or mutation with this stable human message:

> `No compatible fplogin adapter is available for the requested target '<requested target>'. Installed or detected targets were checked, but none satisfies the required adapter capabilities. No changes were made.`

The machine result is `selection_error` with `reason: no_compatible_adapter`, the requested opaque target/query, and retained detection evidence. The process exits nonzero with stable exit code `4` (`no selectable target`). The list is never populated with incompatible choices merely to let the user select one.

If multiple DMs are installed but only one has a compatible adapter, core presents exactly that one selectable target, states that other detected targets were excluded, and requires the same explicit confirmation. It does not auto-select merely because it is the only compatible target.

If zero compatible targets are detected, core shows `No compatible installation target was detected. No changes were made.`, reports provider and adapter evidence plus remediation where available, returns machine reason `no_compatible_target`, and exits with code `4`. It does not install a DM, choose an incompatible adapter, or mutate the host.

## 4. Adapter and platform provider artifact ownership

### Decision

The adapter owns integration content and packaging recipes; the platform provider owns package-manager, filesystem, and service-manager semantics. A future SDDM integration is one SDDM adapter with multiple platform packaging backends, not one adapter per distribution. The adapter ID therefore remains the DM integration identity, while the selected provider determines how its returned artifacts are installed.

The SDDM adapter may keep `packaging/arch/` and later add `packaging/<platform-family>/` backends. Backend selection is adapter-owned based on the provider's declared capabilities and the accepted plan. The provider does not contain SDDM patches, PAM files, themes, PKGBUILD recipes, or DM-specific compatibility rules.

### 4.1 `PrepareArtifacts` handoff

`PrepareArtifactsRequest` is extended with a required `platform_context` object containing:

- selected `platform_id`, provider version, protocol, descriptor digest;
- target architecture and provider-declared package formats/capabilities;
- approved plan ID/digest and operation IDs that consume artifacts;
- restricted workspace/source-cache paths, network policy, and deadline.

The adapter still runs unprivileged and returns `ArtifactSet` entries with canonical workspace path, media type, size, SHA-256 digest, provenance (source revision, patch inputs, backend identity), target architecture, and consuming operation IDs. Each entry also declares its opaque package/file role, but not a new privileged operation kind. The adapter must build reproducibly for the selected provider backend, must not install or write live system paths, and must not return an artifact unrelated to the accepted plan.

The core validates the set and passes it through `PrepareArtifactInstall` to the selected provider. The provider verifies path confinement, digest, media type, architecture, and package-install capability, then returns a provider-owned staging/install reference. During `ApplyOperation`, the core hands that reference to the provider with the existing `install_package_artifact` operation. The core executor therefore knows only the operation type, approved digest, operation ID, and provider reference; it never parses a PKGBUILD, package archive, patch, or other internal format.

The provider owns package signing/verification policy, package database interaction, dependency resolution, installation/removal semantics, file ownership recording, and service activation semantics. The adapter owns which patched SDDM source/assets constitute the integration and verifies DM-specific behavior afterward through `Verify`. Both sides must return receipts/evidence sufficient for the generic journal and manifest.

### 4.2 Why one adapter with multiple backends

A separate adapter per platform would duplicate SDDM detection, version policy, capabilities, authentication semantics, state inspection, and verification, while making manifests and user selection treat packaging differences as different DMs. One adapter with explicit packaging backends keeps the DM contract stable and isolates only genuinely platform-specific construction. Platform capability negotiation prevents an SDDM backend from assuming Arch package semantics, while the provider remains generic. This preserves the analysis rule that platform logic must not leak into the DM contract and does not add `ApplyInstall`, `run_as_root`, or any other operation outside the closed vocabulary.

## Foundation Gate addendum

The following Foundation Gate items from section 3.3 of `CORE_ADAPTER_ANALYSIS.md` must be updated or added because of these resolutions:

- **Update item 7:** `contracts/platform/v1/*.schema.json` must cover `platform.json`, the shared envelope, all provider operation payloads/results, `PlatformError`, artifact handoff, and the closed operation vocabulary without Arch/pacman fields in core-facing types.
- **Update item 9:** add valid and invalid platform descriptor, provider envelope, analyzer-facts, artifact-handoff, and selection-result fixtures under `contracts/**/examples/`.
- **Update item 10:** `internal/protocol/platform/v1/` must mirror the provider schemas, including `PlatformHostReport`, `PlatformAnalyzerFacts`, provider receipts, and artifact staging references.
- **Update item 11:** add or rename the client boundary so bounded process execution and trusted descriptor validation cover both adapters and platform providers; no provider is loaded in-process.
- **Update item 12:** conformance tests must cover provider discovery/selection, duplicate provider IDs, provider protocol mismatch, capability insufficiency, malformed provider output, typed operation rejection, artifact digest/path validation, and analyzer-fact evidence handling.
- **Update item 13:** `adapters/sddm/adapter.json` must declare the platform-neutral adapter identity and supported packaging backends/capability requirements; it must not encode Arch-only core branches.
- **Add:** `platforms/arch/platform.json` as the v1 provider descriptor and its descriptor/schema-valid test fixtures.
- **Add:** analyzer contract schemas and examples under `contracts/analyzer/v1/` for `Finding`, machine report, limitations, and evidence records.

`contracts/analyzer/v1/` is the correct location because analyzer JSON output is consumed by external tools, CI scripts, and the installer postflight report; it is not internal to the core process. The path signals a stable, versionable, externally referenceable contract, consistent with `contracts/adapter/v1/` and `contracts/platform/v1/`. The `v1` directory freezes the schema shape: additive changes increment the minor field in the schema itself, while breaking changes require a new `contracts/analyzer/v2/` directory. This prevents tools consuming analyzer output from breaking when the core implementation changes. `contracts/core/v1/` would incorrectly signal an internal implementation detail and make the schema harder to find and reference from external documentation or tooling.
- **Add:** selection-flow fixtures covering one compatible target, multiple compatible targets, one compatible target among multiple installed DMs, requested target with no compatible adapter, and zero compatible targets.
- **Update item 14:** the architecture-boundary check must prove core has no imports or branches for `sddm`, `arch`, or any provider/adapter ID, while still allowing generic provider and analyzer interfaces.

No existing document is changed by this addendum; implementation files remain outside its scope.
