# fplogin

Biometric login for Linux, under active development. The v1 target is fingerprint login from SDDM with no Enter key, no in-place edits to existing system configuration, and no password storage.

[![fplogin Project Telemetry & Milestone Matrix](docs/assets/dashboard.png)](dashboard.html)

The dashboard reflects the [Sprint 3 physical closeout review](docs/reviews/sprint-3-physical-closure.md) and the [independent Qt5/Qt6 technical review](docs/reviews/sprint-3-e7-2026-11-17.md) (PASS). SDDM timed out before PAM, and GNOME Keyring did not block Hyprland and could be unlocked manually on demand. KWallet unlock was not tested; automatic wallet unlock by fingerprint is outside v1. Explicit owner acceptance of Qt5/Qt6 compatibility and Sprint 3 closure remains pending. [Sprint 2 remains accepted and closed](docs/reviews/sprint-2-acceptance-2026-11-12.md).

## The problem

SDDM does not natively support fingerprint authentication. Users must type their password or, with manual PAM tweaks, press Enter and then place their finger. There is no built-in experience where the reader activates automatically and works in parallel with the password field.

## Planned approach

The Foundation Gate, Sprint 0, Sprint 1 and Sprint 2 are complete and accepted. Sprint 1 is closed by the [2026-10-04 independent review](docs/reviews/sprint-1.md#2026-10-04-sol-independent-acceptance-review--sprint-1-gate). Sprint 2 is accepted and closed by the [2026-11-12 owner acceptance](docs/reviews/sprint-2.md#13-2026-11-12-sprint-2-final-acceptance-and-closure-by-the-project-owner) and [Sprint 2 acceptance review](docs/reviews/sprint-2-acceptance-2026-11-12.md), covering the G01–G16 hardware verification matrix, theme fix, and complete secret audit. Transition to Sprint 3 is authorized.

The [2026-10-20 activation correction](docs/reviews/sprint-2.md#6-2026-10-20-bounded-fprintd-activation-correction) fixes initial availability and explicit Retry when installed fprintd is inactive, without a keepalive or restart loop. The corrected traced guest's [new G04 physical verification and closure](docs/reviews/sprint-2.md#7-2026-10-21-g04-physical-verification-and-laboratory-closure) corroborates invalid-finger retry guidance, PAM attempt exhaustion, retained-input password recovery and absence of an automatic restart in the observed window. The [2026-11-08 G05-a1 physical case](docs/reviews/sprint-2.md#9-2026-11-08-g05-a1--basic-physical-timeoutretained-input-partial-evidence-and-closed-handoff) additionally records post-timeout password retention reported by the owner, normal fingerprint PAM teardown and one same-request password session. The explicit deadline/state causality remains unproven, so the full basic G05 contract is **partial**; both physical races and G05–G16 acceptance remain pending. The [current G05 offline continuation](docs/reviews/sprint-2.md#10-2026-11-08-g05-focused-offline-continuation--current-partial-verdict) demonstrates one test-bound session after loser exit and bounded rejection of a late mock-PAM result, without replacing physical acceptance. The preserved VM is stopped and the owner restored the reader handoff.

The [2026-11-05 offline pre-ACK slice](docs/reviews/g05-preack-control-2026-11-05.md) added authenticated diagnostic reservation before the greeter context ACK. Subsequent offline mock-PAM tests and focused suites covered edge cases. On 2026-11-12, following the owner's manual hardware execution of all remaining physical test cases and the completion of the G16 secret audit, Sprint 2 was formally accepted and closed. Details are tracked in the [Sprint 2 validation checklist](docs/SPRINT_2_VALIDATION_CHECKLIST.md) and [acceptance review](docs/reviews/sprint-2-acceptance-2026-11-12.md). The dashboard capture above reflects this completed state.

The planned product has:

- A minimal, upstream-quality SDDM patch coordinating concurrent PAM authentication methods.
- A dedicated PAM service for biometric authentication (`sddm-fingerprint`).
- An SDDM theme that displays daemon-reported biometric status and requests method start/cancellation.
- An installer that manages SDDM, PAM, and theme assets without in-place edits to existing configuration.
- A system analysis tool that reports password-derived facilities affected by biometric login.

**Theme compatibility:** the [nonvisual theme-context contract](docs/architecture/SDDM_THEME_CONTEXT_CONTRACT.md) preserves the existing login appearance through explicit theme cooperation, not a replacement form. The copied Qt5 `where-is-my-sddm-theme` now has a tested offline automatic-start prototype: scan the actual selection without Enter or revealing hidden labels, Escape cancels and F4 retries. Full lifecycle/independent review, Qt6 consumer, packaging and physical verification remain pending; nothing is installed. Unadapted themes retain password-only compatibility; arbitrary untouched-theme biometric support is not promised.

The SDDM daemon—not the greeter theme or fplogin adapter—coordinates login-time authentication. For one daemon-bound user/session request, it runs separate password and fingerprint helpers. The first successful method wins; the daemon cancels and observes the losing helper before authorizing exactly one PAM transaction to establish credentials, open the session, and start it. The fplogin adapter is an install-time component only.

## Planned v1 scope

| Will | Will not |
|---|---|
| Fingerprint login from SDDM | Store, inject, or recover the user's password |
| Activate the reader automatically when the greeter appears | Unlock wallets (KWallet, GNOME Keyring) via fingerprint |
| Keep password as a simultaneous fallback | Modify existing system PAM files in place |
| Cancel the unused method upon authentication | Replace subsequent authentications (sudo, polkit, su) |
| Install and configure SDDM if not present | Enroll fingerprints (uses those already registered in fprintd) |
| Detect and migrate from another display manager | Integrate with TPM or other cryptographic hardware |
| Uninstall cleanly restoring previous state | Work without fprintd or without an enrolled fingerprint |
| Analyze the system and report operational differences | Support distros outside Arch Linux (v1) |

## Architecture

```text
fplogin/
├── cmd/                         # Core, adapter, and platform executables
├── internal/
│   ├── core/                    # DM-independent selection/install/analyzer logic
│   ├── protocol/                # Versioned Go wire and manifest types
│   ├── adapterclient/           # Bounded adapter process client
│   └── platformclient/          # Bounded platform process client
├── contracts/                   # Versioned JSON schemas and examples
├── platforms/
│   └── arch/                    # Arch package/service provider
├── adapters/
│   └── sddm/
│       ├── patches/             # Pinned SDDM patch series
│       ├── assets/
│       │   ├── pam/             # Dedicated fingerprint PAM service
│       │   └── theme/           # SDDM greeter theme
│       └── packaging/
│           └── arch/            # Arch package recipe
├── tests/                       # Contract, integration, fixture, and VM checks
└── docs/                        # Architecture, plans, hardware, and sprint reviews
```

### Core-adapter contract

`internal/core/` must remain completely agnostic to any display manager. It defines interfaces, state machines, manifest generation, and analysis logic, but never imports, references, or branches on specific display managers:

- **Core defines interfaces:** DM detection and versioning, prerequisite validation, asset install/uninstall, DM state inspection, and authentication capability negotiation.
- **Adapters implement those interfaces:** the planned `adapters/sddm/` executable will implement the contract for SDDM v1. Future adapters (for example LightDM or greetd) implement the same interfaces without changing core logic.
- **Discovery over hardcoding:** The core resolves adapters through capability/support declarations, never through conditional logic like `if dm == "sddm"`.

### Planned installation paths

| Repository path | System destination |
|---|---|
| `adapters/sddm/assets/pam/sddm-fingerprint` | `/etc/pam.d/sddm-fingerprint` |
| `adapters/sddm/assets/theme/*` | `/usr/share/sddm/themes/fplogin/` |
| `adapters/sddm/assets/config/sddm.conf.d/fplogin.conf` | `/etc/sddm.conf.d/fplogin.conf` |

No existing system files will be modified in place. The installer will generate a manifest at `/var/lib/fplogin/manifest.json` containing installed assets, checksums, and previous system state for clean rollback during uninstallation.

## Planned v1 requirements

| Requirement | Required | Notes |
|---|---|---|
| Arch Linux | Yes | Only supported distro in v1 |
| systemd | Yes | DM service management |
| fprintd | Yes | Installer will add it when missing |
| libfprint | Yes | fprintd dependency |
| Compatible fingerprint reader | Yes | Verified during installation |
| Enrolled fingerprint | Yes | Required before login verification; enrollment is outside the greeter |
| SDDM | Yes | Patched package will be installed and configured through the selected adapter/platform provider |
| qt6-declarative | Yes | Required for SDDM QML themes |

## CLI Usage

> **Status (2026-11-12 audit, see [CLI and provider audit](docs/reviews/cli-provider-audit-2026-11-12.md)):** the `fplogin` CLI is **not ready for use**. `install` and `uninstall` cannot complete end to end: discovery fails before any change, and the SDDM adapter and Arch platform provider do not yet implement detection, planning, application or verification. These operations now refuse explicitly instead of reporting success. Do not run `sudo fplogin install` on a real system. `analyze` runs, but its "safe" conclusion is not yet backed by probes and must not be used to make an installation decision.

Intended interface (target of Sprints 3–5, not yet verified):

```bash
fplogin analyze [--json] [--user <username>]   # experimental; conclusions not yet trustworthy
fplogin install --dry-run                        # not functional yet
sudo fplogin install                             # not functional yet — do not run
fplogin status                                   # reports the absence/presence of a manifest
sudo fplogin uninstall                           # not functional yet
```

## Documentation

- [Implementation Plan](docs/IMPLEMENTATION_PLAN.md): Sprint roadmap, verification matrix, security model, and Definition of Done.
- [Emergency Recovery Guide](docs/EMERGENCY_RECOVERY.md): Step-by-step procedures for interrupted transactions, journal recovery, and PAM restore.
- [Supported Versions & Policy](docs/SUPPORTED_VERSIONS.md): Supported Linux distributions, desktop environments, PAM, and toolchain dependencies.
- [Core Language and Adapter Contract](docs/architecture/CORE_ADAPTER_ANALYSIS.md): Language evaluation, adapter protocol, repository foundation, and architectural risks.
- [SDDM Concurrent Authentication Design](docs/architecture/SDDM_AUTHENTICATION_DESIGN.md): Pinned baseline, stock message flow, winner gate, cancellation boundary, and proposed SDDM IPC.
- [SDDM Greeter and Theme Design](docs/architecture/SDDM_GREETER_DESIGN.md): Sprint 2 context correlation, typed reader states, controlling-view lifecycle and password fallback.
- [Sprint 2 Execution Plan](docs/SPRINT_2_EXECUTION_PLAN.md): Implementation slices, affected source paths and actual-surface acceptance matrix.
- [Synaptics Test Hardware](docs/hardware/SYNAPTICS_06CB_00BD.md): Primary physical-reader record and scenario matrix.
- [Research Lessons](docs/LESSONS.md): Grounded investigation, reference platforms, failed experiments, and security analysis.

## License

MIT

