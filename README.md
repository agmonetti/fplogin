# fplogin

Biometric login for Linux, under active development. The v1 target is fingerprint login from SDDM with no Enter key, no in-place edits to existing system configuration, and no password storage.

## The problem

SDDM does not natively support fingerprint authentication. Users must type their password or, with manual PAM tweaks, press Enter and then place their finger. There is no built-in experience where the reader activates automatically and works in parallel with the password field.

## Planned approach

The Foundation Gate, Sprint 0 and Sprint 1 are complete. Sprint 1 is accepted and closed by the [2026-10-04 independent review](docs/reviews/sprint-1.md#2026-10-04-sol-independent-acceptance-review--sprint-1-gate), including the final physical-reader matrix R01–R16. Sprint 2 is integrated, with isolated build/tests and USB-free guest surface verification; physical acceptance G01–G16 remains pending fresh owner authorization and reader handoff. Source, assets and integrity metadata are [preserved in persistent storage](docs/PERSISTENCE.md). Continue the [execution plan](docs/SPRINT_2_EXECUTION_PLAN.md); Sprint 3 remains blocked until Sprint 2 acceptance.

The [2026-10-20 activation correction](docs/reviews/sprint-2.md#6-2026-10-20-bounded-fprintd-activation-correction) fixes initial availability and explicit Retry when installed fprintd is inactive, without a keepalive or restart loop. The exported series passes the isolated build, ten suites and scoped real-service/QML smoke. The preserved guest is not updated; physical G04 and Sprint 2 acceptance remain pending.

The planned product has:

- A minimal, upstream-quality SDDM patch coordinating concurrent PAM authentication methods.
- A dedicated PAM service for biometric authentication (`sddm-fingerprint`).
- An SDDM theme that displays daemon-reported biometric status and requests method start/cancellation.
- An installer that manages SDDM, PAM, and theme assets without in-place edits to existing configuration.
- A system analysis tool that reports password-derived facilities affected by biometric login.

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

## Documentation

- [Agent Instructions](AGENTS.md) and [Persistent Work and Recovery](docs/PERSISTENCE.md): Mandatory storage paths, portable checkpoints, source bundles and verified restoration; `/tmp` is not a durable workspace.
- [Implementation Plan](docs/IMPLEMENTATION_PLAN.md): Sprint roadmap, verification matrix, security model, and Definition of Done.
- [Core Language and Adapter Contract](docs/architecture/CORE_ADAPTER_ANALYSIS.md): Language evaluation, adapter protocol, repository foundation, and architectural risks.
- [SDDM Concurrent Authentication Design](docs/architecture/SDDM_AUTHENTICATION_DESIGN.md): Pinned baseline, stock message flow, winner gate, cancellation boundary, and proposed SDDM IPC.
- [SDDM Greeter and Theme Design](docs/architecture/SDDM_GREETER_DESIGN.md): Sprint 2 context correlation, typed reader states, controlling-view lifecycle and password fallback.
- [Sprint 2 Execution Plan](docs/SPRINT_2_EXECUTION_PLAN.md): Implementation slices, affected source paths and actual-surface acceptance matrix.
- [Synaptics Test Hardware](docs/hardware/SYNAPTICS_06CB_00BD.md): Primary physical-reader record and scenario matrix.
- [Research Lessons](docs/LESSONS.md): Grounded investigation, reference platforms, failed experiments, and security analysis.

## License

MIT
