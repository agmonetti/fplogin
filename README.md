# fplogin

Biometric login for Linux, under active development. The v1 target is fingerprint login from SDDM with no Enter key, no in-place edits to existing system configuration, and no password storage.

[![fplogin Project Telemetry & Milestone Matrix](docs/assets/dashboard.png)](dashboard.html)

The dashboard reflects the accepted closure of [Sprint 6 (security and resilience hardening)](docs/reviews/sprint-6.md) on 2026-11-24 (`fplogin-git 0.2.0.r12.0447a0a-1`, [Threat Model](docs/security/THREAT_MODEL.md), additive SDDM patch `0005-security-hardening.patch`, 250-frame IPC fuzzing, 500-cycle helper endurance with `fd_delta=0`, `fprintd`/`PrepareForSleep` fault injection, 69/69 ASan+UBSan, and Go `O_NOFOLLOW`/TOCTOU hardening). Prior accepted gates: [Sprint 5 (system difference analyzer)](docs/reviews/sprint-5.md) (closed 2026-11-24), [Sprint 4 (transactional installer and uninstaller)](docs/reviews/sprint-4.md) (closed 2026-11-24), [Sprint 3 physical closeout](docs/reviews/sprint-3-physical-closure.md) (closed 2026-11-18), [Sprint 2 acceptance](docs/reviews/sprint-2-acceptance-2026-11-12.md) (closed 2026-11-12), and [Sprint 1 review](docs/reviews/sprint-1.md) (closed 2026-10-04). Next milestone: Sprint 7 — End-to-end validation, release v1.0, and upstream SDDM PR ([Implementation Plan](docs/IMPLEMENTATION_PLAN.md)).

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

The pinned Arch tools package (`fplogin-git 0.2.0.r12.0447a0a-1`) exposes both read-only unprivileged inspection (`components`, `install --dry-run`, `status`, `analyze`) and transactional offline installation/removal/recovery verified on Arch x86_64 with real systemd PID 1. Live `install`, `uninstall`, and `recover` require root privileges, a root-owned offline trust root (`/etc/fplogin/trust`), and explicit approval bound to the core-computed `ChangePlan` SHA-256 (plus separate `--approve-replace-dm` confirmation before replacing a conflicting display manager), followed by non-fatal Phase 13 read-only postflight analysis. See the [Sprint 4 execution plan](docs/SPRINT_4_EXECUTION_PLAN.md), [Sprint 5 review](docs/reviews/sprint-5.md), and [Sprint 6 security review](docs/reviews/sprint-6.md).

```bash
# Unprivileged read-only commands
fplogin components                                              # list packaged providers and adapters
fplogin install --dry-run [--target ADAPTER_ID/TARGET_ID]       # read-only preflight and preview
fplogin status                                                  # read manifest and verify file checksums
fplogin analyze [--json] [--root DIR] [--service NAME]          # read-only password-derived facility analyzer

# Root transactional commands (offline signed archives + /etc/fplogin/trust)
sudo fplogin install --artifacts-dir DIR [--activate] [--approve-plan SHA256] [--approve-replace-dm]
sudo fplogin uninstall [--modified-files preserve|refuse|restore] [--remove-shared-deps] [--yes]
sudo fplogin recover                                            # reconcile any interrupted transaction
```

To build the Arch tools package, run `make package` as an ordinary user in an isolated Arch environment with `base-devel`, Go, Git, and the recipe's runtime dependencies installed. It stages a pinned source archive and prints the package paths. Verify the main archive with `bash tests/integration/arch-tools-package.sh <package>` and the real-systemd KVM guest lifecycle with `bash tests/integration/s4-cli-e2e-run.sh <package>`. The SDDM theme and PAM service are shipped separately in `sddm-fplogin`.

## Documentation

- [Implementation Plan](docs/IMPLEMENTATION_PLAN.md): Sprint roadmap, verification matrix, security model, and Definition of Done.
- [Emergency Recovery Guide](docs/EMERGENCY_RECOVERY.md): Step-by-step procedures for interrupted transactions, journal recovery, and PAM restore.
- [Supported Versions & Policy](docs/SUPPORTED_VERSIONS.md): Supported Linux distributions, desktop environments, PAM, and toolchain dependencies.
- [Core Language and Adapter Contract](docs/architecture/CORE_ADAPTER_ANALYSIS.md): Language evaluation, adapter protocol, repository foundation, and architectural risks.
- [SDDM Concurrent Authentication Design](docs/architecture/SDDM_AUTHENTICATION_DESIGN.md): Pinned baseline, stock message flow, winner gate, cancellation boundary, and proposed SDDM IPC.
- [SDDM Greeter and Theme Design](docs/architecture/SDDM_GREETER_DESIGN.md): Sprint 2 context correlation, typed reader states, controlling-view lifecycle and password fallback.
- [Sprint 2 Execution Plan](docs/SPRINT_2_EXECUTION_PLAN.md): Implementation slices, affected source paths and actual-surface acceptance matrix.
- [Sprint 4 Acceptance Review](docs/reviews/sprint-4.md): Transactional installer/uninstaller closure, packaged KVM E2E evidence, and known limits.
- [Sprint 5 Acceptance Review](docs/reviews/sprint-5.md): Read-only system difference analyzer, Arch `CollectAnalyzerFacts`, Audit A8 closure, and Phase 13 postflight.
- [Sprint 5 Execution Plan](docs/SPRINT_5_EXECUTION_PLAN.md): System difference analyzer corrections, probes, wording accuracy, and postflight integration.
- [Threat Model & Security Boundaries](docs/security/THREAT_MODEL.md): Consolidated five-boundary threat model mapped to §3.2 security invariants.
- [Sprint 6 Security Review](docs/reviews/sprint-6.md): Security & resilience hardening acceptance, 10 remediated findings (`F-S6-01`..`F-S6-10`), IPC fuzzing, 500-cycle endurance, ASan+UBSan, and `0005-security-hardening.patch`.
- [Sprint 6 Execution Plan](docs/SPRINT_6_EXECUTION_PLAN.md): Security hardening slices (`S6-F01`..`S6-F07`) and acceptance criteria.
- [Synaptics Test Hardware](docs/hardware/SYNAPTICS_06CB_00BD.md): Primary physical-reader record and scenario matrix.
- [Research Lessons](docs/LESSONS.md): Grounded investigation, reference platforms, failed experiments, and security analysis.

## License

MIT

