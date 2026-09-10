# fplogin

Biometric login for Linux. Use your fingerprint to log in from SDDM — no Enter key, no system file modifications, no password storage.

## The problem

SDDM does not natively support fingerprint authentication. Users must type their password or, with manual PAM tweaks, press Enter and then place their finger. There is no built-in experience where the reader activates automatically and works in parallel with the password field.

## Approach

fplogin provides a reproducible package, installer, and analyzer for biometric authentication on SDDM. It adds:

- A minimal, upstream-quality patch to SDDM enabling concurrent PAM authentication methods.
- A dedicated PAM service for biometric authentication (`sddm-fingerprint`).
- An SDDM theme that displays biometric status and coordinates with the greeter.
- An installer that manages SDDM, PAM, and theme assets without in-place edits to existing configuration.
- A system analysis tool that informs the user about password-derived facilities affected by biometric login.

The greeter coordinates authentication: when displayed, it requests fingerprint verification for the selected user. If the fingerprint matches, that transaction wins and the session starts. If the user types a password, the password transaction is evaluated concurrently. The first method to succeed wins; the losing attempt is cancelled and cleaned up.

## What it does vs what it doesn't

| Does | Does not |
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

```
fplogin/
├── docs/                        # Architecture, plan, and sprint reviews
│   ├── IMPLEMENTATION_PLAN.md
│   └── LESSONS.md
├── contracts/                   # Versioned adapter/platform/manifest schemas
├── core/                        # Universal components (DM-independent)
│   ├── analyze/                 # System difference analyzer
│   ├── install/                 # Installer logic and state machine
│   └── manifest/                # Install manifest and rollback records
├── platforms/                   # Distribution and service-manager integration
│   └── arch/                    # Arch package/system provider for v1
├── adapters/                    # Display manager-specific integration
│   └── sddm/
│       ├── patches/             # Upstream-quality SDDM patch series
│       ├── pam/
│       │   └── sddm-fingerprint # Dedicated PAM service
│       ├── theme/               # SDDM greeter theme
│       └── packaging/           # Arch PKGBUILD and packaging assets
├── install.sh
├── uninstall.sh
├── .gitignore
└── README.md
```

### Core-adapter contract

`core/` is completely agnostic to any display manager from the first commit. It defines the interfaces, state machines, manifest generation, and analysis logic, but never imports, references, or branches on specific display managers:

- **Core defines interfaces:** DM detection and versioning, prerequisite validation, asset install/uninstall, DM state inspection, and authentication capability negotiation.
- **Adapters implement those interfaces:** `adapters/sddm/` implements the contract for SDDM in v1. Future adapters (e.g. LightDM, greetd) will implement the same interfaces without changing core logic.
- **Discovery over hardcoding:** The core resolves adapters through capability/support declarations, never through conditional logic like `if dm == "sddm"`.

### Installation paths

| Repository path | System destination |
|---|---|
| `adapters/sddm/pam/sddm-fingerprint` | `/etc/pam.d/sddm-fingerprint` |
| `adapters/sddm/theme/*` | `/usr/share/sddm/themes/fplogin/` |
| `adapters/sddm/config/sddm.conf.d/fplogin.conf` | `/etc/sddm.conf.d/fplogin.conf` |

No existing system files are modified in place. The installer generates a manifest at `/var/lib/fplogin/manifest.json` containing everything installed, file checksums, and previous system state for clean rollback during uninstallation.

## Requirements

| Requirement | Required | Notes |
|---|---|---|
| Arch Linux | Yes | Only supported distro in v1 |
| systemd | Yes | DM service management |
| fprintd | Yes | Installed automatically if missing |
| libfprint | Yes | fprintd dependency |
| Compatible fingerprint reader | Yes | Verified during installation |
| Enrolled fingerprint | Yes | Guided during installation if missing |
| SDDM | Yes | Installed and configured via fplogin packaging |
| qt6-declarative | Yes | Required for SDDM QML themes |

## Documentation

- [Implementation Plan](docs/IMPLEMENTATION_PLAN.md): Detailed sprint roadmap, verification matrix, security model, and Definition of Done.
- [Core Language and Adapter Contract](docs/architecture/CORE_ADAPTER_ANALYSIS.md): Language evaluation, exact adapter protocol, repository foundation, and early architectural risks.
- [Research Lessons](docs/LESSONS.md): Grounded investigation, reference platforms (Windows Hello, Touch ID), failed experiments, and security analysis.

## License

MIT
