# fplogin

**Native concurrent fingerprint and password login for Linux Display Managers.**

`fplogin` v1.0 brings zero-friction biometric login to SDDM on Arch Linux: the fingerprint reader activates automatically as soon as the greeter appears, runs in parallel with the password input (no Enter-first gate), keeps your existing Qt5 or Qt6 SDDM theme visually intact by default, never edits stock system PAM or `/etc/sddm.conf` in place, and never stores or synthesizes passwords.

---

## The Problem

Stock SDDM runs a single PAM conversation per login attempt. With manual `pam_fprintd` tweaks, users must either wait for biometric verification to time out before typing a password or press Enter before scanning their finger. There is no native experience where the sensor activates automatically alongside the password field while cleanly releasing the reader on login or cancellation.

## How It Works

1. **Daemon-coordinated concurrent PAM (`sddm-fplogin`):** The SDDM daemon—never the QML theme—runs the existing `sddm` password helper and a dedicated `sddm-fingerprint` PAM helper concurrently under a single request identity (`requestId`, `AuthMethod`, `generation`).
2. **Single-winner arbitration & sensor handoff:** Whichever method succeeds first wins. The daemon cancels and reaps the losing helper *before* authorizing the winning helper to open the session, ensuring screen lockers such as `hyprlock` can immediately claim the reader afterwards.
3. **Untouched user themes (Qt5 & Qt6) + optional status overlay:**
   - By default, `fplogin` preserves your existing SDDM theme 100% visually intact (`AutoFingerprintForLegacyThemes=true`, `FingerprintStatusOverlay=false`) across both Qt6 and Qt5 greeters.
   - Optionally enable a minimal, non-intrusive status pill over your existing theme (`sudo fplogin config set --overlay true`) with a configurable retry shortcut (`--retry-key F4|F8|Ctrl+R|none`), or opt into the bundled `/usr/share/sddm/themes/fplogin` theme.
   - Emergency embedded fallback (`qrc:/theme`) remains strictly password-only.
4. **Transactional CLI, recovery & system analyzer (`fplogin`):**
   - `fplogin install` uses a pre-mutation WAL transaction journal (`/var/lib/fplogin/`), SHA-256-bound interactive approval, atomic file drops, automatic LIFO rollback, and `fplogin recover` for mid-transaction interruptions.
   - `fplogin uninstall` restores your recorded baseline state cleanly while preserving user-modified files.
   - `fplogin analyze` performs a read-only audit of password-derived facilities (KWallet, GNOME Keyring, `systemd-homed`, `/etc/crypttab`, `fprintd` readiness) and clearly reports operational differences and scope limits.

---

## v1.0 Scope

| Supported in v1.0 | Intentionally Out of Scope (v1.0) |
|---|---|
| Concurrent fingerprint + password login in SDDM without pressing Enter | Storing, caching, injecting, or recovering user passwords |
| Automatic reader activation on greeter startup (Qt5 & Qt6 themes) | Unlocking KWallet or GNOME Keyring via fingerprint |
| Simultaneous password fallback surviving every biometric failure/timeout | Modifying stock `/etc/pam.d/sddm` or `/etc/sddm.conf` in place |
| Clean cancellation & reader release (verified with `hyprlock` handoff) | Replacing subsequent authentications (`sudo`, `su`, `polkit`, `ssh`) |
| Preserving existing SDDM themes intact, optional overlay & configurable retry key | Enrolling fingerprints inside the greeter (uses `fprintd` enrollments) |
| Fresh install (with or without existing SDDM), DM conflict guard & clean uninstall | TPM / FIDO2 / smart-card hardware integration |
| Read-only system difference analyzer (`fplogin analyze`) | Non-Arch Linux distributions or non-SDDM display managers |

---

## Requirements

- **OS:** Arch Linux (`x86_64`), `systemd`
- **Biometrics:** `fprintd` + `libfprint`, compatible fingerprint reader, at least one enrolled finger (`fprintd-enroll`)
- **Display Manager:** `sddm-fplogin` (replaces stock `sddm`, ships dual Qt6 + Qt5 greeters, `/etc/pam.d/sddm-fingerprint`, and optional `fplogin` theme)
- **Verified reference hardware:** Synaptics `06cb:00bd` (USB match-on-sensor), Hyprland (`uwsm`), `hyprlock`

---

## CLI Usage

```bash
# Read-only commands (unprivileged)
fplogin components                                              # list packaged providers and adapters
fplogin install --dry-run [--target ADAPTER_ID/TARGET_ID]       # read-only preflight and ChangePlan preview
fplogin analyze [--json] [--root DIR] [--service NAME]          # inspect password-derived facilities impacted by biometric login
fplogin config [show]                                           # inspect persistent SDDM fingerprint settings

# Root transactional & configuration commands
sudo fplogin install --artifacts-dir DIR [--activate] [--approve-plan SHA256] [--approve-replace-dm]
sudo fplogin status                                             # verify manifest integrity and file checksums
sudo fplogin config set [--auto-legacy true|false] [--overlay true|false] [--retry-key KEY|none] [--timeout 5..120] [--theme preserve|fplogin|<name>]
sudo fplogin uninstall [--modified-files preserve|refuse|restore] [--remove-shared-deps] [--yes]
sudo fplogin recover                                            # reconcile any interrupted transaction
```

### Persistent Post-Install Configuration

All runtime settings live in `/etc/sddm.conf.d/90-fplogin.conf` and survive reboots and `sddm-fplogin` upgrades:

```bash
# Keep your current theme visually untouched (default)
sudo fplogin config set --theme preserve --overlay false

# Enable subtle status pill (scanning / retry / timeout) + custom retry shortcut over your current theme
sudo fplogin config set --overlay true --retry-key F8

# Disable the retry shortcut entirely or adjust the scan deadline (5..120 s)
sudo fplogin config set --retry-key none --timeout 45
```

> **Note on SDDM precedence:** `/etc/sddm.conf` overrides `/etc/sddm.conf.d/*.conf`. Because `fplogin` keeps `[Theme]` untouched by default, your configured theme stays active automatically; if you explicitly switch `--theme fplogin`, `fplogin config` warns when `/etc/sddm.conf` sets a different `Current=` theme.

---

## System Paths Managed

| Component | System Path | Ownership / Notes |
|---|---|---|
| CLI & out-of-process workers | `/usr/bin/fplogin`, `/usr/lib/fplogin/` | Installed by `fplogin-git` |
| Dedicated biometric PAM service | `/etc/pam.d/sddm-fingerprint` | Installed by `sddm-fplogin`; stock `/etc/pam.d/sddm` untouched |
| Optional bundled greeter theme | `/usr/share/sddm/themes/fplogin/` | Installed by `sddm-fplogin` |
| Persistent drop-in config | `/etc/sddm.conf.d/90-fplogin.conf` | Managed by `fplogin install` and `fplogin config` |
| Transaction journal & manifest | `/var/lib/fplogin/` (`0700`) | WAL journals, verified backups, checksummed `manifest.json` |
| Offline package trust root | `/etc/fplogin/trust/` | Root-owned keyring & `pacman.conf` for verified offline installs |

---

## Repository Architecture

```text
fplogin/
├── cmd/                         # Core CLI (fplogin), Arch platform worker, SDDM adapter worker
├── internal/
│   ├── core/                    # DM-agnostic discovery, selection, WAL transactions, install, uninstall, analyzer
│   ├── protocol/                # Versioned Go wire and manifest types
│   ├── adapterclient/           # Bounded out-of-process adapter client
│   ├── platformclient/          # Bounded out-of-process platform client
│   ├── descriptortrust/         # Root-owned descriptor and path trust validation
│   └── processrunner/           # Timeout- and output-bounded subprocess execution
├── contracts/                   # Versioned JSON Schemas (adapter, platform, manifest, analyzer) and examples
├── platforms/
│   └── arch/                    # Arch platform descriptor, fplogin PKGBUILD, sddm-fplogin dual Qt6/Qt5 recipe & patches 0000..0006
├── adapters/
│   └── sddm/                    # SDDM adapter descriptor, accepted patches 0001..0002, theme assets, local upstream PR draft
├── scripts/                     # Local reproducible release builder (build_release.sh) & package verification
├── tests/                       # Contract, AST boundary, security, analyzer, and Arch KVM E2E suites
└── docs/                        # Architecture, security threat model, recovery, upstream tracking, and v1.0 validation review
```

`internal/core/` never imports, references, or branches on any display manager or Linux distribution (enforced by AST boundary tests in `tests/contract/architecture_test.go`).

---

## Building & Testing

```bash
# Build binaries and run full Go test suite (with race detector)
make build
go test -race -count=1 ./...
go vet -tags f05lab ./...

# Build offline Arch tools package (fplogin-git)
make package

# Build reproducible local release artifacts + SHA256SUMS (optional --gpg-key <id>)
scripts/build_release.sh --sddm-pkg <path-to-sddm-fplogin.pkg.tar.zst>
```

---

## Documentation

- [Sprint 7 & v1.0.0 Validation Review](docs/reviews/sprint-7.md): End-to-end KVM lifecycle, dual Qt6/Qt5 builds, real Synaptics hardware matrix, `hyprlock` handoff, and v1.0.0 acceptance record.
- [Emergency Recovery Guide](docs/EMERGENCY_RECOVERY.md): TTY recovery, `fplogin recover`, clean uninstall, and offline rollback to stock SDDM.
- [Supported Versions & Policy](docs/SUPPORTED_VERSIONS.md): Supported Arch Linux, systemd, SDDM, Qt6/Qt5, PAM, and libfprint versions.
- [Upstream SDDM Tracking](docs/UPSTREAM_TRACKING.md): Patch rebase policy, conflict handling, and upstream PR workflow.
- [Threat Model & Security Boundaries](docs/security/THREAT_MODEL.md): Five-boundary threat model mapped to security invariants.
- [Implementation Plan](docs/IMPLEMENTATION_PLAN.md): Full v1.0 architecture specification, verification matrix, and Definition of Done.
- [Core-Adapter Architecture](docs/architecture/CORE_ADAPTER_ANALYSIS.md) & [ADRs](docs/architecture/decisions/): Language selection, out-of-process adapter IPC, and WAL transaction journaling.
- [SDDM Authentication & Greeter Design](docs/architecture/SDDM_AUTHENTICATION_DESIGN.md), [Greeter Design](docs/architecture/SDDM_GREETER_DESIGN.md), and [Theme Context Contract](docs/architecture/SDDM_THEME_CONTEXT_CONTRACT.md).
- [Reference Hardware Record (Synaptics 06cb:00bd)](docs/hardware/SYNAPTICS_06CB_00BD.md).

---

## License

- **`fplogin` CLI, core engine, platform/adapter workers, and contracts:** [MIT License](LICENSE).
- **SDDM patch series (`adapters/sddm/patches/`, `platforms/arch/sddm-fplogin/*.patch`) and `sddm-fplogin` package:** `GPL-2.0-or-later` (derived from upstream SDDM; bundled theme assets include `CC-BY-3.0` where noted).
