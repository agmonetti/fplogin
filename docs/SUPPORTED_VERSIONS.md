# Supported Versions & Platform Policy

This document defines the supported distributions, hardware, display managers, authentication subsystems, and build requirements for `fplogin` v1.0.

---

## 1. Operating Systems & Distributions

| Distribution | Version | Support Level | Notes |
|---|---|---|---|
| **Arch Linux** | Rolling (`x86_64`, `glibc` 2.38+) | **Tier 1 (Official / Primary)** | Primary v1.0 target. Packaged via `platforms/arch/PKGBUILD` (`fplogin`) and `platforms/arch/sddm-fplogin/` (`sddm-fplogin`). |
| Fedora | 39 / 40+ | Deferred (Post-v1) | Requires RPM/dnf platform provider adapter. |
| Debian / Ubuntu | 24.04 LTS+ | Deferred (Post-v1) | Requires apt/dpkg platform provider adapter. |

---

## 2. Display Managers & Desktop Environment

| Component | Supported Versions | Adapter / Integration | Status |
|---|---|---|---|
| **SDDM** | `0.21.0` (pinned upstream commit `63780fcd79f1dbf81a30eef48c28c699ab15aded` + `sddm-fplogin` patch series `0000..0005`) | `adapters/sddm`, `cmd/fplogin-adapter-sddm` | **Supported (v1.0)** — upstream PR series prepared (`adapters/sddm/upstream-pr/PR_DESCRIPTION.md`). |
| **Hyprland / hyprlock** | Current Arch Linux rolling | Reference desktop session & lock-screen handoff | **Supported (v1.0)** — SDDM releases the sensor before/after session handoff so `hyprlock` can claim it. |
| GDM / LightDM / greetd | N/A | Deferred (Post-v1) | Conflicting enabled/active DMs (e.g., `greetd.service`) are detected and never replaced without explicit `--approve-replace-dm`. |

See [docs/UPSTREAM_TRACKING.md](UPSTREAM_TRACKING.md) for how `fplogin` tracks new upstream SDDM releases and rebases patches.

---

## 3. Reference Biometric Hardware

| Reader | USB ID | Driver (`libfprint`) | Status |
|---|---|---|---|
| **Synaptics Match-on-Sensor** | `06cb:00bd` | `synaptics` | **Reference v1.0 hardware** |

Other `libfprint`-supported readers that work cleanly with `fprintd` should operate through the same PAM (`sddm-fingerprint`) and D-Bus (`net.reactivated.Fprint`) boundaries, but are not yet individually hardware-certified in v1.0.

---

## 4. Biometric & Authentication Subsystems

| Component | Minimum Version | Verified Baseline | Requirement |
|---|---|---|---|
| **fprintd** | 1.94.0 | 1.94.5 | Required for fingerprint verification and D-Bus availability probing. |
| **libfprint** | 1.94.5 | 1.94.7+ | Driver backend for supported biometric sensors. |
| **Linux PAM** | 1.5.0 | 1.6.0+ | Dedicated `/etc/pam.d/sddm-fingerprint`; global PAM stacks are never edited. |
| **systemd** | 254 | 262 (Arch) | Service management, `systemd-sysusers`, and `PrepareForSleep` suspend notifications. |

---

## 5. Build & Runtime Requirements

| Tool / Library | Version | Purpose |
|---|---|---|
| **Go** | 1.22+ | Core installer, transactional rollback, analyzer, platform provider, and SDDM adapter (`GOTOOLCHAIN=local`). |
| **CMake** | 3.20+ (4.x supported via `0000`) | `sddm-fplogin` build & CTest verification. |
| **Qt 6** | `qt6-base`, `qt6-declarative`, `qt6-tools` (6.5+; verified on 6.12) | Primary SDDM daemon, helper, greeter, and `fplogin` QML theme. |
| **Qt 5** | `qt5-base`, `qt5-declarative`, `qt5-quickcontrols2`, `qt5-svg`, `qt5-tools` (5.15) | Co-installed Qt5 greeter compatibility for third-party Qt5 themes (`merge-qt5.py`). |
| **GCC / Clang** | C++17 compatible | `sddm-fplogin` compilation and ASan/UBSan security suites. |

---

## 6. Protocol & Upgrade Stability Guarantees

1. **Protocol Versioning:** Internal JSON schemas (`contracts/` and `internal/protocol/`) use `major.minor` versioning. Adapters or providers with mismatched major protocol versions are rejected at discovery.
2. **Manifest Backwards Compatibility:** The `v1` install manifest (`/var/lib/fplogin/manifest.json`) guarantees `fplogin status`, `fplogin recover`, and `fplogin uninstall` across minor upgrades.
3. **No In-Place Vendor Edits:** `fplogin` never modifies `/etc/pam.d/system-auth`, `/etc/pam.d/system-login`, `/etc/pam.d/sddm`, or `/etc/sddm.conf` in place. All changes are isolated to manifest-tracked files (`/etc/sddm.conf.d/90-fplogin.conf`, `/etc/pam.d/sddm-fingerprint`, `/usr/share/sddm/themes/fplogin/`) and transactional package operations.
