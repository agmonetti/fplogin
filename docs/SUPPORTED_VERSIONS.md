# Supported Versions & Platform Policy

This document defines the supported distributions, software components, display managers, and tooling versions for `fplogin`.

---

## 1. Operating Systems & Distributions

| Distribution | Version | Support Level | Notes |
|---|---|---|---|
| **Arch Linux** | Rolling (glibc 2.38+) | **Tier 1 (Official / Primary)** | Current target for v1. Arch package and systemd integration provided in `platforms/arch`. |
| Fedora | 39 / 40 | Planned (Tier 2) | Deferred to post-v1 (requires RPM/dnf provider adapter). |
| Debian / Ubuntu | 24.04 LTS | Planned (Tier 2) | Deferred to post-v1 (requires apt/dpkg provider adapter). |

---

## 2. Display Managers

| Display Manager | Supported Versions | Adapter Package | Status |
|---|---|---|---|
| **SDDM** | 0.20.0, 0.21.0 | `adapters/sddm` | In-progress (Core ready, patch series pending acceptance). |
| GDM | N/A | None | Out of scope for v1. |
| LightDM | N/A | None | Future adapter planned. |
| greetd | N/A | None | Future adapter planned. |

---

## 3. Biometric & Authentication Subsystems

| Component | Minimum Version | Recommended Version | Requirement |
|---|---|---|---|
| **fprintd** | 1.94.0 | 1.94.3+ | Mandatory for biometric reader control. |
| **libfprint** | 1.94.5 | 1.94.7+ | Driver backend for supported biometric sensors. |
| **Linux PAM** | 1.5.0 | 1.6.0+ | Pluggable Authentication Modules. |
| **systemd** | 254 | 255+ | Service and session management. |

---

## 4. Development & Build Requirements

| Tool | Version | Purpose |
|---|---|---|
| **Go** | 1.22+ | Core installer, analyzer, and CLI entrypoint. |
| **CMake** | 3.20+ | SDDM patch compilation. |
| **Qt / QML** | Qt 6.5+ (`qt6-declarative`) | SDDM theme components. |
| **GCC / Clang** | C++17 compatible | SDDM concurrent authentication patch. |

---

## 5. Security & Deprecation Lifecycle

1. **Protocol Stability**: Internal protocol schemas (`contracts/` and `internal/protocol`) follow strict semantic versioning (`major.minor`). Adapters with mismatched major protocol versions are rejected at discovery.
2. **Backwards Compatibility**: The manifest schema (`v1`) guarantees uninstallation and rollback support across future minor version updates of `fplogin`.
3. **No In-Place Modification Guarantee**: Upgrades never modify host PAM or vendor configuration files in-place; all changes remain isolated to versioned drop-ins and manifest-tracked files.
