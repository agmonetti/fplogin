# fplogin

**Concurrent fingerprint and password login for SDDM on Linux.**

The fingerprint reader activates as soon as SDDM appears and runs in parallel with the password field—no Enter-first gate, no waiting for timeouts. Your existing Qt5 or Qt6 theme stays untouched by default, and SDDM cancels and reaps the losing PAM helper before opening the session so lockers like `hyprlock` can claim the sensor afterwards.

**[Website & Field Notes](https://agmonetti.github.io/fplogin-page/)** · **[GitHub Releases](https://github.com/agmonetti/fplogin/releases)** · **[Technical Docs](https://agmonetti.github.io/fplogin-page/docs.html)**

---

## Install

Requires `systemd`, `fprintd` + `libfprint`, a supported fingerprint reader, and at least one enrolled finger (`fprintd-enroll`).

### Arch Linux (`x86_64`)

Download `fplogin-git-*.pkg.tar.zst`, `sddm-fplogin-*.pkg.tar.zst`, and `SHA256SUMS` from [GitHub Releases](https://github.com/agmonetti/fplogin/releases) into a clean directory:

```bash
sha256sum --ignore-missing -c SHA256SUMS
sudo pacman -U ./fplogin-git-*.pkg.tar.zst ./sddm-fplogin-*.pkg.tar.zst
fplogin analyze
sudo fplogin install
```

> **Note for `v1.0.1` prebuilt packages:** `sudo fplogin install` without `--artifacts-dir` on Arch requires a build from `main` (or the next release). On `v1.0.1` release packages, write the drop-in and enable SDDM directly after `pacman -U`:
> `sudo fplogin config set --auto-legacy true && sudo systemctl enable sddm.service`

### Other `systemd` Linux (`x86_64` / `aarch64`)

The portable bundle installs the CLI, generic `systemd` provider, and SDDM adapter—it does **not** patch stock SDDM. Install a fingerprint-capable SDDM build first (patches: `adapters/sddm/patches/` + `platforms/arch/sddm-fplogin/`), then download `fplogin-linux-<arch>.tar.gz` and `SHA256SUMS` from [GitHub Releases](https://github.com/agmonetti/fplogin/releases):

```bash
sha256sum --ignore-missing -c SHA256SUMS
mkdir -p fplogin-linux && tar -xzf "fplogin-linux-$(uname -m).tar.gz" -C fplogin-linux
sudo ./fplogin-linux/scripts/install_linux.sh
fplogin install --dry-run
sudo fplogin install
```

---

## What to expect

- **Your theme stays yours.** Legacy Qt5 and Qt6 themes auto-start one bounded scan with zero QML edits (`AutoFingerprintForLegacyThemes=true`). Want a subtle status pill and retry shortcut? Run `sudo fplogin config set --overlay true --retry-key F8`.
- **Password always works.** Type your password at any point without waiting for a scan or timeout. TTY login, `sudo`, `polkit`, and SDDM's emergency fallback remain password-only.
- **Login is not wallet unlock.** `fplogin` never stores, caches, or synthesizes passwords—GNOME Keyring and KWallet may still ask for your password after a fingerprint login. Run `fplogin analyze` to inspect what's affected on your system.
- **Reversible by design.** Stock `/etc/pam.d/sddm` and `/etc/sddm.conf` are never edited in place. Configuration lives in `/etc/sddm.conf.d/90-fplogin.conf` and `/etc/pam.d/sddm-fingerprint`, with WAL-journaled rollback and `sudo fplogin uninstall`.

---

## Everyday commands

```bash
fplogin analyze                                                    # audit keyrings, wallets, crypttab & fprintd (read-only)
fplogin config show                                                # inspect persistent SDDM fingerprint settings
sudo fplogin config set --overlay true --retry-key F8 --timeout 30 # toggle status pill, retry key, timeout (5..120 s) or theme
sudo fplogin status                                                # verify manifest & installed file checksums
fplogin update --check                                             # check latest GitHub Release against SHA256SUMS
sudo fplogin update                                                # download, verify SHA-256, and apply updates
sudo fplogin uninstall                                             # restore recorded pre-fplogin state (or `recover` if interrupted)
```

---

## Documentation & License

- [Emergency Recovery Guide](docs/EMERGENCY_RECOVERY.md) — TTY fallback, `fplogin recover`, clean uninstall, and rollback to stock SDDM
- [Supported Versions & Hardware](docs/SUPPORTED_VERSIONS.md) — distros, SDDM/Qt versions, and reference Synaptics `06cb:00bd` notes
- [Threat Model](docs/security/THREAT_MODEL.md) · [Validation Review (v1.0.0)](docs/reviews/sprint-7.md) · [Upstream SDDM Proposal](adapters/sddm/upstream-pr/PR_DESCRIPTION.md)

`fplogin` CLI, core, workers, and contracts are **MIT** ([LICENSE](LICENSE)). The SDDM patch series and `sddm-fplogin` package are **GPL-2.0-or-later** (bundled theme assets include `CC-BY-3.0` where noted).
