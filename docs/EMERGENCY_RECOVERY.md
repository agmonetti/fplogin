# Emergency Recovery & Troubleshooting Guide

This guide explains how to diagnose and recover a host system if an `fplogin` installation, repair, or uninstallation transaction is interrupted, or if the graphical login screen fails to start.

---

## 1. Transactional Safety Guarantees

`fplogin` enforces the following invariants (verified in real-systemd Arch KVM guests, including mid-transaction `SIGKILL` interruption tests):

1. **Never edits stock PAM or `/etc/sddm.conf` in place:** All `fplogin` configuration lives in isolated drop-ins (`/etc/sddm.conf.d/90-fplogin.conf`), a dedicated PAM service (`/etc/pam.d/sddm-fingerprint`), and theme assets (`/usr/share/sddm/themes/fplogin/`).
2. **Pre-mutation WAL journal:** Every mutation intent is written and `fsync`'d under `/var/lib/fplogin/transactions/tx-*.json` (protected by `/var/lib/fplogin/transaction.lock`) *before* any file, package, or service change occurs.
3. **Automatic rollback & recovery:** If an operation fails during `fplogin install` or `fplogin uninstall`, the core executes LIFO compensation. If the process is killed mid-transaction (`SIGKILL` / power loss), the journal remains in `applying` state and blocks new transactions until `sudo fplogin recover` reconciles it.
4. **Password fallback independence:** Console TTY login (`/bin/login`), `sudo`, `su`, `polkit`, and SSH never use `/etc/pam.d/sddm-fingerprint`. Password login on TTY (`Ctrl+Alt+F3`) remains available even if SDDM or `fprintd` is completely broken.

---

## 2. Automated Recovery via CLI (Recommended First Step)

Switch to a virtual console (`Ctrl+Alt+F3`) and log in with your username and **password**.

### 2.1 Reconcile an interrupted transaction (`fplogin recover`)

If `fplogin install` or `fplogin uninstall` was killed mid-run (or reports `transaction needs recovery`):

```bash
sudo fplogin recover
sudo fplogin status
```

`fplogin recover` replays pending compensations from `/var/lib/fplogin/transactions/`, restores backed-up files and packages, and leaves the system in a clean baseline state.

### 2.2 Clean transactional uninstall (`fplogin uninstall`)

To revert a completed installation back to the exact pre-install display manager state recorded in `/var/lib/fplogin/manifest.json`:

```bash
sudo fplogin uninstall --yes
# Optional: also remove shared Qt5 runtime deps installed solely for sddm-fplogin:
# sudo fplogin uninstall --yes --remove-shared-deps
```

If you manually edited a manifest-owned file after installation, `fplogin uninstall` preserves your edit by default (`--modified-files preserve`); pass `--modified-files refuse` to abort on local edits or `--modified-files restore` to overwrite them back to the recorded baseline after inspecting `fplogin status`.

---

## 3. Package-Level Rollback to Stock SDDM (If CLI Is Unavailable)

If `fplogin` itself cannot run or the greeter fails to display:

1. Switch to a text console (`Ctrl+Alt+F3`) and log in with your **password**.
2. Stop SDDM:
   ```bash
   sudo systemctl stop sddm.service
   ```
3. Reinstall stock `sddm` (its package conflict automatically removes `sddm-fplogin`, `/etc/pam.d/sddm-fingerprint`, and `/usr/share/sddm/themes/fplogin`):
   - **Online:**
     ```bash
     sudo pacman -S sddm
     ```
   - **Offline** (using a verified cached stock archive and its `.sig`):
     ```bash
     pkg=/var/cache/pacman/pkg/sddm-0.21.0-7-x86_64.pkg.tar.zst
     test -f "$pkg" && test -f "$pkg.sig" &&
       sudo pacman-key --verify "$pkg.sig" "$pkg" &&
       sudo pacman -U "$pkg"
     ```
4. Remove the `fplogin` theme drop-in (optional — stock SDDM falls back to its embedded theme if left in place):
   ```bash
   sudo rm -f /etc/sddm.conf.d/90-fplogin.conf
   ```
5. Verify and restart SDDM:
   ```bash
   pacman -Q sddm
   sudo systemctl start sddm.service
   ```

---

## 4. Manual Diagnostics & Troubleshooting

### Inspect journal, manifest, and backups

```bash
sudo ls -la /var/lib/fplogin/ /var/lib/fplogin/transactions/ /var/lib/fplogin/backups/
sudo fplogin status
```

### Common symptoms & checks

| Symptom | Diagnostic Command | Expected Fix / Cause |
|---|---|---|
| Fingerprint UI says `Unavailable` | `fprintd-list "$USER"` and `systemctl status fprintd` | No reader attached, no enrolled prints (`fprintd-enroll`), or `fprintd` D-Bus service failed. Password login works immediately without waiting. |
| Fingerprint timed out after 30 s | `journalctl -u sddm -b --no-pager \| tail -n 50` | Bounded 30 s scan deadline expired; type password or click Retry. |
| `hyprlock` cannot claim fingerprint sensor after login | `journalctl -u fprintd -u sddm -b --no-pager \| tail -n 50` | Verify no lingering `sddm-helper` holds the sensor (`pgrep -a sddm-helper`). |
| Wallet (KWallet / GNOME Keyring) prompts for password after fingerprint login | `fplogin analyze` | Expected by design: fingerprint login does not synthesize or cache your password. See `fplogin analyze` output for exact impact. |
| `fplogin install` refuses conflicting DM (e.g., `greetd`) | Inspect printed plan | Pass `--approve-replace-dm` only if you intentionally want to disable the existing DM and switch to SDDM. |
| Greeter shows `daemon_upgrade_required` | `pacman -Q sddm-fplogin` | Daemon and greeter binaries are out of sync; reboot after upgrading `sddm-fplogin` so the running `sddm` daemon matches the installed greeter. |

---

## 5. What `fplogin` NEVER Modifies

- `/etc/pam.d/system-auth`, `/etc/pam.d/system-login`, `/etc/pam.d/login`, `/etc/pam.d/sudo`, `/etc/pam.d/su`, `/etc/pam.d/polkit-1`, `/etc/pam.d/other`
- `/etc/shadow`, `/etc/passwd`, `/etc/group`
- User home directories, keyrings, or wallet databases (strictly read-only during `fplogin analyze`)
