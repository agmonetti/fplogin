# Emergency Recovery Guide

This guide describes how to diagnose and recover the host system if an `fplogin` installation, upgrade, or uninstallation transaction is interrupted, aborted, or fails unexpectedly.

---

## 1. Safety Guarantees & Transaction Journal

`fplogin` uses an atomic, durable transaction journal (`manifestv1.TransactionJournal`) adhering to **ADR 0003**. 

Key guarantees:
1. **Never in-place edit**: Existing system configuration files (such as `/etc/pam.d/system-login` or `/etc/sddm.conf`) are **never** overwritten in-place. All `fplogin` configurations reside in drop-in directories (e.g. `/etc/sddm.conf.d/fplogin.conf`) or dedicated PAM files (`/etc/pam.d/sddm-fingerprint`).
2. **Pre-mutation durability**: Every mutation intent is written and `fsync`'d to the transaction journal (`/var/lib/fplogin/transaction.json`) *before* any file or service mutation occurs on the system.
3. **Automatic rollback**: If an operation fails during `fplogin install`, the installer automatically runs compensation logic in reverse execution order, restoring any backed up files and deleting temporary files.
4. **Isolated backups**: When a file owned by `fplogin` is updated or replaced, its previous state is backed up to `/var/lib/fplogin/backups/<filename>-<op_id>.bak`.

---

## 2. Automated Recovery via CLI — not available yet

> **Do not rely on `fplogin install`/`uninstall` for recovery.** The [2026-11-12 audit](reviews/cli-provider-audit-2026-11-12.md) found that they cannot complete end to end (discovery fails before any change; adapter and platform operations refuse). `fplogin status` only reports whether a manifest exists. Use the package-level procedure below (§2.1) or the manual steps (§3).

### 2.1 Package-level rollback to stock SDDM (sddm-fplogin)

This applies when the patched SDDM package `sddm-fplogin` is installed. It was rehearsed on 2026-11-12 in a lab VM (no reader): see [Sprint 3 plan](SPRINT_3_EXECUTION_PLAN.md#vm-install-and-rollback-rehearsal-2026-11-12-no-reader).

1. Switch to a text console (`Ctrl`+`Alt`+`F3`, or the rescue shell) and log in as root or a sudo user with your **password** (the fingerprint path is not involved).
2. Stop the greeter: `systemctl stop sddm.service`.
3. Reinstall stock SDDM; the package conflict removes `sddm-fplogin`:
   - offline, from the pacman cache, verifying the signature first:
     ```bash
     pkg=$(ls /var/cache/pacman/pkg/sddm-0.21*-x86_64.pkg.tar.zst | tail -1)
     pacman-key --verify "$pkg.sig" "$pkg"
     pacman -U "$pkg"
     ```
   - or online: `pacman -S sddm`.
4. Check: `pacman -Q sddm` shows `sddm`, not `sddm-fplogin`; `/etc/pam.d/sddm-fingerprint` and `/usr/share/sddm/themes/fplogin` are gone. A modified PAM file is kept as `.pacsave`.
5. Optional: remove any drop-in that selects the fplogin theme (for example `/etc/sddm.conf.d/*fplogin*.conf`). If it is left in place, stock SDDM logs "The configured theme "fplogin" doesn't exist, using the embedded theme instead" and still offers password login.
6. `systemctl start sddm.service` and log in with your password.

---

## 3. Manual Recovery Procedures

If the system cannot boot into a graphical display manager or you are operating from a TTY / rescue shell:

### Step 3.1: Switch to a Virtual Console (TTY)
Press `Ctrl + Alt + F3` (or `F2` through `F6`) to open a text console. Log in with your standard username and password.

### Step 3.2: Inspect Journal and Manifest Files
Check if a transaction or manifest is present:
```bash
ls -la /var/lib/fplogin/
cat /var/lib/fplogin/transaction.json
cat /var/lib/fplogin/manifest.json
```

### Step 3.3: Remove fplogin Drop-in Configuration
If SDDM fails to start or displays an error, remove the `fplogin` configuration drop-ins:
```bash
# Remove SDDM drop-in override (restores default SDDM theme/configuration)
sudo rm -f /etc/sddm.conf.d/fplogin.conf

# Remove dedicated PAM service
sudo rm -f /etc/pam.d/sddm-fingerprint

# Remove installed theme assets if present
sudo rm -rf /usr/share/sddm/themes/fplogin
```

### Step 3.4: Restart the Display Manager
Restart the display manager service to return to stock configuration:
```bash
sudo systemctl restart sddm.service
```

---

## 4. Recovering Backups

If any existing configuration was backed up during a prior operation:
1. Backups are stored in: `/var/lib/fplogin/backups/`.
2. Check the SHA-256 hash against the journal or manifest before restoring:
```bash
sha256sum /var/lib/fplogin/backups/*
```
3. Copy the desired backup back to its target destination with original permissions (`0644` for config files, owned by `root:root`).

---

## 5. What fplogin NEVER Modifies
To assist manual verification:
- `/etc/pam.d/system-login`, `/etc/pam.d/login`, `/etc/pam.d/other` are **never** modified by `fplogin`.
- `/etc/shadow`, `/etc/passwd`, `/etc/group` are **never** modified.
- User home directories and wallet files are strictly read-only and never modified.
