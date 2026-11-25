# Sprint 7 Review — End-to-End Validation, Local Arch Hardware Verification, Release v1.0 Packaging & Upstream SDDM PR Preparation

- **Date:** 2026-11-25
- **Gate status:** **READY FOR OWNER SIGN-OFF** (local/private verification complete; GPG signature `--gpg-key`, `v1.0.0` tag, `git push`, and upstream PR publication intentionally gated on explicit owner authorization)
- **Plan baseline:** [`docs/IMPLEMENTATION_PLAN.md`](../IMPLEMENTATION_PLAN.md) (§10.7, §11, §12)
- **Hardware verified:** Arch Linux x86_64 · systemd · Hyprland (`uwsm`) · `fprintd 1.94.5-2` · `hyprlock 0.9.7-2` · Synaptics `06cb:00bd` (USB match-on-sensor)
- **Tested packages:**
  - `sddm-fplogin 0.21.0-4` (patches `0000..0006`, dual Qt6 + Qt5)
  - `fplogin-git 0.2.0.r258.c47b515-1` (includes `fplogin config` persistent drop-in configurator and real-desktop `graphical.target` preflight fix)

---

## 1. Slice-by-Slice Verification Summary

### S7-F01 — Dual Qt6 + Qt5 Clean Build (`sddm-fplogin` + `fplogin-git`) — PASS

- Added additive patch `platforms/arch/sddm-fplogin/0006-legacy-theme-auto-fingerprint.patch` (`f75ef12`, source commit `e009ae7` in `.work/sddm/sprint7-legacy-theme/`, full-history bundle `.work/checkpoints/sddm-sprint7-0006.bundle`) without mutating accepted `0001` or `0002`.
- Built `sddm-fplogin-0.21.0-4-x86_64.pkg.tar.zst` in a clean disposable `archlinux:base-devel` container:
  - **Qt6 CTest:** 10/10 suites passed, 0 failures, 0 skips (including `GreeterApp::legacyThemeAutoStartsFingerprint` and `GreeterApp::legacyThemeRespectsDisableConfig`).
  - **Qt5 CTest:** 9/9 suites passed, 0 failures, 0 skips (closes Sprint 6 residual risk #1 for `0005` + `0006`).
  - **Qt5 merge:** `62 additions; 243 canonical entries unchanged`.
  - Evidence: `.work/evidence/sprint7/s7-f01-builds/sddm-fplogin-0.21.0-4-qt6-qt5-makepkg.log`.
- Built `fplogin-git-0.2.0.r22.f75ef12-1-x86_64.pkg.tar.zst` offline via `make package` (`67450f3`), with 17/17 Go packages passing `go test` and `go vet -tags f05lab ./...`.
- Updated `/etc/sddm.conf.d/90-fplogin.conf` drop-in to `[General]\nAutoFingerprintForLegacyThemes=true\n`, preserving the user's existing Qt5/Qt6 theme intact without forcing `Current=fplogin`.

### S7-F02 — Clean Arch KVM E2E Lifecycle (`S7-13`) — PASS

- Fixed `pipefail` SIGPIPE on postflight `fplogin analyze` output in `tests/integration/s4-cli-e2e-guest.sh` (`034fac9`).
- Executed all 5 packaged CLI E2E cases in a disposable networkless Arch Linux KVM guest (real systemd PID 1, no USB reader):
  1. `components` + `install --dry-run`
  2. Stock SDDM replacement → `status` → `reinstall` → `repair` → `uninstall` restoring exact stock SDDM state
  3. No-DM host `--activate` → `uninstall`
  4. Conflicting DM (`greetd`) refusal + explicit `--approve-replace-dm` replacement → `uninstall`
  5. Mid-transaction `SIGKILL` interruption + `fplogin recover`
- Every transition verified real `/bin/login` PAM console authentication.
- Evidence: `.work/evidence/sprint7/clean-lifecycle/cli-e2e-serial.log` (SHA-256 `b54ebc0dfbf38e7f18ab59c5b0fdff8e4bfff2e1ecfa99fccda1e642d1faca7c`).

### S7-F03 — Local Upstream SDDM PR Series & Tracking Guide (`S7-14`) — PASS (Private)

- Constructed 5 atomic commits on branch `upstream-pr/concurrent-fingerprint-auth` (`a53646d`) over pinned SDDM `v0.21.0` (`63780fc`) in `.work/sddm/sprint7-upstream-pr/`:
  1. `0001`: concurrent password + fingerprint helpers and single-winner arbitration
  2. `0002`: greeter IPC API and controller-isolated theme lifecycle
  3. `0003`: `fprintd` availability gating, bounded scan deadline, and fixture cleanup
  4. `0004`: socket/IPC/D-Bus/`PrepareForSleep`/secret-wiping hardening
  5. `0005`: non-intrusive auto-start for legacy Qt5/Qt6 themes (`AutoFingerprintForLegacyThemes`)
- Exported `git format-patch` series in `.work/release/upstream-pr/0001..0005`, verified full-history bundle `.work/checkpoints/sddm-sprint7-upstream-pr.bundle`.
- Authored [`adapters/sddm/upstream-pr/PR_DESCRIPTION.md`](../../adapters/sddm/upstream-pr/PR_DESCRIPTION.md) and [`docs/UPSTREAM_TRACKING.md`](../UPSTREAM_TRACKING.md). Zero installer/analyzer/Arch packaging code in the PR series.

### S7-F04 — Real Arch Hardware Lifecycle Matrix & `hyprlock` Handoff (`S7-11`, `S7-12`) — PASS

All hardware runs executed directly on the owner's Arch Linux host with Synaptics `06cb:00bd`, `fprintd 1.94.5-2`, Hyprland (`uwsm`), and `hyprlock 0.9.7-2`, with secret-free allowlisted journald evidence archived under `.work/evidence/sprint7/hardware/`:

| Case | Boot ID | Theme | Correlated Result | Evidence SHA-256 |
|---|---|---|---|---|
| `c1-failed-fp` | `6ab279d5…` | `fplogin` | Stale pre-existing print failed with `PAM_MAXTRIES` (`code 11`); direct password fallback without Enter opened Hyprland cleanly (`sddm-helper[1092]`). Confirmed stale template via `fprintd-verify` (`verify-no-match`) and re-enrolled (`verify-match`). | `971558c4…cac99` |
| `c1-fp-ok` | `c10c1b59…` | `fplogin` | Cold-boot fingerprint login (`sddm-helper[727]`, `--method 1`, `request-id 521fed06…`) opened single Hyprland session (`tty1`) in **2.3 s**, 0 lingering helpers; hardware suspend/resume (`systemd-sleep[4201]`) + `hyprlock[4151]` unlocked by fingerprint with zero sensor contention. | `aed8b315…c7e` |
| `c2-where-fp` | `ade39394…` | `where_is_my_sddm_theme` (untouched!) | Cold-boot auto-fingerprint on untouched user theme (`sddm-fplogin 0.21.0-4`, `sddm-helper[729] --method 1`, `request-id 100113a3…`) opened single Hyprland session in **1.44 s**, 0 lingering helpers; suspend/resume + `hyprlock[1639]` post-fingerprint passed. | `cca9343b…214` |
| `c2b-pw-lock` | `3f13efe2…` | `where_is_my_sddm_theme` (untouched) | Password-wins-cancels-active-fingerprint: `sddm-helper[727]` scanning since `16:04:20`, password `sddm-helper[1057]` authenticated `16:04:41`, daemon terminated losing fingerprint helper `727` (`16:04:46.543`) **6 ms before** opening session (`16:04:46.550`). Subsequent `hyprlock` runs cleanly claimed `/net/reactivated/Fprint/Device/0` and unlocked via both password and fingerprint (`verify-match`). | `16d4d1c2…b17b` |
| `c2c-logout-to` | `3f13efe2…` | `where_is_my_sddm_theme` (untouched) | Clean `uwsm stop` logout → fresh greeter (`6409`) → auto-fingerprint (`6423`) → bounded `PAM_MAXTRIES` (`code 11`, `16:09:32`) → **41 s window with zero spurious retry loops** → password fallback (`6443`) opened Hyprland in 45 ms (`16:10:13`). | `03af7dc5…ed2` |
| `2c-a-stock` | live host | `where_is_my_sddm_theme` (preserved) | Interactive `sudo fplogin install --artifacts-dir ./artifacts-stock` over stock `sddm 0.21.0-7` (`Plan SHA-256 3518a6d35afe`, `tx-1795637165177681192`), `fplogin status` Intact, postflight `analyze` clean, followed by `sudo fplogin uninstall --yes` (`tx-uninstall-1795637846666423877`) cleanly restoring `sddm 0.21.0-7`. Exposed & fixed real-desktop non-DM `graphical.target` service handling (`power-profiles-daemon.service`, commit `c47b515`). | host output |
| `2c-b-nodm` | live host | `where_is_my_sddm_theme` (preserved) | Interactive `sudo fplogin install --artifacts-dir ./artifacts-nodm` from zero-SDDM baseline (`Target: SDDM (new installation)`, `Plan SHA-256 eb363016dbae`, `tx-1795638550585375752`), `fplogin status` Intact, and persistent post-install `fplogin config set --timeout 45` / `show` / `--timeout 30` / `show` round-trip verified in `/etc/sddm.conf.d/90-fplogin.conf`. | host output |

### S7-F05 & S7-F06 — Release Documentation & Reproducible Local Artifacts (`S7-15` Partial)

- Updated [`docs/SUPPORTED_VERSIONS.md`](../SUPPORTED_VERSIONS.md), [`docs/EMERGENCY_RECOVERY.md`](../EMERGENCY_RECOVERY.md), [`docs/UPSTREAM_TRACKING.md`](../UPSTREAM_TRACKING.md), and [`README.md`](../../README.md).
- Added [`scripts/build_release.sh`](../../scripts/build_release.sh) and generated verified local release artifacts in `.work/release/v1.0.0/`:
  - `fplogin-1.0.0.tar.gz` — SHA-256 `e008abe44b63ea3d2b376cc21ec048f54f5156b99c497f476f80bc9838ff62fd`
  - `fplogin-git-0.2.0.r22.f75ef12-1-x86_64.pkg.tar.zst` — SHA-256 `8e92ec143a1278a0c8519b727c52cb53a25076af3fbc8c65d6fa4d970169ca32`
  - `sddm-fplogin-0.21.0-4-x86_64.pkg.tar.zst` — SHA-256 `89d4f07e201ecafa92a6cf593a428c751f1fa0117d2782c3bd5af2a7d6f31413`
  - `SHA256SUMS` verified via `sha256sum -c`.
- **Pending for `S7-15` closure:** detached GPG signature (`scripts/build_release.sh --gpg-key <key-id>`) using the owner's release signing key.

---

## 2. §11 Verification Matrix & §12 Definition of Done Reconciliation

- **Concurrent login without Enter-first gate:** Verified on real hardware (`c1-fp-ok`, `c2-where-fp`, `c2b-pw-lock`, `c2c-logout-to`).
- **Single-winner arbitration & loser cleanup before session open:** Verified on real hardware (`c2b-pw-lock`: 6 ms strict ordering after loser termination) and in unit/integration tests (`AuthAttemptGate`, `DaemonContext`).
- **Sensor handoff to `hyprlock` (`S7-12`):** Verified after both fingerprint login and password-wins login.
- **No in-place edits to stock PAM / `/etc/sddm.conf`, user theme preserved:** Verified on host (`where_is_my_sddm_theme` untouched) and clean KVM (`S7-13`).
- **Clean install / recovery / uninstall back to stock SDDM:** Verified in clean Arch KVM (`S7-13`, 5/5 PASS including `SIGKILL` + `fplogin recover`).
- **System analyzer honesty (`fplogin analyze`):** Verified live on host (KWallet/GNOME Keyring/systemd-homed/fprintd + explicit scope limitations).
- **Security & resilience hardening:** Verified in Sprint 6 (`0005`, fuzzing, 500-cycle endurance, ASan+UBSan 69/69) and rebuilt on Qt6 + Qt5 in Sprint 7 (`0000..0006`).
- **Upstream PR cleanliness:** Verified 5 atomic commits on `v0.21.0` with zero installer/analyzer coupling.

---

## 3. Honest Residual Notes

1. **X11 greeter helper shutdown timing (cosmetic, non-blocking):** In X11 greeter mode on this host, `sddm-helper` for the greeter (`sddm-greeter-qt6`) receives `SIGTERM` ~5 s after user session start and exits after the 5 s grace timeout; user sessions start cleanly on `tty1` with zero leftover helpers.
2. **Multi-user untouched legacy themes:** `AutoFingerprintForLegacyThemes` starts one bounded attempt for the preselected default user (`UserModel::lastUser` / `lastIndex`) because legacy QML themes do not notify C++ on user-switcher changes; switching users and typing a password works normally via `sddm.login(...)`.
3. **Host `where_is_my_sddm_theme` F2 blank `< >` label:** Confirmed to be `where_is_my_sddm_theme`'s `showUserRealNameByDefault` reading an empty `/etc/passwd` GECOS field, unrelated to `fplogin`.
4. **Private-first gate:** Nothing has been GPG-signed with the owner key, tagged (`v1.0.0`), pushed to GitHub, or submitted to `sddm/sddm`.

---

## 4. Owner Acceptance Gate (`S7-16`)

To finalize `v1.0.0` publication when ready:

1. Sign release artifacts with `scripts/build_release.sh --gpg-key <your-gpg-key-id> --sddm-pkg .work/build/sddm-sprint7-0006/out-0006/sddm-fplogin-0.21.0-4-x86_64.pkg.tar.zst`.
2. Explicitly authorize Sprint 7 closure, `v1.0.0` tag + `git push`, and upstream SDDM PR submission.
