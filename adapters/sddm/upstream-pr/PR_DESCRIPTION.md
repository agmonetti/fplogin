# Upstream SDDM Pull Request Draft — Concurrent Password & Fingerprint Authentication

> **Status:** Local / private draft prepared for `github.com/sddm/sddm`. Do not submit publicly until local Arch hardware sign-off and explicit owner authorization.
>
> **Branch:** `upstream-pr/concurrent-fingerprint-auth` (rebased cleanly on SDDM `v0.21.0`, commit `63780fcd79f1dbf81a30eef48c28c699ab15aded`; HEAD `7bbb43f`; self-contained bundle `.work/checkpoints/sddm-sprint7-upstream-pr.bundle`; exported `git format-patch` series in `.work/release/upstream-pr/0001..0005`).

---

## PR Title

`auth/daemon/greeter: concurrent password and fingerprint authentication with single-winner arbitration`

## Summary

Today, SDDM runs a single PAM authentication conversation per login attempt. On systems using `pam_fprintd`, users must either wait for fingerprint verification to time out before typing a password or press Enter first to trigger biometric scanning.

This PR adds **native concurrent authentication methods** (password + fingerprint) to SDDM without synthesizing passwords, without modifying global PAM stacks, and without moving authentication logic into QML themes:

1. **Dual concurrent helpers with single-winner arbitration (`0001`):**
   - Runs the existing password helper (`sddm` PAM service) and an optional dedicated fingerprint helper (`sddm-fingerprint` PAM service) concurrently under a single request identity (`requestId`, `AuthMethod`, `generation`, `authId`).
   - Enforces single-winner arbitration in `Display` / `AuthAttemptGate`: once one method authenticates, the losing helper is cancelled and reaped before session open; a stale or cancelled helper can never open a second session or authenticate a different user.
   - Adds `Q_DECLARE_METATYPE(SDDM::AuthMethod)` for Qt5/Qt6 co-compatibility.
2. **Greeter IPC & controller-isolated theme lifecycle (`0002`):**
   - Extends greeter ↔ daemon IPC with explicit authentication context binding (`SetAuthenticationContext`), method start/cancel, and structured per-method state/availability updates.
   - Enforces single-controller isolation across multi-monitor greeter views so mirror screens cannot initiate or submit authentication.
   - Backward-compatible with existing password-only themes.
3. **`fprintd` availability gating & bounded scan deadline (`0003`):**
   - Probes `net.reactivated.Fprint` availability before starting a fingerprint helper (reporting clean `unavailable` when no reader or no enrollment is present, with zero retry loops).
   - Enforces a bounded 30-second scan deadline so fingerprint helpers cannot wedge indefinitely.
4. **Security & resilience hardening (`0004`):**
   - Locks down `Auth::SocketServer` with `QLocalServer::UserAccessOption` (`0700`) and idempotent pending-handshake accounting against connection floods.
   - Adds connection ceilings and null/malformed-frame guards to greeter `SocketServer`.
   - Subscribes to `org.freedesktop.login1.Manager::PrepareForSleep(bool)` to cancel active scans on external suspend and never auto-trigger hidden scans on resume.
   - Immediately degrades fingerprint state on `fprintd` D-Bus owner loss (`serviceOwnerChanged`) while preserving in-flight password logins.
   - Zero-wipes transient password `QString` buffers via `explicit_bzero` before clearing/reassignment.
5. **Non-intrusive auto-start, optional status overlay & configurable retry shortcut for existing Qt5/Qt6 themes (`0005`):**
   - Adds `[General] AutoFingerprintForLegacyThemes` (default `true`): if a loaded theme does not call `setAuthenticationContext`/`startFingerprint`, `GreeterApp` starts one bounded concurrent fingerprint attempt for the default `UserModel`/`SessionModel` selection without modifying the theme.
   - Adds `[General] FingerprintStatusOverlay` (default `false`): optionally renders a minimal, non-focus-stealing bottom status pill over legacy Qt5/Qt6 themes displaying scanning, retry, failed, timed-out, and matched states.
   - Adds `[General] FingerprintRetryKey` (default `F4`, accepts any single portable `QKeySequence` such as `F8` or `Ctrl+R`, or `none` to disable) so users can explicitly trigger a bounded retry after failure/timeout without colliding with theme keybindings.
   - Emergency embedded fallback (`qrc:/theme`) remains strictly password-only.

## Commit Series (5 atomic commits)

| # | Commit Subject | Scope |
|---|---|---|
| 1 | `auth: support concurrent password and fingerprint helpers with single-winner arbitration` | `src/auth/*`, `src/common/Messages.h`, `src/daemon/AuthAttemptGate.h`, `src/helper/*`, unit/transport tests |
| 2 | `greeter: expose concurrent authentication method API and controller-isolated theme lifecycle` | `src/daemon/{Display,SocketServer}.*`, `src/greeter/{GreeterApp,GreeterProxy}.*`, fallback QML, Qt5 metatype, greeter/daemon tests |
| 3 | `daemon: enforce fprintd availability gating, bounded scan deadline, and fixture cleanup` | `src/daemon/Display.cpp`, `test/DaemonContextTest.cpp`, `test/FingerprintAvailabilityService.cpp` |
| 4 | `security: harden auth/greeter sockets, PrepareForSleep, fprintd crash handling, and secret wiping` | `src/auth/Auth.cpp`, `src/daemon/{Display,SocketServer}.*`, `test/{AuthTransport,DaemonContext,FploginTheme}Test.cpp` |
| 5 | `greeter: auto-start fingerprint with optional status overlay and configurable retry key for legacy themes` | `src/common/Configuration.h`, `src/greeter/{GreeterApp,GreeterProxy}.{h,cpp}`, `test/GreeterAppTest.cpp` |

> **Note for upstream reviewers:** This series contains **zero** distribution packaging, installer, or analyzer code. When rebasing onto upstream `develop` (post-`v0.21.0`), `CMakeLists.txt` already includes upstream commit `228778c` (CMake 3.5 minimum); no CMake shim is included in this PR.

## Verification

- **Unit & Integration CTest (Qt6 & Qt5):** 10/10 suites pass on Qt6 (`Configuration`, `QMLThemeConfig`, `Session`, `AuthMessages`, `AuthAttemptGate`, `AuthTransport`, `GreeterProxy`, `FploginTheme`, `DaemonContext`, `GreeterApp`) and 9/9 on Qt5 with zero failures or skips.
- **Adversarial & Endurance:**
  - 250-frame malformed/truncated/oversized greeter IPC fuzz corpus + 24-connection helper handshake flood + `SO_PEERCRED` mismatch tests.
  - 500-cycle helper lifecycle endurance test (`fd_delta=0`, bounded RSS, zero zombies/orphans).
  - 69/69 security test cases clean under ASan + UBSan (0 ASan errors, 0 UBSan errors).
  - Private D-Bus fault-injection tests covering `fprintd` crash mid-scan, sensor removal/reattachment, and `PrepareForSleep(true/false)`.
- **Hardware validation:** Verified on Arch Linux + systemd + Hyprland + Synaptics `06cb:00bd` (USB match-on-sensor).

## Security Invariants Preserved

- No PAM authentication logic in QML themes.
- No password synthesis or fallback password caching across attempts.
- Dedicated `sddm-fingerprint` PAM service leaves `sddm` password auth untouched; password login survives every biometric failure.
- Request-bound user/session/generation matching prevents cross-user or post-cancel session opens.
