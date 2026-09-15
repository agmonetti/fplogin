# Synaptics `06cb:00bd` test hardware record

**Record ID:** `synaptics-06cb-00bd-arch-amd64`  
**Recorded:** 2026-09-15  
**Purpose:** Primary physical-reader target for fplogin v1 SDDM/Hyprland verification.

## Hardware and stack

| Field | Observed value |
|---|---|
| USB identity | `06cb:00bd` |
| USB description | `Synaptics, Inc. Prometheus MIS Touch Fingerprint Reader` |
| fprintd device name | `Synaptics Sensors` |
| Scan type | press |
| Host architecture | `x86_64` |
| Kernel | `Linux 7.1.8-arch1-3` |
| Distribution | Arch Linux |
| fprintd | `1.94.5-2` |
| libfprint | `1.94.100-1` |
| SDDM | `0.21.0-7` |
| Primary session | Hyprland |
| Test user | `agus-hy` |
| Enrolled finger | `right-index-finger` |

The test record identifies one concrete development device. It does not imply that every device with this USB ID has identical firmware or security properties, and it does not claim hardware attestation or Windows Hello-equivalent sensor trust.

## Read-only inventory evidence

```text
$ lsusb -d 06cb:00bd
Bus 001 Device 004: ID 06cb:00bd Synaptics, Inc. Prometheus MIS Touch Fingerprint Reader

$ fprintd-list agus-hy
found 1 devices
Device at /net/reactivated/Fprint/Device/0
Using device /net/reactivated/Fprint/Device/0
Fingerprints for user agus-hy on Synaptics Sensors (press):
 - #0: right-index-finger
```

## Sprint 0 cancellation observation

A throwaway PAM client used `pam_start_confdir` with an isolated policy containing only:

```text
auth required pam_fprintd.so timeout=30
```

Observed sequence:

```text
READY user=agus-hy pid=43745
PAM_MESSAGE style=4 text=Place your right index finger on the fingerprint reader
SIGNAL SIGTERM handled
```

The client emulated SDDM's `SIGTERM` handling (`SA_RESTART`) while blocked in `pam_authenticate`. It remained alive after `SIGTERM` and required the bounded `SIGKILL` fallback. A second client immediately reached the same fingerprint-reader prompt after the first process exited, proving that process termination released the fprintd claim in this stack.

This validates process termination as the fallback cancellation boundary. It does not validate graceful `pam_end` during a blocked `pam_fprintd` call; the SDDM coordinator must withhold winner session authorization until loser process exit is observed.

## Required later scenarios

Sprint 1 and Sprint 2 must append dated results for:

- fingerprint success and password success through patched SDDM;
- password win while `pam_fprintd` is waiting;
- fingerprint win while password authentication is available;
- invalid finger, reader timeout, and reader unavailable;
- user switch and session switch invalidating an active request;
- simultaneous-success stress with exactly one session start;
- helper/PAM/fprintd cleanup after success, failure, cancellation, timeout, and display stop;
- handoff to hyprlock after the SDDM fingerprint helper exits.

## Safety constraints

- Never record fingerprint templates, PAM responses, or passwords.
- Keep `/etc/pam.d/system-auth`, sudo, polkit, SSH, and unrelated PAM services unchanged.
- Redact credentials and user-sensitive environment values from captured logs.
- Keep password/TTY recovery available during display-manager tests.
