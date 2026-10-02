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

## 2026-10-01 isolated cancellation probe

`fprintd-list agus-hy` found the `Synaptics Sensors` reader and the enrolled
`right-index-finger`. As the unprivileged enrolled user,
`python3 tests/integration/verify_isolated_pam.py --fingerprint` used a private
`pam_start_confdir` service (`auth required pam_fprintd.so timeout=30`) twice.
Both clients reached the informational reader prompt without a finger press.
Both observed `SIGTERM`, remained blocked, and required the five-second
`SIGKILL` fallback; each was reaped (`signal=9`, `elapsed_ms=5002`).
The second client reached the prompt after the first exited. This confirms
bounded process cleanup and subsequent prompt availability for this isolated
PAM probe, **not** SDDM's winner barrier, device-idle attestation, or login.
No host PAM service or active display manager was changed.

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

## Isolated Sprint 1 laboratory

The laboratory assets are [`sddm_lab_vm.py`](../../tests/integration/sddm_lab_vm.py),
[`sddm-lab-trace.patch`](../../tests/integration/sddm-lab-trace.patch), and
[`collect_sddm_lab.py`](../../tests/integration/collect_sddm_lab.py).
The diagnostic patch is separate from the production patch series: apply the
production patch first, then the diagnostic patch to a disposable source tree.
Build and install that tree in a Docker runtime image before preparing the VM.

The VM runs its own kernel, systemd PID 1, system D-Bus, logind and graphical
`seat0` under QEMU TCG. A guest `seat0` is independent of the host `seat0`;
renaming a seat or sharing the host logind socket would not create isolation.
By default no host USB is passed. The explicit reader option below maps only
one USB character node; no whole USB tree, DRM, X/Wayland socket, system D-Bus
or PAM directory is mounted. The guest has no network. VNC is published on host loopback only. Serial
recovery uses a private Unix socket reached with Docker exec, not a TCP root
console. Serial root autologin is restricted to this disposable, networkless
guest; it is not a production recovery configuration.

VNC also listens on the container network. Loopback publication alone does not
exclude Docker bridge peers. Use a trusted, dedicated local Docker environment;
this is not a security boundary against Docker administrators.

### Boot and recovery

```text
python3 tests/integration/sddm_lab_vm.py prepare \
  --lab-dir /tmp/fplogin-sddm-lab --runtime-image fplogin-lab-traced:local
python3 tests/integration/sddm_lab_vm.py start \
  --lab-dir /tmp/fplogin-sddm-lab --vnc-port 5905
python3 tests/integration/sddm_lab_vm.py recovery --lab-dir /tmp/fplogin-sddm-lab
```

In the serial guest console:

```text
fplogin-lab recovery-check
fplogin-lab status
```

Recovery must be exercised before `fplogin-lab start-sddm`. Stop/restart SDDM
from this console and verify that serial access remains usable. Use
`sddm-lab.service`, not `sddm --test-mode`; container test mode does not exercise
the real logind lifecycle. Stop the VM with:

```text
python3 tests/integration/sddm_lab_vm.py stop --lab-dir /tmp/fplogin-sddm-lab
```

### Reader ownership gate

Initial provisioning intentionally passes **no reader**. The active host's
enrollment does not establish guest enrollment: fprintd's per-user records
belong to the system performing verification, even for a match-on-sensor reader.
Do not copy host fingerprint templates or host credential databases.

Before physical-reader scenarios, an administrator must provide exclusive
ownership of the specific `06cb:00bd` device to the isolated system without
leaving the active host dependent on it. Record the physical USB identity/path,
the ownership transition, host-side prevention of competing fprintd claims,
guest-side device enumeration and guest `fprintd-list fplab` result. Establish a
disposable guest password via interactive `passwd`, never a command-line
password or a reused host password. Guest enrollment/verification requires
the enrolled person's physical participation; do not infer it from USB presence.

This match-on-sensor device may retain enrollment slots on the sensor.
Re-enrollment or deletion in another OS can therefore change hardware state;
do not silently replace or erase the active host's enrollment. An administrator
must establish a safe lab enrollment policy before any such operation.

#### Explicit single-reader handoff

The operator must explicitly agree to dedicate this physical match-on-sensor
reader to the lab, including possible loss of host enrollment and later host
re-enrollment. The administrator must confirm password/TTY recovery works
without it, exclude other reader consumers (including other VMs and manually
started daemons), and authorize the local user to access this one device.
The person enrolling must separately consent and participate physically.
Do not run host `fprintd-list`/enrollment while the lab owns the reader.

Rebuild the tooling image from these updated sources before use. `prepare`
builds and pins a new image and creates a new disk; an existing lab manifest
still pins its old entrypoint even if a Docker tag is rebuilt. Prefer preparing
a fresh private lab directory rather than changing a running lab's manifest.

Example for the recorded node (USB addresses can change; verify again each
time). First record the pre-handoff service state and save the node ACL in a
private administrator-controlled file so restoration does not remove unrelated
permissions. Only the administrator performs these host changes:

```text
lsusb -s 001:004
systemctl show fprintd.service -p UnitFileState -p ActiveState -p SubState
sudo sh -c 'umask 077; getfacl -p /dev/bus/usb/001/004 > /root/fplogin-reader.acl'
sudo systemctl mask --runtime --now fprintd.service
sudo setfacl -m u:agus-hy:rw /dev/bus/usb/001/004
systemctl show fprintd.service -p LoadState -p UnitFileState -p ActiveState -p SubState
```

Do not overwrite an existing saved ACL. If the handoff was already performed,
use its recorded previous state instead of treating the changed ACL as the
original. An administrator must resolve a pre-existing persistent service mask;
the launcher requires `masked-runtime`, `inactive`, and `dead` specifically.
It does not grant permissions or mask/stop services itself.

As the authorized ordinary user, with no host fprintd consumer remaining:

```text
python3 tests/integration/sddm_lab_vm.py start \
  --lab-dir /tmp/fplogin-sddm-lab --reader /dev/bus/usb/001/004
python3 tests/integration/sddm_lab_vm.py status --lab-dir /tmp/fplogin-sddm-lab
python3 tests/integration/sddm_lab_vm.py recovery --lab-dir /tmp/fplogin-sddm-lab
```

The launcher checks canonical path, USB character-device numbers, user read/
write access, matching sysfs bus/address and exact `06cb:00bd`, plus host
fprintd state. Docker receives only `--device NODE:NODE:rw` plus a bind mount
of that same single node to preserve its named-user ACL; runc's recreated
device node alone does not retain that ACL. It never uses privileged mode.
QEMU uses the existing xHCI controller with `usb-host` restricted by
host bus/address and VID/PID. Container startup rechecks the node identity.
The local manifest records the explicit node so status/recovery/stop inspect
that exact mapping without requiring the device to remain plugged in or the
host service to remain masked. Starting again without `--reader` restores
the default no-device configuration; it never implicitly reuses the record.

In the guest, run `fplogin-lab status`, `lsusb -d 06cb:00bd`, and
`fprintd-list fplab`. Record enumeration and enrollment metadata only.
An empty guest enrollment is expected until authorized interactive enrollment;
do not import the host store. USB presence and a runtime mask are checks, not
proof of exclusive ownership: already-open descriptors, other administrators,
and later service/device changes remain outside this gate. If the node changes,
stop and recheck identity before a fresh opt-in start; never map the USB tree.

#### Bounded handback

Stop the VM first with `sddm_lab_vm.py stop --lab-dir /tmp/fplogin-sddm-lab`.
It requests ACPI shutdown and uses a bounded container-stop fallback; inspect
the printed outcome. Confirm that its container is gone before restoring host
access. The wrapper deliberately does not undo administrator policy.

After verifying that the saved ACL belongs to this same physical node, the
administrator restores it with
`sudo setfacl --restore=/root/fplogin-reader.acl`. If there was no saved ACL
and the handoff only added a previously absent named-user entry, remove only
that entry with `sudo setfacl -x u:agus-hy /dev/bus/usb/001/004`; do not reset
the whole node's permissions. A replugged/readdressed device needs a fresh
identity and permission review rather than blindly restoring an old path.
Remove only the runtime mask introduced for this lab with
`sudo systemctl unmask --runtime fprintd.service`; preserve any pre-existing
administrator mask. Restart fprintd only if it was previously active or the
administrator explicitly wants host verification now. Check host enrollment
with the owner present and, if necessary, re-enroll interactively under the
agreed policy. No automated delete/reset of sensor slots is authorized.

`NOT_READY` remains the expected acceptance status even after handoff and
enrollment: each matrix requirement needs its own evidence. A recovery
acknowledgment, a running VM, a reader prompt, or zero remaining helpers alone
does not pass this gate.

### Matrix and required evidence

The [2026-10-01 physical execution record](../reviews/sprint-1.md#2026-10-01-teardown-attribution-and-physical-reader-matrix)
documents the authorized handoff, guest enrollment, real-reader JSONL and
per-row results: **9 verified scoped behaviors, 5 partial rows, 2 failed rows**.
Winning-helper exit `9/crash` after `pam_end` and failed session reuse keep
Sprint 1 blocked. The table below is the required contract, not a pass list.
Synthetic diagnostic PAM runs are recorded separately from physical results.

| ID | Scenario | Required observation |
|---|---|---|
| R01 | Fingerprint and password active together | Two helper PIDs, same request, distinct methods; both real PAM authentication phases active |
| R02 | Password wins while reader waits | Fingerprint loser exits before winner authorization; subsequent real fprintd claim/verification succeeds |
| R03 | Fingerprint wins | Genuine biometric match; password loser exits; only winner crosses account/setcred/open-session |
| R04 | Simultaneous-success race, both callback orders | Record both successful PAM results before arbitration where achievable; exactly one session; distinguish controlled interleaving from timing stress |
| R05 | Fingerprint cancellation and late success, both loser-exit orders | Cancelled callback cannot win; observed loser exit releases the selected password winner |
| R06 | Change user during scan | Old request cannot authorize the new user; new request and correct account policy |
| R07 | Change session or replace request during scan | Stale result cannot start the previous session; replacement gets fresh identity |
| R08 | Invalid finger, reader timeout, reader unavailable | Bounded failure and cleanup; password still usable; no repeated automatic loop |
| R09 | Display stop during blocked authentication | Observe terminate/kill intent, exit and bounded reader reuse; no unaccounted helper |
| R10 | Fingerprint failure/cancellation then retry | Fresh request/generation and successful genuine verification; old result ignored |
| R11 | Password failure then retry across old five-second deadlines | Keep one greeter connection; new helper survives old handshake and forced-kill callbacks |
| R12 | Password-only, missing reader and unenrolled account | Normal distro PAM login succeeds without biometric substitution |
| R13 | Autologin | Stock account/session policy; one session without accidental fingerprint transaction |
| R14 | Existing logind session reuse | Record session ID/leader before and after; activate intended session without a duplicate session launch |
| R15 | Logout/relogin, X11 and Hyprland | Session closes, display/greeter restarts, fresh request; X11 authorization and real Wayland lifecycle |
| R16 | Account denial and helper/fprintd failure | Denied account never opens a session; password fallback and reader recovery survive failure |

For each row record run ID, boot ID, monotonic timestamps, request UUID,
daemon/helper/greeter PID, role, method, launch generation, PAM phase/result,
logind session ID/leader and exit status. State unknown bindings explicitly.
Use identifiers, not passwords, PAM responses, environment dumps, X cookies
or fingerprint data. Include setup/cleanup failures rather than counting only
successful runs. Gate acceptance also requires independent review; this matrix
does not authorize Sprint 2.

### Identifier-only capture and teardown diagnostics

Inside the booted guest, start the collector before the scenario:

```text
python3 /usr/local/lib/fplogin-lab/collect_sddm_lab.py \
  --output /root/R01-events.jsonl
```

The collector saves allowlisted structured SDDM/PAM events and logind session
identifiers as mode-0600 JSONL, refusing overwrite. It does not save raw journal
messages, usernames or PAM conversations. Live capture refuses the host and
container-only environments. PID joins are boot-scoped; logind request binding
requires an observed session leader matching a known helper. Missing bindings
remain null and must be resolved with contemporaneous `loginctl` evidence, not
timestamp proximity. Offline `--journal` normalization does not attest isolation.

Helper journal selection also matches the installed executable path: PAM/logind
can move a helper into a session scope, outside `sddm-lab.service`. A unit-only
capture would lose its later session-close/end events.

Reader release needs fprintd Claim/Release or owner-disconnect evidence plus a
subsequent claim/verification. D-Bus tracing must capture method headers and
sender/PID identities only, never message bodies or templates. The JSONL
collector by itself does not attest device-idle state.

For exit `9`, distinguish normal exit code 9 from `exit_status=crash`, correlate
cached helper PID/role with kill intent and PAM close/end, and identify the
signal issuer before assigning a cause. For `QBasicTimer`, the journal emitter
PID identifies the process; obtain a matching-symbol debugger backtrace at
`QBasicTimer::start` during reproduction. Do not set global
`QT_FATAL_WARNINGS=1`: unrelated warnings would change teardown behavior.
No diagnosis is cleared by a zero-helper count.
