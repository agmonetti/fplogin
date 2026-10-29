# G05 diagnostic overlay: offline results and reversal contract

**No deployment or new VM attempt is authorized.** The diagnostic-only source is
`.work/labs/sprint2/g05-diagnostic-source/` at `6262d98bbd2fad951d850a2ff4dafdecfaac8ca8` (unverified HELLO_ACK successor to the fixture-only `cf77aff`).
The portable overlay and hashes are in `sddm-lab-g05-diagnostic.patch` and
`sddm-lab-g05-diagnostic.json`. It applies on traced `c9cf9b7`; it does not
enter the production series or modify production commit `480332c`.

## Blocking review correction — 2026-10-28

**Offline preparation is BLOCKED, not ready for deployment.** The independent
review withdrew its initial readiness/deadlock-safety verdict. See the
[complete closure review](../../docs/reviews/g05-offline-2026-10-28.md) for six
controller defects and the required negative tests. `lab/test_success_first_negative.py`
now records ten synthetic offline checks: one held/same-boot baseline passes,
nine intentionally fail against the unchanged controller. The fixture places
winner selection before the nominal deadline and loser exit after it. The
prelaunch gate check specifies a request-scoped gate before PID discovery;
update the real-helper fixture and controller together when implementing it.
See the [offline protocol specification](../../docs/reviews/g05-controller-protocol-2026-10-29.md)
for identity, ordering and bounded independent recovery requirements. Death recovery requires an
explicit durable `recovery.json` failure verdict, not a silently swallowed unlink.
These tests are specifications, not proof of PAM behavior or safe recovery.
The current helper now requires a bounded explicit unarmed HELLO_ACK bound to auth ID, request, method and generation before backend/PAM; wrong-generation ACK fails before PAM in the isolated selfcheck. Armed ACK is deliberately rejected until daemon-owned prelaunch reservation and recovery are implemented. Nine negatives remain red. The sequence below describes historical diagnostic behavior, **not** an approved prelaunch/recovery protocol or proof that the current controller implements the new specification.

## Diagnostic behavior and scope

- An owner-created root-only `/run/fplogin-g05/hold-password-<request>` gate
  exists **before** password-helper launch. The real helper waits before PAM;
  the collector links its held PID to the helper's generation and request.
  The password helper can therefore remain the live loser while the normal
  terminate/5-second-kill sequence completes. It is never SIGSTOPed by this
  gate. Remove the gate after observed exit; an unattended gate fails closed
  after 40 seconds. Never count a password win as success-first.
- After a genuine fingerprint `pam_authenticate rc=0`, a separately created
  root-only `/run/fplogin-g05/hold-<request>-<pid>` gate can defer its real
  `AUTHENTICATED` frame. Release only from the guest's monotonic deadline-armed
  baseline with a safety margin before the configured deadline. Require
  `winner-selected < t0+duration < loser-helper-exit < loser-barrier-release
  < session-result` on the same boot/request/generation, and **no**
  `deadline-fired` for that winner: winning disarms the timer. A premature
  loser exit or failed gate release makes the case partial/blocked.
- Timeout-first: the same fingerprint gate may be released only after the
  correlated `deadline-fired` and before the normal kill. The diagnostic
  `late-auth-discard` records a valid, identifier-only AUTHENTICATED frame
  received **while the original helper is still alive and stopping**; no
  authentication signal or winner-gate transition is emitted. Require
  `pam rc=0 < deadline-fired < late-auth-discard < helper-exit`, absence of
  winner/authorization/session and a terminal `timed_out` only after exit.
  Without the discard event it is partial, not verified. This checks late
  delivery of a genuine *earlier* PAM success, **not** PAM returning success
  after the deadline; it cannot complete strict G05 timeout-first acceptance.
- The diagnostic wait blocks the helper's Qt event loop; its existing SIGTERM
  notifier remains queued, and the daemon retains its original bounded
  terminate/kill. This induces a controlled delay of SIGTERM processing.
  No SIGTERM handler, winner gate, PAM policy or deadline duration was changed.
  The 40-second hold is a failure limit, not permission to keep a failed attempt alive.
  The autonomous controller (`lab/g05-success-first-controller.py`) forks a
  companion watchdog that monitors a pipe: if the controller process is terminated
  or killed (including SIGKILL), the watchdog attempts gate unlink. It swallows
  unlink errors and neither cancels the attempt nor observes helper exit;
  gate removal does not guarantee that a helper is no longer stuck. Controller failure requires owner-supervised
  verification of unlinked gate files, cancellation and observed helper exit; do not
  start another attempt while any helper remains.

Offline selfchecks: isolated build passed; the actual helper with disposable
mock PAM produced rc=0 then an AUTHENTICATED frame after SIGTERM and before
exit. Separate transport QtTest observed `late-auth-discard` without a winner;
integrated daemon test `G05IntegratedTest` demonstrated genuine mock-PAM
deadline-fired -> late-auth-discard -> helper-exit without winner or session;
existing daemon tests for both orderings and loser barrier passed. Real password
helper was held before PAM and reaped; disposable SIGSTOP/kill and failure
SIGCONT paths left no process. The watchdog test observed file removal only.
One full CTest run passed 9/9; the claim of deterministic resolution is withdrawn.
Besides fixture visibility checks, diagnostic Display.cpp changes the D-Bus
activation timeout from 5000 to 6000ms while retaining the 5000ms probe deadline.
This behavioral change is not in production and needs further scope/repeatability
review. The integrated test's SIGKILL exit is not normal PAM cleanup.
No guest, reader or real fingerprint was checked.
Logs are private at `.work/evidence/sprint2/g05-diagnostic-offline/`.

## Exact reversal, only if a separate owner-approved deployment occurs

The deployment owner must first verify guest recovery, stop SDDM **outside an
attempt**, export original allowlisted events, and preserve a **new**, private,
non-overwriting guest backup of the three originals below (bytes, mode, owner,
SHA-256). Refuse deployment if any original differs from the old ten-entry
`installed-sha256.json`, or if a helper is active. Never overwrite the prior
2026-10-20 backup. Record the backup path and diagnostic installed hashes.

| Guest file | Original SHA-256 |
|---|---|
| `/usr/local/bin/sddm` | `7d799bab8dcb71fc4aa2038283750690d2768343fabc9835dbe7ca316b448dc2` |
| `/usr/local/libexec/sddm-helper` | `1b61e4e8f4f2f10ca11aa42eadcd0eff6ca3ec4e5a2cf8cc35d50d2ff5924812` |
| `/usr/local/libexec/fplogin-collect-sddm-lab.py` | `5b44b067d9854e2f7de476f209c54b08f255b6a43ea21ab32ad1610bf871079c` |

For reversal: stop the diagnostic collector after exporting its allowlisted
originals outside the guest; stop SDDM outside an attempt. Confirm by exact
`/proc/*/exe` enumeration that no SDDM helper/daemon is active or stopped
(`State: T/t`); a process-name-only grep is insufficient. Remove only
`/run/fplogin-g05/hold-*` for the recorded attempt after confirming their
request/PID, then remove that diagnostic directory once empty. Validate all
three private backup hashes against the table **before** writing. Stage each
backup beside its destination with original root ownership and mode, fsync,
atomically replace only those three paths and fsync their parent directories.
Check their restored hashes, then check **all ten** installed-file hashes
against `.work/labs/sprint2/traced-20261020-activation/installed-sha256.json`;
report and stop on any mismatch. Do not restart SDDM automatically. Preserve
backup and evidence; do not recreate the VM disk or touch guest PAM, host
services, reader ACL, enrollment or production patch/checkpoint. Only the
physical-test owner may perform guest reversal and subsequent VM/reader handback.
