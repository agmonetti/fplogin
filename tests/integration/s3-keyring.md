# Sprint 3 keyring evidence (guest only; desktop observation pending)

This collector traces only entry/return, guest monotonic time, PID/TID and numeric return codes for `pam_open_session` and both real `pam_sm_open_session` hooks. It does not read PAM arguments, conversations, memory, keyring contents or raw journal. Trace the actual authorized candidate, not an altered PAM stack or substitute modules.

1. Before requesting a fresh owner single-reader handoff, use a disposable verified copy and check privileged ttyS0 recovery and signed stock rollback. On the guest only, prepare a representative GNOME Keyring/KWallet PAM runtime from compatible signed packages; keep a disposable user with representative keyring state. Record package versions/hashes, guest boot, candidate/helper identity, installed PAM stack, and operator scenario. Both session modules must be installed and configured through `sddm-fingerprint` → `session include sddm`. This script specifically expects `pam_kwallet5.so`, as in the current candidate stack; a different module or unresolvable symbol is **blocked**, not permission to change the packaged PAM policy. Verify `bpftrace` supports `nsecs(monotonic)`, uprobes and uretprobes under the guest kernel; do not weaken kernel restrictions to run it. Do not combine with deadline fault injection.
2. Use two privileged guest shells. With SDDM stopped and no existing target session (`loginctl list-sessions`), launch from the first shell using reviewed copies of the adjacent tooling. Use the known **guest** machine ID from the preflight record, not a value dynamically copied from the machine running the command. Start with an unused directory:

   ```sh
   bash ./s3-keyring-capture.sh GUEST_MACHINE_ID /root/s3-keyring-ATTEMPT
   ```

   In the second shell, wait for at least two `heartbeat` lines, confirm the printed tracer PID is alive and `trace.stderr` is empty, and check the recorded input hashes against the reviewed installed artifacts. Do not start SDDM on uncertain health. The tracer has a 180 s ceiling; stop and reschedule if prerequisites are not ready. Confirm the complete action/recovery sequence before starting SDDM; have the owner use one enrolled scan, no password, and report whether the greeter or newly opened desktop asked for any extra input or appeared blocked. If there is a prompt, do not answer it during the attempt. Record this observation and its scope separately from probe evidence, including desktop/keyring state and observation duration.
3. While the new session is active, and with the tracer still running, confirm there is exactly one new target `seat0` user session and capture it (substitute the actual session ID and test user):

   ```sh
   umask 077
   python3 ./s3-keyring.py snapshot SESSION_ID fplab > /root/s3-keyring-ATTEMPT/session.json
   ```

   Wait for the next heartbeat after the snapshot, then send `kill -TERM TRACER_PID` to the verified guest tracer PID, not SDDM or the wrapper. Check successful wrapper exit. Preserve the allowlisted result files outside the guest before shutdown; inspect any unexpected stderr locally for secrets before exporting it. Record controlled guest shutdown and owner-only handback separately.
4. Offline, run `python3 tests/integration/s3-keyring.py verify EVIDENCE_DIR fplab`. The verifier requires clean capture, a shared boot, both call/return pairs inside one successful libpam call on the same thread, and a later active Wayland `sddm-fingerprint` `seat0` logind snapshot with that helper as session leader. If there is ambiguity, incomplete coverage, a dropped-event warning, or missing invocation, report **BLOCKED**. Operator no-prompt/no-block is visual testimony, not inferred from this metadata. Review optional-module return codes as recorded; they do not by themselves prove keyring unlock, nor is unlock required by this check. This does not replace the fingerprint `VerifyStart`/result collector or full PAM and Sprint 3 review.

For the prepared `fplab`/Hyprland guest, `s3-keyring-physical.sh` automates the capture. Stage it next to the current capture wrapper, probe and verifier. After a fresh authorized handoff, run from the guest's ttyS0 recovery shell:

```sh
bash ./s3-keyring-physical.sh EXPECTED_GUEST_MACHINE_ID EXPECTED_BOOT_ID
```

The runner leaves the confirmed session open even if trace verification reports **BLOCKED**. This preserves the desktop observation, not a passing trace verdict. Before manually logging out, note whether the desktop responds and whether a prompt appears on its own. Then request a disposable test credential from an application and record whether a prompt appears and allows later unlock. Do not capture or record passwords. Export evidence, stop the guest and complete owner handback explicitly.

Offline checks: `python3 tests/integration/s3-keyring-test.py`. They do not attach probes, validate the guest kernel/tool compatibility, or run PAM.
