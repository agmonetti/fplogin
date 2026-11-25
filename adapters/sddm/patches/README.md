# SDDM patch series

The series targets SDDM `v0.21.0` (`63780fcd79f1dbf81a30eef48c28c699ab15aded`). Apply it after the pinned Arch CMake compatibility change `228778c2b4b7e26db1e1d69fe484ed75c5791c3a`; this series does not include or replace that packaging change.

Apply in listed order with `git apply` from the SDDM source root. The series adds request/method identity, deferred winner authorization, concurrent password/fingerprint helpers, greeter control IPC, peer-PID verification, bounded nonblocking helper framing, stale-result rejection and queued context replacement. `0002` also includes the embedded fallback theme; original fplogin theme assets are distributed separately. PAM packaging remains out of scope.

### 0001-concurrent-authentication-methods.patch

The patch includes the security-review corrections, the production winner gate, and a remediation for the helper socket-disconnect/SIGKILL race, destructor-time timers, and logind session reuse. `AuthAttemptGate` covers winner and cancellation order; `AuthTransport` includes a real `Auth`/socket exchange with a synthetic helper that disconnects after authorization and exits 0. Accepted and verified on physical Synaptics `06cb:00bd` hardware.

### 0002-greeter-api-and-theme-lifecycle.patch

Delivers correlated greeter/daemon context IPC, automatic fingerprint start, generation-bound helper retries, prompt proxy state machine, controlling-view ownership, and guarded embedded theme fallback.

The viewport correction remains included: the embedded password theme reserves the active virtual keyboard's geometry and scrolls focused controls into view. Original theme assets separately declare `QtVersion=6` and use the same keyboard-aware viewport behavior.

The activation-corrected `0002` has SHA-256 `1706624e0af02e08bc264b8ab95d26bdfa11637deaa0577df0f2ba33584da4ca`, source `480332c33ee463606a8284a33854077820e9286f`. Initial selection and explicit Retry can activate installed inactive fprintd once within the five-second total availability deadline, then pin device/enrollment queries to its unique owner. Expected initial owner acquisition is allowed; owner loss/replacement and stale replies are invalidated. No keepalive or automatic restart loop.

Supplemental patches `0003`..`0006` (Qt5 compatibility, availability deadline, security hardening, and legacy Qt5/Qt6 theme auto-fingerprint) live under `platforms/arch/sddm-fplogin/`. See [Sprint 7 Validation Review](../../../docs/reviews/sprint-7.md).

