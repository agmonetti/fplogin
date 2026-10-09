# SDDM patch series

The series targets SDDM `v0.21.0` (`63780fcd79f1dbf81a30eef48c28c699ab15aded`). Apply it after the pinned Arch CMake compatibility change `228778c2b4b7e26db1e1d69fe484ed75c5791c3a`; this series does not include or replace that packaging change.

Apply in listed order with `git apply` from the SDDM source root. The series adds request/method identity, deferred winner authorization, concurrent password/fingerprint helpers, greeter control IPC, peer-PID verification, bounded nonblocking helper framing, stale-result rejection and queued context replacement. `0002` also includes the embedded fallback theme; original fplogin theme assets are distributed separately. PAM packaging remains out of scope.

### 0001-concurrent-authentication-methods.patch

The patch includes the earlier five security-review corrections, the production winner gate, and a remediation for the helper socket-disconnect/SIGKILL race, destructor-time timers, and logind session reuse. `AuthAttemptGate` covers winner and cancellation order; `AuthTransport` includes a real `Auth`/socket exchange with a synthetic helper that disconnects after authorization and exits 0. The final physical-reader matrix R01–R16 passed with genuine guest PAM and the Synaptics `06cb:00bd` reader. Sprint 1 is **accepted and closed** by the [2026-10-04 independent review](../../../docs/reviews/sprint-1.md#2026-10-04-sol-independent-acceptance-review--sprint-1-gate).

### 0002-greeter-api-and-theme-lifecycle.patch

Integrated Sprint 2 implementation according to [SPRINT_2_EXECUTION_PLAN.md](../../../docs/SPRINT_2_EXECUTION_PLAN.md). Delivers correlated greeter/daemon context IPC, automatic fingerprint start, generation-bound helper retries, prompt proxy state machine, controlling-view ownership, and guarded embedded theme fallback. Verified in an isolated Arch Qt 6 build container with all 10 CTest suites passing and synthetic PAM helper/surface smoke tests passing. Physical reader matrix G01–G16 requires owner authorization and explicit hardware handoff before sprint acceptance.

The 2026-10-09 viewport correction is included in current `0002` (SHA-256 `fdeeefe687d0842f3c3f25f618fa41b7fcf852c1582c4b078b7462c6c01a2fb6`, source `c1cddef7863422e32c8434ec4b298b2c7c38ad4e`). The embedded password theme reserves the active virtual keyboard's geometry and scrolls focused controls into view. Original theme assets separately declare `QtVersion=6` and use the same keyboard-aware viewport behavior. The current complete pinned series builds successfully; nine production suites and the separate external-theme suite pass. Physical acceptance remains pending.

