# SDDM patch series

The series targets SDDM `v0.21.0` (`63780fcd79f1dbf81a30eef48c28c699ab15aded`). Apply it after the pinned Arch CMake compatibility change `228778c2b4b7e26db1e1d69fe484ed75c5791c3a`; this series does not include or replace that packaging change.

Apply in listed order with `git am` or `git apply` from the SDDM source root. The patch adds request/method identity, deferred winner authorization, concurrent password/fingerprint helpers, greeter control IPC, peer-PID verification, bounded nonblocking helper framing, stale-result rejection and queued context replacement. PAM packaging and QML/theme behavior remain out of scope.

The patch includes source corrections for all five blockers recorded in `docs/reviews/sprint-1-security-review.md` after review of `4312169`: helper handshake receiver handoff, cancellation winner exclusion/barrier release, session-helper logout lifecycle, and launch-generation-scoped timers. The clean pinned patch applies and the Qt 6 source build completes in an isolated Arch container; CTest passes 4/4. No focused coordinator/transport, isolated PAM, SDDM login/session, autologin, X11-cookie, or physical-reader scenario has been run. Sprint 1 remains **unaccepted**; see `docs/reviews/sprint-1.md` and the independent security review.
