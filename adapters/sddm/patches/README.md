# SDDM patch series

The series targets SDDM `v0.21.0` (`63780fcd79f1dbf81a30eef48c28c699ab15aded`). Apply it after the pinned Arch CMake compatibility change `228778c2b4b7e26db1e1d69fe484ed75c5791c3a`; this series does not include or replace that packaging change.

Apply in listed order with `git am` or `git apply` from the SDDM source root. The patch adds request/method identity, deferred winner authorization, concurrent password/fingerprint helpers, greeter control IPC, peer-PID verification, bounded nonblocking helper framing, stale-result rejection and queued context replacement. PAM packaging and QML/theme behavior remain out of scope.

Build/test evidence: configured and built the patched source in the isolated Arch container using Qt 6; all four CTests passed. The seven findings in `docs/reviews/sprint-1-security-review.md` have source-level corrections, but the Qt tests still do not exercise coordinator races, malformed IPC, isolated PAM, X11 cookie delivery, session reuse, autologin, or physical-reader cancellation. Sprint 1 remains **unaccepted** until those scenarios are tested and independently reviewed.
