# SDDM patch series

The series targets SDDM `v0.21.0` (`63780fcd79f1dbf81a30eef48c28c699ab15aded`). Apply it after the pinned Arch CMake compatibility change `228778c2b4b7e26db1e1d69fe484ed75c5791c3a`; this series does not include or replace that packaging change.

Apply in listed order with `git am` or `git apply` from the SDDM source root. The current patch adds helper method/request identity, deferred winner authorization, concurrent password/fingerprint helper coordination, and greeter method-control IPC/API. `sddm-fingerprint` PAM packaging and QML/theme behavior remain future sprint work.

Build/test evidence so far: upstream SDDM configured and built in an isolated current Arch container with Qt 6; all four CTest tests passed. Physical-reader, isolated PAM transaction, simultaneous race, session-reuse, autologin-regression, and actual greeter scenarios remain unverified. This is not Sprint 1 acceptance.
