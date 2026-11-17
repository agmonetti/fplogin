# SDDM common login proposal — WITHDRAWN

**Date:** 2026-11-17. **Status:** rejected direction, not an implementation plan. No source changes, builds, package/guest deployment or physical tests were performed for this proposal.

## Owner requirement

The existing SDDM login must remain exactly the same visually and interactively while fplogin provides automatic fingerprint alongside password for the same selected account/session. No second account, panel, login-mode switch, replacement form or extra biometric login stage.

The owner's earlier choice of one login did **not** authorize replacing its interface. The subsequent clarification explicitly rejects that consequence. It supersedes the common-surface proposal, not accepted authentication safety invariants or historical sprint evidence.

## Rejected direction

A greeter-owned exclusive form would provide authoritative pre-submit user/session selection, but would replace or hide the original theme's controls. A neutral built-in form would additionally discard its appearance. Neither meets the clarified requirement. Do not implement the former C0–C6 proposal or interpret its planning review as approval of these appearance changes.

A separate biometric selector is also rejected: it could target an account/session different from the original theme's visible selection.

## Remaining technical question

The stock theme API publishes current user/session on `sddm.login`, not necessarily before submission. Remembered defaults are not proof of a theme's current selection. Arbitrary themes can use private controls, so adding a proxy property or observing only shared widgets cannot establish universal selection reporting.

At withdrawal, nonvisual integration had not yet been authorized or implemented and the actual theme still needed inspection. The owner subsequently supplied its source and authorized [the nonvisual theme-context contract and initial prototype](SDDM_THEME_CONTEXT_CONTRACT.md). That current record supersedes this investigation's next-step wording, not the rejection of a replacement form. Universal untouched-theme support remains unproven; never guess widget names or substitute remembered values for current selection.

Preserve daemon/PAM authority, request correlation, user/session invalidation, first-success-wins, losing-helper cleanup and password-only recovery. No host package, PAM, service, enrollment or reader modification is authorized by this investigation.

## Next step and gates

Historical next step at withdrawal was to identify and inspect the actual theme. Current work and remaining gates are recorded in [the nonvisual contract](SDDM_THEME_CONTEXT_CONTRACT.md); it requires explicit theme cooperation and does not reinstate this proposal.

The existing pre-physical review remains applicable: `.work/evidence/sprint3-qt5/theme-independence-review-20261117/report.md`. Source `.work/sddm/sprint3-qt5/` remains at `deaee9b94c79486a7b7e65715c3b438cabe9e09e`, unchanged. E7 remains PASS only for its previous password-compatibility scope; expanded biometric support is unresolved. Sprint 2 remains closed; Sprint 3 remains unaccepted. Physical validation requires its separate fresh authorization and prerequisites.
