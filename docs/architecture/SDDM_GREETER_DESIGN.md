# Sprint 2 — SDDM greeter and theme design

**Date:** 2026-10-05  
**Status:** Sol design and implementation handoff; not Sprint 2 acceptance.  
**Prerequisite:** Sprint 1 is accepted and closed. Its [independent acceptance review](../reviews/sprint-1.md#2026-10-04-sol-independent-acceptance-review--sprint-1-gate) is authoritative; do not repeat that gate before beginning this sprint.

## 1. Scope and governing decisions

Implement [Implementation Plan, Sprint 2](../IMPLEMENTATION_PLAN.md#sprint-2--greeter-api-and-sddm-theme), retaining the [authentication design](SDDM_AUTHENTICATION_DESIGN.md) and accepted ADRs. QML expresses intent and displays daemon state. The daemon owns context, request UUIDs, helper selection, cancellation and the winner gate. PAM authenticates and enforces account/session policy; fprintd matches fingerprints. Neither core nor the install-time adapter participates in login.

Deliver a Qt 6 fplogin theme and its safe greeter API. Do not implement packaging, installation, enrollment, wallet unlocking, an alternative authentication broker, or a fprintd/PAM-module fork. Do not modify host PAM, host SDDM configuration, the active display manager or enrollment slots. Theme assets belong under `adapters/sddm/assets/theme/`; SDDM changes remain a pinned patch series.

## 2. Inspected baseline and remaining API work

The source baseline is SDDM `v0.21.0`, commit `63780fcd79f1dbf81a30eef48c28c699ab15aded`, plus Arch CMake delta `228778c2b4b7e26db1e1d69fe484ed75c5791c3a` and the accepted `0001-concurrent-authentication-methods.patch`. The temporary inspection checkout is not a permanent dependency.

Observed source facts, not new Sprint 1 findings:

- `GreeterProxy` already exposes `authenticationMethodsAvailable`, `fingerprintState`, `fingerprintRequestId`, `startFingerprint(user, sessionIndex)` and `cancelFingerprint()`.
- Its method-state decoder discards the numeric state, uses `detail` as the state string, and adopts every received request UUID. The payload lacks username/session binding. Its finished decoder discards success and winning method.
- `Display::startFingerprint` cancels on a different context but does not queue that replacement fingerprint start. Method-only cancellation can precede knowledge of the UUID at the greeter. These seams need an explicit context acknowledgement and latest-context queue.
- `Display::authorizeWinner` and `finishMethodAttempt` currently publish `matched` without identifying the method; a password winner must not appear as a fingerprint match.
- The helper/PAM path exposes information/error conversations and authentication results, not eight typed reader states. `PamBackend::converse` has message styles; these are not a stable sensor-status protocol.
- `GreeterApp::addViewForScreen` creates one QML root per screen but shares one proxy. Its error handler loads `qrc:/theme/Main.qml`; loading a fallback alone does not invalidate a partial theme's authentication intent.

Sprint 2 completes this API surface. It does not change first-success-wins, loser-exit-before-authorization, dedicated PAM services or logind session reuse.

## 3. Context ownership and correlation

### 3.1 Two identities, different authorities

Use a greeter-local monotonically increasing `quint64 contextSerial` and a daemon-generated UUID `request_id`:

- The proxy, not QML, increments the serial on every user/session selection change, context clear and fresh attempt after a completed attempt. A → B → A has three different serials. Socket reconnection starts a fresh serial domain and clears all cached state.
- The serial binds intent before a daemon UUID arrives. It is scoped to the owning socket and is **not** authentication evidence.
- The daemon validates the concrete username and resolved `Session`, owns the UUID and associates both with the serial and socket. Never select a context from an unsolicited state event.
- After a failed/cancelled completed attempt, an explicit new start advances the serial and creates a new UUID even if the selected user/session is unchanged. A serial has at most one acknowledged UUID. Password and fingerprint transactions in the same live attempt share its UUID; a fingerprint-only retry within that attempt uses a new helper launch generation, not a new context that would cancel password. Successful completion keeps that greeter socket committed until retirement; it is not permission for another automatic attempt.
- Existing helper launch generations continue to reject callbacks from a prior helper run. Capture the bound context and generation in every new asynchronous probe, timer and progress callback.

Selection changes invalidate the old attempt before stopping helpers. Keep only the latest replacement context and requested fingerprint start; launch it after the old helpers have exited. Do not drop the replacement or create a second live helper for either method. A password submitted for the latest context uses the existing bounded pending-login mechanism; clear obsolete pending passwords when superseded.

A context-clear request works even before acknowledgement: it has a newer serial, so late acknowledgements, availability probes, method events and results from the old serial cannot update the proxy. A stale method cancellation never acts on a later serial/UUID.

### 3.2 Acknowledgement and commit boundary

Send a context acknowledgement before any method event for that UUID. The proxy accepts a positive acknowledgement only for its latest requested serial and exact username/session identity. A repeated positive acknowledgement must carry the same UUID; an unsolicited new UUID never replaces the binding. Only then may matching method events update its snapshot.

Before session authorization, a valid owning-socket context change invalidates the attempt, including a selected winner still awaiting loser exit. Once winner session authorization has been issued, context replacement is rejected as `session_committed`; it cannot retarget the authorized PAM transaction. Publish that phase before authorization and lock the selection controls until success/failure. Do not display a newly selected account as the identity of an already committed login.

For a UI action racing this boundary, a rejection echoes the rejected request's serial with `accepted=0`, `session_committed` and the actual committed UUID/user/session. Process it only if the rejected serial is the latest pending selection and the returned tuple exactly matches the previous acknowledged context retained by the proxy. Restore that prior binding for completion/failure; never decrement the serial allocator or accept an arbitrary rejection as a new context. This does not authorize the greeter to change the winner.

Context clear, controller promotion and theme fallback obey the same commit boundary. Before commit, clear invalidates and stops the old attempt. The daemon sends an accepted clear acknowledgement only after old helpers exit and all old-attempt feedback is suppressed; this ordered barrier has empty UUID/user, `Session(UnknownSession, "")`, unavailable/idle and `cleared` detail. The proxy retains suppression of uncorrelated legacy feedback until that matching barrier, and does not submit a fallback password before it.

If clear races session authorization, reject it as `session_committed`. Retain correlated routing and the previous acknowledged tuple, disable replacement activation/submission, and consume that committed attempt's completion. A successful committed login proceeds normally; after committed failure, issue a fresh clear serial and enter legacy password fallback only on its accepted barrier. Never try to retract a positive authorization, attach a fallback password to the committed transaction, or claim that changing a view cancelled an already authorized login.

While a selection/clear acknowledgement is pending, retain at most one completion matching the previous acknowledged tuple without displaying it as the new selection's result. A matching `session_committed` rejection restores the tuple and consumes that retained completion; an accepted replacement/clear discards it. This covers a final result arriving before the rejection. Successful completion keeps controls/submission locked until greeter retirement and never targets the established user-session helper for view cleanup.

## 4. Paired method-protocol cutover

The existing stock `Connect`, `Login`, power messages, hostname, power capabilities, `LoginSucceeded`, `LoginFailed` and `InformationMessage` retain their numeric values and wire shapes. Preserve stock password-only themes and autologin.

The unreleased Sprint 1 method payloads cannot carry the required context. Cut over daemon, proxy and all method clients together; do not reinterpret those payloads in place or retain compatibility parsers/aliases:

- Reserve retired greeter method opcodes 7–8 and daemon method-event opcodes 6–7; never reuse their numbers.
- Keep `AuthenticationCapabilities` at daemon opcode 5 with its existing `quint32` bitset shape. Bit `0x1` is the retired method protocol; a Sprint 2 daemon does not advertise it. Bit `0x2` denotes this correlated method protocol. Send this response **only** after the new payload-free `QueryAuthenticationCapabilities` request, never unsolicited on stock `Connect`: an old unframed decoder cannot skip the new payload.
- Append the new messages below with explicit numeric values. An updated proxy queries after `Connect` and enables method control only for `0x2`. A stock upstream daemon can ignore the payload-free unknown query and continue password login. A Sprint 2 daemon supports stock and Sprint 1 proxies in password-only mode by sending only stock frames unless queried/opted in. A Sprint 1-patched daemon requires the paired daemon upgrade: it emits retired method events even for password `Login`, so an updated proxy must report `daemon_upgrade_required` on its `0x1` capability and refuse that unsupported mixed-version session rather than pretend it can skip those payloads.
- Opt into correlated events with `SetAuthenticationContext(has_context=1)`. Context clear (`has_context=0`) leaves correlated mode only at the accepted clear-acknowledgement barrier described above. Do not send method/context payloads to a non-opted-in socket; capability responses require an explicit query, and clear has its explicit acknowledgement. Legacy password login continues without a context-control call.
- Keep the public `startFingerprint`/`cancelFingerprint` names; migrate their implementation and all method-wire consumers. Do not add deprecated API aliases.

Protocol support starts false and a missing query response never delays password login against a stock daemon. The unsupported Sprint 1-daemon pairing is detected by its `0x1` response before any incompatible method traffic is requested; report the paired-upgrade requirement rather than offer a falsely working fallback.

| Direction / opcode | Message | Ordered payload |
|---|---|---|
| greeter → daemon / 9 | `QueryAuthenticationCapabilities` | None |
| greeter → daemon / 10 | `SetAuthenticationContext` | `serial:u64`, `has_context:u32`; if true: `user:QString`, existing `Session` encoding |
| greeter → daemon / 11 | `StartAuthenticationMethod` | `serial:u64`, `method:u32` |
| greeter → daemon / 12 | `CancelAuthenticationMethod` | `serial:u64`, `request_id:QString`, `method:u32` |
| daemon → greeter / 8 | `AuthenticationContext` | `serial:u64`, `accepted:u32`, `request_id:QString`, `user:QString`, `Session`, `availability:u32`, `phase:u32`, `detail_code:QString` |
| daemon → greeter / 9 | `AuthenticationMethodState` | `serial:u64`, `request_id:QString`, `method:u32`, `user:QString`, `Session`, `state:u32`, `phase:u32`, `detail_code:QString` |
| daemon → greeter / 10 | `AuthenticationAttemptFinished` | `serial:u64`, `request_id:QString`, `user:QString`, `Session`, `result:u32`, `winning_method:u32` |

`method` retains `Password=0`, `Fingerprint=1`; start/cancel accept only fingerprint. Define `NoWinner=2` for finished results without a winner. Availability is `Unknown=0`, `Available=1`, `Unavailable=2`. Result is `Failed=0`, `Succeeded=1`, `Cancelled=2`. Phase is `Idle=0`, `Active=1`, `WinnerSelected=2`, `LoserStopping=3`, `SessionAuthorized=4`, `Finished=5`. All boolean-like wire fields are `quint32` restricted to 0/1, not mixed Qt boolean encodings.

The proxy may send an empty cancellation UUID only before initial acknowledgement of that serial. The daemon requires exact current/pending serial and owning socket, cancelling only the fingerprint start/run bound to it; a completed attempt's replacement always has a new serial. Once acknowledged, the proxy sends the UUID and the daemon requires equality. An unknown/stale nonempty UUID cannot become a wildcard. Context clear cancels the whole old attempt, not merely its fingerprint method.

Acknowledged availability may subsequently change for that same serial/UUID as the probe completes. Duplicate starts during an active fingerprint run are idempotent, not retries. Structural decoding uses Qt stream transactions on both peers, the existing bounded input policy, closed enums and complete payload validation before dispatch. Never log password fields or arbitrary PAM text when reporting malformed traffic.

The daemon's context record is socket-owned: a second socket cannot attach a password to it, change selection, cancel it or receive its events. Reject that conflict without invalidating the owner's attempt. Reuse the existing attempt and pending-login fields where possible; do not create a second coordinator or duplicate authoritative user/session values.

For an opted-in socket, password submission retains the legacy `Login` payload but receives correlated password method/final events. The proxy derives the existing QML `loginFailed`/`loginSucceeded` signals from the matching events and ignores duplicate uncorrelated legacy result frames. A password-method failure emits `loginFailed` without ending an active fingerprint run. Non-opted-in themes retain stock aggregate result handling.

## 5. GreeterProxy contract

Extend the existing proxy rather than add a second authentication controller:

- `setAuthenticationContext(user, sessionIndex)` and `clearAuthenticationContext()` express/clear selection. Resolve session indexes through `SessionModel` immediately; the bound identity is session type plus filename, never a mutable list index.
- `startFingerprint(user, sessionIndex)` is retained and delegates to the selected-context/start path. An invalid/empty username, invalid session, unsupported protocol or fallback-disabled control never starts a helper.
- `cancelFingerprint()` targets only the current serial/UUID fingerprint run, including a start awaiting acknowledgement. It leaves a matching password transaction available.
- Existing `authenticationMethodsAvailable` means **protocol support**, not reader/enrollment presence.
- Add read-only `authenticationUser`, `authenticationSessionIndex`, `fingerprintAvailable`, `fingerprintDetailCode` and `authenticationBusy` properties. `fingerprintAvailable` is true only after a current-context positive availability probe; unknown is false with `checking` detail, not a claim that a reader is absent.
- `fingerprintState` becomes one canonical state key from the table below, not a PAM display string. Retain `fingerprintRequestId`; expose a correlated `authenticationFinished(requestId, user, sessionIndex, result, winningMethod)` signal.
- Update all snapshot fields before emitting their notification signals. A request-change observer must never see a new UUID paired with the previous user's state. On context replacement/disconnect, clear the old snapshot immediately and await matching daemon acknowledgement.
- `authenticationBusy` locks selectors/submission once a winner is selected or session authorization is committed and remains locked after successful completion until greeter retirement. A scanning reader alone never disables password entry/submission. A pending password submission may disable only duplicate password submission, not text focus or reader status. A clear barrier/fallback transition gates submission separately while its acknowledgement is pending.

No writable QML success/match/winner property. No PAM service name, password, fingerprint template, device path, enrollment list or reusable credential in these properties/events.

## 6. Availability and eight reader states

### 6.1 Availability and bounded service activation

For a concrete selected context, the daemon performs bounded asynchronous `GetDevices` and `ListEnrolledFingers(user)` queries through its existing Qt D-Bus infrastructure. It does not claim a reader, call `VerifyStart`, match, enroll or delete prints. Return only availability and an allowlisted reason to the proxy, not finger names or templates. A positive probe is advisory; actual authentication still occurs solely through `pam_fprintd`.

**2026-10-20 owner-authorized activation correction:** initial selection and explicit Retry first resolve the service's unique owner. Only `NameHasNoOwner` may trigger one asynchronous `StartServiceByName`; resolve the owner again afterward and send all device/enrollment queries to that unique name. Activation and queries share one five-second total deadline. A missing service, activation failure or unavailable bus returns unavailable without delaying password authentication. There is no keepalive, periodic probe or automatic restart loop.

An initial empty-to-owned service acquisition while the bounded probe has not pinned a different owner is expected, including acquisition caused by that probe's activation. It must not cancel its own probe. Owner loss/replacement, context replacement, clear, teardown and deadline invalidate outstanding replies. Confirm the owner again before publishing positive availability. A service change by itself never starts a new probe or authentication; explicit Retry may re-probe and reactivate an installed inactive service. Keep only the latest pending context and a bounded device list. Availability must never delay password authentication.

### 6.2 State sources and honest meanings

Wire states have explicit values: `Unavailable=0`, `Ready=1`, `Scanning=2`, `Retry=3`, `Matched=4`, `Failed=5`, `Cancelled=6`, `TimedOut=7`.

| QML key | Daemon-authorized source / meaning | UI behavior |
|---|---|---|
| `unavailable` | Unsupported control, no concrete context, missing service/reader/enrollment or inability to establish availability | Explain reason; password remains usable; no automatic loop |
| `ready` | Current-context positive availability, before method launch | Selected user's fingerprint login is available; start once for this activation |
| `scanning` | Fingerprint helper has entered its PAM authentication phase | Verification is pending; not proof of sensor acquisition; password stays focused/usable |
| `retry` | Nonterminal fingerprint `PAM_ERROR_MSG` advisory while PAM authentication is still active | Generic “Try again or use your password”; do not launch another helper |
| `matched` | Current fingerprint helper's valid successful PAM authentication result | “Fingerprint recognized; completing login”; not `LoginSucceeded` and not account-policy success |
| `failed` | Authentication/helper failure, exhausted tries or account/session failure | Explain with stable generic code; permit explicit retry after cleanup |
| `cancelled` | Requested fingerprint cancellation with actual helper exit observed, or cancellation of a queued start that never launched | No active reader claim is implied before observed cleanup; password remains usable |
| `timed_out` | Daemon-owned fingerprint deadline expired and helper exit was observed | Explicit retry only; password survives |

Suppress repeated identical progress snapshots. Unknown PAM messages do not invent sensor facts. A `PAM_ERROR_MSG` advisory is not by itself a terminal authentication failure; the subsequent typed PAM result determines termination. A password winner emits password matched/finished events, never fingerprint `matched`; the fingerprint loser finishes as cancelled after exit.

### 6.3 Timeout distinction

[`pam_fprintd` v1.94.5](https://gitlab.freedesktop.org/libfprint/fprintd/-/blob/v1.94.5/pam/pam_fprintd.c) returns `PAM_AUTHINFO_UNAVAIL` for timeout **and** service/device/enrollment failures. Its retry/timeout prose is localized. Do not parse that prose or classify this return code alone as `timed_out`.

Add a daemon-owned finite fingerprint-authentication deadline, default 30 seconds, using the existing SDDM configuration machinery. This is a total authentication-phase budget, not a per-finger retry budget; internal PAM retries do not reset it. It starts on helper launch, is scoped to context/UUID/helper generation, and never times out password authentication.

Each fingerprint launch has one terminal authentication decision. Disarm its deadline on accepted `AUTHENTICATED` success, terminal failure/unavailability, explicit cancellation or losing-method cancellation. Expiry may act only while that generation is still awaiting authentication: invalidate the fingerprint method, deny authorization, use the accepted asynchronous terminate/five-second kill/observed-exit path, then publish `timed_out`. Success-first survives loser cleanup and winner account/session work even beyond the old deadline; timeout-first rejects late success. The deadline is never a timer on an authorized winner or its user session.

An earlier ambiguous PAM unavailable return is reported as `unavailable` with `authentication_unavailable`, not falsely as a known timeout. Sprint 3 must align its packaged PAM timeout/retry policy with this outer deadline; this sprint neither rewrites host PAM nor changes the module. User-facing text distinguishes the outer request deadline from an unavailable authentication service.

### 6.4 Helper progress transport

Implement the already reserved helper opcode `Msg::METHOD_STATE=8` rather than add a competing transport. Payload: `request_id:QString`, existing `AuthMethod` encoding, `user:QString`, `state:u32`, `detail_code:QString`. `Auth` validates helper/socket identity, bound user, request and allowed progress states before forwarding a typed signal; `Display` also checks current context and launch generation.

`PamBackend` emits scanning immediately before `pam_authenticate`, retry for a `PAM_ERROR_MSG` encountered while that call is active, and a typed generic failure/unavailability after the call returns. Expose the existing stored `PamHandle::m_result` through a read-only result accessor; do not run PAM a second time or replace the boolean authentication API. Fingerprint progress contains allowlisted codes only, never raw conversation text. Preserve the stock password PAM conversation path.

Helper progress cannot select a winner, authorize a session, assert cancellation completion or assert a daemon timeout. `AUTHENTICATED` remains the only PAM-success input to the existing gate. Accept helper progress only for scanning/retry/failed/unavailable; matched, cancelled and timed_out are daemon-owned outcomes. Preserve a typed terminal reason until helper exit so the generic exit callback does not overwrite unavailable or the daemon's cancellation/timeout decision.

For the opted-in greeter, replace new fingerprint information/error forwarding with those typed events. Correlate and sanitize password feedback to stable codes as well; a stale uncorrelated `InformationMessage` must not overwrite the selected user's method display. Legacy password-only themes keep their existing information/result behavior.

## 7. Theme and lifecycle

Author original MIT theme code; do not copy GPL upstream theme/component implementation into the project. Prefer Qt Quick, Qt Quick Controls 2 and Qt Quick Layouts provided by Qt 6. No Plasma imports, shell commands, direct system-bus authentication or custom image/font dependency is needed for a usable login.

Use one modest login panel: explicit user selector, session selector, labelled password field, login button, selected-user fingerprint status, cancel/retry control and capability-gated power controls. Use system fonts, scalable layouts, high-contrast text and visible focus indicators. Every meaningful state has text, not only color/animation. Buttons/fields have accessible names; Tab/Shift-Tab traverses a deterministic order, Enter submits password, Space activates focused buttons and Escape cancels fingerprint without clearing/submitting the password.

The concrete initial user may be the validated remembered user or the first valid local-user model row. `UserModel` exposes `name` (login identity) separately from `realName`; `lastIndex` defaults to zero, so validate count and row before using it. An empty/unknown user or invalid session keeps fingerprint unavailable until selection is concrete. Do not start while a manual username is being edited; commit it through an explicit selection action. `SessionModel` watches session-directory changes: retain type/filename across a reset and invalidate the context if that session disappears, never silently reuse an index now naming a different session.

Automatic start occurs once when the controlling view is ready, the current user/session is acknowledged and availability becomes positive. No Enter press or password interaction is required. Terminal failure/cancellation/timeout does not automatically restart; retry is explicit. A real user/session change creates a new activation. Rendering/status notifications and additional monitor roots are not activations.

There is one controlling view, owned by `GreeterApp`, initially the primary screen. Only it exposes selection/password/power controls and automatic start; other roots display the shared selected identity/status without starting/cancelling methods. Controller ownership is explicit and read-only to QML; the upstream `primaryScreen` context boolean is only a creation-time snapshot and cannot serve as the owner flag. Controller-screen loss/promotion clears context before a new activation; wait for the accepted clear barrier, or preserve the committed tuple with controls disabled if clear is rejected after authorization. A surviving view may render that committed identity while awaiting completion, but cannot start a replacement. Destruction of a noncontrolling mirror must not cancel the controller's attempt.

User/session changes clear local password text, invalidate precommit context immediately and auto-start only the replacement's acknowledged fingerprint context. Only a current-context password-submission failure may otherwise clear that field: fingerprint retry/failure/unavailability/cancellation/timeout must not erase in-progress password text. Password bytes remain only in the field and existing password submission/PAM path, never a new shared state object. The plan's no-theme-readable-secret requirement excludes publishing credentials in method state; the password field necessarily holds the user's typed text.

Controlling-root destruction and theme load failure request clear in C++; do not rely solely on QML `Component.onDestruction`. Selection/lifecycle changes cannot retract committed authorization; route completion as described in §3.2. Precommit greeter/socket loss invalidates the attempt; normal greeter retirement after a successful session must not terminate the user session.

Actual daemon/display shutdown and explicit power actions are teardown, not selection replacement. Invalidate pending authorization and stop still-running authentication helpers through the existing bounded termination path; if positive authorization was already delivered, teardown may terminate that transaction but cannot erase any account/session side effect already performed. Do not send a second authorization response or start a replacement winner. For suspend/hibernate/hybrid sleep, observe authentication-helper cleanup asynchronously before the power action, without blocking the daemon event loop or targeting a normally established user-session helper. No hidden fingerprint reactivation after resume without a fresh visible activation.

## 8. Embedded password fallback

Retain `qrc:/theme/Main.qml` as the fallback. In `GreeterApp`, handle theme failure for the whole greeter rather than leaving one screen on a failed custom theme and another still issuing biometric requests:

1. Disable method control/automatic start for this greeter instance and request context clear before replacing roots. Preserve correlated completion handling if authorization already committed.
2. Destroy partial custom roots and load the embedded theme once for all screens; guard against recursive fallback if the embedded theme itself fails.
3. Recreate valid root/config/model bindings as needed; do not dereference `rootObject()` before a successful load.
4. Enable the embedded `sddm.login` route and stock result signals only after the matching accepted clear barrier. Precommit helpers from the failed theme have then exited and remain ineligible. During a committed race, render completion without accepting replacement password submission; on failure, clear again before enabling fallback.

Do not turn arbitrary runtime QML warnings into fallback or claim to detect every faulty third-party script. Construction/load errors trigger fallback; usability of the shipped theme is established by actual-surface verification. If the embedded theme cannot load, exit cleanly for the normal daemon restart/recovery path; do not loop or present a blank screen as a working fallback.

## 9. Security acceptance for this slice

Before Sprint 2 acceptance, demonstrate:

- A delayed acknowledgement/state/result cannot attach to another serial, user, session, socket or UUID, including A → B → A.
- Cancel before acknowledgement and precommit context/power/destruction paths invalidate before any later success can win. Clear/fallback/controller changes racing session authorization preserve the committed tuple and suppress replacement submission until completion and the accepted opt-out barrier.
- The explicit compatibility matrix preserves stock-peer password operation without unsolicited new payloads. Detect the unsupported updated-proxy/Sprint-1-daemon pairing instead of desynchronizing its unframed stream.
- Only a current fingerprint PAM success produces fingerprint matched; account denial never becomes login success.
- No raw PAM conversation, password, template or environment/cookie dump in new UI state, logs or visual evidence. Screenshots omit visible password entry; identifiers suffice for traces.
- Two screens produce one controlling activation and one fingerprint helper, not competing selections or destructor cancellations.
- Partial precommit theme startup followed by fallback leaves a usable password surface and no eligible obsolete biometric request; delayed legacy feedback cannot clear a new password across the opt-out barrier.

## 10. Observed planning-time evidence and limits

On 2026-10-05:

- Reconstructed the pinned source plus Arch delta and applied the accepted patch successfully. No Sprint 1 build, physical matrix or acceptance review was repeated.
- `docker ps -a` showed all fplogin containers stopped; no QEMU process was found. `lsusb -d 06cb:00bd` identified `/dev/bus/usb/001/004`; `getfacl -p` showed only root owner/group and other entries, with no named-user lab ACL. `systemctl show fprintd.service -p LoadState -p UnitFileState -p ActiveState -p SubState` reported `loaded`, `static`, `inactive`, `dead`. No host mutation or service activation was necessary. Reading `/root/fplogin-reader.acl` was unavailable without a sudo password; exact saved-ACL equality is not claimed.
- Ran the existing real `/usr/local/bin/sddm-greeter-qt6` in the disposable `fplogin-remediation-traced:local` image with `--network none`, offscreen/software Qt and a synthetic local-socket peer. Sent A/scanning, B/scanning and a late A/matched. The real proxy displayed `PROBE_STATE 11111111-1111-4111-8111-111111111111 matched` after the late event. This exercises the current presentation correlation gap, not PAM authentication or a daemon-authority bypass.
- Ran that greeter with `--test-mode --theme /tmp/fplogin-missing-theme` and a five-second timeout. Observed `Fallback to embedded theme` and `Adding view for "" QRect(0,0 800x800)`, followed by the planned SIGTERM. Existing embedded component warnings and an empty-session-model TypeError were present in this offscreen container. Loading is proven; usable login, accessibility and visual fidelity are not.

No new theme/API implementation is claimed. Sprint 2 remains unaccepted until the execution plan's actual SDDM surface, genuine PAM and physical-reader scenarios pass. Neither the synthetic probe nor the existing Sprint 1 acceptance substitutes for that evidence.
