# SDDM concurrent authentication design

**Status:** Sprint 0 design baseline for SDDM `v0.21.0`  
**Scope:** Runtime authentication inside the patched SDDM tree. The fplogin adapter installs and verifies this integration; it does not participate in login-time authentication.

## 1. Pinned baseline

| Input | Pin |
|---|---|
| SDDM upstream tag | `v0.21.0` |
| SDDM upstream commit | `63780fcd79f1dbf81a30eef48c28c699ab15aded` |
| Arch package | `sddm 0.21.0-7` |
| Arch packaging tag | `0.21.0-7` |
| Arch packaging commit | `d31bfcbb0a8d2a8ca7ee4fd01d5d8dacdb1de729` |
| Arch package source checksum | `67394c93f331fc02f89559f68e149a992efaed07690f548e6a83ec384ebb8000` |
| Arch packaging delta | Cherry-pick upstream commit `228778c2b4b7e26db1e1d69fe484ed75c5791c3a` for CMake 4 compatibility |

The supported source baseline is the upstream tag plus the Arch packaging delta. fplogin patches must apply after that delta and must not silently follow SDDM's `develop` branch.

## 2. Stock message and PAM flow

The stock path is serial and owns one `Auth` object per display:

```text
QML theme
  sddm.login(user, password, sessionIndex)
    ↓
GreeterProxy::login
  GreeterMessages::Login(user, password, Session)
    ↓
daemon SocketServer::readyRead
  Display::login → Display::startAuth
    ↓
Display::m_auth (one Auth instance)
  QProcess: sddm-helper --id … --user … --start …
    ↓
HelperApp::doAuth
  PamBackend::start → pam_start("sddm", user)
  PamBackend::authenticate → pam_authenticate → pam_acct_mgmt
    ↓
Msg::AUTHENTICATED(user)
    ↓
Auth::authentication(user, success)
  Display::slotAuthenticationFinished
    ↓
daemon replies with session environment and X cookie
    ↓
winning helper (stock has no competing helper)
  pam_setcred(PAM_ESTABLISH_CRED)
  pam_open_session
  UserSession::start
```

PAM prompts travel in the opposite direction as `Msg::REQUEST`. `Display::slotRequestChanged` supplies the stored password. PAM information and errors travel as `Msg::INFO` and `Msg::ERROR`.

Stock `Display::startAuth` rejects a second request while `m_auth` is active. Stock `HelperApp` also proceeds directly from successful authentication to session setup when `--start` is present. Therefore merely constructing a second helper is insufficient: without a daemon-owned winner gate, two successful helpers could both enter session creation.

## 3. Public QML API limitation

At this baseline `GreeterProxy` exposes one authentication slot:

```cpp
void login(const QString &user, const QString &password, int sessionIndex) const;
```

The greeter protocol exposes only `GreeterMessages::Login`; daemon responses expose only aggregate login success/failure and information text. There is no public operation to:

- start a dedicated fingerprint PAM service;
- identify an authentication method;
- bind method progress to a daemon-generated request ID and selected user;
- cancel one method without cancelling another; or
- submit an independently obtained fingerprint result as authenticated.

A theme-only implementation cannot cross this boundary safely. An empty password still invokes the normal `sddm` PAM path and is not evidence of fingerprint verification.

## 4. Coordinator boundary

`Display` owns one `AuthenticationAttempt` coordinator. A logical attempt binds these immutable values:

- daemon-generated nonzero UUID `request_id`;
- selected username;
- selected `Session` identity;
- display/seat identity;
- zero or one transaction per `AuthMethod`;
- attempt state and optional winning method.

`AuthMethod` is a closed enum with `Password` and `Fingerprint`. It is never a theme-provided PAM service name. The helper maps `Password` to `sddm` and `Fingerprint` to `sddm-fingerprint`.

The coordinator enforces these transitions:

```text
idle → active → winner_selected → loser_stopping → session_authorized
                 ↘ failed
active → cancelled
```

Rules:

1. Only a success carrying the current `request_id`, method, and username is eligible.
2. The first eligible success changes `active` to `winner_selected`; later results cannot change the winner.
3. The daemon withholds post-authentication authorization from every helper until it selects a winner.
4. The loser receives no session environment or cookie and must never call `pam_acct_mgmt`, `pam_setcred`, `pam_open_session`, or start `UserSession`.
5. The winner is authorized only after the loser process exits or reaches the bounded forced-termination path.
6. A user, session, display, or greeter-context change invalidates the attempt before cancellation begins. Late messages from that attempt are ignored after structural validation.
7. Fingerprint failure affects only the fingerprint transaction. The attempt remains available for password submission.
8. Attempt completion emits aggregate success exactly once and starts at most one session.

Qt delivers the helper socket callbacks on the daemon event loop, so the guarded `active → winner_selected` transition is serialized. The implementation must still centralize the transition in one coordinator method rather than duplicate checks in signal handlers.

## 5. Greeter ↔ daemon messages

Existing password themes remain compatible through `Login`. New messages use typed fields; numeric enum values are explicit in the patch and append-only within this SDDM protocol revision.

### Greeter to daemon

| Message | Fields | Meaning |
|---|---|---|
| `StartAuthenticationMethod` | `method`, `user`, `Session` | Request a method for a concrete context. Sprint 1 accepts only `Fingerprint`; the daemon allocates `request_id`. |
| `CancelAuthenticationMethod` | `request_id`, `method` | Cancel only the named method. A stale ID is acknowledged as stale and cannot cancel a newer attempt. |
| existing `Login` | `user`, password bytes, `Session` | Submit password. If context matches an active attempt, add/replace only its password transaction. If context differs, invalidate the old attempt first. |

The password remains confined to the existing password request path and is sent only to the password helper. It is never included in a method-state event or log.

### Daemon to greeter

| Message | Fields | Meaning |
|---|---|---|
| `AuthenticationCapabilities` | capability bitset | Declares whether method control is supported. It does not claim that a specific user has an enrolled print. |
| `AuthenticationMethodState` | `request_id`, `method`, `user`, `state`, stable detail code, display text | Reports `unavailable`, `ready`, `scanning`, `retry`, `matched`, `failed`, `cancelled`, or `timed_out`. |
| `AuthenticationAttemptFinished` | `request_id`, result, optional winning method | Correlated terminal result for the current context. |
| existing `LoginSucceeded` / `LoginFailed` | no new credential fields | `LoginSucceeded` is emitted once for the winning attempt. `LoginFailed` remains the response to a failed password submission so existing themes clear/report the password failure; it does not cancel an active fingerprint method. |

`GreeterProxy` exposes read-only current fingerprint state/request properties plus start/cancel slots. QML displays state and expresses user intent; it never selects PAM services or asserts success.

## 6. Daemon ↔ helper messages

Every authentication message after `HELLO` carries `request_id` and `method`. The helper also receives those values at launch and echoes them in `HELLO`; `Auth::Private` rejects a mismatch before routing any result.

| Direction | Message | Required fields |
|---|---|---|
| helper → daemon | `HELLO` | helper instance ID, `request_id`, method |
| helper → daemon | `REQUEST` | `request_id`, method, typed PAM prompts |
| daemon → helper | `REQUEST` | same identity and responses; password responses only for `Password` |
| helper → daemon | `METHOD_STATE` | identity, user, typed state, stable detail code, bounded display text |
| helper → daemon | `AUTHENTICATED` | identity, PAM-resolved user, result of `pam_authenticate` only; account management has not run |
| daemon → helper | `SESSION_AUTHORIZATION` | identity, `proceed` boolean; environment/cookie only when true |
| helper → daemon | `SESSION_STATUS` | identity and open/start result |

A helper that succeeds at `pam_authenticate` waits for `SESSION_AUTHORIZATION`. `proceed=false` causes normal helper cleanup and `pam_end` without account management, credential establishment, or session open. `proceed=true` lets that same PAM handle run `pam_acct_mgmt`, `pam_setcred`, and `pam_open_session`, preserving PAM transaction continuity while ensuring only the winner crosses the account/session boundary.

A socket `CANCEL` message is not the cancellation primitive because `pam_authenticate` is synchronous and the helper event loop cannot consume it while `pam_fprintd` waits. Cancellation remains process-based.

## 7. Cancellation boundary

Stock `Auth::stop` sends `SIGTERM`, waits up to five seconds, then sends `SIGKILL`. `sddm-helper` installs a `SIGTERM` handler with `SA_RESTART` and dispatches it through a Qt socket notifier. While `pam_authenticate` blocks, the event loop cannot run that notifier. A waiting `pam_fprintd` transaction therefore remains alive after `SIGTERM` and reaches the forced-kill path.

The Sprint 1 coordinator must make this path asynchronous in the daemon:

1. invalidate the transaction and withhold session authorization;
2. call `QProcess::terminate`;
3. start the existing five-second deadline without blocking the daemon event loop;
4. call `QProcess::kill` if the helper remains alive;
5. wait for `QProcess::finished` before authorizing the winner;
6. publish `cancelled` only after exit is observed.

Graceful `pam_end` is expected when PAM returns or a helper receives `proceed=false`. Forced termination is the bounded fallback for a module blocked inside PAM. The process boundary closes its fprintd D-Bus connection; the implementation must verify that the reader can be claimed again before session launch.

## 8. Patch boundary approved for Sprint 1

The minimal production patch touches these SDDM-owned areas:

- `src/common/Messages.h`: typed greeter/daemon method messages;
- `src/greeter/GreeterProxy.{h,cpp}`: method state plus start/cancel API;
- `src/daemon/SocketServer.{h,cpp}`: serialization and validation;
- `src/daemon/Display.{h,cpp}`: `AuthenticationAttempt` ownership and winner gate;
- `src/auth/Auth.{h,cpp}` and `AuthMessages.h`: method/request identity, deferred session authorization, asynchronous stop completion;
- `src/helper/HelperApp.{h,cpp}` and `src/helper/backend/PamBackend.cpp`: fixed method-to-service mapping, typed states, and authorization wait.

No QML code becomes an authentication authority. No arbitrary PAM service name crosses the greeter socket. No fplogin core or adapter process participates at login time.
