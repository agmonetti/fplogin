# SDDM theme context contract — nonvisual cooperation

**Date:** 2026-11-17. **Status:** owner-authorized direction, retained context-publication prototype and tested offline Qt5 automatic-start prototype. Full lifecycle/distribution/physical acceptance is incomplete; nothing is installed. Sprint 3 remains unaccepted. The [replacement-form proposal](SDDM_COMMON_LOGIN_DESIGN.md) remains withdrawn.

## 1. Product boundary

Keep the user's existing SDDM theme, layout, password field, selectors and normal login interaction. No additional login/account panel, replacement form or requirement to switch between authentication modes. Password and automatic fingerprint must refer to the **same current user/session**.

There is no reliable scraper for arbitrary private QML selection state. The stock `login(user, password, sessionIndex)` call reveals it only on submission. Remembered defaults, display labels, widget names and screenshots are not authoritative current selection.

The sustainable compatibility contract is **any compatible theme that explicitly publishes its current context**. A theme may adopt nonvisual bindings without altering its graphics. Shared components can simplify adoption but cannot discover private controls in themes that do not use them. No per-theme name allowlist, heuristic source rewriting or claim of universal untouched-theme biometric support. Propose the contract upstream after evidence/review; no upstream adoption is implied now.

Unadapted themes keep password-only compatibility. Do not silently turn the legacy `login` route into an automatic biometric opt-in or change accepted daemon/PAM arbitration.

## 2. API and authorities

Reuse the existing correlated greeter API; no new PAM service selector, protocol opcode or authentication broker:

| Surface | Contract |
|---|---|
| `setAuthenticationContext(loginUsername, sessionIndex)` | Explicitly publish current user/session intent. Use the actual login username, never realName/display text. Proxy resolves the session to type + filename and daemon validates/acknowledges the tuple. |
| `clearAuthenticationContext()` | Invalidate intent on loss of valid selection/readiness. Only the controlling root may request theme-originated clear; global controller/root replacement remains `GreeterApp`'s responsibility. Accepted clear waits for old-attempt drain. |
| `authenticationMethodsAvailable` | Correlated protocol support, not evidence of reader/enrollment. Feature-detect the API and preserve stock-daemon/theme-runtime password behavior. |
| `authenticationController` | Greeter-owned screen authority. Additional roots cannot publish/clear/start competing contexts. Never infer this from a widget name or creation-time `primaryScreen` flag. |
| `themeAuthentication` | Explicit theme opt-in to one greeter-owned nonvisual policy; register the actual window/root, publish selection and request cancel/retry. Shared stable selection across roots, not shared passwords or a new PAM authority. Distribution is still experimental. |
| Proxy snapshot/acknowledgements | Execution binding and commit state. Publication is intent, not proof of acknowledgement, availability, matching or success. |
| Existing `login(user, password, sessionIndex)` | Submit the password for that same current tuple; preserve password fallback. Invalid selection cannot substitute an invented account. |

The theme owns selection and presentation intent only. SDDM daemon/helpers/PAM retain request UUIDs, helper generations, availability, authentication, first-success-wins, losing-helper cleanup and account/session policy. Password remains in its existing field/submission path, never shared context state, logs or template data.

**Important side effect:** publishing context on the real patched daemon can probe device/enrollment availability and activate installed fprintd. It is not a purely local property write. Zero fingerprint-start frames prove no requested authentication start, **not** absence of real-daemon availability/service work. Current tests use a synthetic socket peer, not a real daemon or reader.

## 3. Complete integration requirements

Before enabling automatic start for a consumer:

- Publish initial current selection after usable controlling-surface readiness; handle capabilities arriving later. Defaults are usable only when adopted by the actual theme, not guessed externally.
- Invalidate on user/session changes, invalid/removed selections, hidden/destroyed surface and controller transfer. Clear password on actual target change; fingerprint-only status/failure must not erase typed password or trigger the theme's password-error animation.
- Preserve stable username and session type/filename across model resets/reorders, not just row indexes. Late acknowledgements/events must not relabel a new target; A → B → A remains separately correlated.
- Respect busy/authorization gates: selection cannot retarget a committed session. Restore the committed tuple after rejected replacement; do not terminate an established user session on greeter retirement.
- Use **one shared nonvisual automatic-start policy**, not copied per-theme authentication logic: one start after current acknowledgement/positive availability, no Enter required, no notification-driven retry loop; explicit cancel/retry and bounded cleanup. Decide its reusable packaging/API after lifecycle review, not by inventing a new privileged service.
- Keep fallback password-only and observe existing clear/commit barriers. Multi-screen roots must share the intended target without conflicting hidden selections or mirror teardown clears.
- Preserve appearance and ordinary keyboard/mouse behavior. Functional safety changes (such as rejecting invalid identities and freezing target changes after commit) are explicit, not a claim of byte-identical behavior in every failure state.

This particular theme intentionally hides user/session labels by default. It still has a real selected tuple. Before automatic scanning, resolve and test its hidden-selection/multi-screen semantics **without silently enabling new visible controls**. The first publication test does not certify a visibly disclosed target, actual compositor readiness or physical usability.

## 4. First consumer and actual first slice

Source: `/home/agus-hy/where-is-my-sddm-theme`, commit `2fddf85ec80ff02a8e20fdcba51a30b436d76e6c`, subdirectory `where_is_my_sddm_theme_qt5`. MIT license retained. The external checkout has pre-existing deletions outside that Qt5 directory; leave them untouched. No external theme/install/config is modified.

- Portable base: `tests/fixtures/themes/where-is-my-sddm-qt5/` (six original text files, including license). No private background, credential or owner account configuration.
- Integration: `adapters/sddm/integrations/where-is-my-sddm-qt5/0001-publish-authentication-context.patch` and `provenance.json` with source/base/patch hashes. This is a **theme integration patch**, not accepted SDDM patch `0001`; never add it to `adapters/sddm/patches/series`.
- Preparation: `tests/integration/theme-context/prepare.py` verifies hashes/inventory, applies only to a new repository `.work/labs/sprint3/` destination and refuses overwrite. It is not an installer or arbitrary-theme rewriter.
- Test harness: `tests/integration/theme-context/` compiles the real pinned `GreeterProxy`, `SessionModel`, `ScreenModel` and configuration consumers against a private synthetic peer, then loads the actual copied theme. Production SDDM clone remains clean at `deaee9b94c79486a7b7e65715c3b438cabe9e09e`.

The patch publishes selection on the controlling shown root, responds to late capabilities, clears invalid/hidden context and blocks user cycling/password submission while committed. It uses one resolved username for context and password and removes the existing `|| "123test"` invented-account fallback. It does not add, remove or restyle visual Items. Stock API missing all extensions remains usable by password.

**Not implemented in this slice:** automatic `startFingerprint`, reusable start policy, Retry/Cancel interaction, model-reset stable selection, full controller promotion/committed-rejection display reconciliation, multi-screen target synchronization or deployment. Therefore this patch is not ready for installation/physical closure. Its shown-window check is only prototype readiness, not proof that the surface is legible/exposed on every compositor.

## 5. Execution order and gates

| Step | Required work | Current scope |
|---|---|---|
| **T0 — contract/baseline** | Record explicit cooperation/appearance boundary, immutable theme/source provenance and independent plan review. | Direction documented; original files preserved. |
| **T1 — publication prototype** | Actual-theme/real-proxy regression: pre-Enter exact login name/session, late capabilities, switches, invalid clear/restoration, legacy password, controller/mirror gates and scoped render comparison. | Implemented and tested offline; **zero authentication-start frames**. Not the complete integration. |
| **T2 — stable lifecycle and shared policy** | Model resets/removal, ready/exposure contract, hidden target semantics, all controller/root/commit races and fingerprint-vs-password feedback routing; shared start-once/cancel/retry policy. Review changed callers/tests before source edits. | Automatic-start prototype implemented and tested **offline only**, as detailed below. Direct session reorder/removal, broader lifecycle/compositor cases and independent core acceptance remain pending; not installation-ready. |
| **T3 — packaging/dual Qt** | Decide module/API distribution, adapt a Qt6 consumer and one consumer without `SddmComponents`; supplementary source/checkpoints only if needed; clean dual builds, full suites, recipe/archive/ABI/render/reproducibility checks. | NOT RUN. Qt5 cooperation does not prove general Qt6/untouched-theme support. |
| **T4 — guest/physical validation** | Fresh authorized guest deployment, original-theme real password login/recovery and installed-hash checks; separately fresh owner reader handoff for automatic fingerprint/concurrency/account/session/retry/deadline tests. | NOT RUN; no host/service/reader authorization from this prototype. |
| **T5 — independent review/owner acceptance** | Review actual implementation/evidence, preserve checkpoint/bundle as applicable, update dashboard/capture before push or milestone closure and request explicit Sprint 3 acceptance. | NOT RUN. E7 remains historical PASS for the narrower password-compatibility scope. |

## 6. Reproduction and verification limits

Run from the fplogin repository root:

```sh
python3 -m unittest discover -s tests/integration/theme-context -p '*_test.py' -v
bash tests/integration/theme-context/run-container.sh UNIQUE_RUN_LABEL
```

The runner uses pinned local container image `sha256:0ccf97570aa91d4d68ea7f2800d33b23df983290ea5ad86c9f5ba6c1c1ab254b`, network disabled, unprivileged UID, read-only production source and original/adapted theme mounts. It depends on the retained SDDM Qt5 generated constants and extracted packaged `SddmComponents`; missing inputs block execution. The image adds only `qt5-graphicaleffects 5.15.19-1` to the retained E4 runtime. No dependency was installed on the host. Logs, exits and image/dependency identity are under `.work/evidence/sprint3-qt5/theme-contract-20261117/`; each runner label refuses overwrite. Test source/build are reconstructible from tracked inputs; this is not a portable production package.

The render comparison uses the actual theme at 1024×768 on Xvfb/software Qt5, matching password geometry and exact image bytes for empty and known masked-synthetic input. Cursor blinking is disabled in both roots solely for deterministic comparison. No actual password or PAM authentication is involved. This does not establish all fonts/scales/animations, Wayland, actual-screen or physical visual equivalence.

Portable integrity/results record: [`verification.json`](../../adapters/sddm/integrations/where-is-my-sddm-qt5/verification.json), binding the private evidence index, exact code hashes, review and verified unchanged-source bundle. No private logs/images or guest state are tracked.

Verification so far: four preparation regressions PASS and final Qt5 CTest **1/1 PASS**, QTest **14 PASS** (12 consumer rows plus init/cleanup), zero failures/skips. Both original/adapted PNG pairs have identical file hashes. The runner's used-label control exits 4 before overwriting evidence. This is a tested publication prototype, not a completed T2 integration or physical acceptance.

Initial T1 failures are retained: test-harness compilation rejected list initialization of explicit `Session` constructor; corrected to direct `Frame()` initialization. An intermediate masked-input visual test compared a pre-input content-dependent `boundingRect` with a post-input one; the harness now compares actual item position/size and still requires exact image equality. Initial invalid-user/session tests found missing clear publication: validity is a separately evaluated QML binding. Adding its change handler, while retaining valid-target handlers, passes the original assertions plus invalid→valid restoration across clear acknowledgement. Independent architect corroborated this source-supported mechanism; no instrumented historical callback chronology is claimed. Existing invalid-index display bindings still emit two `undefined`→QString warnings; they were not silently fixed/restyled. Host LSP lacks isolated SDDM/Qt include paths; actual container compilation/tests, not its cascading missing-header errors, provide C++ verification.

## 7. Owner choices and automatic-start prototype (T2, offline only)

The owner explicitly chose **scan as soon as the theme appears for its actual selection, even when user/session labels are hidden**, preserving the customization. Hidden labels are not grounds for substituting a guessed target or revealing new controls. **Escape cancels fingerprint; F4 explicitly retries.** No new visible buttons, status messages or help-overlay lines are added. Configurable buttons/messages/shortcuts chosen during installation and persisted in a configuration file are a future product direction, **not implemented or authorized installer work in this slice**.

### Implemented boundary

`SDDM::ThemeAuthentication` is a single unprivileged greeter-owned object, exposed explicitly to cooperative themes as `themeAuthentication`. It is inactive for unadapted roots. The Qt5 consumer registers its actual window/root and adopted defaults, then delegates selection/cancel/retry; it does not copy the scan policy. The controlling registered root alone can select or act. Mirrors consume the same username and session type/filename, never their private defaults, and never receive another root's password. GreeterApp selects the controller before publishing the QML controller flag and retains its existing global clear/drain and fallback authority.

Readiness requires completed registration, a visible root/window, non-minimized `QWindow::isExposed()` and a valid selection. This is an actual Qt window exposure gate, **not proof of legibility, occlusion handling or compositor/physical readiness**. Auto-start consumes one logical intent **before** sending Start, only with current correlated ACK/UUID, matching tuple, positive availability and existing submission/busy gates. Failure, timeout, cancellation, repeated notifications, hidden→shown or controller promotion do not rearm that same intent. Escape inhibits before Cancel. F4 is the explicit restart, including one daemon reprobe when availability is unavailable; checking/terminal probe feedback releases the pending explicit request without creating a notification-driven retry loop.

Actual target changes, including synchronous A → B → A, invalidate through the existing clear/drain barrier before republishing the latest intent. User-model reset/reorder preserves the login name, session lookup preserves type/filename, and removed identities are invalid rather than replaced with another row/default. Same-identity reindex does not erase the local password or rearm automatic start. Committed rejection restores the correlated target before promotion; hidden/retired roots do not cancel an authorized session. A separate proxy correction records password-feedback provenance in the retained snapshot: fingerprint-only/cancel/fingerprint-account failures no longer emit the theme's password `loginFailed` animation/clear; real password failures and legacy routing are retained.

### Portable inputs and source reconstruction

- Retained T1 `0001-publish-authentication-context.patch` and its provenance/verification remain unchanged.
- New theme patch: `adapters/sddm/integrations/where-is-my-sddm-qt5/0002-automatic-authentication.patch`, applied **after the theme T1 patch**, not accepted SDDM `0002`.
- Supplementary source checkpoint: `sddm-theme-automatic-policy.patch` beside the theme patch, relative to E7 source `deaee9b94c79486a7b7e65715c3b438cabe9e09e`. It is **not in the accepted series or package recipe**.
- Source candidate: `.work/sddm/sprint3-theme-auto/`, commit `33fbaeeb8d2381520d27e01d7eebb38bc186c76f`. Production Sprint2/E7 clones, recipes, theme assets and accepted patches/series stay unchanged.
- Exact source/patch/code/bundle hashes and exercised results: [`automatic.json`](../../adapters/sddm/integrations/where-is-my-sddm-qt5/automatic.json). Clean replay at `.work/sddm/sprint3-theme-auto-replay/` matches **all 372 source files**; the self-contained full-history source bundle is `.work/checkpoints/sddm-theme-auto-20261117.bundle`.

To reconstruct separately, first reconstruct the E7 supplemented source using [the Qt5 plan](../SPRINT_3_EXECUTION_PLAN.md), verify its manifest, then apply `sddm-theme-automatic-policy.patch` to a **new persistent Git clone**. Alternatively clone the recorded source bundle. Do not apply the checkpoint to the production clone or overwrite an existing directory. The preparer applies only the two theme patches to a new laboratory copy:

```sh
python3 tests/integration/theme-context/prepare.py --automatic .work/labs/sprint3/NEW_THEME_COPY
python3 -m unittest discover -s tests/integration/theme-context -p '*_test.py' -v
bash tests/integration/theme-auto/run-container.sh UNIQUE_RUN_LABEL
```

The automatic runner uses the pinned image/constants/components documented for T1, the separate candidate source, `.work/build/sprint3-theme-auto/consumer/` and unique theme/evidence destinations. It never contacts a real daemon/PAM/reader or installs anything. Full source builds use `.work/build/sprint3-theme-auto/qt{5,6}/`. Private original evidence and exact commands/exits are under `.work/evidence/sprint3-qt5/theme-auto-20261117/`.

### Verification actually exercised

- Preparation **5/5 PASS**; T1 retained publication regression **1/1 CTest /14 QTest PASS**, zero authentication starts.
- Actual Qt5 theme + actual shared policy/proxy/session model, synthetic socket peer: **1/1 CTest /23 QTest PASS** (21 rows plus init/cleanup), zero failures/skips. Includes pre-Enter exposed start, late/repeated availability, Escape/F4 and repeated unavailable recovery, typed-password retention on four terminal states, clear barrier, mirror defaults/promotion, user reset/reorder/removal, unchanged-session reset, asynchronous/synchronous A → B → A, root/window loss, committed-selection gate and racing clear rejection restoring rendered/shared identity, stock fallback and render comparison.
- Candidate source complete suites: **Qt5 9/9**, **Qt6 10/10**, zero failures/skips; Qt6 includes unchanged accepted fplogin theme (13 QTests). Proxy suite includes seven feedback-provenance rows. Real GreeterApp adds a complementary synthetic cooperative-theme test of two roots on **one QScreen**, promotion without automatic retry and embedded fallback opt-out, on both Qt versions.
- Original/adapted empty and masked-synthetic PNG pairs have identical file bytes and password geometry at 1024×768, Xvfb/software Qt5; adapted captures inspected. This does not establish every layout/animation/scale or a personalized private background.
- Architect preflight and integration review caught and corrected coalesced-intent correlation and unavailable-Retry issues. The reviewer then **coauthored the core**: its final review is **not independent core acceptance**. Independent acceptance is pending.

Retained first-run failure: policy signal `targetChanged` collided with `Connections.targetChanged`, preventing QML loading; the harness subsequently dereferenced a missing root. Renaming the signal `identityChanged` passes loading and the final suite; the original failed run remains preserved. A 300-second host-tool wait expired while the Qt6 build continued; subsequent `docker wait` returned 0 and original configure/build/CTest exits all record 0. Existing invalid-index display `undefined`→QString warnings remain; do not claim warning-free QML. Active host LSP cannot resolve isolated Qt/generated headers; actual clean container compilation is the compile check.

**Remaining gates:** directly exercise session reorder/removal and broader lifecycle/committed races, independent core review, actual multi-monitor/compositor/surface behavior, Qt6 original-theme consumer, T3 distribution/package/ABI/reproducibility and fresh-authorized T4 guest/reader validation. No real automatic reader activation or login is claimed. This is preserved T2 offline progress, **not full T2 closure, a package update, deployment or Sprint3 acceptance**.
