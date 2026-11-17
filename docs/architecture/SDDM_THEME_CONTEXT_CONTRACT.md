# SDDM theme context contract — nonvisual cooperation

**Date:** 2026-11-17. **Status:** owner-authorized direction and first context-publication prototype; automatic fingerprint integration is incomplete, not installed or accepted. Sprint 3 remains unaccepted. The [replacement-form proposal](SDDM_COMMON_LOGIN_DESIGN.md) remains withdrawn.

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
| **T2 — stable lifecycle and shared policy** | Model resets/removal, ready/exposure contract, hidden target semantics, all controller/root/commit races and fingerprint-vs-password feedback routing; shared start-once/cancel/retry policy. Review changed callers/tests before source edits. | NOT RUN; blocks enabling automatic scanning. |
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

Initial failures are retained: test-harness compilation rejected list initialization of explicit `Session` constructor; corrected to direct `Frame()` initialization. An intermediate masked-input visual test compared a pre-input content-dependent `boundingRect` with a post-input one; the harness now compares actual item position/size and still requires exact image equality. Initial invalid-user/session tests found missing clear publication: validity is a separately evaluated QML binding. Adding its change handler, while retaining valid-target handlers, passes the original assertions plus invalid→valid restoration across clear acknowledgement. Independent architect corroborated this source-supported mechanism; no instrumented historical callback chronology is claimed. Existing invalid-index display bindings still emit two `undefined`→QString warnings; they were not silently fixed/restyled. Host LSP lacks isolated SDDM/Qt include paths; actual container compilation/tests, not its cascading missing-header errors, provide C++ verification.
