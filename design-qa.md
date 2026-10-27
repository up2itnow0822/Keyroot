# Keyroot design verification

Status: selected light/dark review and bounded synthetic controller/phone journeys verified locally. Full Phase 2 and physical/account admission remain incomplete.

## Reference and state
- Selected option 1: `docs/design/targets/light.png` and `dark.png`, both 1487 × 1058.
- Initial comparison: same viewport, initial three-row synthetic batch, closed details, explicit light/dark appearance.
- Browser: actual host-controlled IAB via CUA at `http://127.0.0.1:4173/`.
- The screen is a labeled design preview. Phone signing and credential mutation remain unavailable in this slice.

## Observed behavior
- Both light and dark themes render. Explicit light choice survives reload.
- Switching dark/light while a finite phone review is open preserves its three named credentials and review draft.
- Follow-system mode preserves the draft and marks the resolved appearance active.
- Details, inventory, evidence and appearance drawers open; phone handoff explains the boundary and links to the separate phone entry point.
- Escape closes the dialog and returns focus to the original visible opener. Browser verification found the original focus loss; the corrected implementation was rechecked.
- At 390 × 844, the inventory stacks into readable rows; document scroll width equals viewport width (390), and the modal fits the viewport.
- Shift-Tab focus remained inside the native dialog. This observation does not constitute a complete assistive-technology audit.

## Source versus render
- P1: no current structural mismatch in selected header/hero/stats/table/footer or theme behavior.
- P2: footer column width adjusted to keep the caveat readable without reducing font size; desktop placement differs slightly from the generated target.
- P3 accepted: local Libre Baskerville/Inter and Phosphor icons approximate generated typography/icons; flat colors replace generated texture.
- Initial defects corrected: system-follow mode left neither theme selected; closing a navigated drawer lost keyboard focus.

## Evidence and remaining checks
- Local screenshot receipts: `runtime/evidence/screenshots/u11a-light.jpg`, `u11a-dark.jpg`, `u11a-mobile-dark.jpg` (synthetic preview only).
- Parent verification: 7 component/theme tests, 46 core tests, typecheck, lint, both builds and 4 Sites tests passed for this wave.
- Reduced-motion CSS is present; the media setting has not yet been exercised in the browser.
- Recheck after controller integration: loading/failure/empty states, actual operation transitions, finite manifest display, phone signing/replay rejection, emergency/recovery paths, updated evidence text and screenshots.
- No physical phone, hardware authenticator, real store/account or production origin is verified by these observations.

## Integrated review checkpoint, 2026-10-26

- Driver: actual host-controlled IAB through CUA; routes `/` and `/phone.html` at `http://127.0.0.1:4173`.
- The current actual viewport is 467 × 674. The advertised viewport override did not change the observed `innerWidth` or screenshot dimensions; it was reset. These captures establish the compact layout only. A fresh 1487 × 1058 comparison and 390-wide check of the integrated revision remain pending.
- After reload, the saved session cookie permitted metadata reads while the in-memory CSRF value was absent. A one-use local CLI code restored write access; this was not a distinct read-only account role.
- Prepared one synthetic lineage, inspected exact account/provider, scopes, TTL, store target, budgets, outage policy and expiry on the separate phone page, and approved with the paired synthetic browser key. This was a same-origin demo, not a physical phone or production origin.
- Running that approved rotation created and validated a synthetic replacement, then visibly held ordinary revocation with `old-generation-use-unverified`. The view kept replacement, issuer outcome and old-key rejection separate. No real provider action occurred.
- Switching light/dark preserved selected scope, proposal and operation progress. The explicit light choice survived reload. The onboarding draft and phone selection survived theme changes and a controller reconnection. Escape returned focus to Add credential.
- Added a nonsecret synthetic inventory lineage through the owner form, reviewed its complete verified descriptor on the phone, approved, then executed the inventory action. Inventory count changed from one to two only after the authorized action. Empty real-inventory admission is separately covered by integration tests; this browser journey began with one demo lineage.
- An expired proposal refused review. A proposal under a stale phone boot context also refused review; reconnecting the phone established the current boot context. Neither refusal was bypassed.
- Issue found during this journey: administrative phone review used generic `admin` copy and hid inventory meaning in Advanced JSON. The final repair checkpoint below supersedes that presentation finding.
- No new console error appeared during these journeys. The review tab retains an earlier Vite CSS hot-reload error from 01:24 UTC, before this checkpoint; the current clean build passes. Phone diagnostics contain no errors.
- Current screenshot receipts (ignored local runtime artifacts): `runtime/evidence/screenshots/u11b-review-light.png`, `u11b-review-dark.png`, `u11b-operation-light.png`, `u11b-operation-dark.png`, and `u11b-onboarding-dark.png`.
- Reduced-motion emulation, full assistive-technology testing, actual hardware WebAuthn, real OAuth consent, four-machine adoption, notification delivery and clean-device recovery remain unverified.

## Final repair checkpoint

- Independent formal review retained eight findings. A bounded post-fix review reports all eight resolved with no introduced P1/P2; the formal and follow-up artifacts remain private. This is a software review, not live admission.
- Actual IAB CUA prepared a policy on `demo-added-lineage` while the other lineage was selected. Before approval, the phone prominently displayed the exact target, seven-day interval and digest; Advanced JSON stayed collapsed. Switching phone themes preserved that review. After its synthetic signature, the owner executed the action and inspected `administration: confirmed` with `local-controller-action-only`.
- The recorded older lifecycle panel separately showed stored/validated/unknown observations while the selected policy panel retained its own administration receipt. This establishes simultaneous-panel attribution in the observed journey; the late-response ordering is covered by the keyed-state regression, not a mounted race test.
- Current captures: `runtime/evidence/screenshots/u11c-policy-phone-light.png`, `u11c-policy-phone-dark.png`, and `u11c-receipts-light.png`. Existing 467-wide main-view theme captures remain valid for the unchanged layout.
- A dedicated Chrome QA tab rendered the desktop connection layout at 1312 × 700 and its light/dark control worked, but authentication did not reach the main review in that browser profile. The same Vite-proxied HTTP login/cookie/metadata flow returned 200/issued/200 in an API check. No browser privacy or extension setting was changed. The temporary tab was closed; current desktop main-review parity remains unverified.
- Ten-minute session expiry returned the owner to connection. No physical emergency authenticator was simulated in the browser; emergency resumption/recovery evidence is synthetic crypto plus component/integration contracts.
