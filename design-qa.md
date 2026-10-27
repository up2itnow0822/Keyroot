# Keyroot design verification

Status: U11a visual/theme slice verified locally; full Phase 2 interface and controller integration remain incomplete.

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
