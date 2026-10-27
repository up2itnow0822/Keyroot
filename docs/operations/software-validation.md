# Local software validation

Checkpoint: 2026-10-26. This is a reviewed local software milestone; full Phase 2 and live admission remain open.

## Verified code behavior

| Gate | Result |
| --- | --- |
| Node/npm | 24.18.0 / 11.16.0 |
| Clean dependency installation | `npm ci` passed in a disposable public-tree copy |
| TypeScript and ESLint | Passed in both working and clean copies |
| Core unit tests | 191 passed; none skipped |
| Integration tests | 77 passed; none skipped, including disposable Docker/OpenBao, actual software cryptography and authenticated encrypted recovery |
| Browser component/crypto contracts | 45 passed; none skipped |
| Sites worker tests | 4 passed |
| Controller, owner and separate phone builds | Passed |
| Traceability schema | All R1–R83 and AE1–AE28 present; pending rows remain open |
| Secret-pattern gate | 185 staged public files plus 108 built client/phone assets scanned; heuristic only |
| DOX | 26 contracts with resolving parent indexes and child links |

The dependency graph was unchanged when final reviewed sources were synchronized into the clean installation. Tests use isolated temporary/synthetic transports and deliberate hermetic REAL admission callbacks where required; those callbacks establish no owner-account readiness. The actual OpenBao container is a disposable protocol reference, not the selected production store.

## Independent review and browser evidence

- Formal Compound Engineering review used ten local lenses and an independent Claude peer. Eight supported findings were repaired; a separate bounded after-fix review reports all eight resolved with no introduced P1/P2. Review receipts and raw artifacts remain private.
- Repairs include both-direction mode separation, incident-hash recovery, exact primary phone disclosure, current emergency-registration resumption, preserved/deduplicated receipt semantics, operation-keyed evidence, redacted CLI codes and signed cancellation of stale reservations without releasing unknown effects or refunding budget.
- Actual CUA covered synthetic finite phone approval through held rotation, approved inventory addition, exact cross-lineage policy disclosure/execution, visible administrative receipts, distinct simultaneous evidence panels, theme persistence/state preservation and Escape focus. See [design QA](../../design-qa.md) for exact routes, captures, failures and limits.
- Deferred receipt ordering is a keyed-state regression, not a mounted race test. Physical emergency gestures, actual emergency close/reopen, complete IndexedDB failure paths and desktop main-review parity remain unverified.

## Open gates

The current entry point does not wire live trusted ports or operator recovery activation. The [1Password proposal](onepassword-pilot-proposal.md) is not accepted or implemented. Store/account authority, separate production HTTPS phone deployment, physical phone/YubiKey custody, four-machine enforcement, browser isolation, clean-device recovery and the owner-effort baseline remain open.

GitHub-hosted CI results belong to the exact PR revision and must be checked there. Passing these local checks does not establish production readiness or complete the global Phase 2 goal.
