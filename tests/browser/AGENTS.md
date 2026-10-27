# Browser Component Contracts

## Purpose
- Verify pure appearance state, rendering semantics and review-state contracts.

## Ownership
- These tests own component contracts. Host CUA owns actual browser behavior and screenshots.

## Local Contracts
- SSR and VM tests cannot prove focus, layout, browser signing or physical device behavior.
- Keep fixtures explicitly synthetic and preserve separation of appearance and operation state.

## Work Guidance
- Add regression coverage for observed defects when the available harness can test the behavior meaningfully.

## Verification
- `npm run test:browser` and root frontend typecheck.
- Actual browser observations remain in root `design-qa.md`.

## Child DOX Index
- None.
