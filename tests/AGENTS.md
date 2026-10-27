# Keyroot Scenario Tests

## Purpose
- Verify application contracts and complete synthetic workflows across package boundaries.

## Ownership
- `browser/` owns component contracts; host CUA owns observed browser journeys.
- `integration/` owns disposable-service, process and lifecycle scenarios.

## Local Contracts
- Component tests do not establish browser behavior, physical custody or live account eligibility.
- Fixtures must exercise real core/controller behavior rather than returning the expected final state.
- No real credentials, accounts or external mutation in test resources.

## Work Guidance
- Preserve direct evidence for failure, unknown outcomes and restart recovery.

## Verification
- `npm run test:browser` runs component contracts.
- `npm run test:integration` includes actual Docker/OpenBao protocol checks and requires a running Docker server.
- Root `design-qa.md` tracks actual browser observations and their limits.

## Child DOX Index
- `integration/AGENTS.md` — disposable services, resource ownership and lifecycle scenarios.
- `browser/AGENTS.md` — component/theme contracts and browser-evidence limits.
