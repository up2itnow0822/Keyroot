# Integration Scenarios

## Purpose
- Verify synthetic cross-boundary behavior against actual processes and disposable services.

## Ownership
- Tests own uniquely named fixture resources and their cleanup, never the owner's deployed services.

## Local Contracts
- OpenBao tests require a running Docker server and the pinned official image digest declared in `openbao.test.ts`.
- Publish fixture ports on loopback only; use synthetic values, no host data mounts and no real account credentials.
- Clean up only resources created by the test. Docker or service unavailability fails the gate explicitly.
- A disposable KV2 success is protocol evidence, not admission of the owner's store or production isolation.
- Process fixtures own their launchers, supervisors, children, grandchildren and unmanaged comparison process; every fixture must clean up all of its resources.
- Broker adversarial tests prove synthetic command mediation, not OS/browser confinement.

## Work Guidance
- Keep fixture errors redacted and preserve fail-closed unknown outcomes.

## Verification
- `npm run test:integration`.
- Focus: `node --import tsx --test tests/integration/openbao.test.ts`.

## Child DOX Index
- None.
