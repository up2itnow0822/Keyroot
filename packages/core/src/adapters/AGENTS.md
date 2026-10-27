# Trusted Transports

## Purpose
- Implement bounded issuer and existing-store protocols inside trusted executors.

## Ownership
- Store owns CAS/pinned reads; issuer owns fixed account/resource methods. Core authority owns permission to dispatch.

## Local Contracts
- One-time values go directly to the existing store; public results and errors contain metadata only.
- Consumer ports expose only explicitly mapped handles and pinned versions, without administration methods.
- Reconciliation compares operation/issuer/account bindings; existence or timeout proves no successful rotation.
- Current issuer mode is synthetic only; actual account admission remains a separate integration.

## Work Guidance
- Validate response shape and scope, bound waits and keep unknown outcomes explicit.

## Verification
- Adapter tests are included in `npm test`.
- `npm run test:integration` exercises the pinned disposable OpenBao fixture.

## Child DOX Index
- None.
