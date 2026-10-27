# Trusted Transports

## Purpose
- Implement bounded issuer and existing-store protocols inside trusted executors.

## Ownership
- Store owns CAS/pinned reads; issuer owns fixed account/resource methods. Core authority owns permission to dispatch.

## Local Contracts
- One-time values go directly to the existing store; public results and errors contain metadata only.
- Consumer ports expose only explicitly mapped handles and pinned versions, without administration methods.
- Reconciliation compares operation/issuer/account bindings; existence or timeout proves no successful rotation.
- Live issuer construction requires a registered scoped account evaluator; real controller dispatch additionally requires its live admission guard. Missing evidence denies by default.
- Account verifier callbacks are trusted constructor ports. Hermetic callback tests demonstrate the boundary and do not establish actual owner permissions.
- Strict descriptor hashes bind scope/expiry/probe/store targets and exact action parameters. Creation rechecks authority immediately before CAS.

## Work Guidance
- Validate response shape and scope, bound waits and keep unknown outcomes explicit.
- Reject HTTP redirects; tokens and request bodies cannot follow an unapproved endpoint.

## Verification
- Adapter tests are included in `npm test`.
- `npm run test:integration` exercises the pinned disposable OpenBao fixture.

## Child DOX Index
- None.
