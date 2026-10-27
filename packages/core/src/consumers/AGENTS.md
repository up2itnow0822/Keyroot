# Consumer Delivery

## Purpose
- Deliver mapped material and authenticate separate direct-use evidence.

## Ownership
- Consumers own configured destination updates; the core engine owns lifecycle decisions.

## Local Contracts
- Fresh authority and an exact signed descriptor are required at every effect boundary; quarantine blocks delivery.
- A successful push confirms delivery only. Direct use requires the configured consumer identity, exact generation/revision and named run evidence.
- Env rewrites use the explicit Node env grammar, parser-verified round trips, restrictive atomic files and vault backups. Rollback needs separate authority and cannot count as successor delivery.
- GitHub uses the maintained sealed-box implementation; platform transports use fixed origins, bounded requests and scoped admission.
- Wrapper children receive an explicit narrow environment, never controller/store administration tokens. Managed process groups stop at grace/issuer expiry or supervisor failure; unmanaged copies are outside that claim.

## Work Guidance
- Keep file contents, resolved values and subprocess output out of receipts and errors.

## Verification
- Consumer/wrapper tests in `npm test`.
- `npm run test:integration` exercises actual child/grandchild cleanup and signed file delivery with synthetic material.

## Child DOX Index
- None.
