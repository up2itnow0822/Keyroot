# Keyroot Core

## Purpose
- Own inventory, finite authority, durable lifecycle coordination and recovery.

## Ownership
- Core validates effects; applications supply authenticated callers.

## Local Contracts
- Journal metadata only. Resolve values only within trusted issuer/consumer executors.
- Delivery, adoption, revocation and observed rejection are distinct evidence.
- Ambiguous effects require reconciliation; a new operation cannot forget a live predecessor.
- Real admission requires scoped provenance, never imported verified flags. Live issuance remains disabled until an owning account-test workflow supplies it; synthetic process-local records cannot survive import or authorize live actions.
- Inventory and authority records contain metadata only. Coverage preserves unresolved sources, and allocation drafts require review of consolidation or outage consequences.

## Work Guidance
- Test public behavior and record proof-first evidence when practical.
- Use `.js` relative imports for Node ESM output.

## Verification
- `npm test`, `npm run typecheck`, `npm run lint`.

## Child DOX Index
- None. This contract owns domain source and tests recursively.
