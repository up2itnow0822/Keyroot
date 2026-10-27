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
- U3 owns canonical signed manifests, transactional finite budgets, durable intents and lineage locks. Boot changes invalidate grants and retain uncertain effects for reconciliation.
- Only verified emergency assertions reserve named lineages. Per-action proofs expire within 30 seconds; narrow containment preserves predecessor uncertainty.
- Compound create/store reserves both effects, signs the store destination/handle and rechecks authority before CAS.
- Current-snapshot digests, bootstrap capability, recovery observations and clock injection are trusted executor inputs, never owner JSON proof.
- Installation epoch checks fence future dispatch but cannot cancel an upstream request or guarantee exactly-once execution.

## Work Guidance
- Test public behavior and record proof-first evidence when practical.
- Use `.js` relative imports for Node ESM output.

## Verification
- `npm test`, `npm run typecheck`, `npm run lint`.
- U3 focus: `node --import tsx --test packages/core/test/U3.test.ts` verifies synthetic cryptographic protocol, not physical custody.

## Child DOX Index
- None. This contract owns domain source and tests recursively.
