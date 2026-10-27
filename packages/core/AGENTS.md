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
- Store adapters expose a mapped, pinned-version consumer port. Reconciliation requires stored operation/issuer/account binding; existence alone is insufficient.
- Current issuer transport is synthetic only. Live admission and complete engine integration remain pending; disposable OpenBao protocol checks do not admit the owner's store.
- Receipt append records evidence only. Explicit action-specific resolution requires complete bound subjects; historical unknowns remain and require an explicit reconciliation marker.
- Recovery observations identify the exact predecessor installation, owner and store version. Stale observations cannot take over a newer epoch.
- Authority uses a trusted constructor clock after asynchronous fences; request timestamps cannot keep expired authority alive.
- The lifecycle engine persists complete stage outcomes, separates named direct use from delivery and probes, and holds uncertainty through timeout or restart. Abort signals do not prove upstream cancellation.
- OAuth metadata owns only explicitly local refresh families; production/third-party refresh stays external. Local recovery observes the original pending intent before fresh authority permits further effects.
- Native sign-out evidence confirms only the configured local command; remote session invalidation remains separately unverified.

## Work Guidance
- Test public behavior and record proof-first evidence when practical.
- Use `.js` relative imports for Node ESM output.

## Verification
- `npm test`, `npm run typecheck`, `npm run lint`.
- U3 focus: `node --import tsx --test packages/core/test/U3.test.ts` verifies synthetic cryptographic protocol, not physical custody.

## Child DOX Index
- `src/adapters/AGENTS.md` — scoped issuer/store transports and value boundaries.
- `src/discovery/AGENTS.md` — read-only source scanning and coverage provenance.
- Core retains authority, engine, OAuth/native contracts and all focused tests.
