# Keyroot Packages

## Purpose
- Own the shared lifecycle domain and isolated synthetic fixtures.

## Ownership
- Core owns typed authority and workflows; fixtures owns synthetic implementations.

## Local Contracts
- Fixtures never establish live provider, signer or hardware evidence.
- Administration material stays outside review code.

## Work Guidance
- Use strict TypeScript and explicit unknown outcomes.

## Verification
- Root static checks and implemented test suites.

## Child DOX Index
- `core/AGENTS.md` — lifecycle domain, adapters and unit evidence.
- `fixtures/AGENTS.md` — synthetic drivers and scenarios.
