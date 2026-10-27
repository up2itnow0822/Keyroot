# Keyroot Controller

## Purpose
- Expose narrow owner workflows and coordinate core services.

## Ownership
- Own local HTTP, CLI and trusted executor callers; core owns lifecycle authority.

## Local Contracts
- Default listener is `127.0.0.1:9047`; production requires explicit TLS/origin configuration.
- Read sessions cannot authorize effects, enrollment or policy edits.
- Demo uses isolated synthetic drivers and cannot connect a real store.
- Durable directories belong to exactly one mode. Reject either mode transition in the file marker and database metadata; never promote demo identities or inventory into real authority.
- Return redacted error codes, never provider bodies or credentials.
- CLI stderr uses bounded JSON error codes from an explicit allowlist and a nonzero exit on failure.
- Signed batch reads may expose an exact, current emergency registration. Registration is not effect approval; preserve fresh per-action WebAuthn checks.
- A new signed cancellation binds an existing target grant and digest even when its old scope is stale. Cancellation does not resolve unknown effects, refund budgets or fabricate receipts.

## Work Guidance
- Preserve core checks at every action entry point.

## Verification
- Root typecheck, lint and build. Bootstrap health is a smoke check only.

## Child DOX Index
- `src/worker/AGENTS.md` — dashboard command/observation mediation and proof limits.
- `src/http/AGENTS.md` — bounded enrollment, native-session and environment-file helpers.
- `src/commands/AGENTS.md` — offline metadata backup and held recovery entry points.
