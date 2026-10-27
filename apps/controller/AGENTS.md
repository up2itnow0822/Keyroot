# Keyroot Controller

## Purpose
- Expose narrow owner workflows and coordinate core services.

## Ownership
- Own local HTTP, CLI and trusted executor callers; core owns lifecycle authority.

## Local Contracts
- Default listener is `127.0.0.1:9047`; production requires explicit TLS/origin configuration.
- Read sessions cannot authorize effects, enrollment or policy edits.
- Demo uses isolated synthetic drivers and cannot connect a real store.
- Return redacted error codes, never provider bodies or credentials.

## Work Guidance
- Preserve core checks at every action entry point.

## Verification
- Root typecheck, lint and build. Bootstrap health is a smoke check only.

## Child DOX Index
- None. This contract owns controller source recursively.
