# Keyroot Applications

## Purpose
- Own the local controller and the review/phone interfaces.

## Ownership
- Controller owns trusted HTTP and CLI entry points; review owns visual and phone source.

## Local Contracts
- Local development binds to loopback. Real actions require core authority checks.
- Review and static Sites builds cannot grant approval or act as the trusted production phone origin.
- Never return secret material in owner responses.

## Work Guidance
- Read nearest child contracts before edits.

## Verification
- Root static checks and build cover application source.

## Child DOX Index
- `controller/AGENTS.md` — controller, CLI and authentication boundaries.
- `review/AGENTS.md` — visual target, phone source and protected hosting runtime.
