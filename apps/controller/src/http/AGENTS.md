# Controller HTTP Helpers

## Purpose
- Implement bounded emergency enrollment, local native-session actions and mapped environment-file inspection.

## Ownership
- This folder owns helpers for controller routes; core owns effect authority and consumer contracts.

## Local Contracts
- Registration verification alone does not prove physical hardware custody or authorize emergency enrollment; retain the separate signed authorization.
- Native sign-out uses trusted absolute executables and fixed arguments without a shell or provider output forwarding.
- Environment inspection is confined to configured targets and returns metadata, not file values or adoption claims.

## Work Guidance
- Preserve exact input validation, expiry and redacted errors at these boundaries.

## Verification
- Root typecheck, lint and relevant integration and core tests.

## Child DOX Index
- None.
