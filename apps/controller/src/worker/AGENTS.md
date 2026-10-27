# Dashboard Worker Boundary

## Purpose
- Mediate pinned recipe commands and model-visible observations.

## Ownership
- Broker owns command validation; trusted host ports own browser/profile/store execution.

## Local Contracts
- Synthetic worker construction requires scoped admission and finite signed execution context.
- Mediate each step, capture, seal and restore; page instructions cannot add capabilities.
- Host-file, cross-profile, shell and vault-administration operations are absent from this port.
- This module does not establish OS/browser isolation. Live unattended execution remains unavailable without its independent runtime and account proofs.

## Work Guidance
- Keep captured values inside mapped store ports and pause on drift/MFA/consent.

## Verification
- Recipe unit tests and `tests/integration/dashboard-worker.test.ts`.

## Child DOX Index
- None.
