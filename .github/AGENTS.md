# CI Configuration

## Purpose
- Run reproducible project verification for changes to the main branch.

## Ownership
- This folder owns GitHub Actions configuration; root npm scripts define the checks.

## Local Contracts
- Keep pull request and main-branch push checks read-only, with no deployment, account operations or repository secrets.
- Pin third-party actions to immutable commit SHAs and verify their upstream provenance before updates.
- Run the real disposable, digest-pinned OpenBao integration with Docker; missing Docker or fixture failure is a failed gate.

## Work Guidance
- Preserve all gates in the plan's Verification Contract and disclose the limits of synthetic and browser-component checks.

## Verification
- Validate workflow syntax and action pins; run relevant root checks when available.

## Child DOX Index
- None. This contract owns the workflow files directly.
