# Keyroot Tooling

## Purpose
- Own development orchestration and repeatable verification.

## Ownership
- Scripts own workflow commands; core owns product behavior.

## Local Contracts
- Missing tests or evidence fail explicitly.
- Tests use synthetic resources and never obtain real credentials.

## Work Guidance
- Keep scripts deterministic and dependency-light.
- The test runner explicitly selects the frontend bundler TypeScript config for component tests and the Node config for core/integration tests.
- Run `verify:secrets` after build; it scans tracked files and both public client/phone output trees and fails when either build is missing. Pattern checks are heuristic, not proof that every secret is absent.

## Verification
- Root lint and observed script invocations.

## Child DOX Index
- None.
