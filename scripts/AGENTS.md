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

## Verification
- Root lint and observed script invocations.

## Child DOX Index
- None.
