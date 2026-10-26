# Keyroot

## Overview

Keyroot is a personal credential lifecycle project for four machines and connected platforms. Its goal is to map credential usage, coordinate approved rotations, and show the evidence for each outcome.

## Current status

Project bootstrap. Application implementation will start with the foundation required for Phase 2 credential rotation.

## Planned behavior

- Reuse an existing secrets store and build a read-only inventory of credentials, mapped consumers, and coverage gaps.
- Review bounded changes through phone approval before executing them.
- Use issuer APIs where available, admitted dashboard procedures where appropriate, and guided steps otherwise.
- Track consumer adoption and issuer revocation evidence separately, keeping unknown outcomes visible.
- Provide an owner API and review interface, with incident handling and independent recovery workflows.

These are design goals, not shipped capabilities or verified integrations.

## Design boundaries

- Native Claude Code and Codex subscription authentication stays native.
- Production requests and credential renewal must not depend on the Keyroot box.
- Secrets must not enter model context or logs.
- A copied bearer key cannot be recalled simply by stopping a wrapper; issuer-side revocation is needed to invalidate it.

## Roadmap

1. **Phase 1 — Minimal foundation:** credential and consumer records, access controls, an audit journal, and secrets-store integration.
2. **Phase 2 — Credential rotation:** develop approved rotation and evidence workflows.
3. **Phase 3 — Breach watcher:** deferred; no automatic breach-triggered rotation is planned in the current scope.

## License

[MIT](LICENSE).
