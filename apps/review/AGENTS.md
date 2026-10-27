# Keyroot Review

## Purpose
- Present the selected owner review, credential onboarding and operation evidence.

## Ownership
- This application owns owner presentation and metadata communication; core/controller retain lifecycle authority.
- `src/components/` owns pure display contracts; `src/phone/` owns the separately built phone interface.
- Parent application guidance: `../AGENTS.md`.

## Local Contracts
- Preserve the warm editorial light/dark design in `../../docs/design/targets/`. Use the selected mock for layout, anatomy, density, spacing, color, typography and hierarchy; render actual known metadata and uncertainty.
- Follow system appearance initially, save an explicit choice and preserve review/operation state during changes.
- Keep phone source/build separate. Local preview is synthetic and does not establish production phone custody or account admission.
- Never import controller administration material or real secret values.
- Credential onboarding accepts nonsecret identifiers and prepares a complete inventory update for a paired routine phone. Inventory changes only after approval and the authorized action.
- Preserve engine observations and journal interpretations in receipt inspection. Bind cached and rendered evidence to its operation ID; late responses cannot appear under a different operation.
- Dialog closure returns focus to the connected opener or visible details action.

## Work Guidance
- Run and inspect the local preview when available. Use Product Design context when the visual source is unclear or no longer matches the goal; record durable design feedback here.
- Keep `.openai/hosting.json`, `worker/index.js`, `scripts/prepare-sites-build.mjs` and `tests/sites-worker.test.mjs` compatible with Sites handoff.
- Frontend TypeScript uses bundler resolution; controller/core retain Node ESM resolution.

## Verification
- Root `test:browser` covers component/theme/phone contracts; root `design-qa.md` records actual CUA and visual limits.
- Run root typecheck, build and Sites tests. Handoff requires `dist/client/index.html`, `dist/server/index.js` and `dist/.openai/hosting.json`.
- Synthetic journeys and software signatures do not verify physical hardware or production origins.

## Child DOX Index
- `src/phone/AGENTS.md` — phone pairing, signing and independent-origin boundary.
