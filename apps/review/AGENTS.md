# Prototype Instructions

## Selected Keyroot contract
- Preserve the selected warm editorial interface in `../../docs/design/targets/light.png` and `dark.png`.
- Follow system appearance initially, save an explicit choice and preserve operational state during changes.
- Keep phone approval source/build separate from the review build. Local phone preview is demo-only.
- Never import controller administration material or real secret values.
- Parent application guidance: `../AGENTS.md`. No child DOX documents yet.
- `src/components/` owns pure display contracts. `App.tsx` currently renders a labeled synthetic preview; controller integration is a separate pending slice.
- Appearance state is independent of review state. Dialog closure returns focus to the connected opener or visible details action.
- `npm run test:browser` from the repository root covers component/theme contracts; actual CUA journeys and visual comparison are recorded in root `design-qa.md`.
- Frontend TypeScript uses bundler resolution in `tsconfig.json`; controller and core retain Node ESM resolution. The root typecheck command covers both.

Run the local server yourself and open the preview in the browser available to this environment. Do not give the user server-start instructions when you can run it.

Before making substantial visual changes, use the Product Design plugin's `get-context` skill when the visual source is unclear or no longer matches the current goal. When the user gives durable prototype-specific design feedback, preferences, or decisions, record them in `AGENTS.md`.

When implementing from a selected generated mock, treat that image as the source of truth for layout, component anatomy, density, spacing, color, typography, visible content, and hierarchy.

Build app UI in `src/`. Keep `.openai/hosting.json`, `worker/index.js`, `scripts/prepare-sites-build.mjs`, and `tests/sites-worker.test.mjs` intact so the same local prototype can be handed to Sites. Before a Sites handoff, run `npm run build` and `npm run test:sites`; the build must leave `dist/client/index.html`, `dist/server/index.js`, and `dist/.openai/hosting.json`.
