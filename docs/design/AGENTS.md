# Keyroot Design Evidence

## Purpose
- Preserve the selected review interface and light/dark visual targets for implementation and QA.

## Ownership
- This folder owns visual references and comparison evidence, not credential data or operational truth.
- Product behavior remains owned by the unified plan in `../plans/`.

## Local Contracts
- The owner selected the first displayed concept and requested light/dark modes.
- `targets/light.png` and `targets/dark.png` are updated states of that selected layout, with corrected API workload labels.
- Images use sample data. Do not infer live authorization, adoption, availability or revocation from mock copy.
- Do not place real credential material or secret-bearing screenshots here.

## Work Guidance
- Match layout, typography, spacing and theme tokens; use actual assets or a matching icon library rather than handmade icon artwork.
- Theme controls preserve workflow state, support keyboard use, follow system appearance initially and remember an explicit choice.
- Keep native subscription sign-ins separate from API-key consumers.

## Verification
- Compare actual source and rendered screenshots at the same viewport/state, covering both themes and primary interactions.
- Record source dimensions, normalization, findings and post-fix comparisons in project-root `design-qa.md`.

## Child DOX Index
- None. This contract owns targets and comparison artifacts recursively.
