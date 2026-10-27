# Metadata Discovery

## Purpose
- Report credential locations, named associations and coverage gaps without retaining values.

## Ownership
- Scanners own read-only metadata extraction. Authority and rotation remain outside this domain.

## Local Contracts
- Scan only trusted configured roots with bounded regular-file reads and symlink checks.
- Ancestor replacement races are not fully eliminated by these APIs; compromised roots require separate containment.
- Unreadable/missing sources stay gaps, and an unavailable root cannot erase other results.
- Provider adapters return names/provenance/availability, never encrypted-secret visibility claims.

## Work Guidance
- Redact parsing failures; preserve declared, inferred and observed distinctions.

## Verification
- Focused discovery/federation tests are included in `npm test`.

## Child DOX Index
- None.
