# Phone Approval Source

## Purpose
- Build the separate phone pairing and approval interface.

## Ownership
- This folder owns phone presentation, local signing and controller communication; core owns manifest and approval authority.

## Local Contracts
- Production approval requires a separately deployed HTTPS origin, reviewed bundle and pinned controller identity; loopback preview is demo-only.
- Render and sign validated canonical manifest bytes and bound descriptors after explicit review; do not import controller administration material or secret values.
- Show the actual administrative purpose, target, consequences, relevant public enrollment fingerprints and digest before approval. Unrecognized administrative scope cannot be approved; raw JSON remains supplementary.
- Resume emergency registration only from a fresh authenticated signed batch read matching the reviewed grant and digest. Registration is not approval or browser-persisted authority.
- A nonextractable browser key and signature do not prove physical custody or hardware provenance.

## Work Guidance
- Keep phone trust configuration in the reviewed bundle and preserve pairing and expiration checks.

## Verification
- Root browser component and phone-crypto tests and separate phone build. Recorded synthetic CUA is bounded evidence; physical custody, hardware gestures and production origins remain external gates.

## Child DOX Index
- None.
