# Offline Recovery

## Purpose
- Authenticate and encrypt metadata snapshots, restore stale state safely, and coordinate independent recovery evidence.

## Ownership
- Core owns archive/hold policy. Controller commands own operator input and runtime wiring; the mature store retains its own value-recovery process.

## Local Contracts
- Use maintained age encryption and independently pinned P256 archive authentication. An archive-supplied key cannot authenticate itself.
- Export only validated known metadata tables, never values/private keys or archive-controlled SQL/paths. Excluded security metadata makes coverage incomplete and blocks release.
- Archived incident intent parameters retain the signed incident plan hash only as a canonical SHA-256 digest; unknown parameters remain rejected.
- Imports rotate installation/boot, invalidate prior authority and retain ambiguous intents/OAuth state in recovery hold.
- Release needs fresh scoped predecessor/store/issuer observations and exact epoch CAS; a new boot cannot stop an old request.
- Lost-phone enrollment additionally requires independent offline material and the pinned emergency assertion. The security key alone cannot recover the controller.
- Controller metadata and operator import are integrated; external store-value recovery, independent hardware and live issuer reconciliation remain required before full recovery is claimed.

## Work Guidance
- Process-local import capabilities must be reauthenticated from offline material after restart, never reconstructed from database flags.

## Verification
- Recovery unit and integration tests use actual age/signatures and synthetic WebAuthn. They do not verify real offline hardware, owner-store backups or issuer-native recovery.

## Child DOX Index
- None.
