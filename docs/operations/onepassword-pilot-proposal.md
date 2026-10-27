# Proposed 1Password pilot profile

Status: proposal for owner confirmation; not an implemented or admitted profile.

## Recommendation

Keep the current 1Password vault and use the local CLI as its integration client. Do not require a new vault just to imitate OpenBao. Separate credential-generation storage from controller ownership, retain all approval and reconciliation rules, and begin with one designated controller and manual recovery. No automatic failover is promised.

Independent architecture critique supports this separation, subject to actual account, isolation and exclusive-owner evidence. A local CLI is not a self-hosted vault, and local database sequencing is not a distributed fence. The [provider assessment](onepassword.md) identifies the documented API limits.

## Proposed API changes

- `createGeneration`: approve an exact provider/account/vault, operation/generation slot, schema, field and create-new-only allocation. The trusted executor binds the provider-returned item ID and revision to that slot once; never rewrite the signed manifest to insert an unknown ID.
- `withGenerationSnapshot`: fetch one coherent item, validate its exact locator, revision, schema and generation binding, and execute on those captured bytes. A metadata read followed by a separate value read is insufficient. An edit after capture does not change the already captured bytes; later reads reject the changed revision.
- Ownership/admission remains a separate trusted port. Preserve the existing shared-CAS profile and OpenBao reference; do not implement a fake CAS adapter for 1Password.
- Creation timeouts, lost responses, ambiguous matches, moved/deleted items and unexpected edits remain held. Never retry issuance or choose an item by title merely because a response was lost.
- Secrets pass only through bounded private process streams and trusted callbacks. Consumer machines receive neither a vault-wide token nor permission to invoke the controller's CLI identity.

## Proposed exclusive-controller limits

- One designated execution host and local transactional journal. Supported boot invalidates old grants; imports/restores start held. A singleton is local exclusion, not proof against an active memory/VM clone.
- No automatic takeover and no supported active-process cloning. Admit this profile only when exclusivity can actually be demonstrated.
- Transfer requires sustained predecessor quiescence or invalidation/replacement of its usable store, issuer, push and session authority, plus terminal reconciliation of all in-flight effects, including work newer than the backup. An expired grant or unreachable host is insufficient.
- Fresh controller/phone enrollment follows clean recovery evidence. If an account cannot establish that evidence, keep its automated mutation disabled or guided.
- Already delivered credentials and native OAuth refresh remain independent of controller availability. Provider-required unlock prompts count toward measured owner effort.
- Phone approval governs Keyroot-mediated administration. It does not globally govern independent native 1Password administration; a desktop unlock is not a Keyroot approval.

## Changes requiring confirmation

1. R2: accept hosted 1Password for the current pilot rather than require a self-hosted secret store.
2. KTD2/KTD13: add this separate generation-storage/exclusive-controller profile; preserve the shared-epoch implementation for stores that support it.
3. R21: make the administration boundary explicitly Keyroot-mediated, with native provider administration outside that enforcement claim.

R18 consumer isolation, R26 single consumption/restored-authority invalidation, R47 secret containment and the independent recovery requirements remain safety constraints. No current account, physical custody, consumer isolation or recovery gate is accepted by this proposal. Implementation begins only after the profile is confirmed; real operation requires its own evidence and concrete approval.
