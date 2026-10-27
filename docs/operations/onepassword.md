# 1Password integration boundary

The current implementation does not admit 1Password as its versioned lifecycle store. OpenBao KV v2 is a tested reference adapter, not evidence that another store has equivalent semantics. A future Infisical-style vault is separate work.

The [proposed 1Password pilot](onepassword-pilot-proposal.md) separates generation storage from ownership so a provider need not imitate KV v2. It awaits confirmation and account-backed validation; it is not an implemented CAS substitute.

The confirmed plan's R2 specifies a self-hosted store. 1Password is hosted. Its desktop CLI can support an owner-interactive integration, but the documented item create/edit interface does not establish the atomic expected-version write or immutable version read required by `ExistingStore`. Observing an item version and then writing is not compare-and-set. A local journal transaction does not fence remote edits or a restored controller.

## Supported documentation and limits

- [Desktop integration](https://developer.1password.com/docs/cli/app-integration/) can require device/app authentication. Installed CLI availability does not establish sign-in, entitlement, unattended availability or physical custody.
- [Item commands](https://developer.1password.com/docs/cli/reference/management-commands/item/) accept JSON through stdin. Secrets must not appear in command arguments, logs, exception text or temporary files. Returned item JSON also requires private handling.
- [CLI identifiers](https://developer.1password.com/docs/cli/reference/) can change when an item moves between vaults. Bind account, vault and item IDs plus observed version; moves and unexpected edits require reconciliation.
- [Service accounts](https://developer.1password.com/docs/service-accounts/get-started/) and [Connect](https://developer.1password.com/docs/connect/get-started/) require suitable vaults, permissions and deployment/account support. Built-in personal/private vault access and per-item least privilege must not be assumed. A vault-wide reader is not a per-consumer capability.
- Store access logs do not establish downstream credential use, issuer revocation or old-key rejection.

## Required contract before automated mutation

1. Choose the hosted/self-hosted pilot scope explicitly.
2. Demonstrate atomic conditional writes and a shared installation epoch, or separately design and validate an equivalent remote authority/fencing protocol. Do not implement a local CAS shim and claim provider enforcement.
3. Establish exact handles, access boundaries, ambiguous-create reconciliation, independent recovery and predecessor quiescence. A convention of creating a new item per operation is not enforced write-once storage or a cross-instance fence.
4. Exercise the actual account and vault through the approved admission workflow. Keep real mutations disabled until store, issuer, signer, consumer and recovery gates pass.

No authentication, item enumeration, secret read or account change was performed for this assessment. The local coordinator can be reviewed and tested while the pilot-store decision remains open; this does not complete the full Phase 2 exit gate.
