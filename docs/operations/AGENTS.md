# Keyroot Operations

## Purpose
- Maintain operator guidance and requirement-to-evidence traceability for the in-progress lifecycle controller.

## Ownership
- This folder owns runbooks, provider coverage, validation records and `traceability.json`; the plan owns normative requirements.

## Local Contracts
- Record bounded software evidence separately from physical and account validation; a fixture, callback or documented API does not admit a live account.
- Never include secret values, private keys, sensitive recordings, or private source material.
- Preserve every R1–R83 and AE1–AE28 ledger entry with an allowed status, specific evidence and limits. Pending status is an open gate, not a failing evidence claim.
- Update commands and recovery instructions only against the current implementation; a documented route does not authorize a real operation.

## Work Guidance
- Keep recovery, issuer, consumer, custody, and browser-isolation assumptions explicit and distinguish local metadata from store-value backups.
- Describe safe reconciliation and manual fallback for ambiguous outcomes; never infer revocation or adoption from silence.

## Verification
- Check referenced files, commands and ledger coverage; `npm run verify:contracts` checks ledger structure, not the truth of its evidence.

## Child DOX Index
- None. This contract owns the operation files directly.
