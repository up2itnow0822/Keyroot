# Operating Keyroot

Keyroot is in active development. The local demo uses synthetic material; real accounts, physical custody, the four machines, the existing store, browser isolation, the separate production phone origin and recovery drills remain unverified. Before a real mutation, satisfy the account and physical gates in the [plan](../plans/2026-10-25-2356-feat-keyroot-credential-lifecycle-plan.md) and obtain authorization for the concrete operation. See [coverage](provider-capabilities.md), [recovery](recovery.md), and the [validation ledger](validation-ledger.md).

The supplied controller entry point does not wire live store, issuer, consumer, admission or recovery ports. Real mode and injectable interfaces are not a deployable live configuration; completing and validating those integrations is a software prerequisite in addition to the account and physical gates.

## Local installation and review

Use Node 24.18 or later within the 24.x series and npm 11 or later:

```sh
npm ci
npm run dev
```

Open `http://127.0.0.1:4173/`. The default demo uses `runtime/demo-dev`, a project-local synthetic controller state; it is not the real installation at `~/.keyroot`. Stop the development processes with Ctrl-C. A local preview or static Sites build is not a trusted production approval origin. The separate phone build is produced by `npm run build` in `apps/review/dist/phone`; its production use requires an independently deployed HTTPS origin, pinned controller identity and reviewed bundle/CSP, plus physical custody verification. Do not treat the same-origin demo as production signing evidence.

The CLI talks to the existing controller through its private local socket; it does not create a separate journal. With the demo running, `npm run keyroot -- session`, `identity`, `status`, or `inventory` retrieves a short-lived local session, controller identity, or metadata. `npm run keyroot -- pair-confirm <request-id> <fingerprint>` confirms pairing only after independently comparing the phone-displayed public fingerprint to the local identity/request information; never enter a private key. The npm wrapper defaults to project-local `runtime/demo-dev` in demo mode; direct controller/CLI entry points default to `~/.keyroot-demo`. Both durable mode markers reject either mode transition. Use a fresh directory for another mode; never relabel or promote demo authority. Explicit `--directory <absolute-path>` selects another controller directory; real mode defaults to `~/.keyroot`.

`npm run keyroot -- prepare <signer-id> <lineage-id>` prepares a finite routine review. `npm run keyroot -- prepare-action <signer-id> <lineage-id> <purpose> <target-id>` prepares a bounded administrative action. After the appropriate phone signature, `npm run keyroot -- run <grant-id> <operation-id>` or `npm run keyroot -- action <route> <grant-id> <operation-id> <action-id>` invokes the corresponding authorized workflow. The CLI reports allowlisted JSON errors on stderr and exits nonzero; unknown errors are redacted. IDs and action purposes must come from the actual owner review/controller response; these examples do not authorize effects. Inspect the manifest, consumer map, budgets, expiry, outage terms, descriptor hashes and limitations before signing.

## Routine changes and interruptions

The forecast warns about long intervals and advances prompts for issuer expiry or reauthorization. A batch is finite; changed scope or expired authority needs fresh approval. A successful push is delivery evidence only. Before revoking an old generation, verify the required direct-use evidence for every named consumer, reconcile any issuer-reported old use, and distinguish issuer control-plane revocation from observed old-key rejection. A timeout, permission error or missing telemetry is unverified. Keep the old value where overlap allows; a single-key replacement requires a separately authorized outage and recovery plan.

The scheduler interlocks effects with the notification outbox and journal. If a configured notification transport fails, the effect fence holds subsequent work and retains the notification for explicit retry; without a transport, the journaled outbox is the notification and the owner must read it. A journal failure also holds work; notification retry alone does not clear it. Inspect operation and receipts, reconcile the effect and journal state, then use fresh authority where needed. Never blindly repeat an ambiguous create or revoke.

## Emergency and outage

`npm run keyroot -- incident-prepare <emergency-signer-id> <lineage-id,...> <continuity-first|revoke-first> [consumer-id=destination-id,...] [--allow-interruption]` prepares a finite incident set. Revoke-first requires `--allow-interruption`; confirm the declared outage and quarantine destinations in the signed scope. Reopening an incident reads its exact current registration through signed batch status; registration itself authorizes no effect. Each incremental emergency action needs fresh proof; reserve the whole affected set before dispatch. A known leaked generation is not a continuity fallback. Quarantined destinations receive no replacement until trust is restored or residual risk is explicitly accepted. Report containment, service restoration and remaining owner action separately.

For box outage, managed local process controls are designed to stop at the configured 15–30 minute grace or earlier issuer expiry. Unmanaged copies and remote platform consumers are outside that guarantee. Use issuer-native actions for a leaked bearer credential. Recovery and rollback instructions are in [recovery.md](recovery.md).

## Required checks

The authoritative final-revision gates are listed in the [plan's Verification Contract](../plans/2026-10-25-2356-feat-keyroot-credential-lifecycle-plan.md#verification-contract). `verify:contracts` only verifies that each ledger key has a status and evidence, not whether the evidence establishes the requirement. `test:browser` covers component contracts, not a host-controlled browser journey. Disposable OpenBao integration requires Docker. Tests and a demo never replace physical/account gates.
