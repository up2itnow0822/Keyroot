# Recovery and rollback

Recovery is a control-plane workflow, not proof that the selected store, issuer accounts, phone or four machines can actually be recovered. Before relying on it, independently test encrypted backups, offline decryption and verification materials, the store's own value backup, an inventory, clean-device issuer-admin access and loss-of-phone recovery. Keep those materials independent and private. The emergency security key is an approver, not a vault or issuer-account backup.

The core archive uses age encryption and an independently pinned signature key. It contains validated metadata, not raw store values or private keys. A separate store-value capsule/backup and its own restore process are required. Import invalidates old approvals, privileged sessions and OAuth authority; ambiguous in-flight actions remain unknown. A local singleton check cannot cancel an upstream request or prove a former controller has stopped.

The current operator import takes private files and a new destination, and leaves the new real-mode installation held:

```sh
npm run keyroot -- recover --archive /absolute/private/archive --identity-file /absolute/private/age-identity --verification-pin-file /absolute/private/pin.json --destination-directory /absolute/private/new-installation --controller-socket /absolute/path/to/existing/boot.sock
```

The archive, identity and verification-pin files must be private, regular, owner-controlled files; the destination must not exist and its parent must be private. Stop the existing controller and use its actual `boot.sock` singleton path, not its `admin.sock` command socket. The local fence does not prove a remote predecessor or upstream request has stopped. The pin must come from an independent trusted source, not the archive. A successful response is `imported-held`, not activation or proof of real restoration. Releasing a hold requires configured recovery coordination, fresh scoped predecessor/store/issuer observations, reconciliation and an exact shared epoch transition; do not fabricate observations or use old authority. The current `recovery-resume` CLI only reauthenticates and reports a held installation; it does not release the hold. The supplied controller entry point does not wire a live recovery coordinator. Real-mode recovered installations cannot be used as public demos.

The offline `backup` command exports encrypted metadata using an independent signing key, and `recovery-resume` reopens a held import. Their required flags are defined in `apps/controller/src/commands/recover.ts`. Neither command backs up store values or establishes that an actual recovery can be completed.

For a lost phone, require independent offline recovery material and a verified emergency ceremony; a copied fingerprint or archived signer is insufficient. For suspected root compromise, use clean issuer-native administration, replace compromised management authority, invalidate sessions where supported, rebuild a trusted controller, and report what could not be invalidated. Reconcile pending issuer work before retry. Store recovery, physical custody, and clean-device drills remain open gates.

For a mapped env-file rollback, use the separately authorized exact rollback descriptor and protected backup; a restored file is not proof of successor delivery or use. For remote targets, use the issuer or destination's supported manual recovery route and record its evidence. Do not publish secret values or raw provider errors in receipts, logs or reports.
