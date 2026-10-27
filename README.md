# Keyroot

Keyroot is an in-progress personal credential lifecycle coordinator for four machines and connected platforms. It maps credential use and coordinates bounded approvals, delivery, adoption evidence, issuer outcomes, incident response and recovery. Native Claude Code and Codex subscription authentication remains native, and production requests and refresh must not depend on the Keyroot box.

The workspace includes an owner controller and review, a separate phone approval build, lifecycle and recovery machinery, and synthetic integration fixtures. The supplied controller entry point does not wire live provider, store, admission or recovery ports. Real account admission, phone custody, the selected existing store, four-machine behavior, isolation and independent recovery remain unverified. A demo or successful fixture does not establish live readiness. The [1Password pilot profile](docs/operations/onepassword-pilot-proposal.md) is a proposal awaiting confirmation, not an admitted adapter.

With Node 24.18+ in the 24.x series and npm 11+:

```sh
npm ci
npm run dev
```

Open `http://127.0.0.1:4173/` for the synthetic local demo. It uses project-local `runtime/demo-dev`; direct controller/CLI defaults are `~/.keyroot-demo` for demo and `~/.keyroot` for real. Runtime directories cannot change modes. The preview is not a trusted production phone origin. See [operating guidance](docs/operations/README.md), [provider coverage](docs/operations/provider-capabilities.md), [recovery](docs/operations/recovery.md), and the [validation ledger](docs/operations/validation-ledger.md). The [plan](docs/plans/2026-10-25-2356-feat-keyroot-credential-lifecycle-plan.md) defines requirements, final verification and the physical/account gates required before real operations.

[MIT License](LICENSE).
