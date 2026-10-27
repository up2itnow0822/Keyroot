# Controller Offline Commands

## Purpose
- Own operator entry points for metadata backup and held recovery import and reauthentication.

## Ownership
- Core recovery owns archive validation and reconciliation; this folder owns private-file and local singleton boundaries.

## Local Contracts
- Use private owner-controlled files and the actual controller singleton fence; never print private material.
- Import and resume remain held and do not establish upstream quiescence, physical recovery or store-value restoration.
- Independent verification pins and separate store-value backups remain required.

## Work Guidance
- Preserve fail-closed staging and explicit limitations; do not fabricate recovery observations or authority.

## Verification
- Root typecheck and recovery integration tests.

## Child DOX Index
- None.
