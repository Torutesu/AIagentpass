# Host/Child XPC release qualification gate

This is one bounded, candidate-bound release gate for the dedicated Host/Child
XPC boundary. It does not change the native implementation and it does not
turn unit or synthetic evidence into macOS qualification.

Validate an evidence document with:

```sh
node scripts/release/xpc/verify-xpc-qualification.mjs XPC-EVIDENCE.json
```

The closed projection must show authenticated-XPC Host activation; an explicit
`live_eight_field` audit-token capture marker plus its digest (never the raw
token); the observed Child process identity; a Child-specific signed requirement
evaluation for the fixed `dev.agentpass.git-sign-xpc` principal whose digest
equals the Host activation record; and denial-before-sign evidence for same-UID
wrong Child, wrong Team, wrong entitlement, and stale/reused audit-token cases.

The live evidence remains external: signed/notarized artifacts, launchd Mach
services, real NSXPC audit-token extraction, and actual Child-helper requirement
evaluation on macOS. A passing validator only proves that the submitted
document is closed and internally bound. Until those observations exist, the
release-matrix row remains `not_proven`.
