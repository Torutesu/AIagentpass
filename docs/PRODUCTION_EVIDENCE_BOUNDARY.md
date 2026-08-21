# A7/A8 production evidence boundary

`scripts/release/verify-production-evidence.mjs` is the final repository-side
envelope validator for the hosted signer (A7) and release/distribution (A8)
gates. It binds KMS, PostgreSQL, and release evidence to one candidate and one
source commit. It does not create provider, database, Apple, or macOS evidence.

## Required inputs

The manifest is canonical JSON and contains exactly these top-level fields:

```text
schema_version, kind, candidate, gates, signature
```

`candidate` contains the exact PKG name/digest, candidate ID, version, and
source commit. `gates` contains:

- a signed production KMS report plus its independently pinned qualification
  public key and key ID;
- a closed PostgreSQL backup/restore envelope from
  `scripts/postgres/backup-restore-qualification.mjs`;
- the existing offline release evidence and a protected macOS attestation.

The bundle signature is checked against a public key supplied outside the
manifest. The key ID and fingerprint in the manifest must match that external
trust pin. Every referenced file is a basename in the evidence root, a
single-link regular file, and is hashed while being read. The signature covers
the complete unsigned manifest, including all descriptors and candidate
bindings.

## Verification

```sh
node scripts/release/verify-production-evidence.mjs \
  /secure/evidence/production-evidence-manifest.json \
  /secure/evidence \
  /secure/keys/production-evidence-public.der \
  production-evidence-2026
```

Only a successful verification returns `status: "closed"`. The release
evidence validator remains offline-only; therefore the bundle additionally
requires a canonical, candidate-bound attestation with
`evidence_origin: "protected_external"`, `verification_mode:
"protected_macos"`, and all three live checks (`notarytool_verified`,
`stapler_verified`, `gatekeeper_verified`) set to true. The attestation is
accepted only because its descriptor is covered by the independently pinned
bundle signature; a JSON status string by itself is never sufficient.

Missing, malformed, unsigned, substituted, fixture-origin, stale, or
candidate-mismatched evidence returns `status: "not_proven"` and a non-zero
exit code. No command in this repository may replace those missing inputs with
mock AWS/GCP credentials, a local PostgreSQL result, or a simulated Apple
result.

## External gates that remain external

The validator proves the binding and integrity of supplied evidence. Operators
must still run the protected AWS/GCP workload-identity qualification, the two
real PostgreSQL instances and restore/PITR rehearsal, and the protected macOS
Developer ID/notarization/Gatekeeper job. The repository's unit tests exercise
rejection and binding paths only; they are not production qualification.
