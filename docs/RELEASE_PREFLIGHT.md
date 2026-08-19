# Release preflight and production gate

This is the release-blocking contract for the native audit delivery and the
external qualification evidence that cannot be established by focused local
tests. A release candidate is promotable only when all five checks below are
`passed` for the same source commit and package/container digest:

| Check | Required live evidence |
| --- | --- |
| `native_audit_delivery` | The current independent native audit delivery, including the live Host/Child identity and lifecycle boundary, reviewed for this exact candidate. A focused test result alone is not sufficient. |
| `cloud_production_deploy` | A real production deployment, immutable revision, ready health check, source commit, and SHA-256 artifact digest. An image push to GHCR or a staging result is not a production deployment. |
| `real_postgresql` | Qualification against a real PostgreSQL instance covering the reviewed roles, migrations, privilege-negative checks, and relevant transaction/concurrency behavior. A skipped live-PostgreSQL test is not `passed`. |
| `developer_id_notarization` | Developer ID application/installer signatures, Apple notarization ticket, stapling, and Gatekeeper verification for the exact package digest. Offline metadata alone is not `passed`. |
| `hardware_qualification` | Signed native candidate qualification on Apple silicon and Intel/T2 hardware, including the native host/device boundary scenarios, with both reports bound to the exact package digest. |

The machine-readable input is supplied by the release system at the path given
to `scripts/ops/verify-release-preflight.mjs`:

```json
{
  "schema_version": 1,
  "candidate": {
    "commit_sha": "<40 lowercase hex characters>",
    "artifact_digest": "sha256:<64 lowercase hex characters>"
  },
  "checks": {
    "native_audit_delivery": {
      "status": "passed|failed|unknown",
      "evidence_ref": "redacted immutable evidence reference",
      "commit_sha": "<same candidate commit>",
      "artifact_digest": "<same candidate digest>"
    }
  }
}
```

The five check objects are required. The example shows the common fields; each
check must be present and must carry its own candidate binding when `status` is
`passed`. Evidence references must not contain tokens, passwords, private keys,
authorization headers, or other secret material.

判定は fail-closed です。

- `passed` (exit `0`) は5項目すべてが `passed` で、同じ commit/digest に束縛されている場合だけです。
- `failed` (exit `1`) は否定的な qualification、schema/binding 不一致、または不正な証跡です。
- `unknown` (exit `2`) は evidence file の欠落、live qualification の未取得、skip、または `unknown` の報告です。これは promotion を許可しません。

現在の独立レビューが記録している実 Cloud/DB、Developer ID/notarization、
Apple silicon/Intel hardware、launchd/NSXPC の production-unverified 状態は、
この契約では `unknown` のままです。`validated_offline` や focused tests の
成功から `passed` を推論してはいけません。

## Local commands

```sh
node scripts/ops/verify-cloud-deployment.mjs path/to/cloud-production-evidence.json
node scripts/ops/verify-release-preflight.mjs path/to/release-evidence.json \
  --candidate-commit-sha "$(git rev-parse HEAD)"
node --test scripts/ops/verify-cloud-deployment.test.mjs \
  scripts/ops/verify-release-preflight.test.mjs
```

`.github/workflows/release-preflight.yml` runs this check in the protected
`production` environment for version tags or an explicitly dispatched run.
Until an approved evidence file is supplied, that workflow intentionally ends
as `unknown`; this checkout therefore must not be described as production-ready.

The existing `cloud-image.yml` publishes a container image with provenance and
SBOM metadata. It is not evidence of a production deployment and is not a
substitute for the `cloud_production_deploy` check.
