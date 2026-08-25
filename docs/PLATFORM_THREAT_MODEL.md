# Platform Threat Model and Abuse-Case Evidence

Status: S2 working release gate
Scope: hosted Platform Session and Platform promotion authority, including the
browser Console boundary, Cloud API, PostgreSQL authority store, and managed
signer boundary.  The local agent/native Secure Enclave boundary is included
only where it is an input to the hosted Platform decision.

This document answers one release question: for every Platform threat that can
be exercised deterministically in this repository, where is the executable
test?  A test link is not a claim that the whole threat is eliminated; it is a
claim that the named abuse case is executable and fail-closed.  Physical,
provider, and production-topology claims are deliberately not represented as
unit-test coverage.  They remain external release evidence with an owner and
an explicit exit condition.

## Trust boundaries

| Boundary | Attacker-controlled input | Required invariant |
| --- | --- | --- |
| Browser / Console → Platform HTTP API | origin, cookies, CSRF, proof/JTI headers, JSON, organization identifiers | The request is same-origin, operation-bound, replay-resistant, and authorized by a Platform role; organization roles cannot become Platform operators. |
| Platform API → PostgreSQL | request digest, session/proof identity, idempotency key, transaction outcome | Authorization, reservation, replay handling, and tenant binding are checked in the database transaction; a failed transaction leaves no authority mutation. |
| Platform API → managed signer | purpose, immutable operation binding, provider result, timeout/connection loss | Sign exactly once or surface an uncertain result; never blind re-sign or expose provider diagnostics. |
| Release artifact / control state | package, dependency, signed bundle, sequence, persisted state | Provenance, signature, version floor, monotonic sequence, and rollback/equivocation checks hold before authority is used. |
| Host / physical device / cloud provider | local administrator or malware, stolen device, KMS/database/provider operator | These are external release qualifications; source tests cannot establish hardware extraction resistance or a production provider's isolation. |

## Abuse-case rules

1. Public intent never carries an authority-bearing role, signer output, or
   tenant selector that is not independently bound by the server.
2. A proof, session, JTI, idempotency key, reservation, or signer operation
   cannot be reused with changed content, another tenant, or another
   operation.
3. PostgreSQL rollback and response loss are different cases: transaction
   rollback must remove the mutation, while a lost response after a durable
   signer boundary must converge without a second signing operation.
4. A downgrade or rollback must fail closed even when the older material is
   otherwise correctly signed.  Same-sequence equivocation is also a failure.
5. External evidence is release-blocking, not an aspirational backlog item.
   A release candidate is not production-qualified while an external row below
   lacks its signed artifact or drill result.

## Evidence ledger

The following JSON block is the source of truth consumed by
`test/platform-threat-model-evidence.test.mjs`.  `scope: "local"` requires at
least one executable test link.  `scope: "external"` requires an explicitly
owned release artifact and exit condition.  Local rows may also carry residual
external evidence when the deterministic test covers only a narrow abuse case.

```json
{
  "schema": "agentpass.platform-threat-ledger.v1",
  "threats": [
    {
      "id": "PTM-01",
      "name": "browser-compromise-or-extension",
      "scope": "local",
      "abuse_case": "A hostile extension or browser-originated request attempts to inject identity headers, ambiguous cookies, or a cross-origin Platform mutation.",
      "local_tests": [
        {
          "file": "apps/cloud-api/test/platform-session-http-api.test.mjs",
          "name": "origin, forbidden identity headers, and ambiguous cookies fail closed"
        }
      ],
      "external_release_evidence": {
        "artifact": "signed-live-browser-console-report.json",
        "owner": "Console security owner",
        "exit_condition": "A clean-browser and hostile-extension matrix records origin, cookie, CSRF, CSP, and no-store behavior against the immutable release candidate."
      }
    },
    {
      "id": "PTM-02",
      "name": "platform-session-theft",
      "scope": "local",
      "abuse_case": "A captured or duplicated platform session attempts to mint authority again, bypass proof binding, or replay bearer material after a lost response.",
      "local_tests": [
        {
          "file": "apps/cloud-api/test/platform-session-webauthn.test.mjs",
          "name": "successful verification never replays bearer material after a lost response"
        },
        {
          "file": "apps/cloud-api/test/platform-session-webauthn.test.mjs",
          "name": "challenge/JTI mismatch fails before one-use claim"
        }
      ],
      "external_release_evidence": {
        "artifact": "signed-session-cookie-rotation-and-revocation-drill.json",
        "owner": "Identity and operations owner",
        "exit_condition": "The release candidate passes browser-profile theft response, cookie rotation, global revoke, and session invalidation drills in production-like TLS and clock conditions."
      }
    },
    {
      "id": "PTM-03",
      "name": "confused-deputy",
      "scope": "local",
      "abuse_case": "Human or Agent Session routes, injected services, or a legacy route are used as a deputy to reach Platform promotion authority without the explicit Platform operator boundary.",
      "local_tests": [
        {
          "file": "apps/cloud-api/test/server-platform-promotion-http-routing-attack.test.mjs",
          "name": "authorized Platform promotion API intercepts the raw request before Human auth"
        },
        {
          "file": "apps/cloud-api/test/platform-promotion-hosted-composition-attack.test.mjs",
          "name": "Human Session and recent-auth availability cannot resurrect Hosted legacy promotion routes"
        }
      ],
      "external_release_evidence": {
        "artifact": "signed-platform-operator-access-review.json",
        "owner": "Platform operations owner",
        "exit_condition": "A production-like route inventory and role review proves no organization role, support path, or legacy endpoint can act as a Platform operator."
      }
    },
    {
      "id": "PTM-04",
      "name": "proof-replay",
      "scope": "local",
      "abuse_case": "A valid WebAuthn proof, challenge, JTI, or idempotency material is replayed or paired with different request content.",
      "local_tests": [
        {
          "file": "apps/cloud-api/test/platform-session-webauthn.test.mjs",
          "name": "challenge/JTI mismatch fails before one-use claim"
        },
        {
          "file": "apps/cloud-api/test/postgres/platform-authorization.integration.test.mjs",
          "name": "0054 real PostgreSQL authorization concurrency and denial matrix"
        }
      ],
      "external_release_evidence": {
        "artifact": "signed-platform-proof-replay-load-report.json",
        "owner": "Identity security owner",
        "exit_condition": "A two-instance replay load against the release candidate records zero second claims and no cross-operation acceptance under production-like latency."
      }
    },
    {
      "id": "PTM-05",
      "name": "tenant-substitution",
      "scope": "local",
      "abuse_case": "An attacker substitutes organization, assignment, device, request digest, or promotion identifiers to authorize work in another tenant.",
      "local_tests": [
        {
          "file": "apps/cloud-api/test/platform-session-webauthn.test.mjs",
          "name": "every authority binding field is exact and cannot be substituted"
        },
        {
          "file": "apps/cloud-api/test/postgres/platform-authorization.integration.test.mjs",
          "name": "0054 real PostgreSQL authorization concurrency and denial matrix"
        }
      ],
      "external_release_evidence": {
        "artifact": "signed-multi-tenant-isolation-report.json",
        "owner": "Cloud API security owner",
        "exit_condition": "A seeded multi-tenant staging run proves denied cross-tenant reads, writes, replays, audit views, and operator actions with opaque responses."
      }
    },
    {
      "id": "PTM-06",
      "name": "local-malware",
      "scope": "local",
      "abuse_case": "Another same-user process or compromised Agent attempts to widen the Platform route, inject an authorizer, or use a session outside its bounded operation.",
      "local_tests": [
        {
          "file": "apps/cloud-api/test/platform-promotion-hosted-composition-attack.test.mjs",
          "name": "Hosted-style composition exposes only the authorized Platform boundary"
        },
        {
          "file": "apps/cloud-api/test/runtime.test.mjs",
          "name": "hosted runtime rejects an externally injected platform operator authorizer"
        }
      ],
      "external_release_evidence": {
        "artifact": "signed-host-compromise-and-native-boundary-report.json",
        "owner": "Native security owner",
        "exit_condition": "A hardened macOS qualification demonstrates process, IPC, keychain/Secure Enclave, launch-at-login, and uninstall behavior against a same-user malware harness; full host root compromise is recorded as out of boundary."
      }
    },
    {
      "id": "PTM-07",
      "name": "signer-uncertainty",
      "scope": "local",
      "abuse_case": "The signer or network fails after the provider boundary, and retry logic either signs twice or reports a false terminal result.",
      "local_tests": [
        {
          "file": "apps/cloud-api/test/provider-operation-reconciliation-adapter.test.mjs",
          "name": "converges response loss after commit without invoking the direct provider twice"
        },
        {
          "file": "apps/cloud-api/test/provider-operation-reconciliation-adapter.test.mjs",
          "name": "rejects a wrong provider signature and fences the operation as uncertain"
        }
      ],
      "external_release_evidence": {
        "artifact": "signed-managed-signer-outage-and-recovery-report.json",
        "owner": "Signer platform owner",
        "exit_condition": "The selected cloud signer is exercised through timeout, connection loss, duplicate delivery, key disablement, rotation, and operator adjudication with provider audit correlation."
      }
    },
    {
      "id": "PTM-08",
      "name": "database-rollback",
      "scope": "local",
      "abuse_case": "A failed transaction or process loss leaves a partial authorization mutation, or an older database state is restored and reused.",
      "local_tests": [
        {
          "file": "apps/cloud-api/test/postgres/platform-authorization-failure-qualification.integration.test.mjs",
          "name": "S1 PostgreSQL failure convergence qualifies rollback, commit-loss reconciliation, and fail-closed database outcomes"
        },
        {
          "file": "test/control-bundle-v2.test.mjs",
          "name": "requires monotonic sequence and same-sequence hash evidence without mutating on failure"
        }
      ],
      "external_release_evidence": {
        "artifact": "signed-postgresql-pitr-rollback-drill.json",
        "owner": "Database operations owner",
        "exit_condition": "A production-like backup/PITR restore proves authority, audit, signer lifecycle, and replay state cannot be rolled back into an accepted older state; the restore and traffic rollback are separately recorded."
      }
    },
    {
      "id": "PTM-09",
      "name": "supply-chain-compromise",
      "scope": "external",
      "abuse_case": "A dependency, build worker, package, container, or release workflow is altered to weaken authorization or exfiltrate signing material.",
      "local_tests": [],
      "external_release_evidence": {
        "artifact": "signed-release-sbom-provenance-and-reproducibility-report.json",
        "owner": "Release engineering owner",
        "exit_condition": "The immutable release candidate has dependency review, lockfile verification, SBOM, SLSA/provenance attestation, secret scan, signed checksums, and an independent build or reproducibility comparison."
      }
    },
    {
      "id": "PTM-10",
      "name": "downgrade",
      "scope": "local",
      "abuse_case": "An older signed control bundle, protocol epoch, or state file is installed to bypass a newer revocation or policy restriction.",
      "local_tests": [
        {
          "file": "test/control-bundle-v2.test.mjs",
          "name": "persists an atomic state head and permanently rejects legacy v1 after first v2"
        },
        {
          "file": "test/remote-control.test.mjs",
          "name": "expired, overlong, and runtime-rollback bundles fail closed"
        }
      ],
      "external_release_evidence": {
        "artifact": "signed-upgrade-downgrade-and-traffic-rollback-report.json",
        "owner": "Release and operations owner",
        "exit_condition": "Upgrade, interrupted upgrade, rollback-without-schema-reversal, uninstall-preserve, and emergency revocation are rehearsed using the exact signed artifact and version floor."
      }
    },
    {
      "id": "PTM-11",
      "name": "physical-device-compromise",
      "scope": "external",
      "abuse_case": "A stolen, unlocked, repaired, or offline device is used to extract a non-exportable key or continue a cached Platform operation.",
      "local_tests": [],
      "external_release_evidence": {
        "artifact": "signed-macos-secure-enclave-and-stolen-device-report.json",
        "owner": "Device security owner",
        "exit_condition": "A Developer ID/notarized release is tested on supported macOS hardware for lock, sleep/wake, offline expiry, key non-exportability, revocation, recovery, and secure uninstall; unsupported hardware is rejected."
      }
    },
    {
      "id": "PTM-12",
      "name": "cloud-provider-or-production-topology-compromise",
      "scope": "external",
      "abuse_case": "A cloud operator, KMS administrator, database superuser, network intermediary, or production misconfiguration bypasses the tested application boundary.",
      "local_tests": [],
      "external_release_evidence": {
        "artifact": "signed-production-cloud-boundary-and-incident-drill-report.json",
        "owner": "Cloud platform security owner",
        "exit_condition": "Independent review, IAM separation, KMS key policy review, TLS/private networking, database role review, alerting, tenant isolation, signer compromise response, and disaster recovery pass in the selected production topology."
      }
    }
  ]
}
```

## Release interpretation

The local ledger is necessary evidence for the application boundary, not a
substitute for the external rows.  Before production enablement, release
engineering must attach the signed artifacts named above to the release
candidate and record the source commit, deployed image/package digests,
database migration head, provider key versions, and the exact environment used
for each drill.  A missing artifact, a skipped scenario, or an unresolved
owner is a release-blocking S2 finding.
