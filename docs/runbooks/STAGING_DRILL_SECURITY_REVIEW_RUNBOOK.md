# Staging drills and independent security review

## Staging entry criteria

Deploy immutable Console/API/worker images, PostgreSQL schema, managed signer
configuration, Platform Auth, TLS/DNS, rate limits, alerts, and operator
access from versioned configuration. Record source/tree, image/package/SBOM
digests, migration/catalog digest, deployment digest, and environment class.
Secret-scan source, image layers, logs, and evidence before traffic. Staging
must not use production private keys or production tenant data.

## Drill matrix

| Drill | Action | Pass condition and evidence |
| --- | --- | --- |
| Canary/drain | Route bounded traffic, stop new work, drain old instances. | No unfenced operation; error/readiness/audit timeline and rollback owner recorded. |
| Signer outage/rotation | Deny provider calls, rotate one purpose, restore service. | Readiness fails closed; no blind retry; exact lookup/receipt and old-key rejection are evidenced. |
| Database failover/PITR | Fail primary, restore isolated PITR target, compare authority state. | Measured RPO/RTO, checksum/row-count/authority comparison, no destructive live rollback. |
| Network/response loss | Drop response after provider acceptance and during commit. | Durable `uncertain` state reconciles exactly or remains operator-actionable; no duplicate sign. |
| Emergency stop/revoke | Revoke agent/device/session and apply global stop. | Next operation denied within measured bound; audit event and cache/offline expiry evidence retained. |
| Recovery/dead letter | Exercise owner recovery, uncertain adjudication, and bounded redrive. | Role/recent-auth/idempotency/If-Match checks hold; no row deletion or secret exposure. |
| Upgrade/rollback | Apply forward migration, deploy previous compatible immutable candidate. | Compatibility and rollback owner approval recorded; no rebuild and no down-migration. |
| Agent E2E | Run Claude Code and Cursor unattended signing, restart, expiry, revoke, and network-loss cases. | Verified commits and denial-after-revoke on exact candidate; hostile substitution and leak scans pass. |

For every drill record trigger, operator, start/end UTC, source/tree and
artifact/deployment digests, scenario ID, expected/observed state, metrics,
stable failure code, logs/trace locations after redaction, and independent
witness. A sandbox `EPERM` or unavailable provider is an environment blocker,
not a passing drill.

## Security review procedure

Commission an independent reviewer with no implementation approval authority.
Provide the exact source/tree, threat model, contracts, relevant code/tests,
workflow/release policy, staging drill packet, and evidence index. Review at
minimum:

- local/XPC privilege and executable trust, loopback onboarding, and Secure
  Enclave/key lifecycle;
- WebAuthn, human session, organization role, tenant isolation, CSRF,
  recent-auth, replay, idempotency, stale-state, and response-loss paths;
- KMS/IAM purpose separation, key version/lifecycle fencing, PostgreSQL roles,
  RLS, migration authority, backup/PITR, and reconciliation;
- package/update supply chain, Developer ID/notarization, entitlements,
  profiles, artifact/archive scanning, and workflow secret exposure; and
- audit integrity, incident/revoke, recovery, privacy, denial of service,
  monitoring, and operational rollback.

The reviewer returns a signed report bound to source/tree and evidence
digests. Each finding includes severity, invariant, exact path/line or test,
impact, exploitability, owner, fix, retest command, retest result, and closure
authority. Critical/high findings block promotion. Medium findings require a
documented risk decision and security retest; a plan status cannot close them.

## Final go/no-go checklist

- [ ] All drills pass with measured RPO, RTO, revocation bound, and alert
  delivery; failures and replacement runs are retained.
- [ ] Security review report is independent, source-bound, and signed.
- [ ] No critical/high finding remains; every security-relevant medium has a
  passing retest or an explicitly approved risk decision.
- [ ] Promotion evidence has exact source/tree/run/job/artifact bindings and no
  `not_run`, `failed`, `not_proven`, skipped, simulated, or ad-hoc result.
- [ ] Incident commander, rollback owner, emergency contacts, disclosure
  policy, retention location, and post-promotion monitor are named.
- [ ] Approver records `GO` only after the release stop conditions pass;
  otherwise records `STOP` with a stable reason code.
