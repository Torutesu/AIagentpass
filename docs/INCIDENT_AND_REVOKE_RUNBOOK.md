# AgentPass incident and revoke runbook

This is the operator procedure for a suspected key, device, agent, session,
provider, deployment, or release incident. It is deliberately fail-closed.
Preserve evidence first; never resolve uncertainty by blindly retrying a
provider call, rebuilding a candidate, or deleting durable rows.

## 0. Safety rules

- Do not paste or record private keys, bearer tokens, cookies, WebAuthn
  assertions, database URLs, provider responses, claims, or secret-manager
  output in tickets, chat, shell history, logs, or evidence.
- Treat a lost response after a provider boundary as `uncertain`, not failed.
  Reconcile through the durable operation/provider receipt lookup.
- Stop new promotion and authority-changing traffic before investigation. Keep
  the last known-good immutable artifact and database state available.
- Do not run down-migrations, delete audit/ledger rows, restore an old schema
  over a live database, or overwrite a release artifact.
- Record UTC timestamps, candidate/source/artifact digests, request IDs, and
  redacted stable reason codes only.

## 1. Declare and contain

Declare an incident when any of these occurs: suspected private-key exposure;
wrong tenant or role decision; invalid signature or purpose/key substitution;
unexpected promotion or deployment generation; provider response loss or
uncertain issuance; database integrity/restore failure; release secret scan
failure; package/notarization mismatch; or revocation not observed within the
bound.

Immediately:

1. Open an incident record and assign incident commander, security owner,
   deployment owner, and communications owner.
2. Capture the exact candidate source commit/tree and artifact digests. Save
   sanitized readiness, audit, and deployment state; do not capture raw
   payloads or credentials.
3. Stop promotion, canary expansion, and new signer issuance for the affected
   purpose/deployment. If the Platform route is unavailable or incompletely
   wired, preserve `404`/`503`; never substitute organization authentication.
4. If compromise scope is global or unknown, use the emergency stop/revoke
   path and disable traffic at the deployment boundary. Confirm the durable
   state and audit event before declaring containment.
5. Notify the key/provider/database/release owner through the approved channel.

## 2. Revoke by scope

Use the narrowest scope that fully contains the incident, then widen if the
scope cannot be proven.

### Local broker and agent identity

```sh
agentpass agent revoke AGENT_ID --confirm REVOKE
agentpass revoke
agentpass status
agentpass audit --verify
```

`agentpass revoke` is the single emergency-stop entry point. In local mode it
advances the audited user-state generation. In native mode it dispatches only
to the protected broker's session-revocation operation; it never writes the
legacy user-state flag or exposes a session token. Use the same command during
an incident, regardless of installation mode.

For explicit native diagnostics, use:

```sh
agentpass native revoke-sessions
agentpass control status
agentpass audit --verify
```

For remote/global control, issue a new offline-signed bundle with a strictly
higher sequence and short expiry, then apply it through the documented control
path. Confirm the host rejects expired, rolled-back, malformed, or conflicting
bundles. Do not reuse an old sequence or expose the control private key.

### Device, organization, or human session

Use the authenticated Console/API operation with the required organization
role, recent resource-bound WebAuthn, CSRF protection, idempotency key, and
expected version. If the response is lost, read the authoritative state by
resource/version before retrying. A stale version or `409` is an investigation
signal, not permission to force an update.

Revoke the device/session first, then verify:

- the authoritative state is `revoked` with a new version/epoch;
- subsequent signed requests are denied;
- the audit event is durable and secret-free;
- cached/offline authority expires or is rejected within the measured bound.

### Managed signer or provider

1. Stop issuance for the affected purpose and key version.
2. Mark in-flight ambiguous operations `uncertain`; retain operation ID,
   request digest, purpose, protocol version, key version, and provider receipt
   identifiers only.
3. Reconcile by exact lookup and signature/public-key verification. Never
   re-sign merely because the HTTP response was lost.
4. Disable/revoke the key at the provider when compromise or unverifiable
   acceptance is suspected. Stage a new non-exportable key and complete the
   dual-key rotation ceremony before resuming issuance.
5. Reject stale lifecycle versions and prohibit old-key signing after the write
   cutover. Attach the redacted provider/KMS evidence to the incident record.

### Release or deployment candidate

1. Quarantine the candidate and prevent publication/traffic promotion.
2. Compare release manifest, source commit/tree, PKG, image, SBOM, migration,
   qualification, and evidence digests. Any mismatch is a stop condition.
3. If a release credential may be exposed, revoke/rotate it through the
   protected provider and review its use; never copy it into the incident.
4. Roll traffic back to the last independently qualified digest only after
   compatibility, database forward-only rules, and rollback owner approval are
   recorded. Never rebuild the promoted candidate during rollback.

## 3. Verify containment

Containment is complete only when all applicable checks pass:

- affected authority is disabled or revoked at the authoritative boundary;
- new operations are denied and cached/offline paths are within the measured
  revocation bound;
- no open `reserved`/`uncertain` operation is being silently retried;
- audit events, deployment state, and evidence are durable and verifiable;
- readiness is fail-closed for any missing/disabled/stale purpose;
- candidate/package/source/tree/run/job/artifact bindings are exact;
- monitoring and alerting show no continuing unauthorized activity.

If any check cannot be proven, keep promotion and affected traffic stopped and
escalate to the incident commander. Do not call the incident contained based on
an HTTP `200`, process health, or a focused test alone.

## 4. Recover and close

1. Preserve the original failure evidence and create a new redacted recovery
   evidence record; do not mutate the original record.
2. Repair the dependency or rotate the authority in a protected environment.
3. Run the relevant qualification, including response loss, restart,
   concurrency, stale-state, and revoke-during-operation cases.
4. Verify the exact candidate/source/tree/artifact bindings and rerun all
   applicable promotion stop conditions.
5. Resume traffic in a bounded canary with an explicit rollback owner. Observe
   revocation, audit, signer, database, and error-rate metrics.
6. Close only after security review signs the timeline, impact, root cause,
   corrective action, retained evidence locations, and follow-up owners.

## Required incident record fields

`incident_id`, severity, commander, start/end UTC, scope, source commit/tree,
candidate/image/PKG/SBOM/migration digests, affected purpose/key version,
operation IDs, stable reason codes, revoke timestamp and measured bound,
authoritative post-revoke result, audit-event ID, rollback target, evidence
digests/retention, reviewer, and closure approval. Values that contain secrets
or raw provider/identity material are prohibited.
