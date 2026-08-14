# AgentPass Cloud API

Bootstrap a new self-hosted organization into a new protected directory:

```bash
npm run bootstrap -- --output-dir /absolute/protected/agentpass-cloud --organization-name "My team" --principal-id SIWC_USER_ID
```

The command prints the owner API token once. Store it as a server secret for the Web Console. It also writes the token verifier, Ed25519 bundle signer, public key, tenant store, and owner membership. Files are created without overwrite; secret files use mode `0600`.

## Provision an upstream identity

Before running `identity-bind`, confirm that:

- the PostgreSQL migrations, including the identity migration, have completed successfully;
- the exact `(organization_id, member_id)` pair exists as an active membership; and
- the operator environment can reach PostgreSQL with TLS certificate verification. `AGENTPASS_DATABASE_URL` is required and must use `sslmode=verify-full`.

The command accepts only the four named arguments below. Supply the database URL through the environment or a secret manager; never put it in an argument, shell command, process title, or pasted incident log. The values below are placeholders, not credentials:

```bash
export AGENTPASS_DATABASE_URL='postgresql://DB_USER:DB_PASSWORD@DB_HOST:5432/DB_NAME?sslmode=verify-full'
npm run identity-bind -- \
  --provider PROVIDER_NAME \
  --subject UPSTREAM_SUBJECT \
  --member-id MEMBER_UUID \
  --organization-id ORGANIZATION_UUID
```

The operation is transactional. It first locks and verifies the exact active membership, then inserts the immutable `(provider, subject) -> member_id` mapping. An exact repeat is idempotent: it reports `already_exists` and does not update or delete the mapping. If the subject already belongs to another member, the command fails closed with `identity_rebind_forbidden`; it never silently rebinds an identity.

### Failure, rollback, and verification

On any non-zero exit, record only the stable JSON error code and treat a database or network failure as an unknown outcome until verified. The transaction rolls back when membership verification, insertion, or conflict handling fails. A failed membership check or rebind attempt must leave no new mapping and must not change an existing mapping.

Verify the result with an approved read-only database client configured from the environment or a secret manager, not with a connection URL on the command line. Check that the exact provider and subject resolve to the expected member and that the membership remains active. If verification shows `created`, the mapping is immutable: do not attempt a delete-and-rebind rollback. Follow the incident procedure to disable the affected membership or identity access, preserve the audit evidence, and have an authorized operator determine the remediation. After an ambiguous transient failure, verify first and rerun only when the expected state is absent; an `already_exists` result is the safe idempotent completion.

Output is bounded JSON metadata only. Success reports the command, stable result (`created` or `already_exists`), and supplied identity/member/organization identifiers. Failure reports only `ok: false` and a stable error code. Database URLs, passwords, SQL text, stack traces, driver errors, tokens, and other credentials must never appear in stdout, stderr, monitoring, or incident tickets.

## Production persistence and human authentication

The production foundation lives in `src/postgres/` and uses the ordered SQL in `contracts/postgres/`. The migration runner verifies immutable SHA-256 checksums, refuses gaps/newer history/dirty attempts, takes a PostgreSQL advisory lock, and applies migrations transactionally. `AGENTPASS_CLOUD_PROFILE` is mandatory: `hosted` constructs only the PostgreSQL control-plane store, while `evaluation` is the only profile allowed to open the protected reference file store.

Hosted additionally requires `AGENTPASS_CAPABILITY_NONCE_SECRET` and `AGENTPASS_OPERATIONAL_PROBE_SECRET`, each a distinct canonical unpadded 32-byte base64url secret shared by the relevant Cloud instances/operators. The capability secret derives retry-stable nonces with a purpose-separated HMAC; PostgreSQL stores only the nonce digest and safe statement metadata. The operational secret authenticates readiness and metrics probes via the `AgentPass-Operational-Token` header. Hosted also requires the owner-recovery notification webhook settings described below; startup fails instead of silently accumulating undeliverable security notifications. Never put these values in a URL or log.

Human authentication modules provide opaque hash-only sessions, exact-origin and session-bound CSRF enforcement, PostgreSQL-backed one-time WebAuthn registration/authentication challenges, a maintained `@simplewebauthn/server` verifier adapter, and operation-bound recent authorization. A recent authorization is consumed atomically for one member, organization, and operation; it is not a reusable bearer token. Migration `0004_human_identity_and_webauthn_registration.sql` adds immutable provider/subject mappings and passkey metadata while challenges retain the exact RP/origin/UV/session/member/organization binding.

When Human Auth is enabled, capability issuance also requires the PostgreSQL organization, member, device, and agent projection to exist. The exact canonical signed-statement hash and issuing membership version are recorded before a bearer envelope is returned. Membership reduction revokes those rows transactionally; every subsequent device bundle fetch merges the bounded, unexpired PostgreSQL revocation set into `revoked_capabilities`. If the authority projection is missing, unavailable, malformed, or exceeds the ControlBundle protocol bound, issuance/bundle generation fails closed. Existing installed bundles learn the change through the authenticated Device API refresh route. Hosted Cloud uses a commit-only PostgreSQL notification as a wake-up hint and always performs a final authoritative query, so lost or duplicated notifications do not change correctness.

Device Activity listing is cursor-based. `GET /v1/organizations/{organization_id}/audit/events` requires one `device_id`, accepts `limit` from 1 through 500 and an optional opaque `cursor`, and returns `{events,next_cursor}` in descending `(device_timestamp,device_id,event_id)` order. Cursors are HMAC-authenticated, expire after 24 hours, and are bound to the exact organization and device. Hosted instances derive this purpose-separated cursor authority from the shared Human cursor root so cursors survive restart and instance switching. Hosted now uses PostgreSQL for the complete control plane; the file store is evaluation-only.

When all Human Auth variables below are present, the Cloud runtime constructs PostgreSQL sessions, immutable upstream-identity membership resolution, durable WebAuthn registration/authentication ceremonies, maintained verifiers, and recent-auth middleware. The Console BFF authenticates with a compact Ed25519 assertion lasting at most 60 seconds; production Human Auth does not accept a Cloud operator bearer or a caller-supplied member/role. Cloud pins the Console public key, issuer, audience, provider, and origin, atomically consumes the assertion JTI in PostgreSQL, and inserts the session only from the exact active membership row. Full PostgreSQL control-plane storage, recovery/abuse controls, and browser/physical-Mac release qualification remain production gates.

Start the API behind a TLS reverse proxy:

```bash
export AGENTPASS_CLOUD_PROFILE=hosted
export AGENTPASS_CLOUD_BUNDLE_PRIVATE_KEY_PATH=/absolute/protected/agentpass-cloud/bundle-private.pem
export AGENTPASS_CLOUD_REFRESH_PRIVATE_KEY_PATH=/absolute/protected/agentpass-cloud/refresh-private.pem
export AGENTPASS_CLOUD_REFRESH_KEY_ID=refresh-2026-08
export AGENTPASS_CLOUD_REFRESH_NONCE_KEYRING_PATH=/absolute/protected/agentpass-cloud/refresh-nonce-keyring.json
export AGENTPASS_CLOUD_HOST=127.0.0.1
export AGENTPASS_CLOUD_PORT=8080
# Enable the production Human Auth path as one all-or-nothing group:
export AGENTPASS_DATABASE_URL='postgresql://agentpass:...@db.example/agentpass?sslmode=verify-full'
export AGENTPASS_DATABASE_MAX_CONNECTIONS=10 # minimum 2; one is reserved while LISTEN is active
export AGENTPASS_CONSOLE_ORIGIN='https://console.example.com'
export AGENTPASS_WEBAUTHN_RP_ID='example.com'
export AGENTPASS_IDENTITY_PROVIDER='chatgpt'
export AGENTPASS_IDENTITY_ASSERTION_ISSUER='agentpass-console'
export AGENTPASS_IDENTITY_ASSERTION_AUDIENCE='agentpass-cloud-session'
export AGENTPASS_IDENTITY_ASSERTION_KID='console-2026-08'
export AGENTPASS_IDENTITY_ASSERTION_PUBLIC_KEY_PATH=/absolute/protected/agentpass-cloud/console-identity-public.pem
# Owner-recovery notifications are delivered to this HTTPS-only provider.
# Store the bearer value in an owner-only regular file, not in the environment:
export AGENTPASS_OWNER_RECOVERY_NOTIFICATION_WEBHOOK_URL='https://notifications.example.com/v1/agentpass/owner-recovery'
export AGENTPASS_OWNER_RECOVERY_NOTIFICATION_CONFIRMATION_URL='https://notifications.example.com/v1/agentpass/owner-recovery/acceptance'
export AGENTPASS_OWNER_RECOVERY_NOTIFICATION_AUTHORIZATION_PATH=/absolute/protected/agentpass-cloud/notification-authorization.txt
# This non-secret tuple is immutable for queued events. Generate the digest
# once, keep it stable across replicas, and rotate the key version/digest when
# the provider account, destination, or authorization authority changes.
export AGENTPASS_OWNER_RECOVERY_NOTIFICATION_BINDING_ID='owner-recovery-primary'
export AGENTPASS_OWNER_RECOVERY_NOTIFICATION_BINDING_KEY_VERSION='1'
export AGENTPASS_OWNER_RECOVERY_NOTIFICATION_BINDING_DIGEST="$(openssl rand -hex 32)"
# Generate once, store in the deployment secret manager, and reuse on every instance:
export AGENTPASS_HUMAN_CURSOR_SECRET="$(openssl rand -base64 32 | tr '+/' '-_' | tr -d '=\n')"
export AGENTPASS_HUMAN_AUTH_SECRET="$(openssl rand -base64 32 | tr '+/' '-_' | tr -d '=\n')"
export AGENTPASS_CAPABILITY_NONCE_SECRET="$(openssl rand -base64 32 | tr '+/' '-_' | tr -d '=\n')"
export AGENTPASS_OPERATIONAL_PROBE_SECRET="$(openssl rand -base64 32 | tr '+/' '-_' | tr -d '=\n')"
npm start
```

The notification authorization file must be a non-empty owner-only regular file (`0600`), with no symlink or hardlink and no trailing newline. The binding tuple is non-secret deployment identity, not a hash of the webhook URL: persist its random digest in the deployment secret/configuration manager, keep it identical across replicas, and rotate both key version and digest before changing provider account, destination, or authorization authority. Events already queued under an old tuple are never silently rebound. The delivery endpoint receives only the secret-free version-1 public event and an `Idempotency-Key` header equal to `event_id`. It must persistently deduplicate that key and return exactly one of these JSON objects with a 2xx status and `application/json`: `{"accepted":true,"duplicate":false}`, `{"accepted":true,"duplicate":true}`, or `{"accepted":false,"duplicate":false}`. Redirects, ambiguous responses, oversized responses, and transport failures are rejected.

The confirmation endpoint must provide a linearizable lookup over that same durable acceptance ledger. AgentPass sends `{"schema_version":1,"kind":"owner-recovery-notification-acceptance-lookup","provider_binding":{"binding_id":"…","key_version":1,"binding_digest":"…"},"idempotency_key":"…"}` and accepts only an exact `200`/`404` JSON response echoing `accepted`, `provider_binding`, and `idempotency_key`. A timeout or lost delivery acknowledgement moves the event to durable `uncertain`; AgentPass then performs bounded confirmation lookups and marks it published only after an exact positive proof. It never blindly resends notification content. A negative or unavailable lookup leaves the row uncertain for later lookup or explicit Owner/Admin retry/suppression.

The refresh signing key must be a separate Ed25519 key from the ControlBundle key. The nonce keyring file is owner-only JSON in this exact form: `{"version":1,"active_key_id":"refresh-nonce-v1","keys":{"refresh-nonce-v1":"<canonical 32-byte base64url secret>"}}`. Every Cloud instance must receive the same active and retained nonce keys. Rotation is dual-read/single-write: add the new key, switch `active_key_id`, retain old keys until every matching outbox/ACK has expired, then remove them. PostgreSQL stores only the key ID and SHA-256 digest, never the raw derived nonce.

Hosted exposes secret-free response contracts at `GET /health/ready` and `GET /health/metrics`, but both endpoints require the `AgentPass-Operational-Token` header. Readiness verifies database access, exact migration version/checksums, pool saturation, drain state, worker availability, dead letters, and bounded notification backlog/lag. It exposes aggregate counts only—never organization, request, event, destination, provider URL, or provider diagnostics. Shutdown marks readiness false, stops new worker cycles, waits for tracked requests and deliveries under the same bound, and only then closes PostgreSQL. Use [the cutover runbook](../../docs/POSTGRES_CUTOVER_RUNBOOK.md) and [backup/restore manifest procedure](../../docs/POSTGRES_BACKUP_RESTORE.md); committed migrations are forward-only and rollback changes application traffic, never authority history.

For provider outages, uncertain delivery, binding rotation, alert thresholds,
and reproducible PostgreSQL 16 qualification, use the
[owner-recovery delivery runbook](../../docs/OWNER_RECOVERY_DELIVERY_RUNBOOK.md).

`AGENTPASS_CLOUD_DATA_DIR` and `AGENTPASS_CLOUD_TOKEN_RECORDS_PATH` are required only with `AGENTPASS_CLOUD_PROFILE=evaluation`, where Human Auth is disabled. `AGENTPASS_CLOUD_PROFILE=hosted` rejects both variables, neither loads the file store nor accepts its bearer credentials, and fails startup on incomplete PostgreSQL, Human Auth, shared-control, or control-plane-store composition.

`AGENTPASS_CONSOLE_ORIGIN` must be an exact HTTPS origin. The RP ID must equal its hostname or be a parent suffix. `AGENTPASS_IDENTITY_PROVIDER` defaults to `chatgpt`; every verified Console subject must have an `upstream_identities` row and an active organization membership before session issuance. The identity assertion public-key file must be a regular owner-only Ed25519 SPKI PEM file; missing or unsafe assertion configuration fails startup. The matching private key belongs only in the Console deployment secret manager. `AGENTPASS_HUMAN_CURSOR_SECRET` authenticates opaque organization/member/invitation cursors. `AGENTPASS_HUMAN_AUTH_SECRET` is a distinct 32-byte root used only for domain-separated HMAC identifiers in Human-auth shared rate limits and signed-identity replay records. Both values must be canonical unpadded base64url and identical across Cloud API replicas; neither is returned as configuration metadata. Rotate either through a coordinated deployment: cursor rotation invalidates pagination, while Human-auth rotation starts fresh limiter/replay namespaces and therefore requires a controlled overlap decision at the deployment layer. Partial Human Auth configuration fails startup.

The process binds loopback by default. Terminate with SIGINT/SIGTERM for graceful shutdown. Hosted device replay evidence, authenticated rate limits, idempotency, and authority survive restart in PostgreSQL. A dedicated shared-control maintenance worker starts independently of recovery delivery, prunes idempotency, nonce, tenant limiter, anonymous limiter, and signed-identity replay records under one bounded budget, and stops before the pool closes. Its counters are fixed and label-free. Evaluation uses the exclusive single-writer file store; never share its JSON data directory between processes.

The API applies a peer-address admission limit before reading a body or running scrypt authentication, then applies a tenant/principal limit after authentication. In hosted mode there is no process-local allowance fallback: unauthenticated or malformed transport scopes map to fixed, purpose-separated HMAC UUID buckets in PostgreSQL, and a repository outage fails closed. Keep the runtime behind a TLS reverse proxy with its own connection and distributed rate limits. The reference runtime intentionally caps token records at 256 to bound authentication work.
