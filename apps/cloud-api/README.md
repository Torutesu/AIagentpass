# AgentPass Cloud API

Bootstrap a new self-hosted organization into a new protected directory:

```bash
npm run bootstrap -- --output-dir /absolute/protected/agentpass-cloud --organization-name "My team" --principal-id SIWC_USER_ID
```

The command prints the owner API token once. Store it as a server secret for the Web Console. It also writes the token verifier, Ed25519 bundle signer, public key, tenant store, and owner membership. Files are created without overwrite; secret files use mode `0600`.

## Provision an upstream identity

After the PostgreSQL migrations have been applied, an operator can bind one upstream identity to an existing active organization membership. The command is non-interactive and reads the database connection only from `AGENTPASS_DATABASE_URL`; the URL must use `sslmode=verify-full`.

```bash
export AGENTPASS_DATABASE_URL='postgresql://agentpass:...@db.example/agentpass?sslmode=verify-full'
npm run identity-bind -- \
  --provider chatgpt \
  --subject UPSTREAM_SUBJECT \
  --member-id 22222222-2222-4222-8222-222222222222 \
  --organization-id 33333333-3333-4333-8333-333333333333
```

The command first locks and verifies the exact active `(organization_id, member_id)` membership. It then inserts the immutable `(provider, subject) -> member_id` mapping. Repeating the same command is safe and reports `already_exists`; attempting to bind an existing subject to another member fails closed with `identity_rebind_forbidden`. It never updates or deletes an identity mapping, runs no interactive prompt, and emits only bounded JSON metadata; database URLs, passwords, driver errors, and credentials are never printed.

## Production persistence and human authentication

The production foundation lives in `src/postgres/` and uses the ordered SQL in `contracts/postgres/`. The migration runner verifies immutable SHA-256 checksums, refuses gaps/newer history/dirty attempts, takes a PostgreSQL advisory lock, and applies migrations transactionally. Run it with a TLS-configured `pg` client; the reference file store remains for self-hosted evaluation and tests.

Human authentication modules provide opaque hash-only sessions, exact-origin and session-bound CSRF enforcement, PostgreSQL-backed one-time WebAuthn registration/authentication challenges, a maintained `@simplewebauthn/server` verifier adapter, and operation-bound recent authorization. A recent authorization is consumed atomically for one member, organization, and operation; it is not a reusable bearer token. Migration `0004_human_identity_and_webauthn_registration.sql` adds immutable provider/subject mappings and passkey metadata while challenges retain the exact RP/origin/UV/session/member/organization binding.

When all Human Auth variables below are present, the Cloud runtime constructs PostgreSQL sessions, immutable upstream-identity membership resolution, durable WebAuthn registration/authentication ceremonies, maintained verifiers, and recent-auth middleware. The BFF token authenticates the Console service only; the browser user receives the role stored in their active PostgreSQL membership. Automated real-PostgreSQL multi-instance E2E, identity provisioning/invitation APIs, session-management UI, and full PostgreSQL control-plane storage remain production gates.

Start the API behind a TLS reverse proxy:

```bash
export AGENTPASS_CLOUD_DATA_DIR=/absolute/protected/agentpass-cloud/data
export AGENTPASS_CLOUD_TOKEN_RECORDS_PATH=/absolute/protected/agentpass-cloud/token-records.json
export AGENTPASS_CLOUD_BUNDLE_PRIVATE_KEY_PATH=/absolute/protected/agentpass-cloud/bundle-private.pem
export AGENTPASS_CLOUD_HOST=127.0.0.1
export AGENTPASS_CLOUD_PORT=8080
# Enable the production Human Auth path as one all-or-nothing group:
export AGENTPASS_DATABASE_URL='postgresql://agentpass:...@db.example/agentpass?sslmode=verify-full'
export AGENTPASS_CONSOLE_ORIGIN='https://console.example.com'
export AGENTPASS_WEBAUTHN_RP_ID='example.com'
export AGENTPASS_IDENTITY_PROVIDER='chatgpt'
npm start
```

`AGENTPASS_CONSOLE_ORIGIN` must be an exact HTTPS origin. The RP ID must equal its hostname or be a parent suffix. `AGENTPASS_IDENTITY_PROVIDER` defaults to `chatgpt`; every verified Console subject must have an `upstream_identities` row and an active organization membership before session issuance. Omitting all three required Human Auth variables keeps the self-hosted compatibility runtime; partially configuring them fails startup.

The process binds loopback by default. Terminate with SIGINT/SIGTERM for graceful shutdown. Device replay evidence and both admission/principal rate-limit buckets survive restart. The file store takes an exclusive process lock and refuses a second writer. For multi-instance production, replace the reference file store, replay cache, and limiters with transactional shared storage; never share the JSON data directory between processes.

The API applies a peer-address admission limit before reading a body or running scrypt authentication, then applies a tenant/principal limit after authentication. Keep the runtime behind a TLS reverse proxy with its own connection and distributed rate limits. The reference runtime intentionally caps token records at 256 to bound authentication work.
