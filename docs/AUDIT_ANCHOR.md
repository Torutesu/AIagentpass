# AgentPass remote audit anchor

The audit anchor preserves signed evidence of an AgentPass host's audit history outside that host. The host sends signed checkpoints—not audit records, repository names, payloads, or secrets. The anchor validates each checkpoint against the tenant's enrolled audit key, appends it to the tenant chain, and returns a signed receipt.

## Security model

There are two independent identities:

- the local broker uses Ed25519, while the native service uses a non-exportable Secure Enclave P-256 audit key, to sign `{entries, head_hash, previous_checkpoint_hash}`;
- the anchor receipt key signs `{tenant, index, checkpoint_hash, received_at, previous_receipt_hash}`.

The host pins the anchor public key and verifies every returned receipt before persisting it. The anchor pins one host audit public key and algorithm at tenant enrollment; Ed25519 and P-256 checkpoints cannot be mixed within a tenant. The first submitted checkpoint must begin at the checkpoint-chain origin; every later checkpoint must extend the last one accepted for that tenant, and its entry count cannot decrease. Repeating an identical checkpoint returns the original receipt, making retries safe when a response is lost.

After at least one checkpoint is accepted, replacing or truncating local checkpoints cannot create a chain that the anchor accepts. Enrollment and the first checkpoint establish the baseline, so enroll the intended audit key and push the first checkpoint before unattended operation.

## Deploy an anchor

Initialize storage on a separately administered machine:

```sh
agentpass-anchor init /var/lib/agentpass-anchor
```

Export the audit public key on each AgentPass host:

```sh
agentpass audit public-key > agentpass-audit.pub
# Native mode:
agentpass native audit-key > agentpass-native-audit.pub
```

Copy only that public key to the anchor administrator, choose a unique tenant slug, and enroll it once:

```sh
agentpass-anchor enroll /var/lib/agentpass-anchor build-mac-01 ./agentpass-audit.pub
agentpass-anchor enroll /var/lib/agentpass-anchor build-mac-01-native ./agentpass-native-audit.pub
agentpass-anchor verify /var/lib/agentpass-anchor build-mac-01
agentpass-anchor prune-head /var/lib/agentpass-anchor build-mac-01 AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
```

The included server deliberately defaults to loopback HTTP so TLS, authentication controls, request limits, backups, and monitoring can be supplied by a hardened reverse proxy:

```sh
agentpass-anchor serve /var/lib/agentpass-anchor --host 127.0.0.1 --port 8787
```

Expose it to clients only through HTTPS. Back up `anchor-private.pem`, `anchor-public.pem`, and `tenants/` with access controls appropriate for security evidence. Keep copies of important receipts in another system if compromise of the anchor itself is in scope.

## Configure a host

Transfer `anchor-public.pem` to the host through an authenticated channel and verify its fingerprint out of band. Then pin it:

```sh
agentpass audit anchor trust \
  --url https://audit-anchor.example.com/ \
  --tenant build-mac-01 \
  --key ./anchor-public.pem
```

Replacing the pinned key or tenant requires `--confirm ROTATE_ANCHOR_TRUST`; old local receipts are archived as untrusted. Changing only the URL while retaining the same key and tenant preserves the receipt chain, but should still be treated as a security-sensitive configuration change.

Create and send a fresh checkpoint:

```sh
agentpass audit anchor push
agentpass audit anchor status
agentpass audit --verify
```

Each push first records the attempt in the local audit log, creates a checkpoint, and sends every unanchored checkpoint in order. Failed submissions remain pending and are retried on the next push. Schedule pushes according to the maximum history-loss window you can tolerate.

In native mode, trust is configured only in root-owned `native-service.json`:

```json
{
  "audit_anchor_url": "https://audit-anchor.example.com/",
  "audit_anchor_tenant": "build-mac-01-native",
  "audit_anchor_public_key": "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----\n",
  "audit_anchor_receipt_path": "/Library/Application Support/AgentPass/audit.anchor.receipts.jsonl"
}
```

Run `agentpass native anchor-push` to submit the next pending checkpoint and `agentpass native anchor-status` to verify the protected receipt chain. Each native push handles one checkpoint, so repeat until `pending` is zero. The native service—not the user configuration—validates the receipt signature and persists it.

## HTTP API

- `GET /v1/public-key` returns the anchor receipt public key.
- `POST /v1/checkpoints/:tenant` accepts `{ "checkpoint": ... }` and returns `{ "receipt": ... }`.
- `GET /v1/checkpoints/:tenant/latest` returns the latest checkpoint and receipt.
- `POST /v1/audit-prunes/:tenant` accepts `{ "authorization": ..., "lease": ... }`; the exact live submit lease is CAS-consumed under the tenant lock before appending the anchor-signed receipt.
- `GET /v1/audit-prunes/:tenant/head?nonce=:base64url32` returns a fresh nonce-bound signed head. It is read-only and never creates or extends a lease.
- `POST /v1/audit-prunes/:tenant/leases` accepts an exact canonical request signed with the tenant's current P-256 audit key. The request binds tenant, nonce, purpose, operation, expected sequence/hash, issue time, and key fingerprint.
- `POST /v1/audit-prunes/:tenant/leases/release` requires the exact lease plus a fresh canonical release request signed by the same current audit principal.

The prune-head response is exact canonical JSON with this schema:

```json
{"anchor_key_fingerprint":"SHA256:...","configured":true,"issued_at":"2029-02-01T00:00:05.000Z","receipt":{"anchor_event_index":3,"anchor_key_fingerprint":"SHA256:...","authorization_hash":"...","previous_anchor_event_hash":"...","previous_receipt_hash":"...","receipt_hash":"...","received_at":"2029-02-01T00:00:04.000Z","sequence":1,"signature":"...","tenant":"build-mac-01-native","version":1},"receipt_hash":"...","request_nonce":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","sequence":1,"signature":"...","tenant":"build-mac-01-native","version":2}
```

The anchor signs both non-empty and zero-state heads for enrolled tenants with its Ed25519 key. An unknown tenant returns the fixed unsigned canonical `{"configured":false,"error":"not_configured","version":1}` response and HTTP 404 before the anchor private key is loaded or used. The HTTP route reads and verifies a bounded canonical snapshot and signs the nonce envelope; it never scans checkpoint, transition, prune, or nonce history on the event loop. The offline `agentpass-anchor prune-head DIR TENANT NONCE` command is intentionally different: it performs complete history verification and is suitable for administration, not request serving. The acquire/release CLI commands consume already audit-key-signed canonical request files and never accept an unauthenticated principal.

Lease acquisition re-verifies complete tenant history under the tenant lock, verifies the current post-transition P-256 principal and canonical low-S request signature, and CAS-checks the expected head before atomically persisting an anchor-signed version-4 lease. The lease binds principal fingerprint, purpose, operation, head, nonce, and a random process epoch. Submit accepts only the exact active `purpose=submit` lease and a prune authorization signed by that same current principal. Release also requires that principal. During one Node process, expiry is governed only by `process.hrtime.bigint()`. A lease from another process epoch remains fenced for a full maximum TTL measured from first monotonic observation after restart, so wall-clock jumps cannot expire it early.

`agentpass-anchor prune DIR TENANT AUTHORIZATION LEASE` likewise requires the exact active lease. The historical three-argument command and direct lease-less API submissions fail closed, so local CLI access cannot bypass the HTTP lease boundary.

## Prune-head snapshot and nonce durability

Server startup performs complete verification for every tenant, then creates or checks a root-private canonical prune-head snapshot signed by the anchor key. The snapshot binds the checkpoint, transition, prune-receipt, shared event, active audit-key, and lease-nonce-ledger positions. Every corresponding writer removes and fsyncs the snapshot before appending, then atomically replaces and fsyncs it after the durable append/tip update while holding the same tenant lock. A crash after invalidation is repaired only at startup after complete verification. An existing signed snapshot that differs from verified history, or an unsafe symlink, hard link, owner, mode, or parent identity, stops startup.

After startup, the server retains each fully verified signed snapshot as an in-memory monotonic floor together with the device/inode identities of the anchor root, tenants directory, and tenant directory. Every tenant read, writer, and lease boundary compares the current signed snapshot with that floor. Equality is an O(1) snapshot-only path. A lower component position, a different hash at the same position, inconsistent event advancement, or storage-path replacement is rejected immediately. Only a strict signed advance enters the rare slow path: under the tenant lock the server re-verifies complete checkpoint, transition, prune, shared-event, nonce-ledger, and signed-tip history, derives a fresh snapshot, and requires byte-exact equality with the durable snapshot before advancing the floor. This permits a valid offline CLI writer but rejects a previously valid future snapshot placed over rolled-back histories. Restart establishes a new floor only after complete on-disk verification.

Lease nonces are immutable canonical JSONL hash-chain records. A separately anchor-signed tip is replaced atomically with file and parent-directory fsync. Startup permits only the exact one-record-ahead state produced by a crash after log fsync and before tip replacement; larger rollback, torn framing, substitution, and unsafe paths fail closed. The ledger has a hard 64 MiB limit. Until an administrator-signed compaction format is implemented, reaching that limit disables new lease acquisition rather than discarding replay history.

The reference server first consumes an in-process global bucket for the remote address (64-request burst, 32 requests/second refill), before tenant lookup. Only enrolled tenants then consume a second tenant bucket (32-request burst, 16 requests/second refill). Each map retains at most 1024 buckets. This prevents rotating unknown tenant names from causing private-key operations or evading the global bound. The HTTP server additionally caps open connections and concurrent requests at 128 and limits a socket to 100 requests. These controls are defense in depth; a reverse proxy must still provide distributed limits and trusted client-address handling.

Requests and responses are bounded to 512 KiB. The client rejects redirects, non-HTTPS production URLs, malformed responses, wrong tenants, wrong checkpoint hashes, invalid receipt signatures, and receipt-chain rollback.

## Remaining limits

- The reference server uses a software receipt key. Put it behind an HSM/KMS signer for a stronger production boundary.
- TLS termination, network authentication, distributed rate limiting, replication, and retention are deployment responsibilities.
- A stolen anchor private key can forge future receipts. Previously copied receipts still provide a comparison point.
- The anchor proves that a particular signed checkpoint was accepted at a stated server time; it does not prove that every host event was honestly generated or that the host clock was correct.
