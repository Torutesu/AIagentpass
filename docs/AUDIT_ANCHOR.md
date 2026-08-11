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

Requests and responses are bounded to 512 KiB. The client rejects redirects, non-HTTPS production URLs, malformed responses, wrong tenants, wrong checkpoint hashes, invalid receipt signatures, and receipt-chain rollback.

## Remaining limits

- The reference server uses a software receipt key. Put it behind an HSM/KMS signer for a stronger production boundary.
- TLS termination, network authentication, rate limiting, replication, and retention are deployment responsibilities.
- A stolen anchor private key can forge future receipts. Previously copied receipts still provide a comparison point.
- The anchor proves that a particular signed checkpoint was accepted at a stated server time; it does not prove that every host event was honestly generated or that the host clock was correct.
