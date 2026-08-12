# Restart-safe refresh nonce contract

The refresh hint nonce is derived by `apps/cloud-api/src/postgres/refresh-nonce-codec.mjs` with HMAC-SHA256. The fixed domain is `agentpass/refresh-nonce/v1`; the HMAC output is truncated to exactly 16 bytes. The authenticated tuple is the lower-case UUID and canonical decimal representation of:

```text
organization_id / device_id / authority_generation / outbox_id
```

Key IDs must exactly match the bounded canonical pattern `refresh-nonce-v[1-9][0-9]{0,8}`. The configured key ring is the actual allow-list: an ID that matches the pattern but is not present in the ring is unavailable and cannot be used. A key ID is never case-folded, aliased, or inferred. Rotation is dual-read/single-write: old IDs remain configured for reconstruction of retained outbox rows, while new enqueue operations use the codec's active ID. Adding v3 or later therefore does not require a schema migration.

The SQL boundary stores `refresh_nonce_key_id` and `refresh_nonce_digest` only. The raw nonce is never a SQL parameter, database column, serialized codec property, or log field. Migration 0013 fails old pending/delivered 0012 deliveries closed because their raw nonce cannot be reconstructed, and atomically marks the matching device state `stale` with `last_error_code: refresh_nonce_rekey_required` (while preserving `revoked`). This makes the migration visible and fail-closed; recovery must explicitly enqueue and observe a new deterministic refresh.

## `pollDeviceRefresh` return shape

`pollDeviceRefresh({ organization_id, device_id, after_generation, wait_ms })` returns `null` when no active (`pending` or `delivered`) outbox item exists beyond `after_generation`. Otherwise it returns this frozen, unsigned object:

```js
{
  organization_id: "lower-case UUID",
  device_id: "lower-case UUID",
  desired_generation: 42,
  refresh_state: "pending", // one of the frozen device refresh states
  outbox_id: "lower-case UUID",
  refresh_nonce_key_id: "refresh-nonce-v3",
  refresh_nonce_digest: "lower-case SHA-256 hex", // non-secret consistency check
  published_at: "2026-08-13T00:00:00.000Z", // immutable outbox created_at
  expires_at: "2026-08-13T00:04:00.000Z"
}
```

The Cloud layer reconstructs the nonce with the four identifiers and the returned key ID, then calls `timingSafeRefreshNonceDigestEqual(derived.nonce_digest_bytes, metadata.refresh_nonce_digest)`. A false result fails closed; only a matching digest may proceed to signing a `refresh-hint.v1`. This repository contract does not return a signed hint, a private key, or a raw nonce. The Cloud layer may expose the derived raw nonce only in the signed protocol envelope; it must not log or persist it.
