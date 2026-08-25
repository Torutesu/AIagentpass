import { normalizeOwnerRecoveryDeliveryBinding } from "../../src/postgres/owner-recovery-delivery-binding.mjs";

const TABLE = "owner_recovery_provider_acceptance_ledger";
const KEY = /^[A-Za-z0-9][A-Za-z0-9._:~-]{0,254}$/u;

export const OWNER_RECOVERY_PROVIDER_ACCEPTANCE_LEDGER_TABLE = TABLE;

export async function ensureOwnerRecoveryProviderAcceptanceLedger(client) {
  assertClient(client);
  await client.query(`CREATE TABLE IF NOT EXISTS ${TABLE} (
    provider_binding_id text NOT NULL CHECK (provider_binding_id ~ '^[a-z0-9][a-z0-9._:-]*$' AND char_length(provider_binding_id) <= 128),
    provider_key_version integer NOT NULL CHECK (provider_key_version BETWEEN 1 AND 2147483647),
    provider_binding_digest bytea NOT NULL CHECK (octet_length(provider_binding_digest) = 32),
    idempotency_key text NOT NULL CHECK (idempotency_key ~ '^[A-Za-z0-9][A-Za-z0-9._:~-]{0,254}$'),
    accepted boolean NOT NULL,
    accepted_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    delivery_attempts integer NOT NULL DEFAULT 1 CHECK (delivery_attempts BETWEEN 1 AND 100),
    PRIMARY KEY (provider_binding_id, provider_key_version, provider_binding_digest, idempotency_key)
  )`);
  return TABLE;
}

export function createOwnerRecoveryProviderAcceptanceLedger({ client } = {}) {
  assertClient(client);

  async function accept({ binding, idempotency_key } = {}) {
    const delivery = normalizeOwnerRecoveryDeliveryBinding(binding);
    const key = normalizeKey(idempotency_key);
    const inserted = await client.query(`INSERT INTO ${TABLE}
      (provider_binding_id,provider_key_version,provider_binding_digest,idempotency_key,accepted)
      VALUES ($1,$2,decode($3,'hex'),$4,true)
      ON CONFLICT (provider_binding_id,provider_key_version,provider_binding_digest,idempotency_key)
      DO NOTHING`, [
      delivery.binding_id, delivery.key_version, delivery.binding_digest, key
    ]);
    if (Number(inserted.rowCount ?? 0) !== 1) {
      await client.query(`UPDATE ${TABLE}
        SET delivery_attempts=LEAST(delivery_attempts+1,100)
        WHERE provider_binding_id=$1 AND provider_key_version=$2
          AND provider_binding_digest=decode($3,'hex') AND idempotency_key=$4`, [
        delivery.binding_id, delivery.key_version, delivery.binding_digest, key
      ]);
    }
    const row = await client.query(`SELECT accepted,delivery_attempts
      FROM ${TABLE}
      WHERE provider_binding_id=$1 AND provider_key_version=$2
        AND provider_binding_digest=decode($3,'hex') AND idempotency_key=$4`, [
      delivery.binding_id, delivery.key_version, delivery.binding_digest, key
    ]);
    if (row.rows?.length !== 1 || typeof row.rows[0].accepted !== "boolean") throw new Error("provider acceptance ledger unavailable");
    return Object.freeze({
      accepted: row.rows[0].accepted,
      duplicate: Number(inserted.rowCount ?? 0) !== 1,
      idempotency_key: key,
      delivery_attempts: Number(row.rows[0].delivery_attempts)
    });
  }

  async function count({ binding, idempotency_key } = {}) {
    const delivery = normalizeOwnerRecoveryDeliveryBinding(binding);
    const key = normalizeKey(idempotency_key);
    const result = await client.query(`SELECT count(*)::int AS count
      FROM ${TABLE}
      WHERE provider_binding_id=$1 AND provider_key_version=$2
        AND provider_binding_digest=decode($3,'hex') AND idempotency_key=$4`, [
      delivery.binding_id, delivery.key_version, delivery.binding_digest, key
    ]);
    return Number(result.rows?.[0]?.count);
  }

  async function lookup({ binding, idempotency_key } = {}) {
    const delivery = normalizeOwnerRecoveryDeliveryBinding(binding);
    const key = normalizeKey(idempotency_key);
    const result = await client.query(`SELECT accepted
      FROM ${TABLE}
      WHERE provider_binding_id=$1 AND provider_key_version=$2
        AND provider_binding_digest=decode($3,'hex') AND idempotency_key=$4`, [
      delivery.binding_id, delivery.key_version, delivery.binding_digest, key
    ]);
    if (!Array.isArray(result.rows) || result.rows.length > 1
      || (result.rows.length === 1 && result.rows[0].accepted !== true)) throw new Error("provider acceptance ledger unavailable");
    return Object.freeze({ accepted: result.rows.length === 1, idempotency_key: key });
  }

  async function removeBinding(binding) {
    const delivery = normalizeOwnerRecoveryDeliveryBinding(binding);
    await client.query(`DELETE FROM ${TABLE}
      WHERE provider_binding_id=$1 AND provider_key_version=$2
        AND provider_binding_digest=decode($3,'hex')`, [delivery.binding_id, delivery.key_version, delivery.binding_digest]);
  }

  return Object.freeze({ accept, lookup, count, removeBinding });
}

export function createOwnerRecoveryFakeProvider({ ledger, binding, afterAcceptance = undefined } = {}) {
  if (!ledger || typeof ledger.accept !== "function") throw new TypeError("acceptance ledger is invalid");
  const delivery = normalizeOwnerRecoveryDeliveryBinding(binding);
  if (afterAcceptance !== undefined && typeof afterAcceptance !== "function") throw new TypeError("afterAcceptance must be a function");

  return Object.freeze({
    binding: delivery,
    async publish(input = {}) {
      const response = await ledger.accept({ binding: delivery, idempotency_key: input.idempotency_key });
      await afterAcceptance?.(response);
      return Object.freeze({
        accepted: response.accepted,
        duplicate: response.duplicate,
        idempotency_key: response.idempotency_key
      });
    },
    async lookupAcceptance(input = {}) {
      if (input.signal?.aborted) throw Object.assign(new Error("lookup aborted"), { code: "aborted" });
      return ledger.lookup({ binding: delivery, idempotency_key: input.idempotency_key });
    }
  });
}

function normalizeKey(value) {
  if (typeof value !== "string" || !KEY.test(value)) throw new TypeError("provider idempotency key is invalid");
  return value;
}

function assertClient(client) {
  if (!client || typeof client.query !== "function") throw new TypeError("provider acceptance ledger client is invalid");
}
