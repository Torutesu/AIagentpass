import assert from "node:assert/strict";
import crypto from "node:crypto";
import { mkdtemp, readFile, symlink, unlink, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import { canonicalJson } from "../../../../packages/protocol/src/index.mjs";
import { loadSqlMigrations } from "../../src/postgres/migration-runner.mjs";
import {
  AUTHORITY_MANIFEST_SCHEMA_VERSION,
  DIAGNOSTICS,
  MANIFEST_KIND,
  AuthorityManifestError,
  canonicalAuthorityManifest,
  compareAuthorityManifests,
  createAuthorityManifest,
  digestBackupArtifact,
  readBoundedRegularFile,
  sealAuthorityManifest,
  verifyAuthorityManifest,
  verifyBackupArtifactDigest,
  verifyDetachedSignature,
  writeAuthorityManifest
} from "../../../../scripts/postgres/authority-manifest.mjs";

const ORG = "11111111-1111-4111-8111-111111111111";
const TABLES = [
  "organizations", "members", "memberships", "human_sessions", "webauthn_credentials", "webauthn_challenges", "upstream_identities",
  "devices", "device_enrollments", "release_candidates", "device_enrollment_possession_receipts", "agents", "agent_session_grants", "agent_sessions", "qualification_grant_control_heads", "qualification_grant_batches", "qualification_grant_batch_steps", "policies", "revocations", "capabilities", "bundle_heads", "bundle_acknowledgements",
  "cloud_agent_audit_heads", "cloud_agent_audit_events",
  "admin_audit_heads", "admin_audit_events", "outbox_events", "organization_invitations", "device_audit_events", "device_audit_heads",
  "device_audit_gaps", "idempotency_records", "device_request_nonces", "rate_limit_buckets", "human_identity_assertion_replays", "control_plane_authority_generations", "device_key_epochs", "device_control_plane_state", "control_bundle_statements", "device_refresh_outbox", "device_refresh_delivery_attempts", "device_bundle_acknowledgements", "device_manual_wake_events", "device_manual_wake_requests", "schema_migration_attempts"
];

const hash = (value) => crypto.createHash("sha256").update(canonicalJson(value), "utf8").digest("hex");

class FakeManifestClient {
  constructor({ rows = {}, badCount = false, invalidConstraint = false } = {}) {
    this.rows = rows;
    this.badCount = badCount;
    this.invalidConstraint = invalidConstraint;
    this.calls = [];
  }

  async query(text, params = []) {
    this.calls.push({ text, params });
    if (["BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY", "COMMIT", "ROLLBACK"].includes(text)) return { rows: [] };
    if (text.includes("authority-manifest:migrations")) {
      const migrations = await loadSqlMigrations();
      return { rows: migrations.map(({ version, checksum }) => ({ version: String(version), checksum })) };
    }
    if (text.includes("authority-manifest:migration-attempts")) return { rows: [] };
    if (text.startsWith("SELECT id AS organization_id")) return { rows: [{ organization_id: ORG }] };
    if (text.includes("authority-manifest:tenant-integrity")) return { rows: [{ violation_count: "0" }] };
    if (text.includes("authority-manifest:columns")) return { rows: [] };
    if (text.includes("authority-manifest:constraints")) return {
      rows: [{ schema_name: "public", table_name: "organizations", constraint_name: "organizations_pkey", constraint_type: "p", validated: !this.invalidConstraint, definition: "PRIMARY KEY (id)" }]
    };
    if (text.includes("authority-manifest:all-row-counts")) {
      return { rows: TABLES.map((table_name) => ({ table_name, row_count: String((this.rows[table_name] ?? []).length + (this.badCount && table_name === "organizations" ? 1 : 0)) })) };
    }
    const table = TABLES.find((name) => text.includes(`authority-manifest:table:${name}`));
    if (table) return { rows: this.rows[table] ?? [] };
    throw new Error(`unexpected query marker: ${text.slice(0, 80)}`);
  }
}

async function emptyManifest(artifact_digest = undefined) {
  const migrations = await loadSqlMigrations();
  const row_counts = Object.fromEntries(TABLES.map((table) => [table, "0"]));
  const empty_digest = hash([]);
  return sealAuthorityManifest({
    schema_version: AUTHORITY_MANIFEST_SCHEMA_VERSION,
    kind: MANIFEST_KIND,
    migration_version: "23",
    migrations: migrations.map(({ version, name, checksum }) => ({ version: String(version), name, checksum })),
    tenant_ids: [ORG],
    tenants: [{ organization_id: ORG }],
    row_counts,
    tables: TABLES.map((table_name) => ({ table_name, row_count: "0", column_count: "0", columns_digest: empty_digest, rows_digest: empty_digest, row_digests: [] })),
    constraints: [],
    ...(artifact_digest === undefined ? {} : { artifact_digest })
  });
}

test("covers every authority/security/audit/outbox/human-auth table and hashes all row fields without emitting values", async () => {
  const client = new FakeManifestClient({ rows: { webauthn_credentials: [{ row: { id: "credential-id", token_hash: "do-not-emit", nested: { assertion_secret: "also-do-not-emit" }, status: "active" } }] } });
  const manifest = await createAuthorityManifest({ client });
  assert.deepEqual(manifest.tables.map((table) => table.table_name), [...TABLES].sort());
  assert.equal(manifest.tables.find((table) => table.table_name === "webauthn_credentials").row_count, "1");
  assert.doesNotMatch(JSON.stringify(manifest), /do-not-emit|also-do-not-emit|token_hash|assertion_secret/iu);
  assert.match(manifest.tables.find((table) => table.table_name === "webauthn_credentials").row_digests[0], /^[0-9a-f]{64}$/u);
  assert.equal(client.calls.filter(({ text }) => text.includes("authority-manifest:table:")).length, TABLES.length);
  verifyAuthorityManifest(manifest);
});

test("rejects correlated count drift, invalid constraints, and tenant-integrity failures", async () => {
  await assert.rejects(createAuthorityManifest({ client: new FakeManifestClient({ badCount: true }) }), (error) => error.code === DIAGNOSTICS.MALFORMED_DATABASE.code);
  await assert.rejects(createAuthorityManifest({ client: new FakeManifestClient({ invalidConstraint: true }) }), (error) => error.code === DIAGNOSTICS.SCHEMA.code);
  const client = new FakeManifestClient();
  client.query = async function query(text, params) {
    if (text.includes("authority-manifest:tenant-integrity")) return { rows: [{ violation_count: "1" }] };
    return FakeManifestClient.prototype.query.call(this, text, params);
  };
  await assert.rejects(createAuthorityManifest({ client }), (error) => error.code === DIAGNOSTICS.CROSS_TENANT.code);
});

test("normalizes before comparison and rejects unknown or secret-like nested fields", async () => {
  const original = await emptyManifest();
  const reordered = structuredClone(original);
  reordered.tables.reverse();
  reordered.migrations.reverse();
  assert.deepEqual(compareAuthorityManifests(original, reordered), { same: true, diagnostic: null });
  const unknown = structuredClone(original);
  unknown.tables[0].nested = { value: true };
  assert.deepEqual(compareAuthorityManifests(original, unknown), { same: false, diagnostic: DIAGNOSTICS.INVALID_FILE });
  const secret = structuredClone(original);
  secret.tables[0].secret_material = "x";
  assert.deepEqual(compareAuthorityManifests(original, secret), { same: false, diagnostic: DIAGNOSTICS.INVALID_FILE });
});

test("verifies externally supplied detached signatures and backup artifact digest bindings", async () => {
  const directory = await mkdtemp(path.join(os.tmpdir(), "agentpass-manifest-test-"));
  const artifact = path.join(directory, "backup.dump");
  await writeFile(artifact, "backup bytes\n", { mode: 0o600 });
  const manifest = await emptyManifest(await digestBackupArtifact(artifact));
  const { privateKey, publicKey } = crypto.generateKeyPairSync("ed25519");
  const signature = crypto.sign(null, Buffer.from(canonicalAuthorityManifest(manifest)), privateKey);
  assert.equal(Buffer.isBuffer(signature), true);
  assert.equal(crypto.verify(null, Buffer.from(canonicalAuthorityManifest(manifest)), publicKey, signature), true);
  assert.equal(verifyDetachedSignature(manifest, signature, publicKey), true);
  assert.equal(await verifyBackupArtifactDigest(manifest, artifact), true);
  await writeFile(artifact, "tampered\n");
  await assert.rejects(verifyBackupArtifactDigest(manifest, artifact), (error) => error.code === DIAGNOSTICS.ARTIFACT.code);
  await unlink(artifact);
  await unlink(directory).catch(() => {});
});

test("uses bounded regular no-symlink input and atomic fsync output", async () => {
  const directory = await mkdtemp(path.join(os.tmpdir(), "agentpass-manifest-file-test-"));
  const input = path.join(directory, "input.json");
  const output = path.join(directory, "output.json");
  const link = path.join(directory, "input-link.json");
  await writeFile(input, "{}\n", { mode: 0o600 });
  await symlink(input, link);
  await assert.rejects(readBoundedRegularFile(link, 1024), (error) => error.code === DIAGNOSTICS.INVALID_FILE.code);
  await writeAuthorityManifest(output, "{}\n");
  assert.equal(await readFile(output, "utf8"), "{}\n");
  await assert.rejects(writeAuthorityManifest(output, "changed\n"), (error) => error.code === DIAGNOSTICS.INVALID_ARGUMENTS.code);
  await unlink(input);
  await unlink(link);
  await unlink(output);
  await unlink(directory).catch(() => {});
});
