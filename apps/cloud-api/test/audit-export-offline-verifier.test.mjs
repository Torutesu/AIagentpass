import assert from "node:assert/strict";
import crypto from "node:crypto";
import test from "node:test";

import { canonicalJson } from "../../../packages/protocol/src/index.mjs";
import {
  AUDIT_ANCHOR_ALGORITHM,
  AUDIT_ANCHOR_PURPOSE,
  AUDIT_ANCHOR_PROTOCOL_VERSION,
  AUDIT_ANCHOR_SIGNATURE_DOMAIN,
  AUDIT_ANCHOR_SIGNING_VERSION,
  AUDIT_ANCHOR_TYPE,
  AUDIT_ANCHOR_VERSION,
  AUDIT_ANCHOR_ZERO_DIGEST,
  auditAnchorPublicKeyFingerprint,
  auditAnchorSigningData,
  auditAnchorStatementHash,
  normalizeAuditAnchorStatement
} from "../src/audit-anchor-statement.mjs";
import { foldAuditExportRoot } from "../src/postgres/audit-export-snapshot-reader.mjs";
import { createOfflineAuditExportVerifier, verifyOfflineAuditExport } from "../src/audit-export-offline-verifier.mjs";

const NOW = Date.parse("2026-08-15T00:00:00.000Z");
const ORGANIZATION_ID = "11111111-1111-4111-8111-111111111111";
const EXPORT_ID = "22222222-2222-4222-8222-222222222222";
const ACTOR_ID = "44444444-4444-4444-8444-444444444444";
const EVENT_ID = "33333333-3333-4333-8333-333333333333";
const KEY_ID = "audit-anchor-production-v1";
const KEY_VERSION = 7;
const LIFECYCLE_VERSION = 3;

function sha256(value) { return crypto.createHash("sha256").update(value, "utf8").digest("hex"); }

function makeFixture({ keyPair = crypto.generateKeyPairSync("ed25519"), now = NOW } = {}) {
  const publicKeyPem = keyPair.publicKey.export({ type: "spki", format: "pem" }).toString();
  const metadata = {
    version: AUDIT_ANCHOR_VERSION,
    type: AUDIT_ANCHOR_TYPE,
    purpose: AUDIT_ANCHOR_PURPOSE,
    domain: AUDIT_ANCHOR_SIGNATURE_DOMAIN,
    protocol_version: AUDIT_ANCHOR_PROTOCOL_VERSION,
    signing_version: AUDIT_ANCHOR_SIGNING_VERSION,
    algorithm: AUDIT_ANCHOR_ALGORITHM,
    key_id: KEY_ID,
    key_version: KEY_VERSION,
    lifecycle_version: LIFECYCLE_VERSION,
    public_key: publicKeyPem,
    public_key_fingerprint: auditAnchorPublicKeyFingerprint(keyPair.publicKey)
  };
  const eventPreimage = {
    version: 2,
    audit_event_id: EVENT_ID,
    organization_id: ORGANIZATION_ID,
    actor_id: ACTOR_ID,
    action: "member.role.changed",
    target_type: "member",
    target_id: null,
    details: { from: "viewer", to: "auditor" },
    previous_hash: AUDIT_ANCHOR_ZERO_DIGEST,
    sequence: 1
  };
  const event = {
    ...eventPreimage,
    event_hash: sha256(canonicalJson(eventPreimage)),
    recorded_at: "2026-08-14T23:59:59.000Z"
  };
  const entry = {
    version: 1,
    organization_id: ORGANIZATION_ID,
    environment: "production",
    chain: "admin",
    export_position: 1,
    source_id: EVENT_ID,
    source_device_id: null,
    source_previous_hash: AUDIT_ANCHOR_ZERO_DIGEST,
    source_hash: event.event_hash,
    source_gap: null,
    event
  };
  const rootDigest = foldAuditExportRoot(AUDIT_ANCHOR_ZERO_DIGEST, entry);
  const range = {
    from_audit_position: 1,
    to_audit_position: 1,
    previous_root_digest: AUDIT_ANCHOR_ZERO_DIGEST,
    root_digest: rootDigest,
    record_count: 1
  };
  const payload = {
    version: 1,
    type: "agentpass.audit-export",
    organization_id: ORGANIZATION_ID,
    environment: "production",
    chain: "admin",
    range,
    entries: [entry]
  };
  const statement = normalizeAuditAnchorStatement({
    version: 1,
    type: "agentpass.audit-anchor",
    organization_id: ORGANIZATION_ID,
    environment: "production",
    chain: "admin",
    export_id: EXPORT_ID,
    audit_position: 1,
    previous_audit_position: 0,
    root_digest: rootDigest,
    previous_root_digest: AUDIT_ANCHOR_ZERO_DIGEST,
    export_digest: sha256(canonicalJson(payload)),
    record_count: 1,
    purpose: AUDIT_ANCHOR_PURPOSE,
    protocol_version: 1,
    signing_version: 1,
    lifecycle_version: LIFECYCLE_VERSION,
    key_id: KEY_ID,
    key_version: KEY_VERSION,
    issued_at: "2026-08-14T23:30:00.000Z",
    expires_at: "2026-08-15T00:30:00.000Z"
  }, { now, allowExpired: true, allowFuture: true });
  const auditAnchor = {
    version: 1,
    type: "agentpass.audit-anchor",
    statement,
    statement_hash: auditAnchorStatementHash(statement),
    signature_algorithm: AUDIT_ANCHOR_ALGORITHM,
    signer_key_fingerprint: metadata.public_key_fingerprint,
    signature: crypto.sign(null, auditAnchorSigningData(statement), keyPair.privateKey).toString("base64url")
  };
  return {
    dto: {
      organization_id: ORGANIZATION_ID,
      export_id: EXPORT_ID,
      environment: "production",
      chain: "admin",
      range,
      payload_digest: sha256(canonicalJson(payload)),
      payload,
      audit_anchor: auditAnchor,
      validity: "active"
    },
    metadata,
    keyPair,
    resolver: async (request) => {
      assert.deepEqual(request, {
        purpose: AUDIT_ANCHOR_PURPOSE,
        algorithm: AUDIT_ANCHOR_ALGORITHM,
        protocol_version: 1,
        signing_version: 1,
        key_id: KEY_ID,
        key_version: KEY_VERSION,
        lifecycle_version: LIFECYCLE_VERSION
      });
      return metadata;
    }
  };
}

test("verifies a complete public export and returns a frozen strict result", async () => {
  const fixture = makeFixture();
  const result = await verifyOfflineAuditExport(fixture.dto, { publicKeyResolver: fixture.resolver, now: NOW });

  assert.deepEqual(result, {
    payload_digest: true,
    root: true,
    anchor: true,
    historical_key: true,
    valid: true,
    reason: "valid"
  });
  assert(Object.isFrozen(result));
  assert.deepEqual(Object.keys(result), ["payload_digest", "root", "anchor", "historical_key", "valid", "reason"]);
});

test("detects payload digest and root tampering while keeping the failure redacted", async () => {
  const fixture = makeFixture();
  const tampered = structuredClone(fixture.dto);
  tampered.payload.entries[0].event.details.to = "owner";
  const eventPreimage = { ...tampered.payload.entries[0].event };
  delete eventPreimage.event_hash;
  delete eventPreimage.recorded_at;
  tampered.payload.entries[0].event.event_hash = sha256(canonicalJson(eventPreimage));
  tampered.payload.entries[0].source_hash = tampered.payload.entries[0].event.event_hash;
  const result = await verifyOfflineAuditExport(tampered, { publicKeyResolver: fixture.resolver, now: NOW });

  assert.equal(result.valid, false);
  assert.equal(result.payload_digest, false);
  assert.equal(result.root, false);
  assert.equal(result.reason, "root_mismatch");
  assert.equal(Object.hasOwn(result, "error"), false);
});

test("rejects legacy admin rows, device gaps, and non-contiguous positions", async () => {
  const fixture = makeFixture();
  const legacy = structuredClone(fixture.dto);
  legacy.payload.entries[0].event.version = 1;
  assert.equal((await verifyOfflineAuditExport(legacy, { publicKeyResolver: fixture.resolver, now: NOW })).reason, "invalid_export");

  const gap = structuredClone(fixture.dto);
  gap.payload.entries[0].source_gap = { expected_previous_hash: "a".repeat(64), received_previous_hash: "b".repeat(64), recorded_at: "2026-08-15T00:00:00.000Z", resolved_at: null };
  assert.equal((await verifyOfflineAuditExport(gap, { publicKeyResolver: fixture.resolver, now: NOW })).reason, "invalid_export");

  const nonContiguous = structuredClone(fixture.dto);
  nonContiguous.range.to_audit_position = 2;
  nonContiguous.payload.range.record_count = 2;
  nonContiguous.payload.range.to_audit_position = 2;
  nonContiguous.payload.range.root_digest = fixture.dto.range.root_digest;
  nonContiguous.payload.range.previous_root_digest = fixture.dto.range.previous_root_digest;
  nonContiguous.payload.range.from_audit_position = 1;
  nonContiguous.range.record_count = 2;
  nonContiguous.payload.entries.push(structuredClone(nonContiguous.payload.entries[0]));
  assert.equal((await verifyOfflineAuditExport(nonContiguous, { publicKeyResolver: fixture.resolver, now: NOW })).reason, "invalid_export");
});

test("uses the historical key and rejects wrong lifecycle or signature", async () => {
  const fixture = makeFixture();
  const wrongLifecycle = { ...fixture.metadata, lifecycle_version: LIFECYCLE_VERSION + 1 };
  const lifecycleResult = await verifyOfflineAuditExport(fixture.dto, { publicKeyResolver: async () => wrongLifecycle, now: NOW });
  assert.equal(lifecycleResult.valid, false);
  assert.equal(lifecycleResult.reason, "historical_key_unavailable");
  assert.equal(lifecycleResult.historical_key, false);

  const wrongSignature = structuredClone(fixture.dto);
  const signatureCharacter = wrongSignature.audit_anchor.signature[10];
  wrongSignature.audit_anchor.signature = `${wrongSignature.audit_anchor.signature.slice(0, 10)}${signatureCharacter === "A" ? "B" : "A"}${wrongSignature.audit_anchor.signature.slice(11)}`;
  const signatureResult = await verifyOfflineAuditExport(wrongSignature, { publicKeyResolver: fixture.resolver, now: NOW });
  assert.equal(signatureResult.valid, false);
  assert.equal(signatureResult.reason, "anchor_invalid");
  assert.equal(signatureResult.historical_key, true);
});

test("fails closed for unknown/private fields, accessors, prototypes, cycles, and oversize input", async () => {
  const fixture = makeFixture();
  const cases = [];
  cases.push({ ...fixture.dto, replayed: false });
  cases.push({ ...fixture.dto, private_key: "-----BEGIN PRIVATE KEY-----" });
  const accessor = structuredClone(fixture.dto);
  Object.defineProperty(accessor, "payload_digest", { enumerable: true, get() { return fixture.dto.payload_digest; } });
  cases.push(accessor);
  const customPrototype = structuredClone(fixture.dto);
  Object.setPrototypeOf(customPrototype, { unexpected: true });
  cases.push(customPrototype);
  const cycle = structuredClone(fixture.dto);
  cycle.payload.entries[0].event.details.cycle = cycle.payload.entries[0].event.details;
  cases.push(cycle);
  const oversized = structuredClone(fixture.dto);
  oversized.payload.entries[0].event.details = { text: "x".repeat(17 * 1024) };
  cases.push(oversized);

  for (const value of cases) {
    const result = await verifyOfflineAuditExport(value, { publicKeyResolver: fixture.resolver, now: NOW });
    assert.equal(result.valid, false);
    assert.equal(result.reason, "invalid_export");
    assert.deepEqual(Object.keys(result), ["payload_digest", "root", "anchor", "historical_key", "valid", "reason"]);
  }
});

test("createOfflineAuditExportVerifier exposes only the six-field public result", async () => {
  const fixture = makeFixture();
  const verifier = createOfflineAuditExportVerifier({ publicKeyResolver: fixture.resolver, now: NOW });
  const result = await verifier.verifyAuditExport(fixture.dto);

  assert.deepEqual(Object.keys(result), ["payload_digest", "root", "anchor", "historical_key", "valid", "reason"]);
  assert.deepEqual(result, { payload_digest: true, root: true, anchor: true, historical_key: true, valid: true, reason: "valid" });
  assert(Object.isFrozen(result));
});

test("redacts resolver failures, private resolver material, and expired anchors", async (t) => {
  const fixture = makeFixture();
  await t.test("resolver failure", async () => {
    const result = await verifyOfflineAuditExport(fixture.dto, {
      publicKeyResolver: async () => { throw new Error("database-secret-must-not-escape"); },
      now: NOW
    });
    assert.deepEqual(result, {
      payload_digest: true,
      root: true,
      anchor: false,
      historical_key: false,
      valid: false,
      reason: "historical_key_unavailable"
    });
    assert.equal(JSON.stringify(result).includes("database-secret"), false);
  });
  await t.test("private resolver material", async () => {
    const privateMetadata = {
      ...fixture.metadata,
      public_key: fixture.keyPair.privateKey.export({ type: "pkcs8", format: "pem" }).toString()
    };
    const result = await verifyOfflineAuditExport(fixture.dto, {
      publicKeyResolver: async () => privateMetadata,
      now: NOW
    });
    assert.equal(result.reason, "historical_key_unavailable");
    assert.equal(JSON.stringify(result).includes("PRIVATE KEY"), false);
  });
  await t.test("expired anchor is never reported as currently valid", async () => {
    const expired = structuredClone(fixture.dto);
    expired.validity = "expired";
    const result = await verifyOfflineAuditExport(expired, {
      publicKeyResolver: fixture.resolver,
      now: Date.parse("2026-08-15T01:00:00.000Z")
    });
    assert.equal(result.valid, false);
    assert.equal(result.historical_key, true);
    assert.equal(result.reason, "anchor_invalid");
  });
});
