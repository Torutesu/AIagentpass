import assert from "node:assert/strict";
import crypto from "node:crypto";
import test from "node:test";

import { canonicalJson } from "../../../packages/protocol/src/index.mjs";
import {
  AUDIT_ANCHOR_ALGORITHM,
  AUDIT_ANCHOR_CHAINS,
  AUDIT_ANCHOR_PURPOSE,
  AUDIT_ANCHOR_PROTOCOL_VERSION,
  AUDIT_ANCHOR_SIGNATURE_DOMAIN,
  AUDIT_ANCHOR_SIGNING_VERSION,
  AUDIT_ANCHOR_TYPE,
  AUDIT_ANCHOR_VERSION,
  AUDIT_ANCHOR_ZERO_DIGEST,
  auditAnchorPublicKeyFingerprint
} from "../src/audit-anchor-statement.mjs";
import { createHostedAuditAnchorSigner } from "../src/audit-anchor-signer.mjs";
import {
  AUDIT_EXPORT_ISSUANCE_ERROR_CODES,
  createAuditExportIssuanceService
} from "../src/audit-export-issuance.mjs";
import { foldAuditExportRoot } from "../src/postgres/audit-export-snapshot-reader.mjs";

const NOW = Date.parse("2026-08-15T00:00:00.000Z");
const ORGANIZATION_ID = "11111111-1111-4111-8111-111111111111";
const OTHER_ORGANIZATION_ID = "99999999-9999-4999-8999-999999999999";
const EXPORT_ID = "22222222-2222-4222-8222-222222222222";
const OTHER_EXPORT_ID = "88888888-8888-4888-8888-888888888888";
const KEY_ID = "audit-anchor-production-v1";
const KEY_VERSION = 7;
const LIFECYCLE_VERSION = 3;
const ENTRIES = [
    {
      version: 1,
      organization_id: ORGANIZATION_ID,
      environment: "production",
      chain: "admin",
      export_position: 1,
      source_id: "33333333-3333-4333-8333-333333333333",
      source_device_id: null,
      source_previous_hash: AUDIT_ANCHOR_ZERO_DIGEST,
      source_hash: "b".repeat(64),
      source_gap: null,
      event: {
        version: 1,
        audit_event_id: "33333333-3333-4333-8333-333333333333",
        organization_id: ORGANIZATION_ID,
        actor_id: "44444444-4444-4444-8444-444444444444",
        action: "member.role.changed",
        target_type: "member",
        target_id: "55555555-5555-4555-8555-555555555555",
        details: { from: "viewer", to: "auditor", reason: "audit_access" },
        previous_hash: AUDIT_ANCHOR_ZERO_DIGEST,
        sequence: 1,
        event_hash: "b".repeat(64),
        recorded_at: "2026-08-14T23:59:58.000Z"
      }
    },
    {
      version: 1,
      organization_id: ORGANIZATION_ID,
      environment: "production",
      chain: "admin",
      export_position: 2,
      source_id: "66666666-6666-4666-8666-666666666666",
      source_device_id: null,
      source_previous_hash: "b".repeat(64),
      source_hash: "c".repeat(64),
      source_gap: null,
      event: {
        version: 1,
        audit_event_id: "66666666-6666-4666-8666-666666666666",
        organization_id: ORGANIZATION_ID,
        actor_id: "44444444-4444-4444-8444-444444444444",
        action: "policy.created",
        target_type: "policy",
        target_id: "77777777-7777-4777-8777-777777777777",
        details: { policy_sequence: 4 },
        previous_hash: "b".repeat(64),
        sequence: 2,
        event_hash: "c".repeat(64),
        recorded_at: "2026-08-14T23:59:59.000Z"
      }
    },
    {
      version: 1,
      organization_id: ORGANIZATION_ID,
      environment: "production",
      chain: "admin",
      export_position: 3,
      source_id: "88888888-8888-4888-8888-888888888888",
      source_device_id: null,
      source_previous_hash: "c".repeat(64),
      source_hash: "d".repeat(64),
      source_gap: null,
      event: {
        version: 1,
        audit_event_id: "88888888-8888-4888-8888-888888888888",
        organization_id: ORGANIZATION_ID,
        actor_id: "44444444-4444-4444-8444-444444444444",
        action: "audit.export.requested",
        target_type: "audit_export",
        target_id: EXPORT_ID,
        details: { chain: "admin", record_count: 3 },
        previous_hash: "c".repeat(64),
        sequence: 3,
        event_hash: "d".repeat(64),
        recorded_at: "2026-08-15T00:00:00.000Z"
      }
    }
  ];
let rootDigest = AUDIT_ANCHOR_ZERO_DIGEST;
for (const entry of ENTRIES) rootDigest = foldAuditExportRoot(rootDigest, entry);
const RANGE = Object.freeze({
  from_audit_position: 1,
  to_audit_position: 3,
  previous_root_digest: AUDIT_ANCHOR_ZERO_DIGEST,
  root_digest: rootDigest,
  record_count: ENTRIES.length
});
const PAYLOAD = deepFreeze({
  version: 1,
  type: "agentpass.audit-export",
  organization_id: ORGANIZATION_ID,
  environment: "production",
  chain: "admin",
  range: RANGE,
  entries: ENTRIES
});
const PAYLOAD_DIGEST = sha256(canonicalJson(PAYLOAD));
const INPUT = Object.freeze({
  organization_id: ORGANIZATION_ID,
  export_id: EXPORT_ID,
  environment: "production",
  chain: "admin",
  idempotency_key: "audit-export-request-0001"
});

function sha256(value) {
  return crypto.createHash("sha256").update(value, "utf8").digest("hex");
}

function deepFreeze(value, seen = new Set()) {
  if (!value || typeof value !== "object" || seen.has(value)) return value;
  seen.add(value);
  Object.freeze(value);
  for (const child of Object.values(value)) deepFreeze(child, seen);
  return value;
}

function requestDigest(input, range = RANGE, payloadDigest = PAYLOAD_DIGEST) {
  return sha256(canonicalJson({
    version: 1,
    organization_id: input.organization_id,
    export_id: input.export_id,
    environment: input.environment,
    chain: input.chain,
    idempotency_key: input.idempotency_key,
    range,
    payload_digest: payloadDigest
  }));
}

function metadataFor(fixture, overrides = {}) {
  return Object.freeze({ ...fixture.metadata, ...overrides });
}

function createSigner({
  keyId = KEY_ID,
  keyVersion = KEY_VERSION,
  lifecycleVersion = LIFECYCLE_VERSION,
  publicKey = undefined,
  sign = undefined,
  metadata = undefined
} = {}) {
  const keys = crypto.generateKeyPairSync("ed25519");
  const publicKeyPem = (publicKey ?? keys.publicKey).export({ type: "spki", format: "pem" }).toString();
  const calls = { metadata: [], sign: [] };
  const provider = {
    async publicKeyMetadata(input) {
      calls.metadata.push(input);
      return { algorithm: AUDIT_ANCHOR_ALGORITHM, key_id: keyId, public_key: publicKeyPem };
    },
    async sign(input) {
      calls.sign.push({ ...input, bytes: Buffer.from(input.bytes) });
      return crypto.sign(null, input.bytes, keys.privateKey);
    }
  };
  const base = createHostedAuditAnchorSigner({
    provider,
    keyId,
    keyVersion,
    lifecycleVersion,
    publicKey: publicKey ?? keys.publicKey,
    now: () => NOW
  });
  const fixture = {
    keys,
    publicKey: publicKeyPem,
    provider,
    base,
    calls,
    metadata: {
      version: AUDIT_ANCHOR_VERSION,
      type: AUDIT_ANCHOR_TYPE,
      purpose: AUDIT_ANCHOR_PURPOSE,
      domain: AUDIT_ANCHOR_SIGNATURE_DOMAIN,
      protocol_version: AUDIT_ANCHOR_PROTOCOL_VERSION,
      signing_version: AUDIT_ANCHOR_SIGNING_VERSION,
      algorithm: AUDIT_ANCHOR_ALGORITHM,
      key_id: keyId,
      key_version: keyVersion,
      lifecycle_version: lifecycleVersion,
      public_key: publicKeyPem,
      public_key_fingerprint: auditAnchorPublicKeyFingerprint(publicKey ?? keys.publicKey)
    }
  };
  fixture.signer = Object.freeze({
    ...base,
    ...(metadata === undefined ? {} : { publicKeyMetadata: metadata }),
    ...(sign === undefined ? {} : { signAuditAnchor: sign })
  });
  return fixture;
}

function reservation(input, overrides = {}) {
  const range = overrides.range ?? RANGE;
  const payloadDigest = overrides.payload_digest ?? PAYLOAD_DIGEST;
  return {
    state: "reserved",
    organization_id: input.organization_id,
    export_id: input.export_id,
    environment: input.environment,
    chain: input.chain,
    idempotency_key: input.idempotency_key,
    range,
    payload_digest: payloadDigest,
    request_digest: requestDigest(input, range, payloadDigest),
    issued_at: new Date(NOW).toISOString(),
    expires_at: new Date(NOW + 60_000).toISOString(),
    key_id: KEY_ID,
    key_version: KEY_VERSION,
    lifecycle_version: LIFECYCLE_VERSION,
    claim_token: "claim-token-0000000000000001",
    ...overrides
  };
}

function committedRecord(input, overrides = {}) {
  const {
    claim_token: ignoredClaimToken,
    state: ignoredState,
    ...authority
  } = input;
  return {
    state: "committed",
    ...authority,
    audit_anchor: input.audit_anchor,
    ...overrides
  };
}

function createRepository({ reserve = undefined, commit = undefined, replay = undefined, getPayload = undefined, retrieve = undefined } = {}) {
  const calls = { reserve: [], commit: [], replay: [], payload: [], retrieve: [], uncertain: [], snapshot: 0 };
  let committed;
  const repository = {
    async reserveAuditExport(input) {
      calls.reserve.push(structuredClone(input));
      if (typeof reserve === "function") return reserve(input, calls, setCommitted);
      if (reserve !== undefined) return structuredClone(reserve);
      if (committed) return structuredClone(committed);
      calls.snapshot += 1;
      return reservation(input);
    },
    async commitAuditExport(input) {
      calls.commit.push(structuredClone(input));
      if (typeof commit === "function") return commit(input, calls, setCommitted);
      committed = committedRecord(input);
      return structuredClone(committed);
    },
    async replayAuditExport(input) {
      calls.replay.push(structuredClone(input));
      if (typeof replay === "function") return replay(input, calls);
      return committed ? structuredClone(committed) : { state: "absent" };
    },
    async getAuditExportPayload(input) {
      calls.payload.push(structuredClone(input));
      if (typeof getPayload === "function") return getPayload(input, calls);
      if (getPayload !== undefined) return structuredClone(getPayload);
      return structuredClone(PAYLOAD);
    },
    async getCommittedAuditExport(input) {
      calls.retrieve.push(structuredClone(input));
      if (typeof retrieve === "function") return retrieve(input, calls);
      if (retrieve !== undefined) return structuredClone(retrieve);
      if (!committed) {
        const error = new Error("not found");
        error.code = "ERR_AUDIT_EXPORT_ISSUANCE_NOT_FOUND";
        throw error;
      }
      return { ...structuredClone(committed), payload: structuredClone(PAYLOAD) };
    },
    async markAuditExportUncertain(input) {
      calls.uncertain.push(structuredClone(input));
      return { state: "uncertain" };
    }
  };
  function setCommitted(value) { committed = value; }
  return { repository, calls, getCommitted: () => committed };
}

function createService({ repository, signer, resolver, now = () => NOW, deploymentMode = "hosted" }) {
  return createAuditExportIssuanceService({
    repository,
    signer,
    publicKeyResolver: resolver,
    now,
    deploymentMode
  });
}

function validService(options = {}) {
  const fixture = createSigner(options.signerOptions);
  const repoFixture = createRepository(options.repositoryOptions);
  const resolverCalls = [];
  const resolver = options.resolver ?? (async (input) => {
    resolverCalls.push(input);
    return fixture.metadata;
  });
  return {
    fixture,
    repoFixture,
    resolverCalls,
    service: createService({ repository: repoFixture.repository, signer: fixture.signer, resolver, now: options.now ?? (() => NOW) })
  };
}

async function createCommittedFixture() {
  const value = validService();
  const issued = await value.service.issueAuditExport(INPUT);
  return { ...value, issued };
}

function unavailableRotatedSigner() {
  const rotated = createSigner({ keyId: "audit-anchor-production-v2", keyVersion: 8, lifecycleVersion: 4 });
  const calls = { metadata: 0, sign: 0 };
  const signer = Object.freeze({
    ...rotated.signer,
    async publicKeyMetadata() {
      calls.metadata += 1;
      throw new Error("current signer must not be consulted for committed replay");
    },
    async signAuditAnchor() {
      calls.sign += 1;
      throw new Error("current signer must not sign committed replay");
    }
  });
  return { rotated, signer, calls };
}

test("uses only caller identity and signs the repository-frozen authoritative descriptor", async () => {
  const value = validService();
  const result = await value.service.issueAuditExport(INPUT);

  assert.deepEqual(Object.keys(INPUT).sort(), ["chain", "environment", "export_id", "idempotency_key", "organization_id"].sort());
  assert.deepEqual(Object.keys(value.repoFixture.calls.reserve[0]).sort(), Object.keys(INPUT).sort());
  assert.deepEqual(value.repoFixture.calls.payload[0], INPUT);
  assert.equal(PAYLOAD_DIGEST, sha256(canonicalJson(PAYLOAD)));
  assert.deepEqual(result.range, RANGE);
  assert.equal(result.payload_digest, PAYLOAD_DIGEST);
  assert.deepEqual(result.payload, PAYLOAD);
  assert.equal(result.validity, "active");
  assert.equal(result.replayed, false);
  assert.deepEqual(Object.keys(result).sort(), [
    "audit_anchor", "chain", "environment", "export_id", "organization_id", "payload", "payload_digest", "range", "replayed", "validity"
  ].sort());
  assert.deepEqual(Object.keys(value.repoFixture.calls.commit[0]).sort(), [
    "audit_anchor", "chain", "claim_token", "environment", "expires_at", "export_id", "idempotency_key",
    "issued_at", "key_id", "key_version", "lifecycle_version", "organization_id", "payload_digest", "range", "request_digest"
  ].sort());
  assert.equal(Object.hasOwn(value.repoFixture.calls.commit[0], "signing_bytes"), false);
  assert.equal(Object.hasOwn(value.repoFixture.calls.commit[0], "provider_diagnostics"), false);
  assert.equal(Object.isFrozen(result), true);
  assert.equal(Object.isFrozen(result.payload), true);
  assert.equal(Object.isFrozen(result.payload.entries), true);
  assert.equal(Object.isFrozen(result.payload.entries[0]), true);
  assert.equal(Object.isFrozen(result.payload.entries[0].event), true);
  assert.equal(Object.isFrozen(result.payload.entries[0].event.details), true);
  assert.equal(Object.isFrozen(result.range), true);
  assert.equal(Object.isFrozen(result.audit_anchor), true);
  assert.equal(Object.keys(result.audit_anchor.statement).filter((key) => key === "protocol_version").length, 1);
});

test("retrieves a committed export by four-field public identity and re-verifies its authority", async () => {
  const value = await createCommittedFixture();
  const input = {
    organization_id: INPUT.organization_id,
    export_id: INPUT.export_id,
    environment: INPUT.environment,
    chain: INPUT.chain
  };
  const result = await value.service.retrieveAuditExport(input);
  assert.deepEqual(value.repoFixture.calls.retrieve, [input]);
  assert.equal(value.repoFixture.calls.payload.length, 1);
  assert.deepEqual(result.payload, PAYLOAD);
  assert.equal(result.payload_digest, PAYLOAD_DIGEST);
  assert.equal(result.replayed, true);
  assert.equal(result.validity, "active");
  assert.equal(Object.hasOwn(result, "idempotency_key"), false);
  assert.equal(Object.hasOwn(result, "request_digest"), false);
  assert.equal(Object.isFrozen(result), true);
  assert.equal(Object.isFrozen(result.payload), true);
});

test("four-field retrieval rejects extra identity and maps opaque absence", async () => {
  const value = validService();
  const input = {
    organization_id: INPUT.organization_id,
    export_id: INPUT.export_id,
    environment: INPUT.environment,
    chain: INPUT.chain
  };
  await assert.rejects(value.service.retrieveAuditExport({ ...input, idempotency_key: INPUT.idempotency_key }), {
    code: AUDIT_EXPORT_ISSUANCE_ERROR_CODES.INPUT
  });
  await assert.rejects(value.service.retrieveAuditExport(input), {
    code: AUDIT_EXPORT_ISSUANCE_ERROR_CODES.NOT_FOUND
  });
});

test("rejects caller-supplied range and payload fields before repository access", async (t) => {
  const value = validService();
  for (const [name, extra] of [["range", { range: RANGE }], ["payload_digest", { payload_digest: PAYLOAD_DIGEST }]]) {
    await t.test(name, async () => {
      await assert.rejects(value.service.issueAuditExport({ ...INPUT, ...extra }), { code: AUDIT_EXPORT_ISSUANCE_ERROR_CODES.INPUT });
      assert.equal(value.repoFixture.calls.reserve.length, 0);
    });
  }
});

test("requires an authoritative contiguous range and a non-zero payload digest", async (t) => {
  await t.test("record count must equal the inclusive range length", async () => {
    const value = validService({ repositoryOptions: {
      reserve: (input) => reservation(input, { range: { ...RANGE, record_count: 2 } })
    } });
    await assert.rejects(value.service.issueAuditExport(INPUT), { code: AUDIT_EXPORT_ISSUANCE_ERROR_CODES.INPUT });
    assert.equal(value.fixture.calls.sign.length, 0);
  });
  await t.test("zero payload digest is rejected", async () => {
    const value = validService({ repositoryOptions: {
      reserve: (input) => reservation(input, { payload_digest: AUDIT_ANCHOR_ZERO_DIGEST })
    } });
    await assert.rejects(value.service.issueAuditExport(INPUT), { code: AUDIT_EXPORT_ISSUANCE_ERROR_CODES.INPUT });
    assert.equal(value.fixture.calls.sign.length, 0);
  });
});

test("replays a committed response-loss record without a second signer call", async () => {
  const fixture = createSigner();
  let committed;
  const repoFixture = createRepository({
    commit: (input, calls, setCommitted) => {
      committed = committedRecord(input);
      setCommitted(committed);
      throw Object.assign(new Error("response lost"), { code: "response_lost", provider_diagnostics: "redacted" });
    }
  });
  const resolverCalls = [];
  const service = createService({
    repository: repoFixture.repository,
    signer: fixture.signer,
    resolver: async (input) => {
      resolverCalls.push(input);
      return fixture.metadata;
    }
  });

  await assert.rejects(service.issueAuditExport(INPUT), { code: AUDIT_EXPORT_ISSUANCE_ERROR_CODES.COMMIT });
  const signCount = fixture.calls.sign.length;
  const replayed = await service.issueAuditExport(INPUT);
  assert.equal(replayed.replayed, true);
  assert.deepEqual(replayed.payload, PAYLOAD);
  assert.equal(Object.isFrozen(replayed.payload), true);
  assert.equal(Object.isFrozen(replayed.payload.entries[2].event.details), true);
  assert.equal(replayed.validity, "active");
  assert.equal(fixture.calls.sign.length, signCount);
  assert.equal(resolverCalls.length, 1);
  assert.equal(repoFixture.calls.payload.length, 1);
  assert.equal(repoFixture.calls.snapshot, 1);
  assert.equal(repoFixture.calls.uncertain.length, 1);
  assert.equal(JSON.stringify(replayed).includes("provider_diagnostics"), false);
});

test("represents in-progress, uncertain, and conflict repository outcomes without signing", async (t) => {
  for (const state of ["in_progress", "uncertain", "conflict"]) {
    await t.test(state, async () => {
      const value = validService({ repositoryOptions: { reserve: { state } } });
      const code = {
        in_progress: AUDIT_EXPORT_ISSUANCE_ERROR_CODES.IN_PROGRESS,
        uncertain: AUDIT_EXPORT_ISSUANCE_ERROR_CODES.UNCERTAIN,
        conflict: AUDIT_EXPORT_ISSUANCE_ERROR_CODES.CONFLICT
      }[state];
      await assert.rejects(value.service.issueAuditExport(INPUT), { code });
      assert.equal(value.fixture.calls.sign.length, 0);
      assert.equal(value.repoFixture.calls.commit.length, 0);
    });
  }
});

test("fails closed for missing, tampered, noncanonical, and private committed payloads without re-signing or re-snapshotting", async (t) => {
  const cases = [
    ["missing", () => undefined],
    ["tampered", () => {
      const payload = structuredClone(PAYLOAD);
      payload.entries[0].event.details.reason = "tampered";
      return payload;
    }],
    ["noncanonical", () => canonicalJson(PAYLOAD)],
    ["private", () => {
      const payload = structuredClone(PAYLOAD);
      payload.entries[0].event.details = { private_key: "-----BEGIN PRIVATE KEY-----" };
      return payload;
    }]
  ];

  for (const [name, payloadFactory] of cases) {
    await t.test(name, async () => {
      let storedPayload = PAYLOAD;
      const value = validService({ repositoryOptions: { getPayload: () => storedPayload } });
      await value.service.issueAuditExport(INPUT);
      const signCount = value.fixture.calls.sign.length;
      storedPayload = payloadFactory();

      const rotated = unavailableRotatedSigner();
      const service = createService({
        repository: value.repoFixture.repository,
        signer: rotated.signer,
        resolver: async () => value.fixture.metadata
      });
      await assert.rejects(service.issueAuditExport(INPUT), { code: AUDIT_EXPORT_ISSUANCE_ERROR_CODES.OUTPUT });
      assert.equal(value.fixture.calls.sign.length, signCount);
      assert.equal(rotated.calls.metadata, 0);
      assert.equal(rotated.calls.sign, 0);
      assert.equal(value.repoFixture.calls.snapshot, 1);
      assert.equal(value.repoFixture.calls.payload.length, 2);
    });
  }
});

test("rejects tenant/export substitutions and inconsistent authoritative request digests", async (t) => {
  const cases = [
    ["tenant", { organization_id: OTHER_ORGANIZATION_ID }],
    ["export id", { export_id: OTHER_EXPORT_ID }],
    ["request digest", { request_digest: "d".repeat(64) }]
  ];
  for (const [name, change] of cases) {
    await t.test(name, async () => {
      const value = validService({ repositoryOptions: {
        reserve: (input) => reservation(input, change)
      } });
      await assert.rejects(value.service.issueAuditExport(INPUT), { code: AUDIT_EXPORT_ISSUANCE_ERROR_CODES.BINDING });
      assert.equal(value.fixture.calls.sign.length, 0);
    });
  }
});

test("quarantines signer failures and exposes no provider diagnostics", async () => {
  const base = createSigner();
  const signer = Object.freeze({
    ...base.signer,
    async signAuditAnchor() {
      throw Object.assign(new Error("provider diagnostic"), { code: "provider_failure", provider_diagnostics: "secret" });
    }
  });
  const value = validService();
  const service = createService({ repository: value.repoFixture.repository, signer, resolver: async () => base.metadata });
  await assert.rejects(service.issueAuditExport(INPUT), (error) => {
    assert.equal(error.code, AUDIT_EXPORT_ISSUANCE_ERROR_CODES.SIGNER);
    assert.equal(error.message.includes("provider diagnostic"), false);
    assert.equal(Object.hasOwn(error, "cause"), false);
    return true;
  });
  assert.equal(value.repoFixture.calls.commit.length, 0);
  assert.equal(value.repoFixture.calls.uncertain[0].reason, "signer_failure");
  assert.equal(Object.hasOwn(value.repoFixture.calls.uncertain[0], "provider_diagnostics"), false);
});

test("rejects current signer lifecycle drift before and after signing", async (t) => {
  await t.test("before signing", async () => {
    const base = createSigner();
    const signer = Object.freeze({
      ...base.signer,
      async publicKeyMetadata() {
        return metadataFor(base, { lifecycle_version: LIFECYCLE_VERSION + 1 });
      }
    });
    const value = validService();
    const service = createService({ repository: value.repoFixture.repository, signer, resolver: async () => base.metadata });
    await assert.rejects(service.issueAuditExport(INPUT), { code: AUDIT_EXPORT_ISSUANCE_ERROR_CODES.STALE_LIFECYCLE });
    assert.equal(base.calls.sign.length, 0);
  });
  await t.test("after signing", async () => {
    const base = createSigner();
    let metadataCalls = 0;
    const signer = Object.freeze({
      ...base.signer,
      async publicKeyMetadata() {
        metadataCalls += 1;
        return metadataFor(base, { lifecycle_version: metadataCalls === 1 ? LIFECYCLE_VERSION : LIFECYCLE_VERSION + 1 });
      }
    });
    const value = validService();
    const service = createService({ repository: value.repoFixture.repository, signer, resolver: async () => base.metadata });
    await assert.rejects(service.issueAuditExport(INPUT), { code: AUDIT_EXPORT_ISSUANCE_ERROR_CODES.STALE_LIFECYCLE });
    assert.equal(value.repoFixture.calls.commit.length, 0);
  });
});

test("committed replay survives current signer rotation through the historical resolver", async () => {
  const committed = await createCommittedFixture();
  const rotated = unavailableRotatedSigner();
  const resolverCalls = [];
  const service = createService({
    repository: committed.repoFixture.repository,
    signer: rotated.signer,
    resolver: async (input) => {
      resolverCalls.push(input);
      return committed.fixture.metadata;
    }
  });
  const replayed = await service.issueAuditExport(INPUT);
  assert.equal(replayed.replayed, true);
  assert.deepEqual(replayed.payload, PAYLOAD);
  assert.equal(replayed.validity, "active");
  assert.equal(rotated.calls.metadata, 0);
  assert.equal(rotated.calls.sign, 0);
  assert.deepEqual(Object.keys(resolverCalls[0]).sort(), [
    "algorithm", "key_id", "key_version", "lifecycle_version", "protocol_version", "purpose", "signing_version"
  ].sort());
  assert.equal(resolverCalls[0].key_id, KEY_ID);
  assert.equal(resolverCalls[0].key_version, KEY_VERSION);
  assert.equal(resolverCalls[0].lifecycle_version, LIFECYCLE_VERSION);
});

test("replays an expired committed envelope by verifying at issued_at and redacts current validity", async () => {
  const first = await createCommittedFixture();
  const rotated = unavailableRotatedSigner();
  const service = createService({
    repository: first.repoFixture.repository,
    signer: rotated.signer,
    now: () => NOW + 120_000,
    resolver: async () => first.fixture.metadata
  });
  const replayed = await service.replayAuditExport(INPUT);
  assert.equal(replayed.replayed, true);
  assert.deepEqual(replayed.payload, PAYLOAD);
  assert.equal(Object.isFrozen(replayed.payload.entries[1].event.details), true);
  assert.equal(replayed.validity, "expired");
  assert.equal(rotated.calls.metadata, 0);
  assert.equal(rotated.calls.sign, 0);
  assert.equal(Object.hasOwn(replayed, "issued_at"), false);
  assert.equal(Object.hasOwn(replayed, "expires_at"), false);
});

test("fails closed on missing, wrong, private, or diagnostic historical resolver output without signer calls", async (t) => {
  const first = await createCommittedFixture();
  const cases = [
    ["missing", async () => undefined],
    ["wrong key", async () => {
      const other = createSigner({ keyId: KEY_ID, keyVersion: KEY_VERSION, lifecycleVersion: LIFECYCLE_VERSION });
      return metadataFor(other, { key_id: KEY_ID, key_version: KEY_VERSION, lifecycle_version: LIFECYCLE_VERSION });
    }],
    ["private material", async () => ({ ...first.fixture.metadata, private_key: "-----BEGIN PRIVATE KEY-----" })],
    ["diagnostics", async () => ({ ...first.fixture.metadata, provider_diagnostics: "secret" })]
  ];
  for (const [name, resolver] of cases) {
    await t.test(name, async () => {
      const rotated = unavailableRotatedSigner();
      const service = createService({ repository: first.repoFixture.repository, signer: rotated.signer, resolver });
      await assert.rejects(service.issueAuditExport(INPUT), { code: AUDIT_EXPORT_ISSUANCE_ERROR_CODES.HISTORICAL_KEY });
      assert.equal(rotated.calls.metadata, 0);
      assert.equal(rotated.calls.sign, 0);
    });
  }
});

test("requires a historical resolver in hosted mode", () => {
  const value = validService();
  assert.throws(() => createAuditExportIssuanceService({
    repository: value.repoFixture.repository,
    signer: value.fixture.signer
  }), { code: AUDIT_EXPORT_ISSUANCE_ERROR_CODES.CONFIG });
});

test("rejects invalid public inputs and keeps public output strictly redacted", async (t) => {
  const value = validService();
  await t.test("unknown input and operation fields", async () => {
    await assert.rejects(value.service.issueAuditExport({ ...INPUT, private_key: "secret" }), { code: AUDIT_EXPORT_ISSUANCE_ERROR_CODES.INPUT });
    await assert.rejects(value.service.issueAuditExport(INPUT, { signing_bytes: Buffer.alloc(0) }), { code: AUDIT_EXPORT_ISSUANCE_ERROR_CODES.INPUT });
    assert.equal(value.repoFixture.calls.reserve.length, 0);
  });
  await t.test("local signer is not accepted in hosted mode", async () => {
    assert.throws(() => createService({ repository: value.repoFixture.repository, signer: { ...value.fixture.signer, local: true }, resolver: async () => value.fixture.metadata }), {
      code: AUDIT_EXPORT_ISSUANCE_ERROR_CODES.CONFIG
    });
  });
  await t.test("redacted output", async () => {
    const result = await value.service.issueAuditExport(INPUT);
    const serialized = JSON.stringify(result);
    assert.equal(serialized.includes("claim-token"), false);
    assert.equal(serialized.includes("signing_bytes"), false);
    assert.equal(serialized.includes("provider_diagnostics"), false);
    assert.equal(result.audit_anchor.signature.length, 86);
    assert.equal(Buffer.isBuffer(result.audit_anchor.signature), false);
  });
});
