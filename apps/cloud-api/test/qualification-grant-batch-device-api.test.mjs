import assert from "node:assert/strict";
import crypto from "node:crypto";
import test from "node:test";

import {
  QUALIFICATION_GRANT_BATCH_DEVICE_HTTP_ERROR_CODES,
  QUALIFICATION_GRANT_BATCH_KIND,
  QUALIFICATION_GRANT_BATCH_STEP_IDENTITIES,
  QUALIFICATION_GRANT_TYPE,
  canonicalQualificationGrantBatchRequest,
  createQualificationGrantBatchDeviceApi
} from "../src/qualification-grant-batch-device-api.mjs";
import {
  AGENT_SESSION_GRANT_SIGNATURE_DOMAIN,
  verifyAgentSessionGrant
} from "../src/agent-session-grant.mjs";
import {
  QUALIFICATION_GRANT_BATCH_MANIFEST_VERSION,
  QUALIFICATION_GRANT_BATCH_MANIFEST_TYPE,
  qualificationGrantBatchManifestSigningData,
  qualificationGrantBatchManifestStatementHash,
  verifyQualificationGrantBatchManifest
} from "../src/qualification-grant-batch-manifest.mjs";
import { canonicalJson } from "../../../packages/protocol/src/index.mjs";

const NOW = Date.parse("2026-08-14T10:00:00.000Z");
const IDS = Object.freeze({
  organization: "11111111-1111-4111-8111-111111111111",
  device: "22222222-2222-4222-8222-222222222222",
  otherDevice: "33333333-3333-4333-8333-333333333333",
  agent: "44444444-4444-4444-8444-444444444444",
  batch: "55555555-5555-4555-8555-555555555555",
  request: "66666666-6666-4666-8666-666666666666"
});
const PATH = `/v1/organizations/${IDS.organization}/devices/${IDS.device}/qualification-grant-batches/${IDS.batch}/claim`;
const GRANT_KEYS = crypto.generateKeyPairSync("ed25519");
const MANIFEST_KEYS = crypto.generateKeyPairSync("ed25519");
const REQUEST = Object.freeze({
  schema_version: 1,
  candidate_sha256: "a".repeat(64),
  source_commit: "b".repeat(40),
  artifact_sha256: "c".repeat(64),
  release_trust_sha256: "d".repeat(64),
  candidate_checkpoint_sha256: "e".repeat(64),
  team_id: "TEAMID1234"
});

function digest(value) {
  return crypto.createHash("sha256").update(value, "utf8").digest("hex");
}

function grantId(index) {
  return `70000000-0000-4000-8000-${String(index + 1).padStart(12, "0")}`;
}

function batch(overrides = {}) {
  const value = {
    schema_version: 1,
    kind: QUALIFICATION_GRANT_BATCH_KIND,
    batch_id: IDS.batch,
    organization_id: IDS.organization,
    device_id: IDS.device,
    agent_id: IDS.agent,
    agent_kind: "claude-code",
    requested_ttl_seconds: 600,
    candidate_sha256: REQUEST.candidate_sha256,
    source_commit: REQUEST.source_commit,
    artifact_sha256: REQUEST.artifact_sha256,
    release_trust_sha256: REQUEST.release_trust_sha256,
    candidate_checkpoint_sha256: REQUEST.candidate_checkpoint_sha256,
    team_id: REQUEST.team_id,
    expires_at: new Date(NOW + 600_000).toISOString(),
    steps: []
  };
  value.steps = QUALIFICATION_GRANT_BATCH_STEP_IDENTITIES.map((identity) => {
    const runBinding = `qualification-run-${identity.index}`;
    const statement = {
      version: 1,
      grant_id: grantId(identity.index),
      organization_id: value.organization_id,
      device_id: value.device_id,
      agent_id: value.agent_id,
      agent_kind: value.agent_kind,
      adapter_id: "88888888-8888-4888-8888-888888888888",
      adapter_version: "1.2.3",
      worktree_binding_sha256: "f".repeat(64),
      process_binding_policy_id: "qualification-v1",
      scope: {
        operations: ["git.commit.sign"],
        repositories: ["/work/project"],
        branches: { allow: ["feature/*"], deny: ["main"] },
        remotes: { allow: ["git@example.test:project.git"], deny: [] }
      },
      max_signatures: 1,
      not_before: new Date(NOW).toISOString(),
      expires_at: value.expires_at,
      control_sequence: 1,
      authority_generation: 1,
      issuer: "agentpass-cloud",
      key_id: "qualification-v1"
    };
    const signature = crypto.sign(null, Buffer.concat([
      Buffer.from(AGENT_SESSION_GRANT_SIGNATURE_DOMAIN, "utf8"),
      Buffer.from(canonicalJson(statement), "utf8")
    ]), GRANT_KEYS.privateKey).toString("base64url");
    const grant = {
      version: 1,
      type: QUALIFICATION_GRANT_TYPE,
      statement,
      statement_hash: digest(canonicalJson(statement)),
      signature
    };
    return { ...identity, run_binding: runBinding, grant };
  });
  value.manifest = manifest(value);
  return { ...value, ...overrides };
}

function manifest(value) {
  const statement = {
    version: QUALIFICATION_GRANT_BATCH_MANIFEST_VERSION,
    type: QUALIFICATION_GRANT_BATCH_MANIFEST_TYPE,
    batch_id: value.batch_id,
    organization_id: value.organization_id,
    device_id: value.device_id,
    agent_id: value.agent_id,
    agent_kind: value.agent_kind,
    requested_ttl_seconds: value.requested_ttl_seconds,
    candidate_sha256: value.candidate_sha256,
    artifact_sha256: value.artifact_sha256,
    source_commit: value.source_commit,
    team_id: value.team_id,
    release_trust_sha256: value.release_trust_sha256,
    candidate_checkpoint_sha256: value.candidate_checkpoint_sha256,
    issued_at: value.steps[0].grant.statement.not_before,
    expires_at: value.expires_at,
    steps: value.steps.map((step) => ({
      index: step.index,
      kind: step.kind,
      scenario: step.scenario,
      phase: step.phase,
      run_binding: step.run_binding,
      grant_id: step.grant.statement.grant_id,
      grant_hash: digest(canonicalJson(step.grant)),
      statement_hash: step.grant.statement_hash,
    })),
    issuer: "agentpass-cloud",
    key_id: "qualification-batch-v1"
  };
  return {
    version: QUALIFICATION_GRANT_BATCH_MANIFEST_VERSION,
    type: QUALIFICATION_GRANT_BATCH_MANIFEST_TYPE,
    statement,
    statement_hash: qualificationGrantBatchManifestStatementHash(statement),
    signature: crypto.sign(null, qualificationGrantBatchManifestSigningData(statement), MANIFEST_KEYS.privateKey).toString("base64url")
  };
}

function body(overrides = {}) {
  return canonicalQualificationGrantBatchRequest({ ...REQUEST, ...overrides });
}

function request({ path = PATH, bodyBytes = body(), headers = { "x-device-auth": "signed" }, method = "POST" } = {}) {
  return { method, url: path, headers, body: bodyBytes };
}

async function fixture({ repository = undefined, grantVerifier = undefined, manifestVerifier = undefined, rateLimiter = undefined } = {}) {
  const calls = { auth: [], repository: [], grants: [], manifests: [], rateLimit: [] };
  const events = [];
  const defaultRepository = async (input) => {
    calls.repository.push(input);
    events.push("repository");
    return { batch: batch() };
  };
  const api = createQualificationGrantBatchDeviceApi({
    now: () => NOW,
    requestIdFactory: () => IDS.request,
    deviceRequestVerifier: async (raw, options) => {
      events.push("auth");
      calls.auth.push({ ...raw, body: Buffer.from(raw.body), options });
      return { principal: { organization_id: IDS.organization, device_id: IDS.device } };
    },
    grantVerifier: async (grant, options) => {
      calls.grants.push({ grant, options });
      if (grantVerifier) return grantVerifier(grant, options);
      return verifyAgentSessionGrant(grant, { publicKey: GRANT_KEYS.publicKey, now: options.now });
    },
    manifestVerifier: async (value, options) => {
      calls.manifests.push({ value, options });
      if (manifestVerifier) return manifestVerifier(value, options);
      return verifyQualificationGrantBatchManifest(value, { publicKey: MANIFEST_KEYS.publicKey, now: options.now });
    },
    repository: { claimQualificationGrantBatch: repository ?? defaultRepository },
    ...(rateLimiter === undefined ? {} : {
      rateLimiter: {
        async acquire(input) {
          calls.rateLimit.push(input);
          return rateLimiter(input);
        }
      }
    })
  });
  return { api, calls, events };
}

test("requires both the existing Grant verifier and the purpose-separated manifest verifier", () => {
  const base = {
    deviceRequestVerifier: async () => ({ principal: { organization_id: IDS.organization, device_id: IDS.device } }),
    repository: { claimQualificationGrantBatch: async () => ({ batch: batch() }) }
  };
  assert.throws(() => createQualificationGrantBatchDeviceApi({ ...base, grantVerifier: async () => true }), /manifestVerifier/u);
  assert.throws(() => createQualificationGrantBatchDeviceApi({ ...base, manifestVerifier: async () => true }), /grantVerifier/u);
});

function assertError(result, status, code) {
  assert.equal(result.status, status);
  assert.equal(result.body.error.code, code);
  assert.equal(result.body.request_id, IDS.request);
  assert.doesNotMatch(JSON.stringify(result.body), /password|private.?key|bearer|secret|cause|stack/iu);
}

test("authenticates exact raw request before interpreting canonical JSON and returns a closed no-store batch", async () => {
  const f = await fixture({ grantVerifier: async (grant) => grant });
  const bytes = body();
  const headers = { "AgentPass-Device": "signed", "AgentPass-Nonce": "nonce" };
  const result = await f.api.handle(request({ bodyBytes: bytes, headers }));

  assert.equal(result.status, 200);
  assert.equal(result.headers["Cache-Control"], "no-store, max-age=0");
  assert.deepEqual(Object.keys(result.body).sort(), ["batch", "request_id"]);
  assert.deepEqual(Object.keys(result.body.batch).sort(), [
    "agent_id", "agent_kind", "artifact_sha256", "batch_id", "candidate_checkpoint_sha256",
    "candidate_sha256", "device_id", "expires_at", "kind", "manifest", "organization_id", "release_trust_sha256",
    "requested_ttl_seconds", "schema_version", "source_commit", "steps", "team_id"
  ]);
  assert.equal(f.events.join(","), "auth,repository");
  assert.equal(f.calls.auth[0].method, "POST");
  assert.equal(f.calls.auth[0].path, PATH);
  assert.deepEqual(f.calls.auth[0].body, bytes);
  assert.strictEqual(f.calls.auth[0].headers, headers);
  assert.equal(f.calls.grants.length, 7);
  assert.equal(f.calls.manifests.length, 1);
  assert.equal(f.calls.manifests[0].options.purpose, QUALIFICATION_GRANT_BATCH_MANIFEST_TYPE);
  assert.equal(f.calls.manifests[0].value.statement.batch_id, IDS.batch);
  assert.deepEqual(Object.keys(f.calls.grants[0].grant).sort(), ["signature", "statement", "statement_hash", "type", "version"]);
  assert.equal(f.calls.grants[0].grant.type, "agentpass.agent-session-grant");
  assert.deepEqual(Object.keys(f.calls.grants[0].grant.statement).sort(), [
    "adapter_id", "adapter_version", "agent_id", "agent_kind", "authority_generation",
    "control_sequence", "device_id", "expires_at", "grant_id", "issuer", "key_id",
    "max_signatures", "not_before", "organization_id", "process_binding_policy_id", "scope", "version",
    "worktree_binding_sha256"
  ]);
  assert.equal("run_binding" in f.calls.grants[0].grant.statement, false);
  assert.equal("candidate_sha256" in f.calls.grants[0].grant.statement, false);
  assert.equal(f.calls.grants[0].grant.statement.max_signatures, 1);
  assert.equal(f.calls.repository[0].organization_id, IDS.organization);
  assert.equal(f.calls.repository[0].device_id, IDS.device);
  assert.equal(f.calls.repository[0].batch_id, IDS.batch);
  assert.equal("headers" in f.calls.repository[0], false);
  assert.equal("body" in f.calls.repository[0], false);
  assert.equal("raw_body" in f.calls.repository[0], false);
  assert.match(f.calls.repository[0].claim_identity_sha256, /^[0-9a-f]{64}$/u);
  assert.deepEqual(f.calls.repository[0].request, REQUEST);
  assert.deepEqual(result.body.batch.steps.map(({ index, kind, scenario, phase }) => ({ index, kind, scenario, phase })), QUALIFICATION_GRANT_BATCH_STEP_IDENTITIES);
  assert.equal(result.body.batch.steps.every((step) => step.grant.statement.organization_id === IDS.organization), true);
  assert.equal(result.body.batch.steps.every((step) => step.grant.statement.device_id === IDS.device), true);
  assert.equal(result.body.batch.steps.every((step) => step.grant.statement.agent_id === IDS.agent), true);
  assert.equal(result.body.batch.steps.every((step) => step.grant.statement.expires_at === result.body.batch.expires_at), true);
});

test("rejects unbound or substituted Grant verifier success results", async () => {
  for (const [index, grantVerifier] of [
    async () => true,
    async () => ({ verified: true }),
    async (grant) => ({ verified: true, grant: { ...grant, statement: { ...grant.statement, grant_id: IDS.otherDevice } } })
  ].entries()) {
    const f = await fixture({ grantVerifier });
    const result = await f.api.handle(request({ bodyBytes: body(), headers: { "x-device-auth": `signed-${index}` } }));
    assertError(result, 403, QUALIFICATION_GRANT_BATCH_DEVICE_HTTP_ERROR_CODES.GRANT_NOT_AUTHORIZED);
  }
});

test("rejects noncanonical, duplicate, unknown, and malformed public request fields after device auth", async () => {
  const f = await fixture();
  const cases = [
    Buffer.from(JSON.stringify(REQUEST), "utf8"),
    Buffer.from(`{"schema_version":1,"candidate_sha256":"${"a".repeat(64)}","source_commit":"${"b".repeat(40)}","artifact_sha256":"${"c".repeat(64)}","release_trust_sha256":"${"d".repeat(64)}","candidate_checkpoint_sha256":"${"e".repeat(64)}","candidate_checkpoint_sha256":"${"e".repeat(64)}","team_id":"TEAMID1234"}`, "utf8"),
    Buffer.from(JSON.stringify({ ...REQUEST, unexpected: true }), "utf8"),
    Buffer.from(JSON.stringify({ ...REQUEST, source_commit: "B".repeat(40) }), "utf8"),
    Buffer.from(JSON.stringify({ ...REQUEST, team_id: "teamid1234" }), "utf8")
  ];
  for (const [index, bodyBytes] of cases.entries()) {
    const result = await f.api.handle(request({ bodyBytes, headers: { nonce: `auth-${index}` } }));
    assertError(result, 400, QUALIFICATION_GRANT_BATCH_DEVICE_HTTP_ERROR_CODES.INVALID_REQUEST);
  }
  assert.equal(f.calls.auth.length, cases.length);
  assert.equal(f.calls.repository.length, 0);
});

test("rejects path and device substitutions before a repository claim", async () => {
  const f = await fixture();
  const wrongPath = `${PATH}/unexpected`;
  const wrongPathResult = await f.api.handle(request({ path: wrongPath }));
  assert.equal(wrongPathResult.status, 404);
  assert.equal(wrongPathResult.body.error.code, QUALIFICATION_GRANT_BATCH_DEVICE_HTTP_ERROR_CODES.NOT_FOUND);
  assert.equal(f.calls.auth.length, 0, "unmatched path is not authenticated");

  const mismatched = await f.api.handle(request({ path: PATH.replace(IDS.device, IDS.otherDevice) }));
  assertError(mismatched, 403, QUALIFICATION_GRANT_BATCH_DEVICE_HTTP_ERROR_CODES.AUDIENCE_MISMATCH);
  assert.equal(f.calls.repository.length, 0);
});

test("rejects method and route-shape substitutions with stable errors", async () => {
  const f = await fixture();
  assertError(await f.api.handle(request({ method: "GET" })), 400, QUALIFICATION_GRANT_BATCH_DEVICE_HTTP_ERROR_CODES.INVALID_REQUEST);
  assertError(await f.api.handle(request({ path: `${PATH}/` })), 404, QUALIFICATION_GRANT_BATCH_DEVICE_HTTP_ERROR_CODES.NOT_FOUND);
  assert.equal(f.calls.repository.length, 0);
});

test("rejects batch, statement, identity, expiry, signature, and unknown-key substitutions", async () => {
  const mutations = [
    (value) => ({ ...value, unknown: true }),
    (value) => ({ ...value, batch_id: "99999999-9999-4999-8999-999999999999" }),
    (value) => ({ ...value, steps: [...value.steps].reverse() }),
    (value) => ({ ...value, steps: value.steps.map((step, index) => index === 1 ? { ...step, run_binding: value.steps[0].run_binding } : step) }),
    (value) => ({ ...value, steps: value.steps.map((step, index) => index === 1 ? { ...step, grant: { ...step.grant, signature: value.steps[0].grant.signature } } : step) }),
    (value) => ({ ...value, steps: value.steps.map((step, index) => index === 1 ? { ...step, grant: { ...step.grant, statement_hash: "f".repeat(64) } } : step) }),
    (value) => ({ ...value, expires_at: new Date(NOW - 1).toISOString() }),
    (value) => ({ ...value, team_id: "OTHER12345" }),
    (value) => ({ ...value, steps: value.steps.map((step, index) => index === 1 ? { ...step, grant: { ...step.grant, statement: { ...step.grant.statement, device_id: IDS.otherDevice } } } : step) }),
    (value) => ({ ...value, steps: value.steps.map((step, index) => index === 1 ? { ...step, grant: { ...step.grant, statement: { ...step.grant.statement, private_key: "-----BEGIN PRIVATE KEY-----" } } } : step) })
  ];
  for (const mutate of mutations) {
    const f = await fixture({ repository: async () => ({ batch: mutate(batch()) }) });
    const result = await f.api.handle(request());
    assertError(result, 503, QUALIFICATION_GRANT_BATCH_DEVICE_HTTP_ERROR_CODES.UNAVAILABLE);
  }
});

test("rejects a Grant whose statement hash is recomputed for a substituted identity", async () => {
  const changed = batch();
  const original = changed.steps[2];
  const statement = { ...original.grant.statement, organization_id: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa" };
  const grant = { ...original.grant, statement, statement_hash: digest(canonicalJson(statement)) };
  changed.steps[2] = { ...original, grant };
  const f = await fixture({ repository: async () => ({ batch: changed }) });
  assertError(await f.api.handle(request()), 503, QUALIFICATION_GRANT_BATCH_DEVICE_HTTP_ERROR_CODES.UNAVAILABLE);
});

test("delegates one-shot and exact-retry ownership to the repository", async () => {
  const calls = [];
  const f = await fixture({ repository: async (input) => {
    calls.push(input);
    return { batch: batch() };
  } });
  const first = await f.api.handle(request({ headers: { nonce: "one" } }));
  const retry = await f.api.handle(request({ headers: { nonce: "two" } }));
  assert.equal(first.status, 200);
  assert.equal(retry.status, 200);
  assert.equal(calls.length, 2);
  assert.equal(calls[0].claim_identity_sha256, calls[1].claim_identity_sha256);
  assert.equal(calls[0].request_sha256, calls[1].request_sha256);
});

test("maps repository failures without exposing causes", async () => {
  for (const [error, status, code] of [
    [{ code: "ERR_GRANT_BATCH_CONFLICT", message: "batch already consumed in tenant SQL" }, 409, QUALIFICATION_GRANT_BATCH_DEVICE_HTTP_ERROR_CODES.BATCH_CONFLICT],
    [{ code: "ERR_GRANT_BATCH_NOT_FOUND", message: "internal lookup" }, 404, QUALIFICATION_GRANT_BATCH_DEVICE_HTTP_ERROR_CODES.NOT_FOUND],
    [{ code: "ERR_DATABASE", message: "password=must-not-leak" }, 503, QUALIFICATION_GRANT_BATCH_DEVICE_HTTP_ERROR_CODES.UNAVAILABLE]
  ]) {
    const f = await fixture({ repository: async () => { throw error; } });
    const result = await f.api.handle(request());
    assertError(result, status, code);
    assert.doesNotMatch(JSON.stringify(result.body), /internal|tenant|password|must-not-leak/iu);
  }
});

test("maps Grant verifier denial and failure to stable opaque responses", async () => {
  const denied = await fixture({ grantVerifier: async () => false });
  assertError(await denied.api.handle(request()), 403, QUALIFICATION_GRANT_BATCH_DEVICE_HTTP_ERROR_CODES.GRANT_NOT_AUTHORIZED);
  assert.equal(denied.calls.grants.length, 1);

  const expired = await fixture({ grantVerifier: async () => { throw Object.assign(new Error("expired SQL detail"), { code: "ERR_AGENT_SESSION_GRANT_EXPIRED" }); } });
  assertError(await expired.api.handle(request()), 409, QUALIFICATION_GRANT_BATCH_DEVICE_HTTP_ERROR_CODES.BATCH_CONFLICT);
});

test("requires and verifies the repository manifest before any 200 response", async () => {
  const missing = await fixture({ repository: async () => ({ batch: { ...batch(), manifest: undefined } }) });
  assertError(await missing.api.handle(request()), 503, QUALIFICATION_GRANT_BATCH_DEVICE_HTTP_ERROR_CODES.UNAVAILABLE);
  assert.equal(missing.calls.grants.length, 0);

  const denied = await fixture({ manifestVerifier: async () => false });
  assertError(await denied.api.handle(request()), 403, QUALIFICATION_GRANT_BATCH_DEVICE_HTTP_ERROR_CODES.GRANT_NOT_AUTHORIZED);
  assert.equal(denied.calls.grants.length, 0);

  const unavailableVerifier = await fixture({ manifestVerifier: async () => { throw Object.assign(new Error("KMS private detail"), { code: "ERR_QUALIFICATION_GRANT_BATCH_MANIFEST_PROVIDER" }); } });
  const unavailableResult = await unavailableVerifier.api.handle(request());
  assertError(unavailableResult, 503, QUALIFICATION_GRANT_BATCH_DEVICE_HTTP_ERROR_CODES.UNAVAILABLE);
  assert.doesNotMatch(JSON.stringify(unavailableResult.body), /KMS|private|detail/iu);

  const verifiedResult = await fixture({ manifestVerifier: async (value) => ({ verified: true, manifest: value }) });
  assert.equal((await verifiedResult.api.handle(request())).status, 200);
});

test("fails closed when the signed manifest is substituted or does not bind all seven Grants", async () => {
  const substitutedManifest = batch();
  substitutedManifest.manifest = {
    ...substitutedManifest.manifest,
    statement: { ...substitutedManifest.manifest.statement, candidate_sha256: "0".repeat(64) }
  };
  const substituted = await fixture({ repository: async () => ({ batch: substitutedManifest }) });
  assertError(await substituted.api.handle(request()), 403, QUALIFICATION_GRANT_BATCH_DEVICE_HTTP_ERROR_CODES.GRANT_NOT_AUTHORIZED);

  const incomplete = batch();
  incomplete.manifest = {
    ...incomplete.manifest,
    statement: {
      ...incomplete.manifest.statement,
      steps: incomplete.manifest.statement.steps.map((step, index) => index === 1 ? { ...step, run_binding: "different-run" } : step)
    }
  };
  const incompleteResult = await fixture({
    repository: async () => ({ batch: incomplete }),
    manifestVerifier: async (value) => ({ verified: true, manifest: { ...value, signature: value.signature } })
  });
  assertError(await incompleteResult.api.handle(request()), 503, QUALIFICATION_GRANT_BATCH_DEVICE_HTTP_ERROR_CODES.UNAVAILABLE);
});

test("applies rate limiting before JSON interpretation and Grant claim", async () => {
  const f = await fixture({ rateLimiter: async () => ({ allowed: false, limit: 10, remaining: 0, retryAfterSeconds: 9 }) });
  const result = await f.api.handle(request({ bodyBytes: Buffer.from("not-json", "utf8") }));
  assertError(result, 429, QUALIFICATION_GRANT_BATCH_DEVICE_HTTP_ERROR_CODES.RATE_LIMITED);
  assert.equal(result.headers["Retry-After"], "9");
  assert.equal(f.calls.repository.length, 0);
  assert.equal(f.calls.rateLimit.length, 1);
});

test("exports a canonical request contract with exact source and Team ID widths", () => {
  const bytes = canonicalQualificationGrantBatchRequest(REQUEST);
  assert.equal(bytes.toString("utf8"), JSON.stringify({
    artifact_sha256: REQUEST.artifact_sha256,
    candidate_checkpoint_sha256: REQUEST.candidate_checkpoint_sha256,
    candidate_sha256: REQUEST.candidate_sha256,
    release_trust_sha256: REQUEST.release_trust_sha256,
    schema_version: 1,
    source_commit: REQUEST.source_commit,
    team_id: REQUEST.team_id
  }));
  for (const key of ["candidate_sha256", "artifact_sha256", "release_trust_sha256", "candidate_checkpoint_sha256"]) {
    assert.throws(() => canonicalQualificationGrantBatchRequest({ ...REQUEST, [key]: "a".repeat(63) }));
  }
  assert.throws(() => canonicalQualificationGrantBatchRequest({ ...REQUEST, source_commit: "a".repeat(64) }));
  assert.throws(() => canonicalQualificationGrantBatchRequest({ ...REQUEST, team_id: "TEAMID123" }));
});
