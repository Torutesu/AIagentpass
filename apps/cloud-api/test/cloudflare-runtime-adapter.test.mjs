import test from "node:test";
import assert from "node:assert/strict";
import {
  CLOUDFLARE_RUNTIME_ERROR_CODES,
  CloudflareRuntimeError,
  createCloudflareRuntimeAdapter,
} from "../src/providers/cloudflare/runtime-adapter.mjs";

const ACCOUNT = "a".repeat(32);
const ARTIFACT = "b".repeat(64);
const REQUEST = "c".repeat(64);
const OPERATION = "11111111-1111-4111-8111-111111111111";
const BASE = { accountId: ACCOUNT, namespaceId: "agentpass-preview", artifact_digest: ARTIFACT, request_digest: REQUEST, target: { kind: "worker", name: "sales-follow-up" }, resources: [{ kind: "worker", name: "sales-follow-up" }], idempotency_key: "publish-20260825-0001" };

test("plan mode is side-effect free and explicitly not_proven", async () => {
  let calls = 0;
  const adapter = createCloudflareRuntimeAdapter({ accountId: ACCOUNT, namespaceId: "agentpass-preview", mode: "plan", transport: { async request() { calls += 1; } }, credentialProvider: async () => ({ authorization: "never-used" }) });
  assert.deepEqual(adapter.qualificationStatus(), { status: "not_proven", provider: "cloudflare", mode: "plan", reason: "plan_only" });
  const plan = adapter.planPublication(BASE);
  assert.equal(plan.status, "planned");
  assert.equal(plan.qualification_status, "not_proven");
  assert.equal(plan.direct_route_allowed, false);
  const reserved = await adapter.reserveOperation({ ...BASE, operation_id: OPERATION });
  assert.equal(reserved.status, "planned");
  assert.equal(calls, 0);
});

test("live mode without injected runtime returns not_proven, never a local pass", async () => {
  const adapter = createCloudflareRuntimeAdapter({ accountId: ACCOUNT, namespaceId: "agentpass-preview", mode: "live" });
  assert.equal(adapter.runtimeAvailable, false);
  const result = await adapter.reserveOperation({ ...BASE, operation_id: OPERATION });
  assert.equal(result.status, "not_proven");
  assert.equal(result.qualification_reason, "live_runtime_unavailable");
  assert.equal(result.state, "unknown");
});

test("publication binds the artifact digest and verifies optional bytes", async () => {
  const adapter = createCloudflareRuntimeAdapter({ accountId: ACCOUNT, namespaceId: "agentpass-preview" });
  const bytes = Buffer.from("immutable-artifact");
  const digest = (await import("node:crypto")).createHash("sha256").update(bytes).digest("hex");
  const good = await adapter.publishArtifact({ ...BASE, artifact_digest: digest, operation_id: OPERATION, artifact_bytes: bytes });
  assert.equal(good.artifact_digest, digest);
  await assert.rejects(() => adapter.publishArtifact({ ...BASE, operation_id: "11111111-1111-4111-8111-111111111112", artifact_bytes: Buffer.from("substituted") }), (error) => error.code === CLOUDFLARE_RUNTIME_ERROR_CODES.DIGEST_MISMATCH);
});

test("idempotency rejects substitution and provider response digest mismatch", async () => {
  const calls = [];
  const adapter = createCloudflareRuntimeAdapter({
    accountId: ACCOUNT,
    namespaceId: "agentpass-preview",
    mode: "live",
    credentialProvider: async () => ({ "x-workload-identity": "opaque" }),
    transport: { async request(request) { calls.push(request); return { status: 200, body: { id: "deployment-1", artifact_digest: "d".repeat(64), state: "active" } }; } },
  });
  await assert.rejects(() => adapter.reserveOperation({ ...BASE, operation_id: OPERATION }), (error) => error.code === CLOUDFLARE_RUNTIME_ERROR_CODES.DIGEST_MISMATCH);
  assert.equal(calls.length, 1);
  assert.equal(calls[0].headers["x-workload-identity"], "opaque");
  assert.doesNotMatch(JSON.stringify(calls[0].body), /token|secret|password/i);
});

test("provider IDs are metadata, not tenant authority, and stale generations fail closed", async () => {
  let count = 0;
  const adapter = createCloudflareRuntimeAdapter({
    accountId: ACCOUNT,
    namespaceId: "agentpass-preview",
    mode: "live",
    credentialProvider: async () => ({}),
    transport: { async request() { count += 1; return { status: 200, body: { id: "provider-id-not-tenant", artifact_digest: ARTIFACT, state: "active", active_generation: count <= 2 ? 4 : 3 } }; } },
  });
  const first = await adapter.reserveOperation({ ...BASE, operation_id: OPERATION, expected_generation: 4 });
  assert.equal(first.provider_deployment_id, "provider-id-not-tenant");
  const reconciled = await adapter.reconcileOperation(OPERATION);
  assert.equal(reconciled.state, "reconciled");
  const second = await adapter.reserveOperation({ ...BASE, operation_id: "11111111-1111-4111-8111-111111111112", idempotency_key: "publish-20260825-0002", expected_generation: 4 });
  assert.equal(second.status, "accepted");
  await assert.rejects(() => adapter.reconcileOperation("11111111-1111-4111-8111-111111111112"), (error) => error.code === CLOUDFLARE_RUNTIME_ERROR_CODES.STALE_GENERATION);
});

test("configuration and resource bounds reject credentials, custom API hosts, and unknown resources", () => {
  assert.throws(() => createCloudflareRuntimeAdapter({ accountId: ACCOUNT, namespaceId: "x", apiToken: "secret" }), (error) => error.code === CLOUDFLARE_RUNTIME_ERROR_CODES.INVALID_CONFIGURATION);
  assert.throws(() => createCloudflareRuntimeAdapter({ accountId: ACCOUNT, namespaceId: "x", apiBaseUrl: "https://evil.example/client/v4" }), CloudflareRuntimeError);
  const adapter = createCloudflareRuntimeAdapter({ accountId: ACCOUNT, namespaceId: "x" });
  assert.throws(() => adapter.planPublication({ ...BASE, target: { kind: "kv", name: "bad" } }), (error) => error.code === CLOUDFLARE_RUNTIME_ERROR_CODES.UNSUPPORTED_RESOURCE);
  assert.throws(() => adapter.planPublication({ ...BASE, resources: Array.from({ length: 17 }, (_, i) => ({ kind: "r2", name: `bucket-${i}` })) }), (error) => error.code === CLOUDFLARE_RUNTIME_ERROR_CODES.INVALID_INPUT);
});

test("provider response and errors do not expose credentials or raw body", async () => {
  const adapter = createCloudflareRuntimeAdapter({ accountId: ACCOUNT, namespaceId: "x", mode: "live", credentialProvider: async () => ({ authorization: "secret-token" }), transport: { async request() { throw new Error("authorization=secret-token response body"); } } });
  const result = await adapter.reserveOperation({ ...BASE, operation_id: OPERATION });
  assert.equal(result.status, "not_proven");
  assert.equal(result.qualification_reason, "provider_response_uncertain");
  assert.doesNotMatch(JSON.stringify(result), /secret-token|authorization=/i);
});
