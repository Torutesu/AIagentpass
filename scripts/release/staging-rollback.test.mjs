import assert from "node:assert/strict";
import crypto from "node:crypto";
import test from "node:test";
import { canonicalJson } from "../../packages/protocol/src/index.mjs";
import {
  STAGING_RESILIENCE_EVENT_TYPES,
  attachStagingRollbackDigest,
  normalizeStagingRollback,
  stagingRollbackSHA256,
  verifyStagingRollback
} from "./staging-rollback.mjs";

const now = Date.parse("2026-08-20T00:30:00.000Z");
const candidate = (suffix) => ({
  artifact_sha256: suffix.repeat(64), candidate_id: `release-pkg-sha256-v1-${suffix.repeat(64)}`,
  release_manifest_sha256: (suffix === "c" ? "d" : "e").repeat(64), source_commit: (suffix === "c" ? "a" : "f").repeat(40), source_tree: (suffix === "c" ? "b" : "0").repeat(40)
});
const deployment = (revision, suffix) => ({
  catalog_digest: (suffix === "e" ? "7" : "8").repeat(64),
  database_schema_digest: (suffix === "e" ? "9" : "a").repeat(64),
  deployment_digest: suffix.repeat(64), deployment_id: "staging-api", environment: "staging",
  image_digest: `sha256:${(suffix === "e" ? "1" : "2").repeat(64)}`,
  revision,
  schema_digest: (suffix === "e" ? "5" : "6").repeat(64),
  service: "agentpass-cloud-api",
  deployment_identity: {
    artifact_sha256: (suffix === "e" ? "c" : "f").repeat(64),
    candidate_id: `release-pkg-sha256-v1-${(suffix === "e" ? "c" : "f").repeat(64)}`,
    catalog_digest: (suffix === "e" ? "7" : "8").repeat(64), configured: true,
    database_schema_digest: (suffix === "e" ? "9" : "a").repeat(64), deployment_id: "staging-api",
    deployment_digest: suffix.repeat(64), environment: "staging",
    image_digest: `sha256:${(suffix === "e" ? "1" : "2").repeat(64)}`, ready: true,
    release_manifest_sha256: (suffix === "e" ? "d" : "e").repeat(64), revision,
    schema_digest: (suffix === "e" ? "5" : "6").repeat(64), service: "agentpass-cloud-api",
    source_commit: (suffix === "e" ? "a" : "f").repeat(40), source_tree: (suffix === "e" ? "b" : "0").repeat(40), version: 1
  }
});
const target = () => ({ candidate: candidate("f"), deployment: deployment("previous-revision", "2"), status: "passed", target_ready: true });

const observerKeys = new Map(STAGING_RESILIENCE_EVENT_TYPES.map((type) => [type, crypto.generateKeyPairSync("ed25519")]));
const sha256 = (value) => crypto.createHash("sha256").update(value).digest("hex");
const observerFingerprint = (type) => sha256(observerKeys.get(type).publicKey.export({ type: "spki", format: "der" }));

function signedEvent(type) {
  const pair = observerKeys.get(type);
  const completedAt = "2026-08-20T00:09:00.000Z";
  const unsignedObserver = {
    attestation: "independent_external", kind: "protected_observer", observed_at: completedAt,
    observer_id: `protected-observer-${type}`, observer_key_fingerprint: observerFingerprint(type),
    public_key_pem: pair.publicKey.export({ type: "spki", format: "pem" })
  };
  const event = {
    candidate: candidate("c"), completed_at: completedAt, deployment: deployment("current-revision", "e"),
    event_type: type, execution_id: `protected-${type}-execution-001`,
    measurements: { rpo_ms: 0, rto_ms: 500, slo_ms: 1_000 }, observer: { ...unsignedObserver, signature: "" },
    started_at: "2026-08-20T00:05:00.000Z", status: "passed", target: target()
  };
  const unsigned = { ...event, observer: unsignedObserver };
  event.observer.signature = crypto.sign(null, Buffer.from(canonicalJson(unsigned), "utf8"), pair.privateKey).toString("base64url");
  return event;
}

const resilience = () => ({ events: STAGING_RESILIENCE_EVENT_TYPES.map(signedEvent) });
const binding = () => ({
  candidate: candidate("c"), deployment: deployment("current-revision", "e"), rollback_target: target(),
  resilience: { events: STAGING_RESILIENCE_EVENT_TYPES.map((event_type) => ({
    event_type, execution_id: `protected-${event_type}-execution-001`, observer_id: `protected-observer-${event_type}`,
    observer_key_fingerprint: observerFingerprint(event_type), rpo_ms: 0, rto_ms: 500, slo_ms: 1_000
  })) }
});

const rollback = () => attachStagingRollbackDigest({
  schema_version: 1, kind: "agentpass.staging-rollback", environment: "staging", service: "agentpass-cloud-api", qualified: true, status: "passed",
  candidate: candidate("c"), current_deployment: deployment("current-revision", "e"), resilience: resilience(),
  rollback: {
    status: "passed", deployment_identity: target().deployment.deployment_identity, executed: true,
    executed_at: "2026-08-20T00:08:00.000Z", execution_id: "protected-rollback-execution-001", tested: true,
    reused_artifact: true, target_ready: true, traffic_restored: true,
    current_revision: "current-revision", started_at: "2026-08-20T00:05:00.000Z", completed_at: "2026-08-20T00:10:00.000Z", target: target()
  },
  issued_at: "2026-08-20T00:00:00.000Z", expires_at: "2026-08-20T12:00:00.000Z", completed_at: "2026-08-20T00:10:00.000Z", evidence_sha256: "0".repeat(64)
});

test("staging rollback binds rollback/failover/PITR/signer-outage/recovery to independent signed measurements", () => {
  const value = rollback();
  const normalized = normalizeStagingRollback(value, { now });
  const result = verifyStagingRollback(normalized, { expected: binding(), now });
  assert.equal(result.qualified, true);
  assert.deepEqual(result.resilience.events.map(({ event_type }) => event_type).sort(), [...STAGING_RESILIENCE_EVENT_TYPES].sort());
  assert.equal(result.rollback.target.deployment.revision, "previous-revision");
  assert.equal(result.evidence_sha256, stagingRollbackSHA256(value));
});

test("staging rollback fails closed for digest, target, and event substitutions", () => {
  for (const [index, mutate] of [
    (value) => { value.candidate = { ...value.candidate, source_commit: "9".repeat(40) }; },
    (value) => { value.current_deployment = { ...value.current_deployment, image_digest: `sha256:${"9".repeat(64)}` }; },
    (value) => { value.current_deployment = { ...value.current_deployment, schema_digest: "9".repeat(64) }; },
    (value) => { value.current_deployment = { ...value.current_deployment, catalog_digest: "9".repeat(64) }; },
    (value) => { value.current_deployment = { ...value.current_deployment, database_schema_digest: "8".repeat(64) }; },
    (value) => { value.resilience.events[0] = { ...value.resilience.events[0], target: { ...value.resilience.events[0].target, deployment: { ...value.resilience.events[0].target.deployment, revision: "current-revision" } } }; },
    (value) => { value.resilience.events[0].observer.signature = "A".repeat(86); },
    (value) => { value.evidence_sha256 = "9".repeat(64); }
  ].entries()) {
    const value = structuredClone(rollback());
    mutate(value);
    assert.throws(() => verifyStagingRollback(value, { expected: binding(), now }), /ERR_STAGING_ROLLBACK/, `mutation ${index}`);
  }
});

test("staging rollback requires every resilience event, independent observer, and measured SLO/RPO/RTO", () => {
  for (const mutate of [
    (value) => { value.resilience.events.pop(); },
    (value) => { value.resilience.events[0].status = "not_run"; },
    (value) => { value.resilience.events[0].observer.attestation = "self_attested"; },
    (value) => { value.resilience.events[0].observer.observer_id = "local"; },
    (value) => { delete value.resilience.events[0].measurements.rto_ms; },
    (value) => { value.resilience.events[0].measurements.rto_ms = 24 * 60 * 60 * 1_000 + 1; },
    (value) => { value.resilience.events[0].observer.observer_key_fingerprint = "0".repeat(64); },
    (value) => { value.resilience.events[0].execution_id = "mock-execution"; }
  ]) {
    const value = structuredClone(rollback());
    mutate(value);
    assert.throws(() => normalizeStagingRollback(value, { now }), /ERR_STAGING_ROLLBACK/);
  }
});

test("staging rollback rejects expected binding substitutions and separate-observer violations", () => {
  const value = rollback();
  for (const mutate of [
    (expected) => { expected.resilience.events[0].execution_id = "protected-other-execution-001"; },
    (expected) => { expected.resilience.events[0].observer_id = "protected-other-observer"; },
    (expected) => { expected.resilience.events[0].slo_ms = 500; },
    (expected) => { expected.resilience.events[0].observer_key_fingerprint = "9".repeat(64); },
    (expected) => { expected.resilience.events[0].observer_id = "self-reporter"; }
  ]) {
    const expected = structuredClone(binding());
    mutate(expected);
    assert.throws(() => verifyStagingRollback(value, { expected, now }), /ERR_STAGING_ROLLBACK/);
  }
});

test("staging rollback rejects stale, future, failed, not-run, same-revision, and secret-shaped evidence", () => {
  const stale = structuredClone(rollback());
  stale.expires_at = "2026-08-20T00:29:00.000Z";
  assert.throws(() => verifyStagingRollback(stale, { expected: binding(), now }), /ERR_STAGING_ROLLBACK/);
  const future = structuredClone(rollback());
  future.completed_at = "2026-08-20T00:40:00.000Z";
  future.rollback.completed_at = future.completed_at;
  assert.throws(() => verifyStagingRollback(future, { expected: binding(), now }), /ERR_STAGING_ROLLBACK/);
  const failed = structuredClone(rollback());
  failed.status = "failed"; failed.qualified = false;
  failed.rollback = { ...failed.rollback, status: "failed", tested: false, target_ready: false, traffic_restored: false };
  assert.throws(() => verifyStagingRollback(failed, { expected: binding(), now }), /ERR_STAGING_ROLLBACK/);
  const notRun = structuredClone(rollback());
  notRun.status = "not_run"; notRun.qualified = false;
  notRun.rollback = { ...notRun.rollback, status: "not_run", deployment_identity: null, executed: false, executed_at: notRun.rollback.completed_at, execution_id: "not_run", tested: false, reused_artifact: false, target_ready: false, traffic_restored: false, target: { ...notRun.rollback.target, status: "not_run", target_ready: false } };
  assert.throws(() => verifyStagingRollback(notRun, { expected: binding(), now }), /ERR_STAGING_ROLLBACK/);
  const sameRevision = structuredClone(rollback());
  sameRevision.rollback.target = { ...sameRevision.rollback.target, deployment: { ...sameRevision.rollback.target.deployment, revision: "current-revision" } };
  assert.throws(() => normalizeStagingRollback(sameRevision, { now }), /ERR_STAGING_ROLLBACK/);
  const extra = structuredClone(rollback());
  extra.secret = "never retain credentials";
  assert.throws(() => normalizeStagingRollback(extra, { now }), /ERR_STAGING_ROLLBACK/);
});

test("staging rollback rejects incomplete deployment identities and execution receipts", () => {
  for (const mutate of [
    (value) => { delete value.current_deployment.schema_digest; },
    (value) => { delete value.current_deployment.catalog_digest; },
    (value) => { delete value.current_deployment.database_schema_digest; },
    (value) => { value.rollback.target.deployment.deployment_identity = { ...value.rollback.target.deployment.deployment_identity, image_digest: "sha256:" + "9".repeat(64) }; },
    (value) => { value.rollback.execution_id = "unknown"; },
    (value) => { delete value.rollback.execution_id; },
    (value) => { delete value.rollback.executed_at; },
    (value) => { value.rollback.deployment_identity = null; }
  ]) {
    const value = structuredClone(rollback());
    mutate(value);
    assert.throws(() => normalizeStagingRollback(value, { now }), /ERR_STAGING_ROLLBACK|ERR_STAGING_READINESS/);
  }
});
