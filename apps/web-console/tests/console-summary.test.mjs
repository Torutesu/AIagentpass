import assert from "node:assert/strict";
import fs from "node:fs";
import test from "node:test";
import { ConsoleSummaryParseError, parseConsoleSummary } from "../app/console-summary.ts";

const ORGANIZATION_ID = "11111111-1111-4111-8111-111111111111";
const DEVICE_ID = "22222222-2222-4222-8222-222222222222";
const AGENT_ID = "33333333-3333-4333-8333-333333333333";
const POLICY_ID = "44444444-4444-4444-8444-444444444444";
const EVENT_ID = "55555555-5555-4555-8555-555555555555";
const DATE = "2026-08-12T00:00:00.000Z";
const HASH = "a".repeat(64);

function scope() {
  return {
    operations: ["git.commit.sign"],
    repositories: ["/work/repository"],
    branches: { allow: ["main"], deny: [] },
    remotes: { allow: ["origin"], deny: [] },
  };
}

function summary(overrides = {}) {
  return {
    organization: { organization_id: ORGANIZATION_ID, name: "Acme", version: 1, created_at: DATE, updated_at: DATE },
    devices: [{
      device_id: DEVICE_ID,
      name: "Build Mac",
      status: "active",
      created_at: DATE,
      last_seen_at: DATE,
      version: 1,
      desired_generation: 2,
      observed_generation: 2,
      refresh_state: "applied",
      bundle_sequence: 4,
      bundle_expires_at: "2026-08-12T01:00:00.000Z",
      last_ack_at: DATE,
      blocked_reason: null,
    }],
    agents: [{
      version: 1,
      agent_id: AGENT_ID,
      organization_id: ORGANIZATION_ID,
      name: "Claude Code",
      kind: "claude-code",
      public_key: "-----BEGIN PUBLIC KEY-----\npublic\n-----END PUBLIC KEY-----",
      created_at: DATE,
      device_id: DEVICE_ID,
      status: "active",
    }],
    policies: [{
      policy_id: POLICY_ID,
      organization_id: ORGANIZATION_ID,
      name: "Commit signing",
      scope: scope(),
      sequence: 1,
      status: "active",
      created_at: DATE,
      updated_at: DATE,
      version: 1,
    }],
    audit: {
      health: [{ device_id: DEVICE_ID, chain_status: "continuous", gap_count: 0, last_event_id: EVENT_ID, last_hash: HASH, event_count: 1 }],
      activity: [{
        organization_id: ORGANIZATION_ID,
        device_id: DEVICE_ID,
        event_id: EVENT_ID,
        event: {
          version: 1,
          event_id: EVENT_ID,
          request_id: "66666666-6666-4666-8666-666666666666",
          agent_id: AGENT_ID,
          operation: "git.commit.sign",
          decision: "allow",
          reason: "allowed",
          policy_sequence: 1,
          capability_sequence: 1,
          repository: "/work/repository",
          branch: "main",
          remote: "origin",
          payload_digest: HASH,
          device_timestamp: DATE,
          previous_hash: HASH,
          event_hash: HASH,
        },
        received_at: DATE,
      }],
      next_cursor: null,
    },
    ...overrides,
  };
}

function parse(input, options) {
  return parseConsoleSummary(input, options);
}

function assertParseError(fn, path) {
  assert.throws(fn, (error) => {
    assert.ok(error instanceof ConsoleSummaryParseError);
    assert.equal(error.code, "ERR_CONSOLE_SUMMARY_PARSE");
    if (path) assert.equal(error.path, path);
    return true;
  });
}

test("parses the current summary response into a safe immutable view model", () => {
  const result = parse(summary(), { organizationId: ORGANIZATION_ID });
  assert.deepEqual(result.organization, { id: ORGANIZATION_ID, name: "Acme", createdAt: DATE, updatedAt: DATE, version: 1 });
  assert.deepEqual(result.devices[0], {
    id: DEVICE_ID, name: "Build Mac", status: "active", tone: "green", createdAt: DATE, lastSeenAt: DATE,
    version: 1, desiredGeneration: 2, observedGeneration: 2, refreshState: "applied", bundleSequence: 4,
    bundleExpiresAt: "2026-08-12T01:00:00.000Z", lastAckAt: DATE, blockedReason: null,
  });
  assert.deepEqual(result.agents[0], { id: AGENT_ID, name: "Claude Code", kind: "claude-code", status: "active", tone: "green", deviceId: DEVICE_ID, createdAt: DATE, version: 1 });
  assert.equal(result.policies[0].tone, "green");
  assert.deepEqual(result.audit.activity[0], {
    eventId: EVENT_ID, deviceId: DEVICE_ID, agentId: AGENT_ID, operation: "git.commit.sign", decision: "allow",
    tone: "green", reason: "allowed", deviceTimestamp: DATE, receivedAt: DATE,
  });
  assert.equal(Object.hasOwn(result.agents[0], "publicKey"), false);
  assert.equal(Object.hasOwn(result.audit.health[0], "lastHash"), false);
  assert.ok(Object.isFrozen(result));
  assert.ok(Object.isFrozen(result.devices));
  assert.ok(Object.isFrozen(result.devices[0]));
  assert.ok(Object.isFrozen(result.policies[0].scope));
  assert.throws(() => { result.devices[0].name = "changed"; }, TypeError);
});

test("accepts an explicitly empty tenant summary without inventing data", () => {
  const result = parse(summary({ devices: [], agents: [], policies: [], audit: { health: [], activity: [], next_cursor: null } }));
  assert.deepEqual(result.devices, []);
  assert.deepEqual(result.agents, []);
  assert.deepEqual(result.policies, []);
  assert.deepEqual(result.audit, { health: [], activity: [], nextCursor: null });
});

test("rejects unknown keys at every closed boundary", () => {
  assertParseError(() => parse(summary({ unexpected: true })), "$");
  assertParseError(() => parse(summary({ organization: { ...summary().organization, unexpected: true } })), "$.organization");
  assertParseError(() => parse(summary({ devices: [{ ...summary().devices[0], unexpected: true }] })), "$.devices[0]");
  assertParseError(() => parse(summary({ policies: [{ ...summary().policies[0], unexpected: true }] })), "$.policies[0]");
  assertParseError(() => parse(summary({ audit: { ...summary().audit, unexpected: true } })), "$.audit");
});

test("rejects missing and wrong-type required values without coercion", () => {
  assertParseError(() => parse(summary({ organization: { ...summary().organization, name: undefined } })), "$.organization.name");
  assertParseError(() => parse(summary({ devices: [{ ...summary().devices[0], status: 1 }] })), "$.devices[0].status");
  assertParseError(() => parse(summary({ agents: [{ ...summary().agents[0], agent_id: 3 }] })), "$.agents[0].agent_id");
  assertParseError(() => parse(summary({ policies: [{ ...summary().policies[0], sequence: "1" }] })), "$.policies[0].sequence");
  assertParseError(() => parse(summary({ audit: { ...summary().audit, activity: {} } })), "$.audit.activity");
});

test("rejects every incomplete nested audit event field", () => {
  for (const field of Object.keys(summary().audit.activity[0].event)) {
    const event = { ...summary().audit.activity[0].event };
    delete event[field];
    assertParseError(() => parse(summary({ audit: { ...summary().audit, activity: [{ ...summary().audit.activity[0], event }] } })), `$.audit.activity[0].event.${field}`);
  }
});

test("rejects oversized arrays and text before returning a model", () => {
  assertParseError(() => parse(summary({ devices: Array.from({ length: 501 }, () => summary().devices[0]) })), "$.devices");
  assertParseError(() => parse(summary({ organization: { ...summary().organization, name: "x".repeat(129) } })), "$.organization.name");
  assertParseError(() => parse(summary({ policies: [{ ...summary().policies[0], scope: { ...scope(), repositories: ["/" + "x".repeat(4096)] } }] })), "$.policies[0].scope.repositories[0]");
});

test("rejects malformed ids, timestamps, statuses, cursor and contradictory device state", () => {
  assertParseError(() => parse(summary({ organization: { ...summary().organization, organization_id: "not an id" } })), "$.organization.organization_id");
  assertParseError(() => parse(summary({ organization: { ...summary().organization, created_at: "2026-02-30T00:00:00.000Z" } })), "$.organization.created_at");
  assertParseError(() => parse(summary({ devices: [{ ...summary().devices[0], status: "unknown" }] })), "$.devices[0].status");
  assertParseError(() => parse(summary({ audit: { ...summary().audit, next_cursor: "not-a-cursor" } })), "$.audit.next_cursor");
  assertParseError(() => parse(summary({ devices: [{ ...summary().devices[0], desired_generation: 1, observed_generation: 2 }] })), "$.devices[0].observed_generation");
  assertParseError(() => parse(summary({ devices: [{ ...summary().devices[0], refresh_state: "blocked", blocked_reason: null }] })), "$.devices[0].blocked_reason");
});

test("rejects cross-tenant organization fields and unknown activity devices", () => {
  const otherTenant = "77777777-7777-4777-8777-777777777777";
  assertParseError(() => parse(summary({ agents: [{ ...summary().agents[0], organization_id: otherTenant }] })), "$.agents[0].organization_id");
  assertParseError(() => parse(summary(), { organizationId: otherTenant }), "$.organization.organization_id");
  assertParseError(() => parse(summary({ audit: { ...summary().audit, health: [{ ...summary().audit.health[0], device_id: otherTenant }] } })), "$.audit.health[0].device_id");
  assertParseError(() => parse(summary({ audit: { ...summary().audit, activity: [{ ...summary().audit.activity[0], organization_id: otherTenant }] } })), "$.audit.activity[0].organization_id");
});

test("rejects secret-bearing values and never copies authority material", () => {
  assertParseError(() => parse(summary({ agents: [{ ...summary().agents[0], private_key: "-----BEGIN PRIVATE KEY-----" }] })), "$.agents[0]");
  assertParseError(() => parse(summary({ agents: [{ ...summary().agents[0], public_key: "-----BEGIN PRIVATE KEY-----" }] })), "$.agents[0].public_key");
  assertParseError(() => parse(summary({ policies: [{ ...summary().policies[0], scope: { ...scope(), repositories: ["https://user:password@example.test/repo"] } }] })), "$.policies[0].scope.repositories[0]");
  assertParseError(() => parse(summary({ audit: { ...summary().audit, activity: [{ ...summary().audit.activity[0], event: { ...summary().audit.activity[0].event, reason: "Bearer secret-token" } }] } })), "$.audit.activity[0].event.reason");
});

test("production Console contains no sample operational state or permissive summary fallback", () => {
  const source = fs.readFileSync(new URL("../app/components/AgentPassConsole.tsx", import.meta.url), "utf8");
  for (const forbidden of [
    "defaultInitialData", "mergeCloudSummary", "initialData", "プロダクトチーム", "佐藤さん",
    "Hiroko の MacBook Pro", "営業資料リライト", "ランディングページ調整",
  ]) assert.doesNotMatch(source, new RegExp(forbidden, "u"));
  assert.match(source, /parseConsoleSummary\(summaryBody, \{ organizationId \}\)/u);
  assert.match(source, /parseDeploymentReadiness\(deploymentBody\)/u);
  assert.match(source, /setData\(emptyConsoleData\(\)\)/u);
  assert.match(source, /const epoch = \+\+summaryEpoch\.current/u);
});
