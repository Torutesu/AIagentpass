import assert from "node:assert/strict";
import crypto from "node:crypto";
import test from "node:test";

import { canonicalJson } from "../../../packages/protocol/src/index.mjs";
import { computeAuditEventHash } from "../src/store.mjs";
import {
  claimDeviceAuditInboxEntry,
  normalizeDeviceAuditInboxEntry,
  settleDeviceAuditInboxEntry,
} from "../src/device-audit-inbox-contract.mjs";

const ids = {
  organization_id: "11111111-1111-4111-8111-111111111111",
  device_id: "22222222-2222-4222-8222-222222222222",
  event_id: "33333333-3333-4333-8333-333333333333",
};
const event = {
  version: 1, event_id: ids.event_id, request_id: ids.event_id, agent_id: "44444444-4444-4444-8444-444444444444",
  operation: "git.commit.sign", decision: "allow", reason: "allowed", policy_sequence: 1, capability_sequence: 1,
  repository: "/work/project", branch: "feature/inbox", remote: "git@example.test:project.git",
  payload_digest: "b".repeat(64), device_timestamp: "2026-08-20T00:00:00.000Z", previous_hash: "0".repeat(64),
};
event.event_hash = computeAuditEventHash(event);
const batchId = `audit-${crypto.createHash("sha256").update(canonicalJson({ events: [event] })).digest("hex")}`;
const now = () => "2026-08-20T00:00:00.000Z";

test("binds an inbox entry to canonical batch payload and tenant/device", () => {
  const entry = normalizeDeviceAuditInboxEntry({ ...ids, batch_id: batchId, events: [event] }, now);
  assert.equal(entry.state, "pending");
  assert.equal(entry.attempt, 0);
  assert.equal(entry.claim_token_digest, null);
  assert.equal(entry.organization_id, ids.organization_id);
  assert.equal(entry.device_id, ids.device_id);
});

test("response-loss is quarantined and retryable failure is bounded", () => {
  const entry = normalizeDeviceAuditInboxEntry({ ...ids, batch_id: batchId, events: [event] }, now);
  const claimed = claimDeviceAuditInboxEntry(entry, { claimToken: "claim-token-123456", now, leaseMs: 30_000 });
  const uncertain = settleDeviceAuditInboxEntry(claimed, { claimToken: "claim-token-123456", outcome: "uncertain", now });
  assert.equal(uncertain.state, "uncertain");
  assert.equal(uncertain.claim_token_digest, null);
  const retryClaim = claimDeviceAuditInboxEntry({ ...entry, attempt: 1, updated_at: now() }, { claimToken: "claim-token-234567", now, leaseMs: 30_000 });
  assert.equal(settleDeviceAuditInboxEntry(retryClaim, { claimToken: "claim-token-234567", outcome: "retryable_failure", now }).state, "pending");
});

test("rejects stale or substituted claim completion", () => {
  const entry = normalizeDeviceAuditInboxEntry({ ...ids, batch_id: batchId, events: [event] }, now);
  const claimed = claimDeviceAuditInboxEntry(entry, { claimToken: "claim-token-123456", now, leaseMs: 30_000 });
  assert.throws(() => settleDeviceAuditInboxEntry(claimed, { claimToken: "other-token-123456", outcome: "accepted", now }));
  assert.throws(() => settleDeviceAuditInboxEntry({ ...claimed, payload_sha256: "b".repeat(64) }, { claimToken: "claim-token-123456", outcome: "accepted", now }));
});
