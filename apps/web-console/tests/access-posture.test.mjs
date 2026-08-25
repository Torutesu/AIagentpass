import assert from "node:assert/strict";
import test from "node:test";

import { deriveAccessPosture } from "../app/access-posture.ts";

const NOW = Date.parse("2026-08-20T00:00:00.000Z");

function input(overrides = {}) {
  return {
    summaryState: "ready",
    session: { expiresAt: "2026-08-20T01:00:00.000Z", recentAuthAt: null },
    platformAuth: { loadState: "ready", browserSupported: true, passkeyCount: 1 },
    agents: [{ status: "active" }],
    devices: [{ status: "active", refreshState: "applied", blockedReason: null }],
    capabilities: [{ expiresAt: "2026-08-20T00:15:00.000Z" }],
    auditHealth: [{ chainStatus: "continuous" }],
    stopped: false,
    ...overrides,
  };
}

test("derives a ready Agent posture from safe metadata only", () => {
  const result = deriveAccessPosture(input(), NOW);
  assert.deepEqual(result.items.map((item) => item.status), ["利用可能", "有効", "1件が有効", "連続性を確認済み", "停止操作を利用可能"]);
  assert.equal(result.activeCapabilityCount, 1);
  assert.equal(result.nextAction?.action, "activity");
  assert.doesNotMatch(JSON.stringify(result), /token|secret|private[_-]?key|bearer/i);
});

test("fails closed and sends the operator to setup when a short-lived capability expired", () => {
  const result = deriveAccessPosture(input({ capabilities: [{ expiresAt: "2026-08-19T23:59:00.000Z" }] }), NOW);
  const agent = result.items.find((item) => item.key === "agent-access");
  assert.equal(agent?.state, "blocked");
  assert.equal(agent?.status, "短期権限が期限切れ");
  assert.equal(result.nextAction?.action, "setup");
});

test("prioritizes auth, audit, and revoke recovery actions for non-engineers", () => {
  const result = deriveAccessPosture(input({
    platformAuth: { loadState: "ready", browserSupported: true, passkeyCount: 0 },
    auditHealth: [{ chainStatus: "gap" }],
    stopped: true,
  }), NOW);
  assert.equal(result.items.find((item) => item.key === "platform-auth")?.status, "設定が必要");
  assert.equal(result.items.find((item) => item.key === "audit")?.status, "1件の途切れ");
  assert.equal(result.items.find((item) => item.key === "revoke")?.status, "組織停止中");
  assert.equal(result.nextAction?.action, "security");
  assert.equal(result.nextAction?.actionLabel, "認証設定を開く");
});

test("never treats unavailable summary data as healthy", () => {
  const result = deriveAccessPosture(input({ summaryState: "error", session: null }), NOW);
  assert.equal(result.items.find((item) => item.key === "human-session")?.state, "checking");
  assert.equal(result.items.find((item) => item.key === "agent-access")?.state, "checking");
  assert.equal(result.items.find((item) => item.key === "audit")?.state, "checking");
  assert.equal(result.nextAction?.action, "retry");
  assert.equal(result.nextAction?.actionLabel, "再同期する");
});
