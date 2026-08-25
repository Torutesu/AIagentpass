import assert from "node:assert/strict";
import test from "node:test";

import { createProcessBindingPolicyRegistry, normalizeProcessBindingPolicyDocument } from "../src/process-binding-policy-registry.mjs";

const POLICY = {
  version: 1,
  policies: [{
    policy_id: "claude-code-release-v1",
    release_id: "agentpass-macos-0.18.0",
    agent_kind: "claude-code",
    adapter_id: "11111111-1111-4111-8111-111111111111",
    adapter_versions: ["1.2.3"],
    status: "enabled"
  }]
};
const INPUT = {
  organization_id: "22222222-2222-4222-8222-222222222222",
  device_id: "33333333-3333-4333-8333-333333333333",
  agent_id: "44444444-4444-4444-8444-444444444444",
  agent_kind: "claude-code",
  adapter_id: POLICY.policies[0].adapter_id,
  adapter_version: "1.2.3",
  process_binding_policy_id: "claude-code-release-v1",
  control_sequence: 7
};

test("allows only the exact release-approved agent, adapter, version, and policy tuple", async () => {
  const registry = createProcessBindingPolicyRegistry(POLICY);
  assert.deepEqual(await registry.resolve(INPUT), { allowed: true, policy_id: "claude-code-release-v1", release_id: "agentpass-macos-0.18.0" });
  for (const changed of [
    { agent_kind: "cursor" },
    { adapter_id: "55555555-5555-4555-8555-555555555555" },
    { adapter_version: "1.2.4" },
    { process_binding_policy_id: "unreviewed" },
    { control_sequence: 0 }
  ]) assert.equal((await registry.resolve({ ...INPUT, ...changed })).allowed, false);
});

test("normalization is closed, deterministic, immutable, and rejects duplicate policies or versions", () => {
  const normalized = normalizeProcessBindingPolicyDocument(POLICY);
  assert(Object.isFrozen(normalized));
  assert(Object.isFrozen(normalized.policies[0]));
  assert.throws(() => normalizeProcessBindingPolicyDocument({ ...POLICY, extra: true }));
  assert.throws(() => normalizeProcessBindingPolicyDocument({ ...POLICY, policies: [...POLICY.policies, POLICY.policies[0]] }));
  assert.throws(() => normalizeProcessBindingPolicyDocument({ ...POLICY, policies: [{ ...POLICY.policies[0], adapter_versions: ["1.2.3", "1.2.3"] }] }));
  assert.throws(() => normalizeProcessBindingPolicyDocument({ ...POLICY, policies: [{ ...POLICY.policies[0], status: "active" }] }));
});
