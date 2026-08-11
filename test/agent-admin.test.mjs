import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import assert from "node:assert/strict";
import { addAgent, revokeAgent, rotateAgent, setAgentScope, setDefaultAgent } from "../lib/agent-admin.mjs";
import { loadConfig, saveConfig } from "../lib/config.mjs";
import { createAgentIdentity, createAuditIdentity } from "../lib/identity.mjs";

function fixture() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "agentpass-agent-admin-"));
  const initial = createAgentIdentity(dir, "initial");
  const auditIdentity = createAuditIdentity(dir);
  saveConfig({
    version: 4,
    agents: [{ id: initial.id, name: initial.name, public_key: initial.public_key, scope: { operations: ["git.commit.sign"], repositories: [dir], branches: { allow: ["*"] }, remotes: { allow: ["*"] } } }],
    default_agent_id: initial.id,
    operations: ["git.commit.sign"],
    repositories: [dir],
    branches: { allow: ["*"] },
    remotes: { allow: ["*"] },
    signing: { key: path.join(dir, "signing-key") },
    audit_signing: { public_key: auditIdentity.public_key },
    session: { required: false, ttl_seconds: 300 }
  }, dir);
  return { dir, initial };
}

test("agent identities can be enrolled, selected, revoked, and rotated", () => {
  const { dir, initial } = fixture();
  const added = addAgent("cursor-agent", dir);
  setAgentScope(added.id, { operations: ["git.commit.sign"], repositories: [dir], branches: { allow: ["feature/*"] }, remotes: { allow: ["git@example.test:repo"] } }, dir);
  setDefaultAgent(added.id, dir);
  revokeAgent(initial.id, dir);
  assert.equal(loadConfig(dir).agents.some((agent) => agent.id === initial.id), false);
  assert.equal(fs.existsSync(path.join(dir, "agents", `${initial.id}.pem`)), false);

  const rotated = rotateAgent(added.id, dir);
  const config = loadConfig(dir);
  assert.equal(config.default_agent_id, rotated.id);
  assert.deepEqual(config.agents.map((agent) => agent.id), [rotated.id]);
  assert.deepEqual(config.agents[0].scope.branches.allow, ["feature/*"]);
  assert.equal(fs.existsSync(path.join(dir, "agents", `${rotated.id}.pem`)), true);
});

test("the only enrolled agent cannot be revoked", () => {
  const { dir, initial } = fixture();
  assert.throws(() => revokeAgent(initial.id, dir), /only enrolled agent/);
});
