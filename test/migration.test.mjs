import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";
import test from "node:test";
import assert from "node:assert/strict";

const projectRoot = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const cli = path.join(projectRoot, "bin", "agentpass.mjs");

function run(args, options) {
  const result = spawnSync(process.execPath, [cli, ...args], { encoding: "utf8", ...options });
  if (result.status !== 0) throw new Error(result.stderr || "AgentPass CLI failed");
  return result.stdout.trim();
}

test("version 3 configuration migrates to version 4 without replacing enrolled agents", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "agentpass-migrate-"));
  const home = path.join(root, "home");
  const repo = path.join(root, "repo");
  fs.mkdirSync(home);
  fs.mkdirSync(repo);
  spawnSync("git", ["-C", repo, "init", "-b", "main"], { encoding: "utf8" });
  const env = { ...process.env, HOME: home };
  run(["init"], { cwd: repo, env });

  const configFile = path.join(home, ".agentpass", "config.json");
  const config = JSON.parse(fs.readFileSync(configFile, "utf8"));
  const originalAgent = config.default_agent_id;
  config.version = 3;
  delete config.audit_signing;
  delete config.agents[0].scope;
  config.remotes = {};
  config.session.ttl_seconds = 999999;
  fs.writeFileSync(configFile, `${JSON.stringify(config, null, 2)}\n`, { mode: 0o600 });
  fs.unlinkSync(path.join(home, ".agentpass", "audit", "checkpoint.pem"));

  run(["migrate"], { cwd: repo, env });
  const migrated = JSON.parse(fs.readFileSync(configFile, "utf8"));
  assert.equal(migrated.version, 4);
  assert.equal(migrated.default_agent_id, originalAgent);
  assert.equal(migrated.agents.some((agent) => agent.id === originalAgent), true);
  assert.deepEqual(migrated.agents[0].scope.remotes.allow, ["*"]);
  assert.equal(migrated.session.ttl_seconds, 86400);
  assert.match(migrated.audit_signing.public_key, /BEGIN PUBLIC KEY/);
  const checkpoint = JSON.parse(run(["audit", "checkpoint"], { cwd: repo, env }));
  assert.equal(checkpoint.entries, 2);
});
