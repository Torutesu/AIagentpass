import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import {
  installIntegration,
  integrationPlan,
  integrationRemovalPlan,
  removeIntegration,
  renderRemoval
} from "../lib/integrations.mjs";

function makePlan(client = "claude-code") {
  const projectDir = fs.mkdtempSync(path.join(os.tmpdir(), "agentpass-removal-"));
  return integrationRemovalPlan({
    client,
    projectDir,
    nodePath: process.execPath,
    mcpServerPath: "/opt/agentpass/mcp.mjs"
  });
}

function write(plan, text) {
  fs.mkdirSync(path.dirname(plan.target), { recursive: true, mode: 0o700 });
  fs.writeFileSync(plan.target, text, { mode: 0o600 });
}

test("removal plans target Claude Code and Cursor without changing install API", () => {
  const claude = makePlan("claude-code");
  const cursor = makePlan("cursor");
  assert.equal(claude.target.endsWith("/.mcp.json"), true);
  assert.equal(cursor.target.endsWith("/.cursor/mcp.json"), true);
  const install = integrationPlan({
    client: "claude-code",
    projectDir: claude.project_dir,
    nodePath: process.execPath,
    mcpServerPath: "/opt/agentpass/mcp.mjs"
  });
  assert.deepEqual(install.server, claude.expected_server);
  assert.equal(Object.hasOwn(install, "project_dir"), false);
  assert.equal(typeof installIntegration, "function");
});

test("dry-run previews owned removal and apply is atomic and idempotent", () => {
  const plan = makePlan("cursor");
  write(plan, JSON.stringify({ settings: { keep: true }, mcpServers: { other: { command: "other" }, agentpass: plan.expected_server } }, null, 2) + "\n");
  const before = fs.readFileSync(plan.target, "utf8");
  const preview = removeIntegration(plan);
  assert.equal(preview.dryRun, true);
  assert.equal(preview.changed, true);
  assert.equal(preview.removed, false);
  assert.equal(fs.readFileSync(plan.target, "utf8"), before);

  const applied = removeIntegration(plan, { dryRun: false });
  assert.equal(applied.atomic, true);
  assert.equal(applied.removed, true);
  assert.equal(JSON.parse(fs.readFileSync(plan.target, "utf8")).mcpServers.other.command, "other");
  const repeated = removeIntegration(plan, { dryRun: false });
  assert.equal(repeated.changed, false);
  assert.equal(repeated.removed, false);
  assert.equal(repeated.reason, "not_present");
  assert.equal(fs.readdirSync(path.dirname(plan.target)).some((name) => name.endsWith(".tmp")), false);
});

test("removes only the owned member while preserving unrelated JSON bytes", () => {
  const plan = makePlan();
  const source = `{
  "name": "keep",
  "mcpServers": {
    "other": { "command": "other", "args": ["--raw"] },
    "agentpass": ${JSON.stringify(plan.expected_server)}
  },
  "tail": true
}\r\n`;
  write(plan, source);
  const rendered = renderRemoval(plan, source);
  const expected = `{
  "name": "keep",
  "mcpServers": {
    "other": { "command": "other", "args": ["--raw"] }\n  },
  "tail": true
}\r\n`;
  assert.equal(rendered.changed, true);
  assert.equal(rendered.content, expected);
  assert.deepEqual(JSON.parse(rendered.content), {
    name: "keep",
    mcpServers: { other: { command: "other", args: ["--raw"] } },
    tail: true
  });
});

test("preserves bytes and refuses to remove a same-name non-AgentPass server", () => {
  const plan = makePlan();
  const source = `{"mcpServers":{"agentpass":{"command":"user-owned","args":[]}},"keep":1}\n`;
  write(plan, source);
  const result = removeIntegration(plan);
  assert.equal(result.changed, false);
  assert.equal(result.reason, "not_agentpass_owned");
  assert.equal(result.content, source);
  assert.equal(fs.readFileSync(plan.target, "utf8"), source);
});

test("handles missing configuration and a pre-removed configuration idempotently", () => {
  const plan = makePlan();
  const missing = removeIntegration(plan);
  assert.equal(missing.changed, false);
  assert.equal(missing.reason, "not_present");
  const source = "{\n  \"mcpServers\": {\n    \"other\": {\"command\": \"other\"}\n  }\n}\n";
  write(plan, source);
  const existing = removeIntegration(plan, { dryRun: false });
  assert.equal(existing.changed, false);
  assert.equal(existing.content, source);
  assert.equal(fs.readFileSync(plan.target, "utf8"), source);
});

test("rejects invalid JSON, ambiguous duplicate keys, and invalid MCP shape", () => {
  const plan = makePlan();
  for (const source of ["{", "[]", '{"mcpServers":[]}']) {
    write(plan, source);
    assert.throws(() => removeIntegration(plan), /invalid JSON|JSON object|mcpServers/);
    fs.unlinkSync(plan.target);
  }
  const nonObject = '{"mcpServers":{"agentpass":1}}';
  write(plan, nonObject);
  assert.equal(removeIntegration(plan).changed, false);
  assert.equal(fs.readFileSync(plan.target, "utf8"), nonObject);
  fs.unlinkSync(plan.target);
  write(plan, '{"mcpServers":{"agentpass":{},"agentpass":{}}}');
  assert.throws(() => removeIntegration(plan), /Duplicate agentpass/);
  fs.unlinkSync(plan.target);
  write(plan, '{"mcpServers":{"agentpass":{}},"mcpServers":{}}');
  assert.throws(() => removeIntegration(plan), /Duplicate mcpServers/);
  fs.unlinkSync(plan.target);
  write(plan, `{"mcpServers":{"agentpass":{"command":${JSON.stringify(process.execPath)},"command":${JSON.stringify(process.execPath)},"args":["/opt/agentpass/mcp.mjs"],"env":{"AGENTPASS_PROJECT_DIR":${JSON.stringify(plan.project_dir)}}}}}`);
  assert.throws(() => removeIntegration(plan), /Duplicate command/);
});

test("rejects unsafe symlink targets and parent directories in dry-run and apply", () => {
  const plan = makePlan();
  const outside = fs.mkdtempSync(path.join(os.tmpdir(), "agentpass-removal-outside-"));
  const outsideFile = path.join(outside, "mcp.json");
  fs.writeFileSync(outsideFile, JSON.stringify({ mcpServers: { agentpass: plan.expected_server } }));
  fs.symlinkSync(outsideFile, plan.target);
  assert.throws(() => removeIntegration(plan), /regular file/);
  assert.throws(() => removeIntegration(plan, { dryRun: false }), /regular file/);
  fs.unlinkSync(plan.target);

  const dangling = makePlan();
  fs.symlinkSync(path.join(outside, "does-not-exist.json"), dangling.target);
  assert.throws(() => removeIntegration(dangling), /regular file/);

  const cursor = makePlan("cursor");
  fs.symlinkSync(outside, path.dirname(cursor.target));
  assert.throws(() => removeIntegration(cursor), /real directory/);
  assert.throws(() => removeIntegration(cursor, { dryRun: false }), /real directory/);
  fs.unlinkSync(path.dirname(cursor.target));

  const danglingParent = makePlan("cursor");
  fs.symlinkSync(path.join(outside, "does-not-exist-directory"), path.dirname(danglingParent.target));
  assert.throws(() => removeIntegration(danglingParent), /real directory/);

  const writableParent = makePlan("cursor");
  fs.mkdirSync(path.dirname(writableParent.target), { mode: 0o700 });
  fs.chmodSync(path.dirname(writableParent.target), 0o777);
  assert.throws(() => removeIntegration(writableParent), /group\/world writable/);
});

test("rejects a plan that escapes its project ownership boundary", () => {
  const plan = makePlan();
  assert.throws(() => removeIntegration({ ...plan, target: path.join(plan.project_dir, "..", "outside.json") }), /escapes/);
});
