import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { installIntegration, integrationPlan, renderIntegration } from "../lib/integrations.mjs";

function fixture(client = "claude-code") {
  const projectDir = fs.mkdtempSync(path.join(os.tmpdir(), "agentpass-integration-"));
  return integrationPlan({ client, projectDir, nodePath: process.execPath, mcpServerPath: "/opt/agentpass/mcp.mjs" });
}

test("builds official project-scoped paths for Claude Code and Cursor", () => {
  assert.equal(fixture("claude-code").target.endsWith("/.mcp.json"), true);
  assert.equal(fixture("cursor").target.endsWith("/.cursor/mcp.json"), true);
});

test("preserves unrelated MCP servers and settings", () => {
  const plan = fixture();
  const rendered = JSON.parse(renderIntegration(plan, JSON.stringify({ setting: true, mcpServers: { other: { command: "other" } } })));
  assert.equal(rendered.setting, true);
  assert.equal(rendered.mcpServers.other.command, "other");
  assert.deepEqual(rendered.mcpServers.agentpass, plan.server);
});

test("dry run does not write and install is atomic and idempotent", () => {
  const plan = fixture("cursor");
  const preview = installIntegration(plan);
  assert.equal(preview.changed, true);
  assert.equal(fs.existsSync(plan.target), false);
  const installed = installIntegration(plan, { dryRun: false });
  assert.equal(installed.installed, true);
  const repeated = installIntegration(plan, { dryRun: false });
  assert.equal(repeated.changed, false);
  assert.equal(repeated.installed, false);
});

test("refuses invalid or structurally unsafe existing configuration", () => {
  const plan = fixture();
  assert.throws(() => renderIntegration(plan, "{"), /invalid JSON/);
  assert.throws(() => renderIntegration(plan, "[]"), /JSON object/);
  assert.throws(() => renderIntegration(plan, JSON.stringify({ mcpServers: [] })), /mcpServers/);
  const cursor = fixture("cursor");
  const outside = fs.mkdtempSync(path.join(os.tmpdir(), "agentpass-outside-"));
  fs.symlinkSync(outside, path.join(path.dirname(path.dirname(cursor.target)), ".cursor"));
  assert.throws(() => installIntegration(cursor, { dryRun: false }), /real directory/);
});

test("requires known clients and absolute executable paths", () => {
  const projectDir = fs.mkdtempSync(path.join(os.tmpdir(), "agentpass-integration-"));
  assert.throws(() => integrationPlan({ client: "unknown", projectDir, nodePath: process.execPath, mcpServerPath: "/x" }), /Unsupported/);
  assert.throws(() => integrationPlan({ client: "cursor", projectDir, nodePath: "node", mcpServerPath: "/x" }), /nodePath/);
});

test("CLI previews by default and writes only with explicit install", () => {
  const projectDir = fs.mkdtempSync(path.join(os.tmpdir(), "agentpass-cli-integration-"));
  const root = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
  const cli = path.join(root, "bin", "agentpass.mjs");
  const preview = spawnSync(process.execPath, [cli, "integrate", "claude-code", "--project", projectDir], { encoding: "utf8" });
  assert.equal(preview.status, 0, preview.stderr);
  assert.equal(JSON.parse(preview.stdout).installed, false);
  assert.equal(fs.existsSync(path.join(projectDir, ".mcp.json")), false);
  const install = spawnSync(process.execPath, [cli, "integrate", "claude-code", "--install", "--project", projectDir], { encoding: "utf8" });
  assert.equal(install.status, 0, install.stderr);
  assert.equal(JSON.parse(install.stdout).installed, true);
  assert.deepEqual(Object.keys(JSON.parse(install.stdout).configuration.mcpServers), ["agentpass"]);
  assert.equal(JSON.parse(fs.readFileSync(path.join(projectDir, ".mcp.json"), "utf8")).mcpServers.agentpass.command, process.execPath);
  const invalid = spawnSync(process.execPath, [cli, "integrate", "cursor", "--unknown"], { encoding: "utf8" });
  assert.notEqual(invalid.status, 0);
  assert.match(invalid.stderr, /Usage/);
});
