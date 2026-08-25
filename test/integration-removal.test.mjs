import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
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

test("recovers a durable removal journal after every replacement boundary", () => {
  const plan = makePlan();
  const source = JSON.stringify({ mcpServers: { agentpass: plan.expected_server }, keep: true }, null, 2) + "\n";
  write(plan, source);
  const rendered = renderRemoval(plan, source);
  const quarantine = `${plan.target}.agentpass-remove.quarantine`;
  const replacement = `${plan.target}.agentpass-remove.replacement`;
  fs.writeFileSync(replacement, rendered.content, { mode: 0o600 });
  fs.renameSync(plan.target, quarantine);

  const preview = removeIntegration(plan);
  assert.equal(preview.reason, "recovery_pending");
  assert.equal(fs.existsSync(plan.target), false);
  const recovered = removeIntegration(plan, { dryRun: false });
  assert.equal(recovered.removed, true);
  assert.equal(fs.existsSync(quarantine), false);
  assert.equal(fs.existsSync(replacement), false);
  assert.equal(fs.readFileSync(plan.target, "utf8"), rendered.content);
});

test("never overwrites a concurrent writer at the final installation boundary", () => {
  const plan = makePlan();
  write(plan, JSON.stringify({ mcpServers: { agentpass: plan.expected_server } }, null, 2) + "\n");
  const originalLink = fs.linkSync;
  fs.linkSync = (source, destination) => {
    if (destination === plan.target && source.endsWith(".agentpass-remove.replacement")) {
      fs.writeFileSync(destination, '{"mcpServers":{"other":{"command":"concurrent"}}}\n', { flag: "wx", mode: 0o600 });
    }
    return originalLink(source, destination);
  };
  try {
    assert.throws(() => removeIntegration(plan, { dryRun: false }), /final installation/);
  } finally {
    fs.linkSync = originalLink;
  }
  assert.equal(fs.readFileSync(plan.target, "utf8"), '{"mcpServers":{"other":{"command":"concurrent"}}}\n');
  assert.equal(fs.existsSync(`${plan.target}.agentpass-remove.quarantine`), true);
});

test("journal reservation and recovery never overwrite competing files", () => {
  const reservation = makePlan();
  write(reservation, JSON.stringify({ mcpServers: { agentpass: reservation.expected_server } }) + "\n");
  const reservationJournal = `${reservation.target}.agentpass-remove.quarantine`;
  const originalLink = fs.linkSync;
  fs.linkSync = (source, destination) => {
    if (destination === reservationJournal) fs.writeFileSync(destination, "competing-journal\n", { flag: "wx", mode: 0o600 });
    return originalLink(source, destination);
  };
  try { assert.throws(() => removeIntegration(reservation, { dryRun: false }), /journal already exists or is competing/); }
  finally { fs.linkSync = originalLink; }
  assert.equal(fs.readFileSync(reservationJournal, "utf8"), "competing-journal\n");
  assert.equal(fs.existsSync(reservation.target), true);

  const recovery = makePlan();
  write(recovery, JSON.stringify({ mcpServers: { agentpass: recovery.expected_server } }) + "\n");
  const recoveryJournal = `${recovery.target}.agentpass-remove.quarantine`;
  fs.renameSync(recovery.target, recoveryJournal);
  fs.linkSync = (source, destination) => {
    if (source === recoveryJournal && destination === recovery.target) fs.writeFileSync(destination, "concurrent\n", { flag: "wx", mode: 0o600 });
    return originalLink(source, destination);
  };
  try { assert.throws(() => removeIntegration(recovery, { dryRun: false }), /prevented journal recovery/); }
  finally { fs.linkSync = originalLink; }
  assert.equal(fs.readFileSync(recovery.target, "utf8"), "concurrent\n");
  assert.equal(fs.existsSync(recoveryJournal), true);
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

test("CLI previews removal and applies it only with explicit execute", () => {
  const project = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "agentpass-removal-cli-")));
  const root = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
  const cli = path.join(root, "bin", "agentpass.mjs");
  const install = spawnSync(process.execPath, [cli, "integrate", "claude-code", "--install", "--project", project], { encoding: "utf8" });
  assert.equal(install.status, 0, install.stderr);
  const target = path.join(project, ".mcp.json");
  const installed = fs.readFileSync(target, "utf8");
  const preview = spawnSync(process.execPath, [cli, "integrate", "claude-code", "--remove", "--project", project], { encoding: "utf8" });
  assert.equal(preview.status, 0, preview.stderr);
  assert.equal(JSON.parse(preview.stdout).changed, true);
  assert.equal(JSON.parse(preview.stdout).removed, false);
  assert.equal(fs.readFileSync(target, "utf8"), installed);
  const execute = spawnSync(process.execPath, [cli, "integrate", "claude-code", "--remove", "--execute", "--project", project], { encoding: "utf8" });
  assert.equal(execute.status, 0, execute.stderr);
  assert.equal(JSON.parse(execute.stdout).removed, true);
  assert.deepEqual(JSON.parse(fs.readFileSync(target, "utf8")).mcpServers, {});
});
