import test from "node:test";
import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import { PassThrough } from "node:stream";
import { createCliRunner, minimalEnvironment } from "../src/cli-runner.mjs";
import { createMcpServer } from "../src/server.mjs";
import { MAX_AUDIT_TAIL_COUNT } from "../src/schemas.mjs";
import { createToolHandler } from "../src/tools.mjs";

function rpc(id, method, params) {
  return { jsonrpc: "2.0", id, method, ...(params === undefined ? {} : { params }) };
}

async function initializedServer(commandRunner = async () => ({ code: 0, stdout: "", stderr: "" })) {
  const server = createMcpServer({ commandRunner });
  await server.handle(rpc(1, "initialize", { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "test", version: "1" } }));
  await server.handle({ jsonrpc: "2.0", method: "notifications/initialized" });
  return server;
}

test("advertises the policy and Small Software read-only tools with strict schemas", async () => {
  const server = await initializedServer();
  const result = await server.handle(rpc(2, "tools/list", {}));
  assert.deepEqual(result.result.tools.map((tool) => tool.name), [
    "agentpass_status", "agentpass_check", "agentpass_setup", "agentpass_audit_tail",
    "agentpass_app_inspect", "agentpass_publish_prepare", "agentpass_deployment_status",
    "agentpass_apps_list", "agentpass_app_open", "agentpass_maintenance_status"
  ]);
  for (const tool of result.result.tools) assert.equal(tool.inputSchema.additionalProperties, false);
  assert.equal(result.result.tools.some((tool) => tool.name.includes("sign")), false);
});

test("status is spawned with an argument array and path-bearing fields stay local", async () => {
  const calls = [];
  const server = await initializedServer(async (args) => {
    calls.push(args);
    return { code: 0, stdout: JSON.stringify({ version: 4, repositories: ["/private/repo"], audit: "/private/audit.jsonl", revoked: false, generation: 2, operations: ["git.commit.sign"], agents: [{ id: "agent-1", name: "worker", default: true }], audit_key_fingerprint: "SHA256:test" }), stderr: "" };
  });
  const result = await server.handle(rpc(3, "tools/call", { name: "agentpass_status", arguments: {} }));
  const value = JSON.parse(result.result.content[0].text);
  assert.deepEqual(calls, [["status"]]);
  assert.equal(value.audit, undefined);
  assert.equal(value.repositories, undefined);
  assert.equal(value.revoked, false);
});

test("check preserves a policy denial without leaking command diagnostics", async () => {
  const server = await initializedServer(async (args) => {
    assert.deepEqual(args, ["check"]);
    return { code: 1, stdout: JSON.stringify({ allowed: false, reason: "session_required", cwd: "/private/repo" }), stderr: "/private/token-path" };
  });
  const result = await server.handle(rpc(4, "tools/call", { name: "agentpass_check", arguments: {} }));
  assert.deepEqual(JSON.parse(result.result.content[0].text), { allowed: false, reason: "session_required" });
});

test("setup is editor-scoped and does not return local paths", async () => {
  const calls = [];
  const server = await initializedServer(async (args) => {
    calls.push(args);
    return { code: 0, stdout: "mkdir -p /Users/user/.agentpass/keys\n", stderr: "" };
  });
  const result = await server.handle(rpc(5, "tools/call", { name: "agentpass_setup", arguments: { editor: "cursor" } }));
  const value = JSON.parse(result.result.content[0].text);
  assert.deepEqual(calls, [["integrate", "cursor"]]);
  assert.equal(value.editor, "cursor");
  assert.equal(JSON.stringify(value).includes("/Users/user"), false);
  assert.equal(value.configuration.mcpServers.agentpass.command, process.execPath);
  assert.equal(value.configuration.mcpServers.agentpass.args[0].startsWith("/"), true);
});

test("audit tail is bounded, redacted, and rejects oversized counts", async () => {
  const audit = Array.from({ length: MAX_AUDIT_TAIL_COUNT + 5 }, (_, index) => JSON.stringify({ timestamp: `2026-01-01T00:00:${String(index).padStart(2, "0")}Z`, operation: "git.commit.sign", decision: "deny", reason: "session_required", cwd: "/private/repo", token: "secret" })).join("\n");
  const server = await initializedServer(async (args) => {
    assert.deepEqual(args, ["audit", "--tail", String(MAX_AUDIT_TAIL_COUNT)]);
    return { code: 0, stdout: audit, stderr: "" };
  });
  const result = await server.handle(rpc(6, "tools/call", { name: "agentpass_audit_tail", arguments: { count: MAX_AUDIT_TAIL_COUNT } }));
  const value = JSON.parse(result.result.content[0].text);
  assert.equal(value.events.length, MAX_AUDIT_TAIL_COUNT);
  assert.equal(JSON.stringify(value).includes("cwd"), false);
  assert.equal(JSON.stringify(value).includes("secret"), false);
  const invalid = await server.handle(rpc(7, "tools/call", { name: "agentpass_audit_tail", arguments: { count: MAX_AUDIT_TAIL_COUNT + 1 } }));
  assert.equal(invalid.error.code, -32602);
});

test("tool arguments are strict and signing payloads are not accepted", async () => {
  const server = await initializedServer();
  const extra = await server.handle(rpc(8, "tools/call", { name: "agentpass_status", arguments: { payload: "bytes" } }));
  assert.equal(extra.error.code, -32602);
  const unknown = await server.handle(rpc(9, "tools/call", { name: "agentpass_sign", arguments: { payload: "bytes" } }));
  assert.equal(unknown.error.code, -32602);
});

test("CLI runner disables shell and whitelists the inherited environment", async () => {
  let observed;
  const fakeSpawn = (executable, args, options) => {
    observed = { executable, args, options };
    const child = new EventEmitter();
    child.stdout = new PassThrough();
    child.stderr = new PassThrough();
    queueMicrotask(() => { child.stdout.end("{}"); child.stderr.end(); child.emit("close", 0, null); });
    return child;
  };
  const runner = createCliRunner({ spawnImpl: fakeSpawn, executable: "/usr/local/bin/node", agentpassPath: "/repo/bin/agentpass.mjs", environment: { HOME: "/home/test", PATH: "/bin", NODE_OPTIONS: "--inspect", AGENTPASS_SESSION: "safe_token" } });
  await runner(["status"]);
  assert.deepEqual(observed.args, ["/repo/bin/agentpass.mjs", "status"]);
  assert.equal(observed.options.shell, false);
  assert.deepEqual(observed.options.env, { HOME: "/home/test", PATH: "/usr/bin:/bin:/usr/sbin:/sbin", AGENTPASS_SESSION: "safe_token" });
  assert.equal(minimalEnvironment({ NODE_OPTIONS: "--inspect", SECRET: "x" }).SECRET, undefined);
});

test("supports MCP ping and honors a validated project working directory", async () => {
  const server = await initializedServer();
  assert.deepEqual((await server.handle(rpc(10, "ping", {}))).result, {});
  let observed;
  const fakeSpawn = (_executable, _args, options) => {
    observed = options;
    const child = new EventEmitter(); child.stdout = new PassThrough(); child.stderr = new PassThrough();
    queueMicrotask(() => { child.stdout.end("{}"); child.stderr.end(); child.emit("close", 0, null); });
    return child;
  };
  await createCliRunner({ spawnImpl: fakeSpawn, executable: "/usr/bin/node", agentpassPath: "/agentpass.mjs", environment: { HOME: "/home/test", AGENTPASS_PROJECT_DIR: "/work/project" } })(["status"]);
  assert.equal(observed.cwd, "/work/project");
  assert.equal(observed.env.AGENTPASS_PROJECT_DIR, "/work/project");
});

test("CLI runner terminates commands that exceed the deadline", async () => {
  let killed = false;
  const fakeSpawn = () => {
    const child = new EventEmitter();
    child.stdout = new PassThrough();
    child.stderr = new PassThrough();
    child.kill = () => { killed = true; };
    return child;
  };
  const runner = createCliRunner({ spawnImpl: fakeSpawn, executable: "/usr/bin/node", agentpassPath: "/agentpass.mjs", timeoutMs: 5 });
  await assert.rejects(runner(["status"]), /timed out/);
  assert.equal(killed, true);
});

const ORG = "00000000-0000-4000-8000-000000000001";
const APP = "00000000-0000-4000-8000-000000000002";
const RELEASE = "00000000-0000-4000-8000-000000000003";

function softwareSurfaceHarness() {
  const operations = [];
  const surface = {
    async authorize(input) { operations.push(["authorize", input]); return true; },
    async inspectApp(input) { operations.push(["inspect", input]); return { organization_id: ORG, app_id: APP, state: "active", name: "CRM", local_path: "/private/project", token: "never-return" }; },
    async preparePublish(input) {
      operations.push(["prepare", input]);
      return {
        organization_id: ORG, app_id: APP, state: "complete", idempotency_key: input.idempotency_key,
        publish_plan: { organization_id: ORG, app_id: APP, release_id: RELEASE, risk_classification: "low", artifact_digest: "a".repeat(64), source_bundle_digest: "b".repeat(64), build_receipt_digest: "c".repeat(64), approval_required: false },
        deployment_receipt: { organization_id: ORG, app_id: APP, release_id: RELEASE, state: "active", active_generation: 1, route: "https://apps.example.test/crm", provider_deployment_id: "provider-1" }
      };
    },
    async deploymentStatus(input) { operations.push(["deployment", input]); return { organization_id: ORG, app_id: APP, release_id: RELEASE, state: "active", active_generation: 1, provider_deployment_id: "provider-1", provider_secret: "hidden" }; },
    async listApps(input) { operations.push(["list", input]); return { organization_id: ORG, apps: [{ organization_id: ORG, app_id: APP, name: "CRM", state: "active", local_path: "/private/project" }] }; },
    async openApp(input) { operations.push(["open", input]); return { organization_id: ORG, app_id: APP, app_url: "https://apps.example.test/crm", console_url: "https://console.example.test/apps/2", bearer_token: "hidden" }; },
    async maintenanceStatus(input) { operations.push(["maintenance", input]); return { organization_id: ORG, app_id: APP, state: "idle", jobs: [{ organization_id: ORG, app_id: APP, state: "completed", private_path: "/private/project" }] }; }
  };
  return { surface, operations };
}

async function initializedSoftwareServer() {
  const harness = softwareSurfaceHarness();
  const server = createMcpServer({ commandRunner: async () => ({ code: 0, stdout: "{}", stderr: "" }), smallSoftwareSurface: harness.surface });
  await server.handle(rpc(20, "initialize", { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "test", version: "1" } }));
  await server.handle({ jsonrpc: "2.0", method: "notifications/initialized" });
  return { server, ...harness };
}

test("Small Software tools bind tenant and idempotency inputs, and redact provider/local data", async () => {
  const { server, operations } = await initializedSoftwareServer();
  const base = { organization_id: ORG, app_id: APP };
  const inspect = await server.handle(rpc(21, "tools/call", { name: "agentpass_app_inspect", arguments: base }));
  assert.deepEqual(JSON.parse(inspect.result.content[0].text), { organization_id: ORG, app_id: APP, state: "active", name: "CRM" });
  const prepared = await server.handle(rpc(22, "tools/call", { name: "agentpass_publish_prepare", arguments: { ...base, idempotency_key: "preview-001", source_bundle: { version: 1, kind: "agentpass.source-bundle" } } }));
  const preparedValue = JSON.parse(prepared.result.content[0].text);
  assert.equal(preparedValue.deployment_receipt.state, "active");
  assert.equal(preparedValue.deployment_receipt.route, "https://apps.example.test/crm");
  assert.equal(JSON.stringify(preparedValue).includes("provider-1"), true);
  assert.equal(JSON.stringify(preparedValue).includes("token"), false);
  const list = await server.handle(rpc(23, "tools/call", { name: "agentpass_apps_list", arguments: { organization_id: ORG } }));
  assert.equal(JSON.parse(list.result.content[0].text).apps[0].local_path, undefined);
  assert.equal(operations.filter(([kind]) => kind === "authorize").length, 3);
  assert.equal(operations.find(([kind]) => kind === "prepare")[1].idempotency_key, "preview-001");
});

test("Small Software tools reject cross-tenant results and unavailable surfaces", async () => {
  const { server } = await initializedSoftwareServer();
  const crossTenant = { organization_id: ORG, app_id: APP };
  const bad = createMcpServer({ commandRunner: async () => ({ code: 0, stdout: "{}", stderr: "" }), smallSoftwareSurface: { async inspectApp() { return { organization_id: "00000000-0000-4000-8000-000000000099", app_id: APP }; } } });
  await bad.handle(rpc(30, "initialize", { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "test", version: "1" } }));
  await bad.handle({ jsonrpc: "2.0", method: "notifications/initialized" });
  const denied = await bad.handle(rpc(31, "tools/call", { name: "agentpass_app_inspect", arguments: crossTenant }));
  assert.equal(denied.result.isError, true);
  assert.match(denied.result.content[0].text, /cross-tenant/u);
  const unavailableServer = createMcpServer({ commandRunner: async () => ({ code: 0, stdout: "{}", stderr: "" }) });
  await unavailableServer.handle(rpc(32, "initialize", { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "test", version: "1" } }));
  await unavailableServer.handle({ jsonrpc: "2.0", method: "notifications/initialized" });
  const unavailable = await unavailableServer.handle(rpc(33, "tools/call", { name: "agentpass_app_open", arguments: crossTenant }));
  assert.equal(unavailable.result.isError, true);
  assert.equal(unavailable.result.content[0].text, "Small Software surface is unavailable");
});

test("Small Software arguments are closed and bounded", async () => {
  const { server } = await initializedSoftwareServer();
  const extra = await server.handle(rpc(40, "tools/call", { name: "agentpass_apps_list", arguments: { organization_id: ORG, limit: 51 } }));
  assert.equal(extra.error.code, -32602);
  const noOrg = await server.handle(rpc(41, "tools/call", { name: "agentpass_app_inspect", arguments: { app_id: APP } }));
  assert.equal(noOrg.error.code, -32602);
  const secretBytes = await server.handle(rpc(42, "tools/call", { name: "agentpass_publish_prepare", arguments: { organization_id: ORG, app_id: APP, idempotency_key: "preview-002", source_bundle: { token: "secret" } } }));
  assert.equal(secretBytes.error.code, -32602);
});
