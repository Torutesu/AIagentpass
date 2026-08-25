import { spawn } from "node:child_process";
import fs from "node:fs";
import http from "node:http";
import path from "node:path";
import process from "node:process";

const portValue = Number.parseInt(process.env.PLAYWRIGHT_PORT ?? "4173", 10);
const port = Number.isInteger(portValue) && portValue >= 1024 && portValue <= 65_535 ? portValue : 4173;
// This is a deliberately frozen qualification count. A test addition or
// removal must update the protected CI inputs and the evidence contract in
// the same change; silently deriving it at runtime would allow an empty or
// reduced suite to qualify.
const expectedTests = Number.parseInt(process.env.AGENTPASS_EXPECTED_BROWSER_E2E_TESTS ?? "83", 10);
const resultPath = process.env.AGENTPASS_BROWSER_E2E_RESULT_PATH;
const startupTimeoutMs = Number.parseInt(process.env.PLAYWRIGHT_STARTUP_TIMEOUT_MS ?? "60000", 10);
const cloudPortValue = Number.parseInt(process.env.PLAYWRIGHT_CLOUD_API_PORT ?? "4310", 10);
const cloudPort = Number.isInteger(cloudPortValue) && cloudPortValue >= 1024 && cloudPortValue <= 65_535 ? cloudPortValue : 4_310;
const cloudUrl = `http://127.0.0.1:${cloudPort}/`;
const organizationId = "11111111-1111-4111-8111-111111111111";
const cursorSecret = "A".repeat(43);
const output = (value) => process.stdout.write(`${JSON.stringify(value)}\n`);
const emitResult = (value) => {
  output(value);
  if (resultPath) {
    fs.mkdirSync(path.dirname(resultPath), { recursive: true, mode: 0o700 });
    fs.writeFileSync(resultPath, `${JSON.stringify(value)}\n`, { encoding: "utf8", mode: 0o600, flag: "wx" });
  }
};

function classifyError(error, fallback = "loopback_unavailable") {
  const text = `${error?.code ?? ""} ${error?.message ?? ""}`.toLowerCase();
  if (text.includes("eaddrinuse") || text.includes("address already in use")) return "port_collision";
  if (text.includes("eperm") || text.includes("eacces") || text.includes("operation not permitted") || text.includes("permission denied")) return "sandbox_eperm";
  return fallback;
}

const detachedProcessGroup = process.platform !== "win32";

function requestReady() {
  return new Promise((resolve) => {
    const request = http.get(`http://127.0.0.1:${port}/`, (response) => {
      response.resume();
      response.once("end", () => resolve(true));
    });
    request.once("error", () => resolve(false));
    request.setTimeout(500, () => {
      request.destroy();
      resolve(false);
    });
  });
}

function collectResults(suite, results) {
  for (const spec of suite?.specs ?? []) {
    for (const test of spec.tests ?? []) {
      for (const result of test.results ?? []) results.push(result.status);
    }
  }
  for (const child of suite?.suites ?? []) collectResults(child, results);
}

async function stop(child) {
  if (!child || child.exitCode !== null || child.signalCode !== null) return;
  const signalChild = (signal) => {
    if (detachedProcessGroup && child.pid) {
      try {
        process.kill(-child.pid, signal);
        return;
      } catch (error) {
        if (error?.code !== "ESRCH") throw error;
      }
    }
    child.kill(signal);
  };
  signalChild("SIGTERM");
  await new Promise((resolve) => {
    const timer = setTimeout(() => {
      if (child.exitCode === null && child.signalCode === null) signalChild("SIGKILL");
      resolve();
    }, 5_000);
    timer.unref?.();
    child.once("close", () => {
      clearTimeout(timer);
      resolve();
    });
  });
}

function serverEnvironment() {
  const env = { ...process.env };
  delete env.NODE_OPTIONS;
  delete env.NODE_DEBUG;
  return {
    ...env,
    NODE_ENV: "test",
    AGENTPASS_BROWSER_E2E_MANAGED_SERVER: "true",
    AGENTPASS_CLOUD_API_URL: cloudUrl,
    AGENTPASS_ALLOW_INSECURE_LOOPBACK_CLOUD_API: "true",
    AGENTPASS_ORGANIZATION_ID: organizationId,
    AGENTPASS_CONSOLE_CURSOR_SECRET: cursorSecret,
  };
}

const server = spawn(process.platform === "win32" ? "npm.cmd" : "npm", ["run", "dev", "--", "--hostname", "127.0.0.1", "--port", String(port)], {
  cwd: process.cwd(),
  env: serverEnvironment(),
  stdio: ["ignore", "ignore", "pipe"],
  shell: false,
  detached: detachedProcessGroup,
});
let serverStderr = "";
let serverSpawnError;
server.once("error", (error) => { serverSpawnError = error; });
server.stderr.on("data", (chunk) => {
  if (serverStderr.length < 8_192) serverStderr += chunk.toString();
});

let ready = false;
const deadline = Date.now() + (Number.isInteger(startupTimeoutMs) && startupTimeoutMs >= 1_000 && startupTimeoutMs <= 180_000 ? startupTimeoutMs : 60_000);
while (!ready && !serverSpawnError && Date.now() < deadline && server.exitCode === null && server.signalCode === null) {
  ready = await requestReady();
  if (!ready) await new Promise((resolve) => setTimeout(resolve, 100));
}

if (!ready) {
  const reason = classifyError(serverSpawnError ?? { message: serverStderr }, server.exitCode === null && !serverSpawnError ? "loopback_unavailable" : "server_start_failed");
  await stop(server);
  emitResult({ schema_version: 1, kind: "agentpass-browser-e2e-result", phase: "startup", status: "not_run", qualified: false, reason, executed: 0, expected: expectedTests });
  process.exitCode = 2;
} else {
  const env = serverEnvironment();
  env.AGENTPASS_BROWSER_E2E_MANAGED_SERVER = "true";
  env.PLAYWRIGHT_PORT = String(port);
  const child = spawn(process.execPath, ["node_modules/@playwright/test/cli.js", "test", "--reporter=json"], {
    cwd: process.cwd(), env, stdio: ["ignore", "pipe", "pipe"], shell: false,
  });
  let stdout = "";
  let stderr = "";
  let childSpawnError;
  child.once("error", (error) => { childSpawnError = error; });
  child.stdout.on("data", (chunk) => { stdout += chunk; process.stdout.write(chunk); });
  child.stderr.on("data", (chunk) => { stderr += chunk; process.stderr.write(chunk); });
  const exitCode = await new Promise((resolve) => child.once("close", resolve));
  let report;
  try { report = JSON.parse(stdout); } catch { report = undefined; }
  const results = [];
  for (const suite of report?.suites ?? []) collectResults(suite, results);
  const executedResults = results.filter((status) => status !== "skipped" && status !== "interrupted");
  const executed = executedResults.length;
  const complete = executed === expectedTests;
  const exit = Number.isInteger(exitCode) ? exitCode : 2;
  const reason = exit === 0 && complete && executedResults.every((status) => status === "passed") ? null : (complete ? classifyError(childSpawnError ?? { message: stderr }, "e2e_failed") : (childSpawnError ? classifyError(childSpawnError, "browser_unavailable") : "incomplete_execution"));
  const passed = exit === 0 && complete && executed > 0 && executedResults.every((status) => status === "passed");
  await stop(server);
  emitResult({ schema_version: 1, kind: "agentpass-browser-e2e-result", phase: "tests", status: passed ? "passed" : "failed", qualified: passed, reason: passed ? null : reason, executed, expected: expectedTests, exit_code: exit });
  if (!passed) process.exitCode = exit;
}
