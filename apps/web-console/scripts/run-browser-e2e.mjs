import { spawn } from "node:child_process";
import fs from "node:fs";
import net from "node:net";
import path from "node:path";
import process from "node:process";

const portValue = Number.parseInt(process.env.PLAYWRIGHT_PORT ?? "4173", 10);
const port = Number.isInteger(portValue) && portValue >= 1024 && portValue <= 65_535 ? portValue : 4173;
const expectedTests = Number.parseInt(process.env.AGENTPASS_EXPECTED_BROWSER_E2E_TESTS ?? "54", 10);
const resultPath = process.env.AGENTPASS_BROWSER_E2E_RESULT_PATH;
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

async function probeLoopback() {
  return await new Promise((resolve) => {
    const server = net.createServer();
    server.once("error", (error) => resolve({ ok: false, reason: classifyError(error), error: String(error.message ?? error) }));
    server.listen({ host: "127.0.0.1", port }, () => {
      server.close(() => resolve({ ok: true }));
    });
  });
}

const probe = await probeLoopback();
if (!probe.ok) {
  emitResult({ schema_version: 1, kind: "agentpass-browser-e2e-result", phase: "startup", status: "not_run", qualified: false, reason: probe.reason, detail: probe.error, executed: 0, expected: expectedTests });
  process.exitCode = 2;
} else {
  const env = { ...process.env };
  delete env.NODE_OPTIONS;
  delete env.NODE_DEBUG;
  const child = spawn(process.execPath, ["node_modules/@playwright/test/cli.js", "test", "--reporter=json"], {
    cwd: process.cwd(), env, stdio: ["ignore", "pipe", "pipe"],
  });
  let stdout = "";
  let stderr = "";
  child.stdout.on("data", (chunk) => { stdout += chunk; process.stdout.write(chunk); });
  child.stderr.on("data", (chunk) => { stderr += chunk; process.stderr.write(chunk); });
  const exitCode = await new Promise((resolve) => child.once("close", resolve));
  let report;
  try { report = JSON.parse(stdout); } catch { report = undefined; }
  const results = [];
  for (const suite of report?.suites ?? []) for (const spec of suite.specs ?? []) for (const test of spec.tests ?? []) for (const result of test.results ?? []) results.push(result.status);
  const executed = results.filter((status) => status !== "skipped" && status !== "interrupted").length;
  const reason = exitCode === 0 && executed > 0 ? null : (classifyError({ message: stderr }, "e2e_failed"));
  const complete = executed === expectedTests;
  const passed = exitCode === 0 && complete && executed > 0;
  emitResult({ schema_version: 1, kind: "agentpass-browser-e2e-result", phase: "tests", status: passed ? "passed" : "failed", qualified: passed, reason: passed ? null : (complete ? reason : "incomplete_execution"), executed, expected: expectedTests, exit_code: exitCode });
  if (!passed) process.exitCode = exitCode || 2;
}
