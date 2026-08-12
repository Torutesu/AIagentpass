import { spawn as nodeSpawn } from "node:child_process";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const DEFAULT_PATH = "/usr/bin:/bin:/usr/sbin:/sbin";
const MAX_OUTPUT_BYTES = 2 * 1024 * 1024;
const SESSION_PATTERN = /^[A-Za-z0-9_-]{1,256}$/;

export const cliPath = fileURLToPath(new URL("../../../bin/agentpass.mjs", import.meta.url));

export class CliRunnerError extends Error {
  constructor(message, code = "cli_failed") {
    super(message);
    this.name = "CliRunnerError";
    this.code = code;
  }
}

/**
 * Keep the child environment deliberately small. In particular, NODE_OPTIONS,
 * arbitrary user variables, and shell configuration are never inherited.
 * AGENTPASS_SESSION is passed only so `check` can evaluate the current local
 * session; it is never included in an MCP response.
 */
export function minimalEnvironment(source = process.env) {
  const env = {
    HOME: typeof source.HOME === "string" && source.HOME ? source.HOME : os.homedir(),
    PATH: DEFAULT_PATH
  };
  for (const key of ["LANG", "LC_ALL", "AGENTPASS_AGENT_ID"]) {
    if (typeof source[key] === "string" && source[key].length <= 256) env[key] = source[key];
  }
  if (typeof source.AGENTPASS_PROJECT_DIR === "string" && path.isAbsolute(source.AGENTPASS_PROJECT_DIR) && source.AGENTPASS_PROJECT_DIR.length <= 4096) env.AGENTPASS_PROJECT_DIR = source.AGENTPASS_PROJECT_DIR;
  if (typeof source.AGENTPASS_SESSION === "string" && SESSION_PATTERN.test(source.AGENTPASS_SESSION)) {
    env.AGENTPASS_SESSION = source.AGENTPASS_SESSION;
  }
  return env;
}

export function createCliRunner({
  spawnImpl = nodeSpawn,
  executable = process.execPath,
  agentpassPath = cliPath,
  environment = process.env,
  cwd = undefined,
  maxOutputBytes = MAX_OUTPUT_BYTES,
  timeoutMs = 10_000
} = {}) {
  if (typeof spawnImpl !== "function") throw new TypeError("spawnImpl must be a function");
  if (!path.isAbsolute(executable) || !path.isAbsolute(agentpassPath)) throw new TypeError("CLI paths must be absolute");
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 120_000) throw new TypeError("CLI timeout is invalid");
  if (!Number.isSafeInteger(maxOutputBytes) || maxOutputBytes < 1024 || maxOutputBytes > 16 * 1024 * 1024) throw new TypeError("CLI output limit is invalid");
  const projectCwd = cwd ?? environment.AGENTPASS_PROJECT_DIR ?? process.cwd();
  if (!path.isAbsolute(projectCwd)) throw new TypeError("CLI working directory must be absolute");

  return (args) => new Promise((resolve, reject) => {
    if (!Array.isArray(args) || args.some((arg) => typeof arg !== "string")) {
      reject(new CliRunnerError("Invalid CLI arguments", "invalid_arguments"));
      return;
    }
    let child;
    try {
      child = spawnImpl(executable, [agentpassPath, ...args], {
        cwd: projectCwd,
        env: minimalEnvironment(environment),
        shell: false,
        windowsHide: true,
        stdio: ["ignore", "pipe", "pipe"]
      });
    } catch (error) {
      reject(new CliRunnerError("Unable to start AgentPass", "spawn_failed"));
      return;
    }

    let stdout = "";
    let stderr = "";
    let outputBytes = 0;
    let settled = false;
    const timer = setTimeout(() => {
      try { child.kill("SIGKILL"); } catch {}
      fail(new CliRunnerError("AgentPass command timed out", "timeout"));
    }, timeoutMs);
    const fail = (error) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      reject(error);
    };
    const append = (target, chunk) => {
      const text = Buffer.isBuffer(chunk) ? chunk.toString("utf8") : String(chunk);
      outputBytes += Buffer.byteLength(text);
      if (outputBytes > maxOutputBytes) {
        try { child.kill(); } catch {}
        fail(new CliRunnerError("AgentPass output exceeded the limit", "output_too_large"));
        return target;
      }
      return target + text;
    };

    child.stdout?.on("data", (chunk) => { stdout = append(stdout, chunk); });
    child.stderr?.on("data", (chunk) => { stderr = append(stderr, chunk); });
    child.once("error", () => fail(new CliRunnerError("Unable to run AgentPass", "spawn_failed")));
    child.once("close", (code, signal) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve({ stdout, stderr, code: Number.isInteger(code) ? code : null, signal: signal ?? null });
    });
  });
}
