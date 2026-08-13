#!/usr/bin/env node

import fs from "node:fs";
import fsp from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { spawn } from "node:child_process";

import { startFixture, stopFixture } from "./postgres-tls/fixture.mjs";

const SCRIPT_DIRECTORY = path.dirname(fileURLToPath(import.meta.url));
const REPOSITORY_ROOT = path.resolve(SCRIPT_DIRECTORY, "../..");
const CONSOLE_ROOT = path.join(REPOSITORY_ROOT, "apps/web-console");
const LIVE_TEST = path.join(REPOSITORY_ROOT, "test/p0b-live-process.integration.test.mjs");
const LIVE_BROWSER_TEST = path.join(REPOSITORY_ROOT, "test/p0b-live-browser.integration.test.mjs");
const DEFAULT_FIXTURE_TIMEOUT_MS = 45_000;
const MAX_ENV_FILE_BYTES = 16 * 1024;
const MAX_CHILD_OUTPUT_BYTES = 256 * 1024;
const REQUIRED_ENV_KEYS = Object.freeze([
  "P0B_POSTGRES_ADMIN_URL",
  "AGENTPASS_TEST_POSTGRES_ADMIN_URL",
  "P0B_POSTGRES_CA_FILE",
  "PGSSLROOTCERT",
  "P0B_POSTGRES_TLS_STATE_FILE",
  "P0B_POSTGRES_TLS_IMAGE",
  "P0B_POSTGRES_TLS_CONTAINER_ID"
]);
const ENV_KEY = /^[A-Z][A-Z0-9_]*$/u;
const CONTAINER_ID = /^[a-f0-9]{12,64}$/u;

export class OrchestrationError extends Error {
  constructor(code, message = code) {
    super(message);
    this.name = "OrchestrationError";
    this.code = code;
  }
}

export function parseArgs(argv) {
  const options = { fixtureTimeoutMs: DEFAULT_FIXTURE_TIMEOUT_MS };
  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];
    if (argument === "--help" || argument === "-h") return Object.freeze({ help: true });
    if (argument === "--fixture-timeout-ms") {
      const value = Number(argv[++index]);
      if (!Number.isSafeInteger(value) || value < 1) {
        throw new OrchestrationError("invalid_argument", "fixture timeout must be a positive integer");
      }
      options.fixtureTimeoutMs = value;
      continue;
    }
    if (argument === "--fixture-image") {
      const value = argv[++index];
      if (typeof value !== "string" || value.length === 0 || value.length > 256) {
        throw new OrchestrationError("invalid_argument", "fixture image is invalid");
      }
      options.fixtureImage = value;
      continue;
    }
    throw new OrchestrationError("invalid_argument", "unknown option");
  }
  return Object.freeze(options);
}

export async function readProtectedEnvironment(file) {
  if (typeof file !== "string" || !path.isAbsolute(file)) {
    throw new OrchestrationError("invalid_env_file", "fixture env file must be absolute");
  }
  let handle;
  try {
    handle = await fsp.open(file, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW ?? 0));
    const metadata = await handle.stat();
    if (!metadata.isFile() || (metadata.mode & 0o077) !== 0 || metadata.size > MAX_ENV_FILE_BYTES) {
      throw new Error("invalid protected env metadata");
    }
    const contents = await handle.readFile("utf8");
    return parseProtectedEnvironment(contents);
  } catch (error) {
    if (error instanceof OrchestrationError) throw error;
    throw new OrchestrationError("invalid_env_file", "fixture env file is unreadable");
  } finally {
    await handle?.close().catch(() => {});
  }
}

export function parseProtectedEnvironment(contents) {
  if (typeof contents !== "string" || contents.length > MAX_ENV_FILE_BYTES || contents.includes("\u0000")) {
    throw new OrchestrationError("invalid_env_file", "fixture env file is invalid");
  }
  const values = Object.create(null);
  const lines = contents.split("\n");
  if (lines.at(-1) === "") lines.pop();
  for (const line of lines) {
    if (line.length === 0 || line.includes("\r")) {
      throw new OrchestrationError("invalid_env_file", "fixture env file is invalid");
    }
    const separator = line.indexOf("=");
    if (separator <= 0) throw new OrchestrationError("invalid_env_file", "fixture env file is invalid");
    const key = line.slice(0, separator);
    const value = line.slice(separator + 1);
    if (!ENV_KEY.test(key) || Object.hasOwn(values, key) || value.includes("\n") || value.includes("\r")) {
      throw new OrchestrationError("invalid_env_file", "fixture env file is invalid");
    }
    values[key] = value;
  }
  for (const key of REQUIRED_ENV_KEYS) {
    if (typeof values[key] !== "string" || values[key].length === 0) {
      throw new OrchestrationError("invalid_env_file", "fixture env file is incomplete");
    }
  }
  const allowed = new Set(REQUIRED_ENV_KEYS);
  if (Object.keys(values).some((key) => !allowed.has(key))) {
    throw new OrchestrationError("invalid_env_file", "fixture env file contains an unsupported key");
  }
  if (![values.P0B_POSTGRES_CA_FILE, values.PGSSLROOTCERT, values.P0B_POSTGRES_TLS_STATE_FILE]
    .every((value) => path.isAbsolute(value))) {
    throw new OrchestrationError("invalid_env_file", "fixture env paths must be absolute");
  }
  if (!CONTAINER_ID.test(values.P0B_POSTGRES_TLS_CONTAINER_ID)) {
    throw new OrchestrationError("invalid_env_file", "fixture container id is invalid");
  }
  validatePostgresUrl(values.P0B_POSTGRES_ADMIN_URL);
  validatePostgresUrl(values.AGENTPASS_TEST_POSTGRES_ADMIN_URL);
  return Object.freeze({ ...values });
}

export function buildTestEnvironment(base, fixtureEnvironment) {
  if (!base || typeof base !== "object") throw new TypeError("base environment is required");
  return Object.freeze({
    ...base,
    ...fixtureEnvironment,
    // A caller's stale disable flag must not turn this live qualification into
    // a successful-looking skipped test.
    P0B_DISABLE_EXTERNAL: "false"
  });
}

export function stableReason(error) {
  const code = typeof error?.code === "string" ? error.code : "error";
  return /^[a-z][a-z0-9_]*$/u.test(code) ? code : "error";
}

export function usage() {
  return `Usage: node scripts/p0b/run-live-process.mjs [options]

Starts the existing PostgreSQL TLS fixture, runs the live Console/Cloud/
PostgreSQL process qualification, and always stops the fixture.

Options:
  --fixture-timeout-ms <integer>  PostgreSQL fixture readiness timeout
  --fixture-image <image>        PostgreSQL 17 image override
  --help                         Show this help
`;
}

export async function main(argv = process.argv.slice(2)) {
  let options;
  try {
    options = parseArgs(argv);
  } catch (error) {
    emitFailure("arguments", error);
    return 1;
  }
  if (options.help) {
    process.stdout.write(usage());
    return 0;
  }

  const orchestrationRoot = await fsp.mkdtemp(path.join(os.tmpdir(), "agentpass-p0b-run-"));
  const manifestFile = path.join(orchestrationRoot, "fixture.manifest.json");
  let manifest;
  let failure;
  let interrupted = false;
  let activeChild;
  const onSignal = (signal) => {
    interrupted = true;
    if (activeChild && !activeChild.killed) activeChild.kill("SIGTERM");
    // Keep the handler installed until the finally block so the fixture is
    // stopped before the process returns control to the shell.
    void signal;
  };
  process.once("SIGINT", onSignal);
  process.once("SIGTERM", onSignal);

  try {
    try {
      manifest = await startFixture({
        outputFile: manifestFile,
        timeoutMs: options.fixtureTimeoutMs,
        ...(options.fixtureImage ? { image: options.fixtureImage } : {})
      });
      if (interrupted) throw new OrchestrationError("interrupted");
    } catch (error) {
      failure = { stage: "fixture-start", error };
    }

    let fixtureEnvironment;
    if (!failure) {
      try {
        const publicManifest = await readManifest(manifestFile, manifest);
        fixtureEnvironment = await readProtectedEnvironment(publicManifest.env_file);
        if (fixtureEnvironment.P0B_POSTGRES_TLS_STATE_FILE !== publicManifest.state_file
          || fixtureEnvironment.P0B_POSTGRES_CA_FILE !== publicManifest.ca_file) {
          throw new OrchestrationError("fixture_manifest_mismatch");
        }
      } catch (error) {
        failure = { stage: "fixture-env", error };
      }
    }

    if (!failure) {
      const result = await runChild(process.env.npm_execpath ? process.execPath : "npm",
        process.env.npm_execpath ? [process.env.npm_execpath, "run", "build"] : ["run", "build"],
        { cwd: CONSOLE_ROOT, env: process.env, setActive: (child) => { activeChild = child; } });
      activeChild = undefined;
      if (result.spawnError || result.code !== 0 || result.signal) {
        failure = { stage: "console-build", error: new OrchestrationError(result.reason) };
      }
    }

    if (!failure) {
      try {
        if (interrupted) throw new OrchestrationError("interrupted");
        const result = await runChild(process.execPath,
          ["--test", "--test-reporter", "tap", path.relative(REPOSITORY_ROOT, LIVE_BROWSER_TEST)],
          {
            cwd: REPOSITORY_ROOT,
            env: { ...buildTestEnvironment(process.env, fixtureEnvironment), P0B_LIVE_BROWSER: "1" },
            setActive: (child) => { activeChild = child; }
          });
        activeChild = undefined;
        if (result.spawnError || result.signal || result.code !== 0) {
          failure = { stage: "live-browser", error: new OrchestrationError(result.reason) };
        } else if (result.output.includes("# SKIP")) {
          failure = { stage: "live-browser", error: new OrchestrationError("test_skipped") };
        } else if (interrupted) {
          failure = { stage: "live-browser", error: new OrchestrationError("interrupted") };
        }
      } catch (error) {
        failure = { stage: "live-browser", error };
      }
    }

    if (!failure) {
      try {
        if (interrupted) throw new OrchestrationError("interrupted");
        const result = await runChild(process.execPath,
          ["--test", "--test-reporter", "tap", "test/p0b-live-process.integration.test.mjs"],
          {
            cwd: REPOSITORY_ROOT,
            env: buildTestEnvironment(process.env, fixtureEnvironment),
            setActive: (child) => { activeChild = child; }
          });
        activeChild = undefined;
        if (result.spawnError || result.signal || result.code !== 0) {
          failure = { stage: "live-test", error: new OrchestrationError(result.reason) };
        } else if (result.output.includes("# SKIP")) {
          failure = { stage: "live-test", error: new OrchestrationError("test_skipped") };
        } else if (interrupted) {
          failure = { stage: "live-test", error: new OrchestrationError("interrupted") };
        }
      } catch (error) {
        failure = { stage: "live-test", error };
      }
    }
  } catch (error) {
    failure ??= { stage: "orchestration", error };
  } finally {
    process.removeListener("SIGINT", onSignal);
    process.removeListener("SIGTERM", onSignal);
    let cleanupFailure;
    if (manifest?.state_file) {
      try {
        await stopFixture(manifest.state_file);
      } catch (error) {
        cleanupFailure = error;
      }
    }
    await fsp.rm(orchestrationRoot, { recursive: true, force: true }).catch(() => {});
    if (cleanupFailure && !failure) failure = { stage: "fixture-stop", error: cleanupFailure };
    if (cleanupFailure && failure) failure.cleanup = true;
  }

  if (failure) {
    emitFailure(failure.stage, failure.error, failure.cleanup);
    return 1;
  }
  process.stdout.write("p0b-orchestration: pass\n");
  return 0;
}

async function readManifest(file, fallback) {
  let parsed;
  try {
    parsed = JSON.parse(await fsp.readFile(file, "utf8"));
  } catch {
    throw new OrchestrationError("invalid_manifest");
  }
  const value = parsed && typeof parsed === "object" ? parsed : fallback;
  if (!value || typeof value.env_file !== "string" || typeof value.state_file !== "string"
    || typeof value.ca_file !== "string" || !path.isAbsolute(value.env_file)
    || !path.isAbsolute(value.state_file) || !path.isAbsolute(value.ca_file)) {
    throw new OrchestrationError("invalid_manifest");
  }
  return value;
}

function validatePostgresUrl(value) {
  let url;
  try {
    url = new URL(value);
  } catch {
    throw new OrchestrationError("invalid_env_file");
  }
  if (url.protocol !== "postgresql:" || !url.hostname || !url.username || !url.password
    || url.searchParams.get("sslmode") !== "verify-full" || [...url.searchParams.keys()].length !== 1) {
    throw new OrchestrationError("invalid_env_file");
  }
}

function runChild(command, args, { cwd, env, setActive }) {
  return new Promise((resolve) => {
    let output = "";
    let child;
    try {
      child = spawn(command, args, { cwd, env, shell: false, stdio: ["ignore", "pipe", "pipe"] });
    } catch {
      resolve({ spawnError: true, reason: "child_spawn_failed", output });
      return;
    }
    setActive(child);
    const capture = (chunk) => {
      if (output.length < MAX_CHILD_OUTPUT_BYTES) output += String(chunk).slice(0, MAX_CHILD_OUTPUT_BYTES - output.length);
    };
    child.stdout?.on("data", capture);
    child.stderr?.on("data", capture);
    child.once("error", () => resolve({ spawnError: true, reason: "child_spawn_failed", output }));
    child.once("close", (code, signal) => resolve({
      code,
      signal,
      reason: signal ? `child_signal_${String(signal).toLowerCase()}` : `child_exit_${code ?? "unknown"}`,
      output
    }));
  });
}

function emitFailure(stage, error, cleanup = false) {
  const reason = stableReason(error);
  process.stderr.write(`p0b-orchestration: fail stage=${stage} reason=${reason}${cleanup ? " cleanup=failed" : ""}\n`);
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().then((code) => { process.exitCode = code; }).catch(() => {
    emitFailure("orchestration", new OrchestrationError("error"));
    process.exitCode = 1;
  });
}
