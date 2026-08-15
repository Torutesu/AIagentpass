#!/usr/bin/env node

import fs from "node:fs";
import fsp from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { chromium } from "../../apps/web-console/node_modules/@playwright/test/index.mjs";
import { collectFixtureProvenance, startFixture, stopFixture } from "./postgres-tls/fixture.mjs";
import { runQualificationCommand } from "./qualification/command.mjs";
import {
  buildP0BQualificationReport,
  digestArtifactTree,
  resolveSourceState,
  writeP0BQualificationReport
} from "./qualification/report.mjs";
import { collectBrowserMetadata, evidenceDigest } from "./qualification/runtime-evidence.mjs";

const SCRIPT_DIRECTORY = path.dirname(fileURLToPath(import.meta.url));
const REPOSITORY_ROOT = path.resolve(SCRIPT_DIRECTORY, "../..");
const CONSOLE_ROOT = path.join(REPOSITORY_ROOT, "apps/web-console");
const LIVE_TEST = path.join(REPOSITORY_ROOT, "test/p0b-live-process.integration.test.mjs");
const LIVE_BROWSER_TEST = path.join(REPOSITORY_ROOT, "test/p0b-live-browser.integration.test.mjs");
const DEFAULT_FIXTURE_TIMEOUT_MS = 45_000;
const MAX_ENV_FILE_BYTES = 16 * 1024;
const DEFAULT_REPORT_OUTPUT = path.join(REPOSITORY_ROOT, ".agentpass", "qualification", "p0b.json");
const BUILD_TIMEOUT_MS = 180_000;
// The live browser matrix intentionally provisions an isolated PostgreSQL,
// Cloud, and Console stack per authority scenario. Keep the outer supervisor
// above the complete matrix budget; each scenario retains its own tighter
// deadline so a single stuck interaction still fails locally.
const BROWSER_TIMEOUT_MS = 900_000;
const PROCESS_TIMEOUT_MS = 180_000;
// Only these static TAP fragments may cross the child-output boundary. The
// command runner retains the fixed code, never the matched line or adjacent
// diagnostics, so assertions, URLs, credentials, SQL, and tenant data remain
// unavailable to the orchestrator and CI log.
const LIVE_BROWSER_SAFE_FAILURE_MARKERS = Object.freeze([
  [null, "P0B_SAFE_STATE_MISSING_SYNCED", "device_state_synced"],
  [null, "P0B_SAFE_STATE_MISSING_PENDING", "device_state_pending"],
  [null, "P0B_SAFE_STATE_MISSING_BLOCKED", "device_state_blocked"],
  [null, "P0B_SAFE_STATE_MISSING_STALE", "device_state_stale"],
  [null, "P0B_SAFE_STATE_MISSING_OFFLINE", "device_state_offline"],
  [null, "P0B_SAFE_STATE_MISSING_REVOKED", "device_state_revoked"],
  [null, "P0B_SAFE_KEYBOARD_FOCUS_FAILED", "keyboard_wake_focus"],
  [null, "P0B_SAFE_KEYBOARD_PRESS_FAILED", "keyboard_wake_press"],
  [null, "P0B_SAFE_KEYBOARD_OUTCOME_FAILED", "keyboard_wake_outcome"],
  [null, "P0B_SAFE_WAKE_ACCEPTED_FAILED", "wake_ledger_accepted"],
  [null, "P0B_SAFE_WAKE_COALESCED_FAILED", "wake_ledger_coalesced"],
  [null, "P0B_SAFE_WAKE_NO_PENDING_FAILED", "wake_ledger_no_pending"],
  [null, "P0B_SAFE_ADMIN_OPEN_CONTEXT_FAILED", "admin_open_context"],
  [null, "P0B_SAFE_ADMIN_OPEN_AUTHENTICATOR_FAILED", "admin_open_authenticator"],
  [null, "P0B_SAFE_ADMIN_OPEN_BOOTSTRAP_TRANSPORT_FAILED", "admin_open_bootstrap_transport"],
  [null, "P0B_SAFE_ADMIN_OPEN_BOOTSTRAP_HTTP_FAILED", "admin_open_bootstrap_http"],
  [null, "P0B_SAFE_ADMIN_OPEN_BOOTSTRAP_CONTRACT_FAILED", "admin_open_bootstrap_contract"],
  [null, "P0B_SAFE_ADMIN_OPEN_REGISTRATION_FAILED", "admin_open_registration"],
  [null, "P0B_SAFE_ADMIN_OPEN_RELOAD_FAILED", "admin_open_reload"],
  [null, "P0B_SAFE_ADMIN_OPEN_READINESS_FAILED", "admin_open_readiness"],
  [null, "P0B_SAFE_ADMIN_WAKE_CLICK_FAILED", "admin_wake_click"],
  [null, "P0B_SAFE_ADMIN_WAKE_OUTCOME_FAILED", "admin_wake_outcome"],
  [5, "auditor receives no wake mutation control", "auditor_wake_denial"],
  [6, "viewer receives no wake mutation control", "viewer_wake_denial"],
  [7, "owner without an available authenticator fails before wake mutation", "missing_authenticator_denial"],
  [8, "owner stale authorization is rejected by the real Cloud boundary", "stale_authorization_denial"],
  [9, "owner replayed authorization is rejected by the real Cloud boundary", "replayed_authorization_denial"],
  [10, "owner cross_operation authorization is rejected by the real Cloud boundary", "cross_operation_denial"],
  [11, "owner cross_tenant authorization is rejected by the real Cloud boundary", "cross_tenant_denial"],
  [12, "owner completes distinct real WebAuthn device revoke", "owner_device_revoke"],
  [13, "admin completes distinct real WebAuthn device revoke", "admin_device_revoke"]
].map(([index, name, code]) => Object.freeze({ marker: index === null ? name : `not ok ${index} - ${name}`, code })));
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
    if (argument === "--report-output") {
      const value = argv[++index];
      if (!isSafeAbsolutePath(value)) throw new OrchestrationError("invalid_argument", "report output must be an absolute path");
      options.reportOutput = value;
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
    ...qualificationBaseEnvironment(base),
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
  --report-output <absolute>     qualification report output path
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

  let sourceBefore;
  let reportOutput;
  try {
    reportOutput = resolveQualificationOutput(options.reportOutput, process.env.P0B_QUALIFICATION_OUTPUT);
    await prepareQualificationOutput(reportOutput);
    sourceBefore = resolveSourceState(REPOSITORY_ROOT);
  } catch (error) {
    emitFailure("source", error);
    return 1;
  }

  const startedAt = new Date().toISOString();
  const orchestrationRoot = await fsp.mkdtemp(path.join(os.tmpdir(), "agentpass-p0b-run-"));
  const manifestFile = path.join(orchestrationRoot, "fixture.manifest.json");
  let manifest;
  let failure;
  let interrupted = false;
  let activeChild;
  let publicManifest;
  let fixtureEnvironment;
  let postgresEvidence;
  let browserEvidence;
  let consoleArtifact;
  const commands = [];
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

    if (!failure) {
      try {
        publicManifest = await readManifest(manifestFile, manifest);
        fixtureEnvironment = await readProtectedEnvironment(publicManifest.env_file);
        if (fixtureEnvironment.P0B_POSTGRES_TLS_STATE_FILE !== publicManifest.state_file
          || fixtureEnvironment.P0B_POSTGRES_CA_FILE !== publicManifest.ca_file
          || fixtureEnvironment.P0B_POSTGRES_TLS_IMAGE !== publicManifest.image
          || fixtureEnvironment.P0B_POSTGRES_TLS_CONTAINER_ID !== publicManifest.container_id) {
          throw new OrchestrationError("fixture_manifest_mismatch");
        }
      } catch (error) {
        failure = { stage: "fixture-env", error };
      }
    }

    if (!failure) {
      try {
        postgresEvidence = await collectFixtureProvenance({
          manifest: publicManifest,
          adminUrl: fixtureEnvironment.P0B_POSTGRES_ADMIN_URL,
          caFile: fixtureEnvironment.P0B_POSTGRES_CA_FILE
        });
      } catch (error) {
        failure = { stage: "postgres-provenance", error };
      }
    }

    if (!failure) {
      const result = await runQualificationCommand("npm", ["run", "build"], {
        cwd: CONSOLE_ROOT,
        env: qualificationBaseEnvironment(process.env),
        timeoutMs: BUILD_TIMEOUT_MS,
        onChild: (child) => { activeChild = child; }
      });
      commands.push(commandEvidence("console-build", ["npm", "run", "build"], "apps/web-console", result));
      activeChild = undefined;
      if (result.status !== "passed") {
        failure = { stage: "console-build", error: new OrchestrationError(result.reason) };
      }
    }

    if (!failure) {
      try {
        consoleArtifact = await digestArtifactTree(path.join(CONSOLE_ROOT, "dist"), { name: "console-dist", kind: "build" });
        browserEvidence = await collectBrowserMetadata({ chromium });
      } catch (error) {
        failure = { stage: "build-provenance", error };
      }
    }

    if (!failure) {
      try {
        if (interrupted) throw new OrchestrationError("interrupted");
        const childArgs = ["--test", "--test-reporter", "tap", path.relative(REPOSITORY_ROOT, LIVE_BROWSER_TEST)];
        const result = await runQualificationCommand(process.execPath, childArgs, {
          cwd: REPOSITORY_ROOT,
          env: { ...buildTestEnvironment(process.env, fixtureEnvironment), P0B_LIVE_BROWSER: "1" },
          timeoutMs: BROWSER_TIMEOUT_MS,
          safeFailureMarkers: LIVE_BROWSER_SAFE_FAILURE_MARKERS,
          onChild: (child) => { activeChild = child; }
        });
        commands.push(commandEvidence("browser-e2e", ["node", ...childArgs], "repository", result));
        activeChild = undefined;
        if (result.status !== "passed") {
          const diagnostic = result.internal.safe_failure_code;
          failure = { stage: "live-browser", error: new OrchestrationError(diagnostic === null ? result.reason : `child_exit_nonzero_${diagnostic}`) };
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
        const childArgs = ["--test", "--test-reporter", "tap", "test/p0b-live-process.integration.test.mjs"];
        const result = await runQualificationCommand(process.execPath, childArgs, {
          cwd: REPOSITORY_ROOT,
          env: buildTestEnvironment(process.env, fixtureEnvironment),
          timeoutMs: PROCESS_TIMEOUT_MS,
          onChild: (child) => { activeChild = child; }
        });
        commands.push(commandEvidence("process-e2e", ["node", ...childArgs], "repository", result));
        activeChild = undefined;
        if (result.status !== "passed") {
          failure = { stage: "live-test", error: new OrchestrationError(result.reason) };
        } else if (interrupted) {
          failure = { stage: "live-test", error: new OrchestrationError("interrupted") };
        }
      } catch (error) {
        failure = { stage: "live-test", error };
      }
    }

    if (!failure) {
      try {
        const afterArtifact = await digestArtifactTree(path.join(CONSOLE_ROOT, "dist"), { name: "console-dist-after", kind: "build-verification" });
        if (afterArtifact.sha256 !== consoleArtifact.sha256 || afterArtifact.bytes !== consoleArtifact.bytes) {
          throw new OrchestrationError("build_artifact_changed");
        }
        const sourceAfter = resolveSourceState(REPOSITORY_ROOT);
        if (sourceAfter.commit !== sourceBefore.commit) throw new OrchestrationError("source_commit_changed");
      } catch (error) {
        failure = { stage: "final-provenance", error };
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
  try {
    const completedAt = new Date().toISOString();
    const report = buildP0BQualificationReport({
      source_commit: sourceBefore.commit,
      started_at: startedAt,
      completed_at: completedAt,
      commands,
      postgres: postgresEvidence,
      browser: browserEvidence,
      artifacts: [consoleArtifact],
      gates: [
        gateEvidence("build-integrity", { source_commit: sourceBefore.commit, command: commands[0].result, artifact: consoleArtifact }),
        gateEvidence("browser-flow", { source_commit: sourceBefore.commit, command: commands[1].result, browser: browserEvidence, artifact: consoleArtifact }),
        gateEvidence("process-flow", { source_commit: sourceBefore.commit, command: commands[2].result, postgres: postgresEvidence, artifact: consoleArtifact })
      ]
    }, { repositoryRoot: REPOSITORY_ROOT });
    await writeP0BQualificationReport(reportOutput, report);
    process.stdout.write(`p0b-qualification: ${report.report_digest}\n`);
  } catch (error) {
    emitFailure("qualification-report", error);
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

export function qualificationBaseEnvironment(base) {
  if (!base || typeof base !== "object") throw new TypeError("base environment is required");
  const result = Object.create(null);
  const exact = new Set(["PATH", "HOME", "TMPDIR", "LANG", "CI", "NO_COLOR", "PLAYWRIGHT_BROWSERS_PATH"]);
  for (const [key, value] of Object.entries(base)) {
    if ((exact.has(key) || key.startsWith("LC_")) && typeof value === "string") result[key] = value;
  }
  return result;
}

export function resolveQualificationOutput(argument, environment) {
  const value = argument ?? environment ?? DEFAULT_REPORT_OUTPUT;
  if (!isSafeAbsolutePath(value)) throw new OrchestrationError("invalid_report_output");
  return path.resolve(value);
}

export async function prepareQualificationOutput(outputFile) {
  if (!isSafeAbsolutePath(outputFile)) throw new OrchestrationError("invalid_report_output");
  const directory = path.dirname(outputFile);
  await fsp.mkdir(directory, { recursive: true, mode: 0o700 });
  const metadata = await fsp.lstat(directory);
  const uid = typeof process.getuid === "function" ? process.getuid() : undefined;
  if (!metadata.isDirectory() || metadata.isSymbolicLink() || (metadata.mode & 0o077) !== 0 || (uid !== undefined && metadata.uid !== uid)) {
    throw new OrchestrationError("unsafe_report_directory");
  }
  try {
    const existing = await fsp.lstat(outputFile);
    if (!existing.isFile() || existing.nlink !== 1 || (existing.mode & 0o077) !== 0 || (uid !== undefined && existing.uid !== uid)) {
      throw new OrchestrationError("unsafe_report_output");
    }
    await fsp.unlink(outputFile);
  } catch (error) {
    if (error?.code !== "ENOENT") throw error;
  }
}

function commandEvidence(id, argv, cwd, result) {
  return Object.freeze({ id, argv: Object.freeze(argv), cwd, result });
}

function gateEvidence(id, metadata) {
  return Object.freeze({ id, status: "passed", evidence_sha256: evidenceDigest(metadata) });
}

function isSafeAbsolutePath(value) {
  return typeof value === "string" && value.length > 0 && value.length <= 4096 && path.isAbsolute(value)
    && !value.includes("\u0000") && !value.includes("\n") && !value.includes("\r");
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
