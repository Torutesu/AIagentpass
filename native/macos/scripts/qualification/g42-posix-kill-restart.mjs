#!/usr/bin/env node

/**
 * G4.2 subprocess kill/restart durability-model lane.
 *
 * This is intentionally self-contained and does not modify the Swift package.
 * It exercises the durable protocol shape against real POSIX files and a
 * deterministic local Device API fixture. The fixture is HTTP on loopback and
 * is never passed to NativeDeviceSyncHTTPTransport. Production HTTPS is only
 * probed with normal certificate verification; an untrusted local certificate
 * is an explicit SKIP, never a reason to disable TLS verification.
 */

import {
  chmodSync,
  closeSync,
  existsSync,
  fchmodSync,
  fsyncSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  openSync,
  readFileSync,
  readdirSync,
  renameSync,
  rmSync,
  statSync,
  unlinkSync,
  writeFileSync,
  writeSync,
} from "node:fs";
import { createHash } from "node:crypto";
import { request as httpRequest, createServer } from "node:http";
import { connect as tlsConnect } from "node:tls";
import { spawn } from "node:child_process";
import { createInterface } from "node:readline";
import { once } from "node:events";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const SCRIPT = resolve(fileURLToPath(import.meta.url));
const ORG = "11111111-1111-4111-8111-111111111111";
const DEVICE = "22222222-2222-4222-8222-222222222222";
const GENERATION = 1;
const SEQUENCE = 1;
const NONCE = "qualification-nonce-v1";
const SECRET_MARKER = "G42_QUALIFICATION_PRIVATE_SENTINEL_7b8d";
const REQUEST_TIMEOUT_MS = 1_000;
const CHILD_TIMEOUT_MS = 5_000;
const FIXTURE_TIMEOUT_MS = 2_000;
const BOUNDARIES = [
  "after-hint",
  "after-fetching",
  "after-bundle-stage",
  "after-activation",
  "before-ack",
  "after-ack-before-state",
];

function log(message) {
  process.stdout.write(`${message}\n`);
}

function fail(message) {
  throw new Error(message);
}

function assert(condition, message) {
  if (!condition) fail(message);
}

function canonical(value) {
  if (Array.isArray(value)) return value.map(canonical);
  if (value && typeof value === "object") {
    return Object.fromEntries(Object.keys(value).sort().map((key) => [key, canonical(value[key])]));
  }
  return value;
}

function canonicalJSON(value) {
  return JSON.stringify(canonical(value));
}

function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
}

function mode(path) {
  return lstatSync(path).mode & 0o777;
}

function assertPrivateRegular(path, expectedMode) {
  const info = lstatSync(path);
  assert(info.isFile(), `expected regular file: ${path}`);
  assert((info.mode & 0o777) === expectedMode, `unexpected mode for ${path}`);
  assert(info.uid === process.getuid(), `unexpected owner for ${path}`);
}

function assertPrivateDirectory(path) {
  const info = lstatSync(path);
  assert(info.isDirectory(), `expected directory: ${path}`);
  assert((info.mode & 0o777) === 0o700, `unexpected directory mode: ${path}`);
  assert(info.uid === process.getuid(), `unexpected directory owner: ${path}`);
}

function fsyncDirectory(path) {
  const descriptor = openSync(path, "r");
  try {
    fsyncSync(descriptor);
  } finally {
    closeSync(descriptor);
  }
}

function atomicWrite(path, bytes, expectedMode = 0o600) {
  const temporary = `${path}.tmp-${process.pid}-${Date.now()}`;
  const descriptor = openSync(temporary, "wx", expectedMode);
  try {
    writeFileSync(descriptor, bytes);
    fchmodSync(descriptor, expectedMode);
    fsyncSync(descriptor);
  } finally {
    closeSync(descriptor);
  }
  renameSync(temporary, path);
  fsyncDirectory(dirname(path));
  assertPrivateRegular(path, expectedMode);
}

function safeReadJSON(path) {
  assertPrivateRegular(path, 0o600);
  return JSON.parse(readFileSync(path, "utf8"));
}

function ensureNoSymlinks(root) {
  const pending = [root];
  while (pending.length > 0) {
    const current = pending.pop();
    const info = lstatSync(current);
    assert(!info.isSymbolicLink(), `symlink found in qualification root: ${current}`);
    if (!info.isDirectory()) continue;
    for (const entry of readdirSync(current)) pending.push(join(current, entry));
  }
}

function assertRedactedArtifacts(root, logs) {
  ensureNoSymlinks(root);
  const pending = [root];
  const haystacks = [logs.join("\n")];
  while (pending.length > 0) {
    const current = pending.pop();
    const info = lstatSync(current);
    if (info.isDirectory()) {
      for (const entry of readdirSync(current)) pending.push(join(current, entry));
    } else {
      haystacks.push(readFileSync(current));
    }
  }
  for (const haystack of haystacks) {
    const text = Buffer.isBuffer(haystack) ? haystack.toString("utf8") : haystack;
    assert(!text.includes(SECRET_MARKER), "secret marker leaked into qualification artifacts");
    assert(!text.includes("private_key"), "private_key field leaked into qualification artifacts");
    assert(!text.includes("raw_signature"), "raw_signature field leaked into qualification artifacts");
  }
}

function makeBundle() {
  const bundle = {
    device_id: DEVICE,
    expires_at: "2030-01-01T00:00:00.000Z",
    generation: GENERATION,
    issuer: "agentpass-qualification-fixture",
    organization_id: ORG,
    policy_scope: { operations: ["git.commit.sign"], repositories: ["/qualification/repo"] },
    sequence: SEQUENCE,
  };
  const bundleBytes = Buffer.from(canonicalJSON(bundle));
  return { bundle, bundleBytes, statementHash: sha256(bundleBytes), contentHash: sha256(bundleBytes) };
}

function fixtureStatePath(root) {
  return join(root, "fixture-state.json");
}

function loadFixtureState(root) {
  const path = fixtureStatePath(root);
  if (!existsSync(path)) return { ackCount: 0, failureConsumed: false, requests: [] };
  return safeReadJSON(path);
}

function saveFixtureState(root, value) {
  atomicWrite(fixtureStatePath(root), Buffer.from(canonicalJSON(value)), 0o600);
}

function startFixture(root, failFirstAck) {
  const bundle = makeBundle();
  const server = createServer((request, response) => {
    let body = "";
    request.setEncoding("utf8");
    request.on("data", (chunk) => { body += chunk; });
    request.on("end", () => {
      const state = loadFixtureState(root);
      state.requests.push(`${request.method} ${request.url}`);
      try {
        const url = new URL(request.url, "http://127.0.0.1");
        if (request.method === "GET" && url.pathname.endsWith(`/organizations/${ORG}/devices/${DEVICE}/refresh`)) {
          const after = Number(url.searchParams.get("after_generation"));
          assert(Number.isSafeInteger(after), "fixture received invalid after_generation");
          response.writeHead(200, { "content-type": "application/json", "cache-control": "no-store" });
          response.end(JSON.stringify({
            hint: {
              authority_generation: GENERATION,
              device_id: DEVICE,
              expires_at: "2030-01-01T00:05:00.000Z",
              nonce: NONCE,
              organization_id: ORG,
            },
          }));
        } else if (request.method === "GET" && url.pathname.endsWith(`/organizations/${ORG}/bundles/${DEVICE}`)) {
          response.writeHead(200, { "content-type": "application/json", "cache-control": "no-store" });
          response.end(JSON.stringify({ desired_generation: GENERATION, bundle: bundle.bundle }));
        } else if (request.method === "POST" && url.pathname.endsWith(`/organizations/${ORG}/bundles/${DEVICE}/acknowledgements`)) {
          const acknowledgement = JSON.parse(body);
          assert(acknowledgement.organization_id === ORG, "fixture ACK organization mismatch");
          assert(acknowledgement.device_id === DEVICE, "fixture ACK device mismatch");
          assert(acknowledgement.sequence === SEQUENCE, "fixture ACK sequence mismatch");
          assert(acknowledgement.statement_hash === bundle.statementHash, "fixture ACK statement mismatch");
          assert(acknowledgement.nonce === NONCE, "fixture ACK nonce mismatch");
          assert(!Object.hasOwn(acknowledgement, "private_key"), "fixture received private key field");
          if (failFirstAck && !state.failureConsumed) {
            state.failureConsumed = true;
            saveFixtureState(root, state);
            response.writeHead(503, { "content-type": "application/json", "cache-control": "no-store" });
            response.end(JSON.stringify({ error: "deterministic_fixture_failure" }));
            return;
          }
          state.ackCount += 1;
          state.lastAcknowledgement = {
            device_id: acknowledgement.device_id,
            nonce: acknowledgement.nonce,
            result: acknowledgement.result,
            sequence: acknowledgement.sequence,
            statement_hash: acknowledgement.statement_hash,
          };
          saveFixtureState(root, state);
          response.writeHead(200, { "content-type": "application/json", "cache-control": "no-store" });
          response.end(JSON.stringify({ accepted: true, duplicate: state.ackCount > 1, observed_generation: GENERATION, refresh_state: "applied" }));
        } else if (request.method === "GET" && url.pathname === "/__qualification/state") {
          response.writeHead(200, { "content-type": "application/json", "cache-control": "no-store" });
          response.end(JSON.stringify(state));
        } else {
          response.writeHead(404, { "content-type": "application/json" });
          response.end(JSON.stringify({ error: "not_found" }));
        }
      } catch {
        response.writeHead(400, { "content-type": "application/json", "cache-control": "no-store" });
        response.end(JSON.stringify({ error: "deterministic_fixture_rejected_request" }));
      }
    });
  });
  server.listen(0, "127.0.0.1");
  return new Promise((resolvePromise, rejectPromise) => {
    server.once("error", rejectPromise);
    server.once("listening", () => {
      server.removeListener("error", rejectPromise);
      const address = server.address();
      resolvePromise({ server, baseURL: `http://127.0.0.1:${address.port}/v1` });
    });
  });
}

function requestJSON(baseURL, method, path, body) {
  const url = new URL(`${baseURL}${path}`);
  return new Promise((resolvePromise, rejectPromise) => {
    const request = httpRequest({
      hostname: url.hostname,
      port: url.port,
      path: `${url.pathname}${url.search}`,
      method,
      headers: { accept: "application/json", ...(body ? { "content-type": "application/json" } : {}) },
      timeout: REQUEST_TIMEOUT_MS,
    }, (response) => {
      let responseBody = "";
      response.setEncoding("utf8");
      response.on("data", (chunk) => { responseBody += chunk; });
      response.on("end", () => {
        let parsed;
        try { parsed = responseBody ? JSON.parse(responseBody) : {}; } catch { parsed = {}; }
        if (response.statusCode < 200 || response.statusCode >= 300) {
          const error = new Error(`fixture_http_${response.statusCode}`);
          error.code = `HTTP_${response.statusCode}`;
          rejectPromise(error);
          return;
        }
        resolvePromise(parsed);
      });
    });
    request.once("timeout", () => request.destroy(new Error("fixture_timeout")));
    request.once("error", (error) => rejectPromise(error));
    if (body) request.end(JSON.stringify(body)); else request.end();
  });
}

function statePath(root) { return join(root, "refresh.state.json"); }
function bundlePath(root) { return join(root, "bundles", `g${GENERATION}-s${SEQUENCE}.bundle`); }
function pointerPath(root) { return join(root, "active.pointer"); }

function initialState() {
  return { generation: 0, nonce: null, sequence: null, statementHash: null, state: "idle", revision: 0 };
}

function loadWorkerState(root) {
  const path = statePath(root);
  if (!existsSync(path)) return initialState();
  assertPrivateRegular(path, 0o600);
  const state = safeReadJSON(path);
  assert(["idle", "hinted", "fetching", "staging", "applied", "ack_pending", "acknowledged"].includes(state.state), "unknown durable state");
  return state;
}

function saveWorkerState(root, state) {
  state.revision += 1;
  atomicWrite(statePath(root), Buffer.from(canonicalJSON(state)), 0o600);
}

function workerBoundary(name, requested) {
  // Use a synchronous pipe write so the parent observes the marker before the
  // child freezes. SIGSTOP prevents even one subsequent durable mutation;
  // only the parent can resume the lifecycle by delivering SIGKILL.
  writeSync(1, `BOUNDARY ${name}\n`);
  if (requested === name) {
    process.kill(process.pid, "SIGSTOP");
    fail("worker resumed after an exact kill boundary");
  }
}

async function runWorker({ root, baseURL, killBoundary, failFirstAck }) {
  assertPrivateDirectory(root);
  assertPrivateDirectory(join(root, "bundles"));
  let state = loadWorkerState(root);
  const prefix = `/organizations/${ORG}`;

  if (state.state === "idle" || state.state === "acknowledged") {
    const refresh = await requestJSON(baseURL, "GET", `${prefix}/devices/${DEVICE}/refresh?after_generation=${state.generation}&wait_ms=0`);
    assert(refresh.hint?.authority_generation === GENERATION, "unexpected fixture generation");
    assert(refresh.hint?.nonce === NONCE, "unexpected fixture nonce");
    state = { ...state, generation: GENERATION, nonce: NONCE, state: "hinted" };
    saveWorkerState(root, state);
    workerBoundary("after-hint", killBoundary);
  }

  if (state.state === "hinted") {
    state = { ...state, state: "fetching" };
    saveWorkerState(root, state);
    workerBoundary("after-fetching", killBoundary);
  }

  if (state.state === "fetching") {
    const fetched = await requestJSON(baseURL, "GET", `${prefix}/bundles/${DEVICE}`);
    assert(fetched.desired_generation === GENERATION, "unexpected desired generation");
    const bytes = Buffer.from(canonicalJSON(fetched.bundle));
    const statementHash = sha256(bytes);
    assert(statementHash === makeBundle().statementHash, "fixture bundle hash mismatch");
    const path = bundlePath(root);
    const temporary = `${path}.stage-${process.pid}`;
    const descriptor = openSync(temporary, "wx", 0o600);
    try {
      writeFileSync(descriptor, bytes);
      fchmodSync(descriptor, 0o400);
      fsyncSync(descriptor);
    } finally {
      closeSync(descriptor);
    }
    renameSync(temporary, path);
    fsyncDirectory(dirname(path));
    assertPrivateRegular(path, 0o400);
    state = { ...state, sequence: SEQUENCE, statementHash, state: "staging" };
    saveWorkerState(root, state);
    workerBoundary("after-bundle-stage", killBoundary);
  }

  if (state.state === "staging") {
    const staged = bundlePath(root);
    assertPrivateRegular(staged, 0o400);
    const pointerBytes = Buffer.from(`${staged}\n`);
    atomicWrite(pointerPath(root), pointerBytes, 0o600);
    state = { ...state, state: "applied" };
    workerBoundary("after-activation", killBoundary);
    saveWorkerState(root, state);
  }

  if (state.state === "applied" || state.state === "ack_pending") {
    assertPrivateRegular(bundlePath(root), 0o400);
    const acknowledgement = {
      device_id: DEVICE,
      nonce: state.nonce,
      organization_id: ORG,
      result: "applied",
      sequence: state.sequence,
      statement_hash: state.statementHash,
    };
    workerBoundary("before-ack", killBoundary);
    try {
      await requestJSON(baseURL, "POST", `${prefix}/bundles/${DEVICE}/acknowledgements`, acknowledgement);
    } catch (error) {
      state = { ...state, state: "ack_pending" };
      saveWorkerState(root, state);
      if (failFirstAck && error.code === "HTTP_503") process.exitCode = 42;
      else throw error;
      return;
    }
    workerBoundary("after-ack-before-state", killBoundary);
    state = { ...state, state: "acknowledged" };
    saveWorkerState(root, state);
  }

  assert(loadWorkerState(root).state === "acknowledged", "worker did not reach acknowledged state");
  process.stdout.write("RESULT applied\n");
}

function spawnWorker({ root, baseURL, killBoundary = "", failFirstAck = false }) {
  const args = [SCRIPT, "--role", "worker", "--root", root, "--base-url", baseURL];
  if (killBoundary) args.push("--kill-boundary", killBoundary);
  if (failFirstAck) args.push("--fail-first-ack");
  const child = spawn(process.execPath, args, { stdio: ["ignore", "pipe", "pipe"] });
  const lines = [];
  const errors = [];
  const output = createInterface({ input: child.stdout });
  output.on("line", (line) => { lines.push(line); process.stdout.write(`  child: ${line}\n`); });
  child.stderr.on("data", (chunk) => { errors.push(String(chunk)); });
  const completion = once(child, "close").then(([code, signal]) => ({ code, signal, lines, errors }));
  return { child, lines, errors, completion };
}

async function waitForBoundary(worker, expected) {
  const deadline = Date.now() + CHILD_TIMEOUT_MS;
  while (Date.now() < deadline) {
    if (worker.lines.includes(`BOUNDARY ${expected}`)) return;
    if (worker.child.exitCode !== null) fail(`worker exited before ${expected}: ${worker.errors.join("")}`);
    await new Promise((resolvePromise) => setTimeout(resolvePromise, 10));
  }
  fail(`worker did not reach boundary ${expected}`);
}

async function killAndWait(worker) {
  assert(worker.child.exitCode === null, "worker already exited before deterministic kill");
  worker.child.kill("SIGKILL");
  const result = await Promise.race([
    worker.completion,
    new Promise((_, rejectPromise) => setTimeout(() => rejectPromise(new Error("worker kill timeout")), CHILD_TIMEOUT_MS)),
  ]);
  assert(result.signal === "SIGKILL", `expected SIGKILL, got ${result.signal ?? result.code}`);
}

async function stopServer(server) {
  if (!server) return;
  await new Promise((resolvePromise) => server.close(() => resolvePromise()));
}

async function runScenario(name, { boundary = "", failFirstAck = false } = {}) {
  const root = mkdtempSync(join(process.env.TMPDIR || "/tmp", "agentpass-g42-posix-"));
  chmodSync(root, 0o700);
  mkdirSync(join(root, "bundles"), { mode: 0o700 });
  assertPrivateDirectory(root);
  assertPrivateDirectory(join(root, "bundles"));
  let fixture;
  const logs = [];
  try {
    mkdirSync(join(root, "fixture"), { mode: 0o700 });
    fixture = await startFixture(join(root, "fixture"), failFirstAck);
    // The fixture creates its state lazily; this directory remains private.
    assertPrivateDirectory(join(root, "fixture"));
    log(`SCENARIO ${name}`);
    let worker = spawnWorker({ root, baseURL: fixture.baseURL, killBoundary: boundary, failFirstAck });
    if (boundary) {
      await waitForBoundary(worker, boundary);
      logs.push(...worker.lines, ...worker.errors);
      await killAndWait(worker);
      worker = spawnWorker({ root, baseURL: fixture.baseURL, failFirstAck });
    }
    const result = await Promise.race([
      worker.completion,
      new Promise((_, rejectPromise) => setTimeout(() => rejectPromise(new Error("worker lifecycle timeout")), CHILD_TIMEOUT_MS)),
    ]);
    logs.push(...worker.lines, ...worker.errors);
    assert(result.code === (failFirstAck && !boundary ? 42 : 0), `unexpected worker exit for ${name}: ${result.code}`);

    if (failFirstAck && !boundary) {
      assert(safeReadJSON(statePath(root)).state === "ack_pending", "failed ACK was not durably pending");
      const restarted = spawnWorker({ root, baseURL: fixture.baseURL });
      const restartResult = await Promise.race([
        restarted.completion,
        new Promise((_, rejectPromise) => setTimeout(() => rejectPromise(new Error("restart timeout")), CHILD_TIMEOUT_MS)),
      ]);
      logs.push(...restarted.lines, ...restarted.errors);
      assert(restartResult.code === 0, `failure recovery restart failed: ${restartResult.code}`);
    }

    const finalState = safeReadJSON(statePath(root));
    assert(finalState.state === "acknowledged", `${name} did not converge after restart`);
    assertPrivateRegular(statePath(root), 0o600);
    assertPrivateRegular(bundlePath(root), 0o400);
    assertPrivateRegular(pointerPath(root), 0o600);
    assert(readFileSync(pointerPath(root), "utf8") === `${bundlePath(root)}\n`, `${name} active pointer mismatch`);
    const fixtureState = safeReadJSON(fixtureStatePath(join(root, "fixture")));
    assert(fixtureState.ackCount >= 1, `${name} did not reach fixture ACK`);
    if (boundary === "after-ack-before-state") assert(fixtureState.ackCount === 2, "ACK replay was not observed");
    assertRedactedArtifacts(root, logs);
    log(`PASS ${name} state=acknowledged ack_count=${fixtureState.ackCount}`);
  } finally {
    if (fixture) await stopServer(fixture.server);
    assert(existsSync(root), "qualification root unexpectedly disappeared before cleanup");
    rmSync(root, { recursive: true, force: true });
    assert(!existsSync(root), `qualification cleanup failed: ${root}`);
  }
}

async function tlsPreflight() {
  const configured = process.env.AGENTPASS_QUALIFICATION_HTTPS_BASE_URL;
  if (!configured) {
    log("SKIP production HTTPS execution: AGENTPASS_QUALIFICATION_HTTPS_BASE_URL is not configured");
    return;
  }
  let url;
  try { url = new URL(configured); } catch { log("SKIP production HTTPS execution: configured URL is invalid"); return; }
  if (url.protocol !== "https:") {
    log("SKIP production HTTPS execution: configured URL is not HTTPS");
    return;
  }
  await new Promise((resolvePromise) => {
    const socket = tlsConnect({ host: url.hostname, port: Number(url.port || 443), servername: url.hostname, rejectUnauthorized: true }, () => {
      socket.end();
      log("PASS HTTPS trust preflight");
      resolvePromise();
    });
    socket.setTimeout(FIXTURE_TIMEOUT_MS, () => {
      socket.destroy();
      log("SKIP production HTTPS execution: TLS trust preflight timed out");
      resolvePromise();
    });
    socket.once("error", () => {
      socket.destroy();
      log("SKIP production HTTPS execution: certificate/privilege preflight failed with verification enabled");
      resolvePromise();
    });
  });
}

async function runParent() {
  await tlsPreflight();
  for (const boundary of BOUNDARIES) await runScenario(boundary, { boundary });
  await runScenario("deterministic-ack-failure-recovery", { failFirstAck: true });
  log(`DURABILITY MODEL PASS scenarios=${BOUNDARIES.length + 1}`);
}

function parseArgs(argv) {
  const values = {};
  for (let index = 0; index < argv.length; index += 1) {
    if (!argv[index].startsWith("--")) continue;
    const key = argv[index].slice(2).replaceAll("-", "_");
    values[key] = argv[index + 1] && !argv[index + 1].startsWith("--") ? argv[++index] : true;
  }
  return values;
}

const args = parseArgs(process.argv.slice(2));
if (args.role === "fixture" || args.role === "worker") {
  // Roles are intentionally not exported as public commands; the parent owns
  // lifecycle and cleanup. This branch is retained for deterministic child use.
  if (args.role === "worker") {
    runWorker({
      root: resolve(String(args.root)),
      baseURL: String(args.base_url),
      killBoundary: String(args.kill_boundary || ""),
      failFirstAck: Boolean(args.fail_first_ack),
    }).catch((error) => {
      process.stderr.write(`${error instanceof Error ? error.message : "worker_failure"}\n`);
      process.exitCode = 1;
    });
  }
} else {
  runParent().catch((error) => {
    process.stderr.write(`DURABILITY MODEL FAIL: ${error instanceof Error ? error.message : "unknown_failure"}\n`);
    process.exitCode = 1;
  });
}
