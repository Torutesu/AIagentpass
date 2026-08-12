#!/usr/bin/env node

import crypto from "node:crypto";
import fs from "node:fs";
import fsp from "node:fs/promises";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { spawn } from "node:child_process";
import tls from "node:tls";

import { Client } from "pg";

const SCRIPT_DIRECTORY = path.dirname(fileURLToPath(import.meta.url));
const FIXTURE_PREFIX = "agentpass-p0b-postgres-tls-";
const FIXTURE_LABEL = "agentpass.p0b.postgres-tls";
const DEFAULT_IMAGE = "postgres:17-alpine";
const DEFAULT_TIMEOUT_MS = 45_000;
const LOOPBACK = "127.0.0.1";
const POSTGRES_DATABASE = "agentpass_p0b";
const POSTGRES_USER = "agentpass_p0b";
const STATE_SCHEMA_VERSION = 1;

export class FixtureError extends Error {
  constructor(code, message) {
    super(message);
    this.name = "FixtureError";
    this.code = code;
  }
}

export function parseArgs(argv) {
  const [command = "help", ...rest] = argv;
  const options = { command, timeoutMs: DEFAULT_TIMEOUT_MS, image: DEFAULT_IMAGE };
  for (let index = 0; index < rest.length; index += 1) {
    const argument = rest[index];
    if (argument === "--help" || argument === "-h") {
      options.command = "help";
      continue;
    }
    if (argument === "--timeout-ms") {
      options.timeoutMs = parsePositiveInteger(rest[++index], "--timeout-ms");
      continue;
    }
    if (argument === "--image") {
      options.image = validatePostgres17Image(rest[++index]);
      continue;
    }
    if (argument === "--state-file" || argument === "--output") {
      const value = rest[++index];
      if (!value || !path.isAbsolute(value)) throw new FixtureError("invalid_argument", `${argument} requires an absolute path`);
      options[argument === "--state-file" ? "stateFile" : "outputFile"] = value;
      continue;
    }
    if (argument === "--keep") {
      options.keep = true;
      continue;
    }
    throw new FixtureError("invalid_argument", `unknown option ${argument}`);
  }
  if (!["start", "stop", "status", "help"].includes(options.command)) {
    throw new FixtureError("invalid_argument", `unknown command ${options.command}`);
  }
  if ((options.command === "stop" || options.command === "status") && !options.stateFile) {
    throw new FixtureError("invalid_argument", `${options.command} requires --state-file`);
  }
  return Object.freeze(options);
}

export function validatePostgres17Image(image) {
  if (typeof image !== "string" || image.length === 0 || image.length > 256) {
    throw new FixtureError("invalid_image", "PostgreSQL image is invalid");
  }
  // Keep this fixture tied to the PostgreSQL 17 family while allowing a pinned
  // registry or digest selected by the caller.
  if (!/(?:^|\/)postgres(?::17(?:[-.][a-z0-9._-]+)?|@sha256:[a-f0-9]{64})$/u.test(image)) {
    throw new FixtureError("invalid_image", "PostgreSQL image must be a PostgreSQL 17 image");
  }
  return image;
}

export async function createFixtureRoot(prefix = FIXTURE_PREFIX) {
  const directory = await fsp.mkdtemp(path.join(os.tmpdir(), prefix));
  await fsp.chmod(directory, 0o700);
  return directory;
}

export async function createTlsMaterial(directory, { openssl = "openssl" } = {}) {
  assertAbsoluteDirectory(directory);
  const files = {
    caKey: path.join(directory, "ca.key.pem"),
    caCertificate: path.join(directory, "ca.cert.pem"),
    serverKey: path.join(directory, "server.key.pem"),
    serverCsr: path.join(directory, "server.csr.pem"),
    serverCertificate: path.join(directory, "server.cert.pem"),
    caConfig: path.join(directory, "ca.cnf"),
    serverConfig: path.join(directory, "server.cnf")
  };
  await writeExclusive(files.caConfig, `[req]
prompt = no
distinguished_name = distinguished_name
x509_extensions = ca_extensions

[distinguished_name]
CN = AgentPass P0-B local test CA

[ca_extensions]
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
basicConstraints = critical, CA:true, pathlen:1
keyUsage = critical, keyCertSign, cRLSign
`, 0o600);
  await writeExclusive(files.serverConfig, `[req]
prompt = no
distinguished_name = distinguished_name
req_extensions = server_extensions

[distinguished_name]
CN = localhost

[server_extensions]
basicConstraints = critical, CA:false
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @subject_alt_names

[subject_alt_names]
DNS.1 = localhost
IP.1 = 127.0.0.1
IP.2 = ::1
`, 0o600);
  try {
    await runCommand(openssl, [
      "req", "-x509", "-newkey", "rsa:3072", "-nodes", "-sha256",
      "-keyout", files.caKey, "-out", files.caCertificate, "-days", "1",
      "-config", files.caConfig, "-extensions", "ca_extensions"
    ], { cwd: directory });
    await runCommand(openssl, [
      "req", "-new", "-newkey", "rsa:2048", "-nodes", "-sha256",
      "-keyout", files.serverKey, "-out", files.serverCsr, "-config", files.serverConfig
    ], { cwd: directory });
    await runCommand(openssl, [
      "x509", "-req", "-sha256", "-in", files.serverCsr,
      "-CA", files.caCertificate, "-CAkey", files.caKey,
      "-set_serial", `0x${crypto.randomBytes(16).toString("hex")}`,
      "-out", files.serverCertificate, "-days", "1",
      "-extfile", files.serverConfig, "-extensions", "server_extensions"
    ], { cwd: directory });
  } catch (error) {
    if (error?.code === "command_missing") throw new FixtureError("openssl_missing", "openssl is unavailable");
    throw new FixtureError("certificate_generation_failed", "TLS certificate generation failed");
  }
  for (const file of [files.caKey, files.serverKey, files.caConfig, files.serverConfig]) await fsp.chmod(file, 0o600);
  for (const file of [files.caCertificate, files.serverCertificate]) await fsp.chmod(file, 0o600);
  return Object.freeze(files);
}

export function generateCredentials({ randomBytes = crypto.randomBytes } = {}) {
  const password = randomBytes(32).toString("base64url");
  return Object.freeze({ user: POSTGRES_USER, password, database: POSTGRES_DATABASE });
}

export function buildAdminUrl({ user, password, database, host = "localhost", port }) {
  if (!Number.isInteger(port) || port < 1 || port > 65_535) throw new FixtureError("invalid_port", "PostgreSQL port is invalid");
  const url = new URL(`postgresql://${host}:${port}/${encodeURIComponent(database)}`);
  url.username = user;
  url.password = password;
  url.searchParams.set("sslmode", "verify-full");
  return url.toString();
}

export async function writeEnvironmentFile(file, { adminUrl, caFile, stateFile, image, containerId }) {
  if (![adminUrl, caFile, stateFile, image, containerId].every((value) => typeof value === "string" && value.length > 0)) {
    throw new FixtureError("invalid_manifest", "fixture environment is incomplete");
  }
  const contents = [
    `P0B_POSTGRES_ADMIN_URL=${adminUrl}`,
    `AGENTPASS_TEST_POSTGRES_ADMIN_URL=${adminUrl}`,
    `P0B_POSTGRES_CA_FILE=${caFile}`,
    `PGSSLROOTCERT=${caFile}`,
    `P0B_POSTGRES_TLS_STATE_FILE=${stateFile}`,
    `P0B_POSTGRES_TLS_IMAGE=${image}`,
    `P0B_POSTGRES_TLS_CONTAINER_ID=${containerId}`,
    ""
  ].join("\n");
  await writeExclusive(file, contents, 0o600);
}

export function publicManifest(state) {
  return Object.freeze({
    schema_version: STATE_SCHEMA_VERSION,
    fixture: "agentpass-p0b-postgres-tls",
    status: state.status,
    image: state.image,
    container_id: state.containerId,
    host: state.host,
    port: state.port,
    database: state.database,
    user: state.user,
    root_dir: state.rootDir,
    state_file: state.stateFile,
    env_file: state.envFile,
    ca_file: state.caFile,
    started_at: state.startedAt
  });
}

export async function startFixture({ outputFile, timeoutMs = DEFAULT_TIMEOUT_MS, image = DEFAULT_IMAGE } = {}) {
  image = validatePostgres17Image(image);
  const rootDir = await createFixtureRoot();
  const stateFile = path.join(rootDir, "state.json");
  const tlsDirectory = path.join(rootDir, "tls");
  await fsp.mkdir(tlsDirectory, { mode: 0o700 });
  const tlsMaterial = await createTlsMaterial(tlsDirectory);
  const credentials = generateCredentials();
  const dockerEnvFile = path.join(rootDir, "docker.env");
  const envFile = path.join(rootDir, "fixture.env");
  const containerName = `${FIXTURE_PREFIX}${process.pid}-${crypto.randomBytes(6).toString("hex")}`;
  let containerId;
  try {
    await ensureDockerImage(image);
    await writeExclusive(dockerEnvFile, [
      `POSTGRES_USER=${credentials.user}`,
      `POSTGRES_PASSWORD=${credentials.password}`,
      `POSTGRES_DB=${credentials.database}`,
      "POSTGRES_INITDB_ARGS=--auth-host=scram-sha-256",
      ""
    ].join("\n"), 0o600);
    containerId = (await runDocker([
      "run", "--detach", "--name", containerName,
      "--env-file", dockerEnvFile,
      "--publish", `${LOOPBACK}::5432`,
      "--mount", `type=bind,src=${tlsDirectory},dst=/run/agentpass-p0b-tls,readonly`,
      "--tmpfs", "/var/lib/postgresql/data:rw,noexec,nosuid,nodev,mode=700",
      "--tmpfs", "/var/run/postgresql:rw,noexec,nosuid,nodev,mode=775",
      "--label", `com.agentpass.fixture=${FIXTURE_LABEL}`,
      "--label", `com.agentpass.fixture-state=${stateFile}`,
      "--health-cmd", `pg_isready -U ${credentials.user} -d ${credentials.database}`,
      "--health-interval", "1s", "--health-timeout", "1s", "--health-retries", "60",
      image, "sh", "-ec",
      "install -d -m 700 /var/lib/postgresql/tls; cp /run/agentpass-p0b-tls/ca.cert.pem /var/lib/postgresql/tls/ca.cert.pem; cp /run/agentpass-p0b-tls/server.cert.pem /var/lib/postgresql/tls/server.cert.pem; cp /run/agentpass-p0b-tls/server.key.pem /var/lib/postgresql/tls/server.key.pem; chown -R postgres:postgres /var/lib/postgresql/tls; chmod 644 /var/lib/postgresql/tls/ca.cert.pem /var/lib/postgresql/tls/server.cert.pem; chmod 600 /var/lib/postgresql/tls/server.key.pem; exec docker-entrypoint.sh postgres -c ssl=on -c ssl_cert_file=/var/lib/postgresql/tls/server.cert.pem -c ssl_key_file=/var/lib/postgresql/tls/server.key.pem -c ssl_ca_file=/var/lib/postgresql/tls/ca.cert.pem -c ssl_min_protocol_version=TLSv1.2"
    ])).trim();
    if (!/^[a-f0-9]{12,64}$/u.test(containerId)) throw new FixtureError("docker_failed", "Docker returned an invalid container id");
    const port = await waitForPublishedPort(containerId, timeoutMs);
    const adminUrl = buildAdminUrl({ ...credentials, port });
    const state = {
      schemaVersion: STATE_SCHEMA_VERSION,
      fixture: "agentpass-p0b-postgres-tls",
      status: "starting",
      image,
      containerId,
      containerName,
      host: "localhost",
      port,
      database: credentials.database,
      user: credentials.user,
      rootDir,
      stateFile,
      envFile,
      caFile: tlsMaterial.caCertificate,
      adminUrl,
      password: credentials.password,
      startedAt: new Date().toISOString()
    };
    await waitForPostgres(state, tlsMaterial.caCertificate, timeoutMs);
    state.status = "ready";
    await writeEnvironmentFile(envFile, { adminUrl, caFile: tlsMaterial.caCertificate, stateFile, image, containerId });
    await writeState(stateFile, state);
    const manifest = publicManifest(state);
    if (outputFile) await writeExclusive(outputFile, `${JSON.stringify(manifest, null, 2)}\n`, 0o600);
    return manifest;
  } catch (error) {
    if (containerId) await removeContainer(containerId);
    await removeFixtureRoot(rootDir);
    if (error instanceof FixtureError) throw error;
    if (error?.code === "command_missing") throw new FixtureError("docker_missing", "docker is unavailable");
    throw new FixtureError("fixture_start_failed", "PostgreSQL TLS fixture failed to become ready");
  }
}

export async function stopFixture(stateFile) {
  const state = await readAndValidateState(stateFile);
  await assertOwnedContainer(state);
  await removeContainer(state.containerId);
  await removeFixtureRoot(state.rootDir);
  return Object.freeze({ schema_version: STATE_SCHEMA_VERSION, fixture: state.fixture, status: "stopped", state_file: state.stateFile });
}

export async function statusFixture(stateFile) {
  const state = await readAndValidateState(stateFile);
  await assertOwnedContainer(state);
  const status = (await runDocker(["inspect", "--format", "{{.State.Status}}", state.containerId], { allowFailure: true })).trim();
  return Object.freeze({ ...publicManifest(state), status: status || "stopped" });
}

async function waitForPostgres(state, caFile, timeoutMs) {
  const ca = await fsp.readFile(caFile, "utf8");
  const deadline = Date.now() + timeoutMs;
  let lastFailure = null;
  while (Date.now() < deadline) {
    try {
      const status = (await runDocker(["inspect", "--format", "{{.State.Status}}", state.containerId], { allowFailure: true })).trim();
      if (status !== "running") throw new Error("container is not running");
      await verifyTls(state.port, ca);
      const client = new Client({
        host: "localhost",
        port: state.port,
        user: state.user,
        password: state.password,
        database: state.database,
        ssl: { ca, rejectUnauthorized: true },
        connectionTimeoutMillis: 2_000
      });
      try {
        await client.connect();
        const result = await client.query("SELECT current_setting('server_version_num') AS version, ssl FROM pg_stat_ssl WHERE pid = pg_backend_pid()");
        if (!String(result.rows[0]?.version ?? "").startsWith("17") || result.rows[0]?.ssl !== true) throw new Error("PostgreSQL TLS/version check failed");
      } finally {
        await client.end().catch(() => {});
      }
      return;
    } catch (error) {
      lastFailure = error;
      await delay(150);
    }
  }
  if (lastFailure?.code === "command_missing") throw new FixtureError("docker_missing", "docker is unavailable");
  throw new FixtureError("readiness_timeout", "PostgreSQL TLS fixture readiness timed out");
}

function verifyTls(port, ca) {
  return new Promise((resolve, reject) => {
    const socket = tls.connect({ host: LOOPBACK, port, servername: "localhost", ca, rejectUnauthorized: true }, () => {
      socket.end();
      resolve();
    });
    socket.setTimeout(2_000, () => socket.destroy(new Error("TLS readiness timeout")));
    socket.once("error", reject);
  });
}

async function waitForPublishedPort(containerId, timeoutMs) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const value = (await runDocker(["port", containerId, "5432/tcp"], { allowFailure: true })).trim();
    const match = value.match(/:(\d+)\s*$/u);
    if (match) return Number(match[1]);
    await delay(100);
  }
  throw new FixtureError("port_timeout", "Docker did not publish a PostgreSQL port");
}

async function ensureDockerImage(image) {
  const inspected = await runDocker(["image", "inspect", image], { allowFailure: true });
  if (inspected.trim() !== "") return;
  await runDocker(["pull", "--quiet", image]);
}

async function assertOwnedContainer(state) {
  const labels = (await runDocker(["inspect", "--format", "{{index .Config.Labels \"com.agentpass.fixture\"}}\t{{index .Config.Labels \"com.agentpass.fixture-state\"}}", state.containerId], { allowFailure: true })).trim();
  const [fixtureLabel, stateLabel] = labels.split("\t");
  if (fixtureLabel !== FIXTURE_LABEL || stateLabel !== state.stateFile) throw new FixtureError("ownership_check_failed", "Docker container is not owned by this fixture");
}

async function removeContainer(containerId) {
  if (!containerId) return;
  await runDocker(["rm", "--force", containerId], { allowFailure: true });
}

async function readAndValidateState(stateFile) {
  if (typeof stateFile !== "string" || !path.isAbsolute(stateFile)) throw new FixtureError("invalid_state", "state file must be an absolute path");
  let state;
  try {
    state = JSON.parse(await fsp.readFile(stateFile, "utf8"));
  } catch {
    throw new FixtureError("invalid_state", "fixture state file is unreadable");
  }
  if (state?.schemaVersion !== STATE_SCHEMA_VERSION || state?.fixture !== "agentpass-p0b-postgres-tls") throw new FixtureError("invalid_state", "fixture state file is invalid");
  if (!/^[a-f0-9]{12,64}$/u.test(state.containerId ?? "")) throw new FixtureError("invalid_state", "fixture container id is invalid");
  if (state.stateFile !== stateFile || !path.isAbsolute(state.rootDir) || path.dirname(stateFile) !== state.rootDir || !path.basename(state.rootDir).startsWith(FIXTURE_PREFIX)) {
    throw new FixtureError("invalid_state", "fixture state path is invalid");
  }
  return state;
}

async function writeState(file, state) {
  const safeState = { ...state };
  delete safeState.password;
  delete safeState.adminUrl;
  await writeExclusive(file, `${JSON.stringify(safeState, null, 2)}\n`, 0o600);
}

async function writeExclusive(file, contents, mode) {
  await fsp.writeFile(file, contents, { encoding: "utf8", flag: "wx", mode });
  await fsp.chmod(file, mode);
}

async function removeFixtureRoot(directory) {
  if (!directory || !path.isAbsolute(directory) || !path.basename(directory).startsWith(FIXTURE_PREFIX)) return;
  await fsp.rm(directory, { recursive: true, force: true }).catch(() => {});
}

function assertAbsoluteDirectory(directory) {
  if (typeof directory !== "string" || !path.isAbsolute(directory)) throw new FixtureError("invalid_directory", "fixture directory must be absolute");
}

function parsePositiveInteger(value, label) {
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < 1) throw new FixtureError("invalid_argument", `${label} must be a positive integer`);
  return parsed;
}

function runCommand(command, args, { cwd, allowFailure = false } = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, { cwd, shell: false, stdio: ["ignore", "pipe", "pipe"] });
    let stdout = "";
    child.stdout?.on("data", (chunk) => { stdout = `${stdout}${chunk}`.slice(-16_384); });
    child.stderr?.resume();
    child.once("error", (error) => {
      if (error.code === "ENOENT") reject(new FixtureError("command_missing", `${command} is unavailable`));
      else reject(new FixtureError("command_failed", `${command} could not be started`));
    });
    child.once("close", (code) => {
      if (code === 0 || allowFailure) resolve(stdout);
      else reject(new FixtureError("command_failed", `${command} failed`));
    });
  });
}

function runDocker(args, options = {}) { return runCommand("docker", args, options); }

function delay(milliseconds) { return new Promise((resolve) => setTimeout(resolve, milliseconds)); }

function help() {
  return `Usage: node scripts/p0b/postgres-tls/fixture.mjs <start|stop|status> [options]

start creates an ephemeral PostgreSQL 17 Docker container with TLS enabled.
The single JSON line on stdout contains paths only; credentials are in env_file.

Options:
  --output <absolute-path>    write the public manifest to this path as well as stdout
  --state-file <absolute-path> state file for stop/status
  --timeout-ms <integer>      readiness timeout (default: ${DEFAULT_TIMEOUT_MS})
  --image <postgres-17-image> Docker image (default: ${DEFAULT_IMAGE})
`;
}

export async function main(argv = process.argv.slice(2)) {
  const options = parseArgs(argv);
  if (options.command === "help") {
    process.stdout.write(help());
    return;
  }
  const result = options.command === "start"
    ? await startFixture(options)
    : options.command === "stop" ? await stopFixture(options.stateFile) : await statusFixture(options.stateFile);
  process.stdout.write(`${JSON.stringify(result)}\n`);
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch((error) => {
    const code = error instanceof FixtureError ? error.code : "fixture_failed";
    process.stderr.write(`p0b-postgres-tls: ${code}\n`);
    process.exitCode = 1;
  });
}
