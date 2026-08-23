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
const PROVENANCE_INSPECT_FORMAT = [
  "{{.Id}}",
  "{{.Image}}",
  "{{.State.StartedAt}}",
  '{{index .Config.Labels "com.agentpass.fixture"}}',
  '{{index .Config.Labels "com.agentpass.fixture-state"}}'
].join("\t");
const MAX_CLOCK_SKEW_MS = 5_000;
const MAX_PROTECTED_ENV_BYTES = 16 * 1024;
const MAX_CA_BYTES = 1024 * 1024;
const COMMAND_TIMEOUT_MS = 120_000;

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

/**
 * Collects the small, non-secret set of facts that qualifies a live fixture.
 *
 * `manifest` is the public manifest emitted by startFixture. `adminUrl` and
 * `caFile` must come from the protected fixture environment, rather than from
 * the public manifest. The command runner and Client constructor are
 * injectable so this boundary can be tested without Docker or PostgreSQL.
 */
export async function collectFixtureProvenance({
  manifest,
  adminUrl,
  caFile,
  runDocker: docker = runDocker,
  Client: ClientConstructor = Client
} = {}) {
  const normalized = validateProvenanceManifest(manifest);
  const connection = validateAdminUrl(adminUrl, normalized);
  await validateManifestEnvironment({ manifest: normalized, adminUrl, caFile });
  const ca = await readProtectedCa(caFile);

  let inspected;
  try {
    const output = await docker([
      "inspect",
      "--format",
      PROVENANCE_INSPECT_FORMAT,
      normalized.container_id
    ]);
    inspected = parseProvenanceInspect(output, normalized);
  } catch (error) {
    if (error instanceof FixtureError && [
      "provenance_container_metadata_invalid",
      "provenance_container_started_in_future",
      "provenance_ownership_mismatch"
    ].includes(error.code)) throw error;
    throw new FixtureError("provenance_docker_inspect_failed", "Docker provenance could not be collected");
  }

  let client;
  let row;
  try {
    client = new ClientConstructor({
      host: connection.host,
      port: connection.port,
      user: connection.user,
      password: connection.password,
      database: connection.database,
      ssl: {
        ca,
        rejectUnauthorized: true,
        servername: connection.host
      },
      connectionTimeoutMillis: 2_000
    });
    await client.connect();
    const result = await client.query(`SELECT
      current_setting('server_version') AS server_version,
      current_setting('server_version_num') AS server_version_num,
      (SELECT ssl FROM pg_stat_ssl WHERE pid = pg_backend_pid()) AS ssl`);
    row = result?.rows?.[0];
  } catch {
    throw new FixtureError("provenance_postgres_connect_failed", "PostgreSQL provenance connection failed");
  } finally {
    if (client) await client.end().catch(() => {});
  }

  const serverVersion = validatePostgresProvenanceRow(row);
  return Object.freeze({
    image: normalized.image,
    image_digest: inspected.imageDigest,
    container_id: inspected.containerId,
    container_started_at: inspected.startedAt,
    server_version: serverVersion
  });
}

function validateProvenanceManifest(manifest) {
  if (!manifest || typeof manifest !== "object" || Array.isArray(manifest)) {
    throw new FixtureError("invalid_manifest", "fixture manifest is invalid");
  }
  if (manifest.schema_version !== STATE_SCHEMA_VERSION || manifest.fixture !== "agentpass-p0b-postgres-tls" || manifest.status !== "ready") {
    throw new FixtureError("invalid_manifest", "fixture manifest is invalid");
  }
  try {
    validatePostgres17Image(manifest.image);
  } catch {
    throw new FixtureError("invalid_manifest", "fixture manifest is invalid");
  }
  if (!/^[a-f0-9]{12,64}$/u.test(manifest.container_id ?? "")) {
    throw new FixtureError("invalid_manifest", "fixture manifest is invalid");
  }
  if (manifest.host !== "localhost" || !Number.isInteger(manifest.port) || manifest.port < 1 || manifest.port > 65_535) {
    throw new FixtureError("invalid_manifest", "fixture manifest is invalid");
  }
  if (typeof manifest.user !== "string" || manifest.user.length === 0 || typeof manifest.database !== "string" || manifest.database.length === 0) {
    throw new FixtureError("invalid_manifest", "fixture manifest is invalid");
  }
  for (const field of ["root_dir", "state_file", "env_file", "ca_file"]) {
    if (!isSafeAbsolutePath(manifest[field])) throw new FixtureError("invalid_manifest", "fixture manifest is invalid");
  }
  if (manifest.state_file !== path.join(manifest.root_dir, "state.json")) {
    throw new FixtureError("invalid_manifest", "fixture manifest is invalid");
  }
  return manifest;
}

function validateAdminUrl(adminUrl, manifest) {
  if (typeof adminUrl !== "string" || adminUrl.length === 0 || adminUrl.length > 4_096) {
    throw new FixtureError("invalid_manifest_identity", "fixture environment identity is invalid");
  }
  let url;
  try {
    url = new URL(adminUrl);
  } catch {
    throw new FixtureError("invalid_manifest_identity", "fixture environment identity is invalid");
  }
  if (!["postgresql:", "postgres:"].includes(url.protocol) || url.hostname !== manifest.host || url.port !== String(manifest.port) || url.hash !== "") {
    throw new FixtureError("invalid_manifest_identity", "fixture environment identity is invalid");
  }
  if (url.searchParams.get("sslmode") !== "verify-full" || url.searchParams.getAll("sslmode").length !== 1) {
    throw new FixtureError("invalid_manifest_identity", "fixture environment identity is invalid");
  }
  let user;
  let password;
  let database;
  try {
    user = decodeURIComponent(url.username);
    password = decodeURIComponent(url.password);
    database = decodeURIComponent(url.pathname.slice(1));
  } catch {
    throw new FixtureError("invalid_manifest_identity", "fixture environment identity is invalid");
  }
  if (!user || !password || !database || user !== manifest.user || database !== manifest.database || url.pathname === "/") {
    throw new FixtureError("invalid_manifest_identity", "fixture environment identity is invalid");
  }
  return Object.freeze({ host: url.hostname, port: manifest.port, user, password, database });
}

async function validateManifestEnvironment({ manifest, adminUrl, caFile }) {
  if (!isSafeAbsolutePath(caFile) || caFile !== manifest.ca_file) {
    throw new FixtureError("invalid_manifest_identity", "fixture environment identity is invalid");
  }
  const environment = await readProtectedEnvironment(manifest.env_file);
  const expected = {
    P0B_POSTGRES_ADMIN_URL: adminUrl,
    AGENTPASS_TEST_POSTGRES_ADMIN_URL: adminUrl,
    P0B_POSTGRES_CA_FILE: caFile,
    PGSSLROOTCERT: caFile,
    P0B_POSTGRES_TLS_STATE_FILE: manifest.state_file,
    P0B_POSTGRES_TLS_IMAGE: manifest.image,
    P0B_POSTGRES_TLS_CONTAINER_ID: manifest.container_id
  };
  for (const [key, value] of Object.entries(expected)) {
    if (environment[key] !== value) throw new FixtureError("invalid_manifest_identity", "fixture environment identity is invalid");
  }
}

async function readProtectedEnvironment(file) {
  await assertProtectedRegularFile(file, "invalid_manifest_identity", MAX_PROTECTED_ENV_BYTES);
  let contents;
  try {
    contents = await fsp.readFile(file, "utf8");
  } catch {
    throw new FixtureError("invalid_manifest_identity", "fixture environment identity is invalid");
  }
  const values = Object.create(null);
  for (const line of contents.split(/\r?\n/u)) {
    if (line === "") continue;
    const separator = line.indexOf("=");
    if (separator < 1 || !/^[A-Z][A-Z0-9_]*$/u.test(line.slice(0, separator))) {
      throw new FixtureError("invalid_manifest_identity", "fixture environment identity is invalid");
    }
    const key = line.slice(0, separator);
    if (Object.hasOwn(values, key)) throw new FixtureError("invalid_manifest_identity", "fixture environment identity is invalid");
    values[key] = line.slice(separator + 1);
  }
  return values;
}

async function readProtectedCa(file) {
  if (!isSafeAbsolutePath(file)) throw new FixtureError("invalid_manifest_identity", "fixture environment identity is invalid");
  await assertProtectedRegularFile(file, "invalid_manifest_identity", MAX_CA_BYTES);
  try {
    return await fsp.readFile(file, "utf8");
  } catch {
    throw new FixtureError("invalid_manifest_identity", "fixture environment identity is invalid");
  }
}

async function assertProtectedRegularFile(file, errorCode, maxBytes) {
  try {
    const stats = await fsp.lstat(file);
    if (!stats.isFile() || (stats.mode & 0o077) !== 0 || (maxBytes !== undefined && stats.size > maxBytes)) {
      throw new Error("unsafe file");
    }
  } catch {
    throw new FixtureError(errorCode, "fixture environment identity is invalid");
  }
}

function parseProvenanceInspect(output, manifest) {
  if (typeof output !== "string") throw new FixtureError("provenance_container_metadata_invalid", "Docker container metadata is invalid");
  const fields = output.trimEnd().split("\t");
  if (fields.length !== 5 || fields.some((field) => field.length === 0)) {
    throw new FixtureError("provenance_container_metadata_invalid", "Docker container metadata is invalid");
  }
  const [containerId, imageDigest, startedAt, fixtureLabel, stateLabel] = fields;
  if (!/^[a-f0-9]{12,64}$/u.test(containerId) || containerId !== manifest.container_id || !/^sha256:[a-f0-9]{64}$/u.test(imageDigest)) {
    throw new FixtureError("provenance_container_metadata_invalid", "Docker container metadata is invalid");
  }
  const startedTimestamp = Date.parse(startedAt);
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z$/u.test(startedAt) || !Number.isFinite(startedTimestamp) || startedTimestamp <= 0) {
    throw new FixtureError("provenance_container_metadata_invalid", "Docker container metadata is invalid");
  }
  if (startedTimestamp > Date.now() + MAX_CLOCK_SKEW_MS) {
    throw new FixtureError("provenance_container_started_in_future", "Docker container start time is in the future");
  }
  if (fixtureLabel !== FIXTURE_LABEL || stateLabel !== manifest.state_file) {
    throw new FixtureError("provenance_ownership_mismatch", "Docker container ownership does not match the fixture");
  }
  return Object.freeze({ containerId, imageDigest, startedAt: new Date(startedTimestamp).toISOString() });
}

function validatePostgresProvenanceRow(row) {
  if (!row || row.ssl !== true) throw new FixtureError("provenance_postgres_not_tls", "PostgreSQL connection is not TLS protected");
  const serverVersion = typeof row.server_version === "string" ? row.server_version : "";
  const versionNumber = typeof row.server_version_num === "string" ? row.server_version_num : String(row.server_version_num ?? "");
  const numericVersion = Number(versionNumber);
  const major = Math.floor(numericVersion / 10_000);
  const minor = numericVersion % 10_000;
  if (!/^17(?:[.\s]|$)/u.test(serverVersion) || !/^\d+$/u.test(versionNumber) || major !== 17 || !Number.isSafeInteger(minor)) {
    throw new FixtureError("provenance_postgres_version_invalid", "PostgreSQL server version is not 17");
  }
  return `${major}.${minor}`;
}

function isSafeAbsolutePath(value) {
  return typeof value === "string" && value.length > 0 && value.length <= 4_096 && path.isAbsolute(value) && !value.includes("\0") && !value.includes("\n") && !value.includes("\r");
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
  const remaining = await runDocker(["inspect", "--format", "{{.Id}}", containerId], { allowFailure: true });
  if (remaining.trim() !== "") throw new FixtureError("container_cleanup_failed", "Docker fixture cleanup failed");
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

function runCommand(command, args, { cwd, allowFailure = false, timeoutMs = COMMAND_TIMEOUT_MS } = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, { cwd, shell: false, detached: process.platform !== "win32", stdio: ["ignore", "pipe", "pipe"] });
    let stdout = "";
    let settled = false;
    let timer;
    let killTimer;
    const finish = (callback) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      clearTimeout(killTimer);
      callback();
    };
    const terminate = () => {
      try {
        if (process.platform !== "win32" && Number.isSafeInteger(child.pid) && child.pid > 0) process.kill(-child.pid, "SIGTERM");
        else child.kill("SIGTERM");
      } catch {}
      killTimer = setTimeout(() => {
        try {
          if (process.platform !== "win32" && Number.isSafeInteger(child.pid) && child.pid > 0) process.kill(-child.pid, "SIGKILL");
          else child.kill("SIGKILL");
        } catch {}
      }, 500);
    };
    child.stdout?.on("data", (chunk) => { stdout = `${stdout}${chunk}`.slice(-16_384); });
    child.stderr?.resume();
    child.once("error", (error) => {
      finish(() => {
        if (error.code === "ENOENT") reject(new FixtureError("command_missing", `${command} is unavailable`));
        else reject(new FixtureError("command_failed", `${command} could not be started`));
      });
    });
    child.once("close", (code) => {
      finish(() => {
        if (code === 0 || allowFailure) resolve(stdout);
        else reject(new FixtureError("command_failed", `${command} failed`));
      });
    });
    timer = setTimeout(() => {
      terminate();
      finish(() => reject(new FixtureError("command_timeout", `${command} timed out`)));
    }, timeoutMs);
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
