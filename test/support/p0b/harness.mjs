import crypto from "node:crypto";
import fs from "node:fs";
import fsp from "node:fs/promises";
import http from "node:http";
import https from "node:https";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";

import { Pool } from "pg";

const REPOSITORY_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../..");
const LOOPBACK = "127.0.0.1";
const PG_DATABASE = /^[a-z][a-z0-9_]{0,62}$/u;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu;
const SECRET_ENV_PREFIX = "AGENTPASS_";
const MAX_CAPTURED_OUTPUT = 8 * 1024;

export class P0BSkip extends Error {
  constructor(code, diagnostic) {
    super(diagnostic);
    this.name = "P0BSkip";
    this.code = code;
    this.diagnostic = diagnostic;
  }
}

export function p0bRepositoryRoot() { return REPOSITORY_ROOT; }

export function requireTrustedHttpsLoopback(value) {
  let url;
  try { url = new URL(value); } catch { throw new TypeError("P0-B URL is invalid"); }
  if (url.protocol !== "https:" || !["localhost", "127.0.0.1", "::1"].includes(url.hostname)
    || url.username || url.password || url.search || url.hash || url.pathname !== "/") {
    throw new TypeError("P0-B requires a trusted HTTPS loopback origin");
  }
  return url;
}

export function requireVerifiedPostgresUrl(value, label = "PostgreSQL URL") {
  let url;
  try { url = new URL(value); } catch { throw new TypeError(`${label} is invalid`); }
  const parameters = [...url.searchParams.entries()];
  if (url.protocol !== "postgresql:" || !url.hostname || !url.username || !url.password || url.hash
    || parameters.length !== 1 || parameters[0][0] !== "sslmode" || parameters[0][1] !== "verify-full") {
    throw new TypeError(`${label} must use authenticated PostgreSQL TLS (sslmode=verify-full)`);
  }
  return url;
}

export function p0bEnvironment(base = process.env, overrides = {}) {
  const env = {};
  for (const [key, value] of Object.entries(base ?? {})) {
    if (key.startsWith(SECRET_ENV_PREFIX) || key === "NODE_OPTIONS" || key === "NODE_PATH") continue;
    if (key === "PATH" || key === "HOME" || key === "TMPDIR" || key === "LANG" || key.startsWith("LC_")) env[key] = value;
  }
  for (const [key, value] of Object.entries(overrides)) {
    if (value === undefined) delete env[key];
    else env[key] = String(value);
  }
  return env;
}

export async function createP0BTempDirectory(prefix = "agentpass-p0b-") {
  const directory = await fsp.mkdtemp(path.join(os.tmpdir(), prefix));
  await fsp.chmod(directory, 0o700);
  return directory;
}

export async function createTestCertificates(directory) {
  if (typeof directory !== "string" || !path.isAbsolute(directory)) throw new TypeError("certificate directory must be absolute");
  const openssl = "openssl";
  const caKey = path.join(directory, "ca-key.pem");
  const caCert = path.join(directory, "ca-cert.pem");
  const leafKey = path.join(directory, "localhost-key.pem");
  const leafCsr = path.join(directory, "localhost.csr");
  const leafCert = path.join(directory, "localhost-cert.pem");
  const config = path.join(directory, "localhost.cnf");
  await fsp.writeFile(config, "[req]\nprompt = no\ndistinguished_name = dn\nreq_extensions = ext\n[dn]\nCN = localhost\n[ext]\nsubjectAltName = DNS:localhost,IP:127.0.0.1,IP:::1\n", { mode: 0o600, flag: "wx" });
  try {
    await runCommand(openssl, ["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", caKey, "-out", caCert, "-subj", "/CN=AgentPass P0-B Test CA", "-days", "1", "-sha256"], directory);
    await runCommand(openssl, ["req", "-new", "-newkey", "rsa:2048", "-nodes", "-keyout", leafKey, "-out", leafCsr, "-config", config], directory);
    await runCommand(openssl, ["x509", "-req", "-in", leafCsr, "-CA", caCert, "-CAkey", caKey, "-CAcreateserial", "-out", leafCert, "-days", "1", "-sha256", "-extfile", config, "-extensions", "ext"], directory);
  } catch (error) {
    if (error?.code === "ENOENT") throw new P0BSkip("openssl_missing", "openssl is unavailable; P0-B TLS harness skipped");
    throw new Error("P0-B TLS certificate generation failed");
  }
  for (const file of [caKey, caCert, leafKey, leafCert]) await fsp.chmod(file, file === caCert || file === leafCert ? 0o644 : 0o600);
  return Object.freeze({ caCert, caKey, cert: leafCert, key: leafKey });
}

export async function createDisposablePostgres({ adminUrl, databaseName = randomDatabaseName(), env = process.env } = {}) {
  if (env.P0B_DISABLE_EXTERNAL === "true") throw new P0BSkip("external_disabled", "P0-B external dependencies disabled");
  const source = adminUrl ?? env.P0B_POSTGRES_ADMIN_URL ?? env.AGENTPASS_TEST_POSTGRES_ADMIN_URL;
  if (!source) throw new P0BSkip("postgres_admin_missing", "P0B_POSTGRES_ADMIN_URL is not configured; PostgreSQL lane skipped");
  if (!PG_DATABASE.test(databaseName)) throw new TypeError("P0-B database name is invalid");
  const admin = requireVerifiedPostgresUrl(source, "P0-B PostgreSQL admin URL");
  const pool = new Pool({ connectionString: admin.toString(), ssl: { rejectUnauthorized: true }, max: 1, connectionTimeoutMillis: 3_000, idleTimeoutMillis: 3_000 });
  try {
    await pool.query(`CREATE DATABASE ${quoteIdentifier(databaseName)}`);
  } catch (error) {
    await pool.end().catch(() => {});
    if (["ECONNREFUSED", "ENOTFOUND", "ETIMEDOUT", "EAI_AGAIN"].includes(error?.code)) throw new P0BSkip("postgres_unavailable", "PostgreSQL is unavailable; P0-B lane skipped");
    throw new Error("P0-B disposable PostgreSQL database could not be created");
  }
  await pool.end();
  const database = new URL(admin.toString());
  database.pathname = `/${databaseName}`;
  const databasePool = new Pool({ connectionString: database.toString(), ssl: { rejectUnauthorized: true }, max: 8, connectionTimeoutMillis: 3_000, idleTimeoutMillis: 3_000 });
  let removed = false;
  return Object.freeze({
    url: database.toString(),
    async close() {
      if (removed) return;
      removed = true;
      await databasePool.end().catch(() => {});
      const cleanupPool = new Pool({ connectionString: admin.toString(), ssl: { rejectUnauthorized: true }, max: 1, connectionTimeoutMillis: 3_000, idleTimeoutMillis: 3_000 });
      try { await cleanupPool.query(`DROP DATABASE ${quoteIdentifier(databaseName)} WITH (FORCE)`); }
      finally { await cleanupPool.end().catch(() => {}); }
    },
    pool: databasePool
  });
}

export async function startP0BHarness({ env = process.env, repoRoot = REPOSITORY_ROOT, consoleBuild = true, waitTimeoutMs = 20_000 } = {}) {
  if (env.P0B_DISABLE_EXTERNAL === "true") throw new P0BSkip("external_disabled", "P0-B external dependencies disabled");
  const temp = await createP0BTempDirectory();
  let database;
  let cloudProcess;
  let consoleProcess;
  let cloudProxy;
  let consoleProxy;
  try {
    const certificates = await createTestCertificates(temp);
    database = await createDisposablePostgres({ env });
    const files = await createRuntimeFiles(temp);
    const cloudPort = await reservePort();
    const cloudTlsPort = await reservePort();
    const consolePort = await reservePort();
    const consoleTlsPort = await reservePort();
    const organizationId = crypto.randomUUID();
    const common = {
      AGENTPASS_DATABASE_URL: database.url,
      AGENTPASS_CLOUD_PROFILE: "hosted",
      AGENTPASS_CLOUD_HOST: LOOPBACK,
      AGENTPASS_CLOUD_PORT: cloudPort,
      AGENTPASS_CLOUD_BUNDLE_PRIVATE_KEY_PATH: files.bundlePrivateKey,
      AGENTPASS_CLOUD_REFRESH_PRIVATE_KEY_PATH: files.refreshPrivateKey,
      AGENTPASS_CLOUD_REFRESH_KEY_ID: "p0b-refresh-v1",
      AGENTPASS_CLOUD_REFRESH_NONCE_KEYRING_PATH: files.nonceKeyring,
      AGENTPASS_CAPABILITY_NONCE_SECRET: files.capabilitySecret,
      AGENTPASS_HUMAN_CURSOR_SECRET: files.cursorSecret,
      AGENTPASS_OPERATIONAL_PROBE_SECRET: files.probeSecret,
      AGENTPASS_CONSOLE_ORIGIN: `https://localhost:${consoleTlsPort}`,
      AGENTPASS_WEBAUTHN_RP_ID: "localhost",
      AGENTPASS_IDENTITY_ASSERTION_ISSUER: "agentpass-p0b-console",
      AGENTPASS_IDENTITY_ASSERTION_AUDIENCE: "agentpass-p0b-cloud",
      AGENTPASS_IDENTITY_ASSERTION_KID: "p0b-console-v1",
      AGENTPASS_IDENTITY_ASSERTION_PUBLIC_KEY_PATH: files.identityPublicKey
    };
    cloudProcess = spawnProcess(process.execPath, [path.join(repoRoot, "apps/cloud-api/src/main.mjs")], repoRoot, p0bEnvironment(env, common));
    cloudProxy = await createTlsProxy({ cert: certificates.cert, key: certificates.key, targetPort: cloudPort, port: cloudTlsPort });
    await waitForHttps(`https://localhost:${cloudTlsPort}/`, certificates.caCert, { path: "/health/ready", headers: { "AgentPass-Operational-Token": files.probeSecret }, expectedStatus: 200, timeoutMs: waitTimeoutMs });
    const consoleEnv = p0bEnvironment(env, {
      NODE_ENV: "test",
      PORT: consolePort,
      AGENTPASS_CLOUD_API_URL: `https://localhost:${cloudTlsPort}/`,
      AGENTPASS_CONSOLE_ORIGIN: `https://localhost:${consoleTlsPort}`,
      AGENTPASS_ORGANIZATION_ID: organizationId,
      AGENTPASS_CONSOLE_CURSOR_SECRET: files.cursorSecret,
      AGENTPASS_IDENTITY_ASSERTION_PRIVATE_KEY: files.identityPrivateKeyPem,
      AGENTPASS_IDENTITY_ASSERTION_ISSUER: "agentpass-p0b-console",
      AGENTPASS_IDENTITY_ASSERTION_AUDIENCE: "agentpass-p0b-cloud",
      AGENTPASS_IDENTITY_ASSERTION_KID: "p0b-console-v1",
      AGENTPASS_IDENTITY_PROVIDER: "chatgpt",
      NODE_EXTRA_CA_CERTS: certificates.caCert,
      WRANGLER_LOG_PATH: path.join(temp, "wrangler.log"),
      MINIFLARE_REGISTRY_PATH: path.join(temp, "registry")
    });
    if (consoleBuild && !fs.existsSync(path.join(repoRoot, "apps/web-console/dist"))) throw new P0BSkip("console_build_missing", "Console dist is missing; run the Console build before P0-B");
    consoleProcess = spawnProcess(process.execPath, [path.join(repoRoot, "apps/web-console/node_modules/vinext/dist/cli.js"), "start", "--hostname", LOOPBACK, "--port", String(consolePort)], path.join(repoRoot, "apps/web-console"), consoleEnv);
    consoleProxy = await createTlsProxy({ cert: certificates.cert, key: certificates.key, targetPort: consolePort, port: consoleTlsPort });
    await waitForHttps(`https://localhost:${consoleTlsPort}/`, certificates.caCert, { path: "/", expectedStatus: 200, timeoutMs: waitTimeoutMs });
    return Object.freeze({
      cloudUrl: `https://localhost:${cloudTlsPort}/`, consoleUrl: `https://localhost:${consoleTlsPort}/`, caCert: certificates.caCert,
      databaseUrl: database.url, organizationId,
      async close() { await closeP0BHarness({ cloudProcess, consoleProcess, cloudProxy, consoleProxy, database, temp }); }
    });
  } catch (error) {
    await closeP0BHarness({ cloudProcess, consoleProcess, cloudProxy, consoleProxy, database, temp });
    if (error instanceof P0BSkip) throw error;
    throw error instanceof Error && error.message.startsWith("P0-B") ? error : new Error("P0-B harness startup failed");
  }
}

export async function closeP0BHarness({ cloudProcess, consoleProcess, cloudProxy, consoleProxy, database, temp } = {}) {
  await consoleProxy?.close?.().catch(() => {});
  await cloudProxy?.close?.().catch(() => {});
  await stopProcess(consoleProcess);
  await stopProcess(cloudProcess);
  await database?.close?.().catch(() => {});
  if (temp) await fsp.rm(temp, { recursive: true, force: true }).catch(() => {});
}

export function randomDatabaseName() { return `agentpass_p0b_${process.pid}_${crypto.randomBytes(6).toString("hex")}`.slice(0, 63); }

async function createRuntimeFiles(directory) {
  const bundle = crypto.generateKeyPairSync("ed25519");
  const refresh = crypto.generateKeyPairSync("ed25519");
  const identity = crypto.generateKeyPairSync("ed25519");
  const bundlePrivateKey = path.join(directory, "bundle-private.pem");
  const refreshPrivateKey = path.join(directory, "refresh-private.pem");
  const identityPublicKey = path.join(directory, "identity-public.pem");
  await writePrivate(bundlePrivateKey, bundle.privateKey.export({ type: "pkcs8", format: "pem" }));
  await writePrivate(refreshPrivateKey, refresh.privateKey.export({ type: "pkcs8", format: "pem" }));
  await fsp.writeFile(identityPublicKey, identity.publicKey.export({ type: "spki", format: "pem" }), { mode: 0o644, flag: "wx" });
  const nonceKeyring = path.join(directory, "refresh-nonce-keyring.json");
  await writePrivate(nonceKeyring, `${JSON.stringify({ version: 1, active_key_id: "p0b-nonce-v1", keys: { "p0b-nonce-v1": crypto.randomBytes(32).toString("base64url") } })}\n`);
  return Object.freeze({
    bundlePrivateKey, refreshPrivateKey, identityPublicKey, nonceKeyring,
    identityPrivateKeyPem: identity.privateKey.export({ type: "pkcs8", format: "pem" }),
    capabilitySecret: crypto.randomBytes(32).toString("base64url"), cursorSecret: crypto.randomBytes(32).toString("base64url"),
    probeSecret: crypto.randomBytes(32).toString("base64url")
  });
}

async function writePrivate(file, value) { await fsp.writeFile(file, value, { mode: 0o600, flag: "wx" }); await fsp.chmod(file, 0o600); }

function quoteIdentifier(value) { return `"${value.replaceAll('"', '""')}"`; }

async function reservePort() {
  const server = net.createServer();
  await new Promise((resolve, reject) => { server.once("error", reject); server.listen(0, LOOPBACK, resolve); });
  const port = server.address().port;
  await new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
  return port;
}

function spawnProcess(command, args, cwd, env) {
  const child = spawn(command, args, { cwd, env, shell: false, detached: process.platform !== "win32", stdio: ["ignore", "pipe", "pipe"] });
  drain(child.stdout); drain(child.stderr);
  return child;
}

function drain(stream) { if (!stream) return; let size = 0; stream.on("data", (chunk) => { size = Math.min(MAX_CAPTURED_OUTPUT, size + chunk.length); }); stream.resume(); }

async function stopProcess(child) {
  if (!child || child.exitCode !== null || child.signalCode !== null) return;
  const pid = child.pid;
  try { process.kill(process.platform === "win32" ? pid : -pid, "SIGTERM"); } catch { try { child.kill("SIGTERM"); } catch {} }
  await new Promise((resolve) => {
    const timer = setTimeout(() => { try { process.kill(process.platform === "win32" ? pid : -pid, "SIGKILL"); } catch { try { child.kill("SIGKILL"); } catch {} } resolve(); }, 3_000);
    child.once("exit", () => { clearTimeout(timer); resolve(); });
  });
}

async function createTlsProxy({ cert, key, targetPort, port }) {
  const server = https.createServer({ cert: await fsp.readFile(cert), key: await fsp.readFile(key), minVersion: "TLSv1.2" }, (request, response) => {
    const headers = { ...request.headers, host: `${LOOPBACK}:${targetPort}` };
    delete headers.connection; delete headers["proxy-connection"]; delete headers["keep-alive"];
    const upstream = http.request({ host: LOOPBACK, port: targetPort, method: request.method, path: request.url, headers }, (incoming) => { response.writeHead(incoming.statusCode ?? 502, incoming.headers); incoming.pipe(response); });
    upstream.on("error", () => { if (!response.headersSent) response.writeHead(502); response.end(); });
    request.pipe(upstream);
  });
  await new Promise((resolve, reject) => { server.once("error", reject); server.listen(port, LOOPBACK, resolve); });
  return Object.freeze({ port, async close() { await new Promise((resolve) => server.close(() => resolve())); } });
}

async function waitForHttps(origin, ca, { path: requestPath, headers = {}, expectedStatus = 200, timeoutMs = 20_000 } = {}) {
  const caPem = await fsp.readFile(ca, "utf8");
  const deadline = Date.now() + timeoutMs;
  let lastError;
  while (Date.now() < deadline) {
    try {
      const result = await httpsRequest(new URL(requestPath, origin), { ca: caPem, headers, timeoutMs: 1_500 });
      if (result.status === expectedStatus) return result;
      lastError = new Error(`status_${result.status}`);
    } catch (error) { lastError = error; }
    await new Promise((resolve) => setTimeout(resolve, 150));
  }
  throw new Error(`P0-B health check failed (${lastError?.message?.replace(/[^a-z0-9_ -]/giu, "").slice(0, 64) ?? "unavailable"})`);
}

function httpsRequest(url, { ca, headers, timeoutMs }) {
  return new Promise((resolve, reject) => {
    const request = https.request({ protocol: url.protocol, hostname: url.hostname, port: url.port, path: `${url.pathname}${url.search}`, method: "GET", ca, rejectUnauthorized: true, headers }, (response) => {
      let body = ""; response.setEncoding("utf8"); response.on("data", (chunk) => { if (body.length < 64 * 1024) body += chunk; });
      response.on("end", () => resolve({ status: response.statusCode, body }));
    });
    request.setTimeout(timeoutMs, () => request.destroy(new Error("timeout")));
    request.once("error", reject); request.end();
  });
}

function runCommand(command, args, cwd) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, { cwd, shell: false, stdio: ["ignore", "ignore", "ignore"] });
    child.once("error", reject); child.once("exit", (code) => code === 0 ? resolve() : reject(new Error("command failed")));
  });
}
