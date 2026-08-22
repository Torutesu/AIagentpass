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
import { createMigrationRunner, loadSqlMigrations } from "../../../apps/cloud-api/src/postgres/migration-runner.mjs";
import { canonicalJson } from "../../../packages/protocol/src/index.mjs";
import { POSTGRES_SCHEMA_IDENTITY_QUERY, postgresSchemaIdentityDigest } from "../../../apps/cloud-api/src/postgres/schema-identity.mjs";

const REPOSITORY_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../..");
const LOOPBACK = "127.0.0.1";
const PG_DATABASE = /^[a-z][a-z0-9_]{0,62}$/u;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu;
const SECRET_ENV_PREFIX = "AGENTPASS_";
const MAX_CAPTURED_OUTPUT = 8 * 1024;
const MAX_DIAGNOSTIC_OUTPUT = 2 * 1024;
const MAX_CA_BYTES = 256 * 1024;
const P0B_PROCESS_TERM_TIMEOUT_MS = 1_000;
const P0B_PROCESS_FORCE_TIMEOUT_MS = 1_000;
const P0B_PROXY_CLOSE_TIMEOUT_MS = 1_500;
const P0B_POOL_CLOSE_TIMEOUT_MS = 2_000;
const P0B_DATABASE_QUERY_TIMEOUT_MS = 2_000;
const P0B_TEMP_CLEANUP_TIMEOUT_MS = 2_000;
const TRUSTED_HTTPS_LOOPBACK_HOSTS = new Set(["localhost", "127.0.0.1", "[::1]"]);
const POSTGRES_CA_ENV_NAMES = ["P0B_POSTGRES_CA_FILE", "AGENTPASS_TEST_POSTGRES_CA_FILE"];
const P0B_CLOUD_PROCESS = path.join(REPOSITORY_ROOT, "test/support/p0b/cloud-runtime-process.mjs");
const P0B_DATABASE_ROLES = Object.freeze({
  app: "agentpass_app",
  migration: "agentpass_migrator",
  signer: "agentpass_signer",
  maintenance: "agentpass_maintenance"
});
const PROCESS_STOP_PROMISES = new WeakMap();
const RESOURCE_CLOSE_PROMISES = new WeakMap();

export class P0BSkip extends Error {
  constructor(code, diagnostic) {
    super(diagnostic);
    this.name = "P0BSkip";
    this.code = code;
    this.diagnostic = diagnostic;
  }
}

export function p0bRepositoryRoot() { return REPOSITORY_ROOT; }

async function p0BDeploymentDigests({ repoRoot, database, sourceCommit, sourceTree }) {
  if (!/^[0-9a-f]{40}$/u.test(sourceCommit ?? "") || !/^[0-9a-f]{40}$/u.test(sourceTree ?? "")) {
    throw new Error("P0-B source identity is unavailable");
  }
  let migrations;
  try { migrations = await loadSqlMigrations(); }
  catch { throw new Error("P0-B deployment migration digest failed"); }
  const manifest = {
    schema_version: 1,
    source_commit: sourceCommit,
    source_tree: sourceTree,
    migrations: migrations.map((migration) => ({ name: migration.name, bytes: Buffer.byteLength(migration.sql, "utf8"), sha256: migration.checksum }))
  };
  const schemaDigest = crypto.createHash("sha256").update(`${canonicalJson(manifest)}\n`, "utf8").digest("hex");
  let catalogBytes;
  try { catalogBytes = await fsp.readFile(path.resolve(repoRoot, "contracts/catalog-v1.json")); }
  catch { throw new Error("P0-B deployment catalog digest failed"); }
  const catalogDigest = crypto.createHash("sha256").update(catalogBytes).digest("hex");
  try {
    let result;
    try { result = await database.pool.query(POSTGRES_SCHEMA_IDENTITY_QUERY); }
    catch (error) { throw new Error(`P0-B deployment schema identity ${schemaQueryFailureClass(error)} failed`); }
    try {
      const snapshot = typeof result?.rows?.[0]?.snapshot === "string" ? JSON.parse(result.rows[0].snapshot) : result?.rows?.[0]?.snapshot;
      return Object.freeze({ schemaDigest, catalogDigest, databaseSchemaDigest: postgresSchemaIdentityDigest(snapshot) });
    } catch { throw new Error("P0-B deployment schema identity failed"); }
  } catch (error) {
    if (/^P0-B deployment schema identity [a-z_]+ failed$/u.test(error?.message ?? "")) throw error;
    throw new Error("P0-B deployment schema identity failed");
  }
}

function schemaQueryFailureClass(error) {
  const code = typeof error?.code === "string" ? error.code : "";
  if (code === "42P01") return "relation_missing";
  if (code === "42703") return "column_missing";
  if (code === "42883") return "function_missing";
  if (code === "42804") return "type_mismatch";
  if (code === "42501") return "permission_denied";
  if (code === "42601") return "syntax_invalid";
  if (code === "0A000") return "feature_unsupported";
  if (code === "22023") return "parameter_invalid";
  if (/^08/u.test(code) || ["ECONNREFUSED", "ETIMEDOUT", "ENOTFOUND"].includes(code)) return "connection_failed";
  return "query_failed";
}

export function requireTrustedHttpsLoopback(value) {
  let url;
  try { url = new URL(value); } catch { throw new TypeError("P0-B URL is invalid"); }
  if (url.protocol !== "https:" || !TRUSTED_HTTPS_LOOPBACK_HOSTS.has(url.hostname)
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

export function createVerifiedPostgresPoolOptions(value, { ca } = {}) {
  const url = requireVerifiedPostgresUrl(value instanceof URL ? value.toString() : value);
  const options = {
    host: url.hostname.startsWith("[") && url.hostname.endsWith("]") ? url.hostname.slice(1, -1) : url.hostname,
    user: decodeUrlComponent(url.username, "PostgreSQL username"),
    password: decodeUrlComponent(url.password, "PostgreSQL password"),
    database: url.pathname.length > 1 ? decodeUrlComponent(url.pathname.slice(1), "PostgreSQL database") : undefined,
    ssl: { rejectUnauthorized: true }
  };
  if (url.port) options.port = Number(url.port);
  if (ca !== undefined) options.ssl.ca = ca;
  return options;
}

async function prepareP0BDatabaseAuthorities(database) {
  const rolesSql = (await fsp.readFile(path.join(REPOSITORY_ROOT, "scripts/postgres/roles.sql"), "utf8"))
    .replace(/^\\set\s+ON_ERROR_STOP\s+on\s*$/mu, "")
    .trim();
  await database.pool.query(rolesSql);

  const migrationClient = await database.pool.connect();
  try {
    await createMigrationRunner({ client: migrationClient, applicationVersion: "p0b-authority-bootstrap" }).run();
  } finally {
    migrationClient.release();
  }

  await database.pool.query(rolesSql);

  const credentials = Object.create(null);
  for (const [authority, role] of Object.entries(P0B_DATABASE_ROLES)) {
    const password = crypto.randomBytes(32).toString("hex");
    await database.pool.query(`ALTER ROLE ${role} PASSWORD '${password}'`);
    const roleUrl = new URL(database.url);
    roleUrl.username = role;
    roleUrl.password = password;
    credentials[authority] = roleUrl.toString();
  }
  return Object.freeze(credentials);
}

export async function readPostgresCaFile(caFile, { env = process.env } = {}) {
  const source = caFile ?? POSTGRES_CA_ENV_NAMES.map((name) => env?.[name]).find((value) => value !== undefined && value !== "");
  if (source === undefined) return undefined;
  if (typeof source !== "string" || !path.isAbsolute(source)) throw new TypeError("P0-B PostgreSQL CA file must be an absolute path");
  let pem;
  try {
    const handle = await fsp.open(source, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW ?? 0));
    try {
      const metadata = await handle.stat();
      if (!metadata.isFile() || (metadata.mode & 0o022) !== 0) throw new Error("invalid CA file metadata");
      if (metadata.size > MAX_CA_BYTES) throw new Error("CA file is too large");
      pem = await handle.readFile("utf8");
    } finally {
      await handle.close().catch(() => {});
    }
  } catch {
    throw new TypeError("P0-B PostgreSQL CA file is unreadable");
  }
  if (pem.length > MAX_CA_BYTES || /-----BEGIN [^-]*PRIVATE KEY-----/u.test(pem)) throw new TypeError("P0-B PostgreSQL CA file is invalid");
  const certificates = [...pem.matchAll(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/gu)].map(([certificate]) => certificate);
  if (certificates.length === 0 || pem.replaceAll(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/gu, "").trim() !== "") throw new TypeError("P0-B PostgreSQL CA file is invalid");
  try {
    const parsed = certificates.map((certificate) => new crypto.X509Certificate(certificate));
    if (parsed.some((certificate) => certificate.ca !== true)) throw new Error("certificate is not a CA");
  } catch {
    throw new TypeError("P0-B PostgreSQL CA file is invalid");
  }
  return Object.freeze({ file: source, pem });
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
  const caConfig = path.join(directory, "ca.cnf");
  await fsp.writeFile(config, "[req]\nprompt = no\ndistinguished_name = dn\nreq_extensions = v3_req\n[dn]\nCN = localhost\n[v3_req]\nbasicConstraints = critical, CA:false\nkeyUsage = critical, digitalSignature, keyEncipherment\nextendedKeyUsage = serverAuth\nsubjectAltName = DNS:localhost,IP:127.0.0.1,IP:::1\n[v3_ca]\nsubjectKeyIdentifier = hash\nauthorityKeyIdentifier = keyid:always,issuer\nbasicConstraints = critical, CA:true, pathlen:1\nkeyUsage = critical, keyCertSign, cRLSign\n", { mode: 0o600, flag: "wx" });
  await fsp.writeFile(caConfig, "[req]\nprompt = no\ndistinguished_name = dn\nx509_extensions = v3_ca\n[dn]\nCN = AgentPass P0-B Test CA\n[v3_ca]\nsubjectKeyIdentifier = hash\nauthorityKeyIdentifier = keyid:always,issuer\nbasicConstraints = critical, CA:true, pathlen:1\nkeyUsage = critical, keyCertSign, cRLSign\n", { mode: 0o600, flag: "wx" });
  try {
    await runCommand(openssl, ["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", caKey, "-out", caCert, "-subj", "/CN=AgentPass P0-B Test CA", "-days", "1", "-sha256", "-config", caConfig, "-extensions", "v3_ca"], directory);
    await runCommand(openssl, ["req", "-new", "-newkey", "rsa:2048", "-nodes", "-keyout", leafKey, "-out", leafCsr, "-config", config], directory);
    await runCommand(openssl, ["x509", "-req", "-in", leafCsr, "-CA", caCert, "-CAkey", caKey, "-CAcreateserial", "-out", leafCert, "-days", "1", "-sha256", "-extfile", config, "-extensions", "v3_req"], directory);
  } catch (error) {
    if (error?.code === "ENOENT") throw new P0BSkip("openssl_missing", "openssl is unavailable; P0-B TLS harness skipped");
    throw new Error("P0-B TLS certificate generation failed");
  }
  for (const file of [caKey, caCert, leafKey, leafCert]) await fsp.chmod(file, file === caCert || file === leafCert ? 0o644 : 0o600);
  return Object.freeze({ caCert, caKey, cert: leafCert, key: leafKey });
}

export async function certificateSpkiPin(file) {
  if (typeof file !== "string" || !path.isAbsolute(file)) throw new TypeError("certificate path must be absolute");
  let handle;
  try {
    handle = await fsp.open(file, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW ?? 0));
    const metadata = await handle.stat();
    if (!metadata.isFile() || (metadata.mode & 0o022) !== 0 || metadata.size > MAX_CA_BYTES) throw new Error("unsafe certificate");
    const certificate = new crypto.X509Certificate(await handle.readFile());
    const spki = certificate.publicKey.export({ type: "spki", format: "der" });
    return crypto.createHash("sha256").update(spki).digest("base64");
  } catch {
    throw new TypeError("P0-B certificate pin could not be derived");
  } finally {
    await handle?.close().catch(() => {});
  }
}

export async function createDisposablePostgres({ adminUrl, databaseName = randomDatabaseName(), env = process.env, caFile } = {}) {
  if (env.P0B_DISABLE_EXTERNAL === "true") throw new P0BSkip("external_disabled", "P0-B external dependencies disabled");
  const source = adminUrl ?? env.P0B_POSTGRES_ADMIN_URL ?? env.AGENTPASS_TEST_POSTGRES_ADMIN_URL;
  if (!source) throw new P0BSkip("postgres_admin_missing", "P0B_POSTGRES_ADMIN_URL is not configured; PostgreSQL lane skipped");
  if (!PG_DATABASE.test(databaseName)) throw new TypeError("P0-B database name is invalid");
  const admin = requireVerifiedPostgresUrl(source, "P0-B PostgreSQL admin URL");
  const ca = await readPostgresCaFile(caFile, { env });
  const baseOptions = createVerifiedPostgresPoolOptions(admin, { ca: ca?.pem });
  const pool = new Pool({ ...baseOptions, max: 1, connectionTimeoutMillis: 3_000, idleTimeoutMillis: 3_000 });
  let created = false;
  try {
    await pool.query(`CREATE DATABASE ${quoteIdentifier(databaseName)}`);
    created = true;
  } catch (error) {
    await endPool(pool);
    if (["ECONNREFUSED", "ENOTFOUND", "ETIMEDOUT", "EAI_AGAIN"].includes(error?.code)) throw new P0BSkip("postgres_unavailable", "PostgreSQL is unavailable; P0-B lane skipped");
    throw new Error("P0-B disposable PostgreSQL database could not be created");
  }
  if (!await endPool(pool)) {
    if (created) await dropDisposableDatabase(baseOptions, databaseName);
    throw new Error("P0-B PostgreSQL admin pool could not close (cleanup timeout)");
  }
  const database = new URL(admin.toString());
  database.pathname = `/${databaseName}`;
  const databaseOptions = createVerifiedPostgresPoolOptions(database, { ca: ca?.pem });
  const databasePool = new Pool({ ...databaseOptions, max: 8, connectionTimeoutMillis: 3_000, idleTimeoutMillis: 3_000 });
  let closePromise;
  return Object.freeze({
    url: database.toString(),
    caCertificate: ca?.pem,
    async close() {
      if (!closePromise) {
        closePromise = (async () => {
          await endPool(databasePool);
          const cleanupPool = new Pool({ ...baseOptions, max: 1, connectionTimeoutMillis: 3_000, idleTimeoutMillis: 3_000 });
          try {
            await boundedCleanup(
              () => cleanupPool.query(`DROP DATABASE ${quoteIdentifier(databaseName)} WITH (FORCE)`),
              P0B_DATABASE_QUERY_TIMEOUT_MS,
              () => forceDestroyPool(cleanupPool)
            );
          } finally {
            await endPool(cleanupPool);
          }
        })();
      }
      await closePromise;
    },
    pool: databasePool
  });
}

export async function startP0BHarness({ env = process.env, repoRoot = REPOSITORY_ROOT, consoleBuild = true, waitTimeoutMs = 20_000, prepareDatabase } = {}) {
  if (env.P0B_DISABLE_EXTERNAL === "true") throw new P0BSkip("external_disabled", "P0-B external dependencies disabled");
  if (prepareDatabase !== undefined && typeof prepareDatabase !== "function") throw new TypeError("P0-B database preparation must be a function");
  const temp = await createP0BTempDirectory();
  let database;
  let cloudProcess;
  let consoleProcess;
  let cloudProxy;
  let consoleProxy;
  try {
    const certificates = await createTestCertificates(temp);
    database = await createDisposablePostgres({ env });
    const databaseAuthorities = await prepareP0BDatabaseAuthorities(database);
    const organizationId = crypto.randomUUID();
    const files = await createRuntimeFiles(temp);
    if (prepareDatabase) await prepareDatabase(Object.freeze({
      pool: database.pool,
      organizationId,
      refreshNonceKeyId: files.refreshNonceKeyId,
      refreshNonceKey: Buffer.from(files.refreshNonceKey)
    }));
    const deploymentDigests = await p0BDeploymentDigests({
      repoRoot,
      database,
      sourceCommit: env.P0B_SOURCE_COMMIT,
      sourceTree: env.P0B_SOURCE_TREE
    });
    const trustedCaBundle = await createTrustedCaBundle(temp, [certificates.caCert], [database.caCertificate]);
    const cloudPort = await reservePort();
    const cloudTlsPort = await reservePort();
    const consolePort = await reservePort();
    const consoleTlsPort = await reservePort();
    const common = {
      P0B_SOURCE_COMMIT: env.P0B_SOURCE_COMMIT,
      P0B_SOURCE_TREE: env.P0B_SOURCE_TREE,
      AGENTPASS_DATABASE_URL: databaseAuthorities.app,
      AGENTPASS_MIGRATION_DATABASE_URL: databaseAuthorities.migration,
      AGENTPASS_SIGNER_DATABASE_URL: databaseAuthorities.signer,
      AGENTPASS_MAINTENANCE_DATABASE_URL: databaseAuthorities.maintenance,
      AGENTPASS_MAINTENANCE_DATABASE_MAX_CONNECTIONS: "2",
      AGENTPASS_CLOUD_PROFILE: "hosted",
      AGENTPASS_CLOUD_HOST: LOOPBACK,
      AGENTPASS_CLOUD_PORT: cloudPort,
      AGENTPASS_CLOUD_CONTROL_BUNDLE_KEY_ID: "p0b-control-bundle-v1",
      AGENTPASS_CLOUD_CONTROL_BUNDLE_PUBLIC_KEY: files.controlBundlePublicKeyPem,
      AGENTPASS_CLOUD_CONTROL_BUNDLE_TIMEOUT_MS: "5000",
      AGENTPASS_CLOUD_CAPABILITY_KEY_ID: "p0b-capability-v1",
      AGENTPASS_CLOUD_CAPABILITY_PUBLIC_KEY: files.capabilityPublicKeyPem,
      AGENTPASS_CLOUD_CAPABILITY_TIMEOUT_MS: "5000",
      AGENTPASS_CLOUD_AUDIT_ANCHOR_KEY_ID: "p0b-audit-anchor-v1",
      AGENTPASS_CLOUD_AUDIT_ANCHOR_PUBLIC_KEY: files.auditAnchorPublicKeyPem,
      AGENTPASS_CLOUD_AUDIT_ANCHOR_TIMEOUT_MS: "5000",
      AGENTPASS_CLOUD_PROMOTION_EVIDENCE_KEY_ID: "p0b-promotion-evidence-v1",
      AGENTPASS_CLOUD_PROMOTION_EVIDENCE_PUBLIC_KEY: files.promotionEvidencePublicKeyPem,
      AGENTPASS_CLOUD_PROMOTION_EVIDENCE_TIMEOUT_MS: "5000",
      AGENTPASS_CLOUD_REFRESH_PUBLIC_KEY: files.refreshPublicKeyPem,
      AGENTPASS_CLOUD_REFRESH_TIMEOUT_MS: "5000",
      AGENTPASS_CLOUD_REFRESH_KEY_ID: "p0b-refresh-v1",
      AGENTPASS_CLOUD_REFRESH_NONCE_KEYRING_PATH: files.nonceKeyring,
      AGENTPASS_CAPABILITY_NONCE_SECRET: files.capabilitySecret,
      AGENTPASS_HUMAN_CURSOR_SECRET: files.cursorSecret,
      AGENTPASS_HUMAN_AUTH_SECRET: Buffer.alloc(32, 0x35).toString("base64url"),
      ...p0bHostedBootstrapEnvironment(consoleTlsPort),
      AGENTPASS_IDENTITY_PROVIDER: "chatgpt",
      AGENTPASS_OPERATIONAL_PROBE_SECRET: files.probeSecret,
      AGENTPASS_CONSOLE_ORIGIN: `https://localhost:${consoleTlsPort}`,
      AGENTPASS_WEBAUTHN_RP_ID: "localhost",
      AGENTPASS_IDENTITY_ASSERTION_ISSUER: "agentpass-p0b-console",
      AGENTPASS_IDENTITY_ASSERTION_AUDIENCE: "agentpass-p0b-cloud",
      AGENTPASS_IDENTITY_ASSERTION_KID: "p0b-console-v1",
      AGENTPASS_IDENTITY_ASSERTION_PUBLIC_KEY_PATH: files.identityPublicKey,
      AGENTPASS_CLOUD_AGENT_SESSION_KEY_ID: "p0b-agent-session-v1",
      AGENTPASS_CLOUD_AGENT_SESSION_PUBLIC_KEY: files.agentSessionPublicKeyPem,
      AGENTPASS_CLOUD_AGENT_SESSION_PROCESS_POLICIES_PATH: files.processPolicies,
      AGENTPASS_CLOUD_QUALIFICATION_MANIFEST_KEY_ID: "p0b-qualification-manifest-v1",
      AGENTPASS_CLOUD_QUALIFICATION_MANIFEST_PUBLIC_KEY: files.qualificationManifestPublicKeyPem,
      AGENTPASS_CLOUD_POSSESSION_RECEIPT_KEY_ID: "p0b-possession-receipt-v1",
      AGENTPASS_CLOUD_POSSESSION_RECEIPT_PUBLIC_KEY: files.possessionReceiptPublicKeyPem,
      AGENTPASS_KMS_PROVIDER: "aws",
      AGENTPASS_KMS_AGENT_SESSION_KEY_RESOURCE: "arn:aws:kms:us-east-1:000000000000:key/p0b-agent-session",
      AGENTPASS_KMS_QUALIFICATION_MANIFEST_KEY_RESOURCE: "arn:aws:kms:us-east-1:000000000000:key/p0b-qualification-manifest",
      AGENTPASS_KMS_POSSESSION_RECEIPT_KEY_RESOURCE: "arn:aws:kms:us-east-1:000000000000:key/p0b-possession-receipt",
      AGENTPASS_KMS_REFRESH_HINT_KEY_RESOURCE: "arn:aws:kms:us-east-1:000000000000:key/p0b-refresh-hint",
      AGENTPASS_KMS_CONTROL_BUNDLE_KEY_RESOURCE: "arn:aws:kms:us-east-1:000000000000:key/p0b-control-bundle",
      AGENTPASS_KMS_CAPABILITY_KEY_RESOURCE: "arn:aws:kms:us-east-1:000000000000:key/p0b-capability",
      AGENTPASS_KMS_AUDIT_ANCHOR_KEY_RESOURCE: "arn:aws:kms:us-east-1:000000000000:key/p0b-audit-anchor",
      AGENTPASS_KMS_PROMOTION_EVIDENCE_KEY_RESOURCE: "arn:aws:kms:us-east-1:000000000000:key/p0b-promotion-evidence",
      // Hosted runtime startup requires a complete deployment identity even
      // for this disposable qualification tenant. Keep these values fixed and
      // secret-free; release provenance is bound by the outer report.
      AGENTPASS_CLOUD_SOURCE_COMMIT: env.P0B_SOURCE_COMMIT,
      AGENTPASS_CLOUD_SOURCE_TREE: env.P0B_SOURCE_TREE,
      AGENTPASS_CLOUD_IMAGE_DIGEST: `sha256:${"c".repeat(64)}`,
      AGENTPASS_CLOUD_DEPLOYMENT_ID: "p0b-cloud",
      AGENTPASS_CLOUD_DEPLOYMENT_REVISION: "p0b",
      AGENTPASS_CLOUD_SCHEMA_DIGEST: deploymentDigests.schemaDigest,
      AGENTPASS_CLOUD_CATALOG_DIGEST: deploymentDigests.catalogDigest,
      AGENTPASS_CLOUD_DATABASE_SCHEMA_DIGEST: deploymentDigests.databaseSchemaDigest,
      AGENTPASS_OWNER_RECOVERY_NOTIFICATION_WEBHOOK_URL: "https://notifications.example.test/owner-recovery",
      AGENTPASS_OWNER_RECOVERY_NOTIFICATION_CONFIRMATION_URL: "https://notifications.example.test/owner-recovery/acceptance",
      AGENTPASS_OWNER_RECOVERY_NOTIFICATION_AUTHORIZATION_PATH: files.ownerRecoveryAuthorization,
      AGENTPASS_OWNER_RECOVERY_NOTIFICATION_BINDING_ID: "p0b-owner-recovery",
      AGENTPASS_OWNER_RECOVERY_NOTIFICATION_BINDING_KEY_VERSION: "1",
      AGENTPASS_OWNER_RECOVERY_NOTIFICATION_BINDING_DIGEST: "a".repeat(64),
      P0B_LIVE_BROWSER: "1",
      P0B_CONTROL_BUNDLE_PRIVATE_KEY_PATH: files.controlBundlePrivateKey,
      P0B_CAPABILITY_PRIVATE_KEY_PATH: files.capabilityPrivateKey,
      P0B_AUDIT_ANCHOR_PRIVATE_KEY_PATH: files.auditAnchorPrivateKey,
      P0B_PROMOTION_EVIDENCE_PRIVATE_KEY_PATH: files.promotionEvidencePrivateKey,
      P0B_AGENT_SESSION_PRIVATE_KEY_PATH: files.agentSessionPrivateKey,
      P0B_QUALIFICATION_MANIFEST_PRIVATE_KEY_PATH: files.qualificationManifestPrivateKey,
      P0B_POSSESSION_RECEIPT_PRIVATE_KEY_PATH: files.possessionReceiptPrivateKey,
      P0B_REFRESH_HINT_PRIVATE_KEY_PATH: files.refreshPrivateKey,
      NODE_EXTRA_CA_CERTS: trustedCaBundle
    };
    cloudProcess = spawnProcess(process.execPath, [P0B_CLOUD_PROCESS], repoRoot, p0bEnvironment(env, common));
    cloudProxy = await createTlsProxy({ cert: certificates.cert, key: certificates.key, targetPort: cloudPort, port: cloudTlsPort });
    await waitForHttps(`https://localhost:${cloudTlsPort}/`, certificates.caCert, { path: "/health/ready", headers: { "AgentPass-Operational-Token": files.probeSecret }, expectedStatus: 200, timeoutMs: waitTimeoutMs, process: cloudProcess, label: "cloud" });
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
      NODE_EXTRA_CA_CERTS: trustedCaBundle,
      VINEXT_TRUSTED_HOSTS: `localhost:${consoleTlsPort}`,
      WRANGLER_LOG_PATH: path.join(temp, "wrangler.log"),
      MINIFLARE_REGISTRY_PATH: path.join(temp, "registry")
    });
    if (consoleBuild && !fs.existsSync(path.join(repoRoot, "apps/web-console/dist"))) throw new P0BSkip("console_build_missing", "Console dist is missing; run the Console build before P0-B");
    consoleProcess = spawnProcess(process.execPath, [path.join(repoRoot, "apps/web-console/node_modules/vinext/dist/cli.js"), "start", "--hostname", LOOPBACK, "--port", String(consolePort)], path.join(repoRoot, "apps/web-console"), consoleEnv);
    consoleProxy = await createTlsProxy({ cert: certificates.cert, key: certificates.key, targetPort: consolePort, port: consoleTlsPort });
    await waitForHttps(`https://localhost:${consoleTlsPort}/`, certificates.caCert, { path: "/", expectedStatus: 200, timeoutMs: waitTimeoutMs, process: consoleProcess, label: "console" });
    return Object.freeze({
      cloudUrl: `https://localhost:${cloudTlsPort}/`, consoleUrl: `https://localhost:${consoleTlsPort}/`, caCert: certificates.caCert,
      tlsSpkiPin: await certificateSpkiPin(certificates.cert),
      databaseUrl: database.url, organizationId,
      cloudProcessState() {
        if (!cloudProcess) return "exited";
        return cloudProcess.p0bSpawnError || cloudProcess.exitCode !== null || cloudProcess.signalCode !== null ? "exited" : "running";
      },
      async cloudReadinessState() {
        if (!cloudProcess || cloudProcess.p0bSpawnError || cloudProcess.exitCode !== null || cloudProcess.signalCode !== null) return "unavailable";
        try {
          const ca = await fsp.readFile(certificates.caCert, "utf8");
          const result = await httpsRequest(new URL("/health/ready", `https://localhost:${cloudTlsPort}/`), {
            ca,
            headers: { "AgentPass-Operational-Token": files.probeSecret },
            timeoutMs: 1_500
          });
          return result.status === 200 ? "ready" : "unavailable";
        } catch {
          return "unavailable";
        }
      },
      async close() { await closeP0BHarness({ cloudProcess, consoleProcess, cloudProxy, consoleProxy, database, temp }); }
    });
  } catch (error) {
    await closeP0BHarness({ cloudProcess, consoleProcess, cloudProxy, consoleProxy, database, temp });
    if (error instanceof P0BSkip) throw error;
    if (error instanceof Error && error.message.startsWith("P0-B")) throw error;
    const diagnostic = redactP0BDiagnostic(error?.message ?? "unknown");
    throw new Error(`P0-B harness startup failed (${diagnostic || "unknown"})`);
  }
}

export function p0bHostedBootstrapEnvironment(consoleTlsPort) {
  if (!Number.isSafeInteger(consoleTlsPort) || consoleTlsPort < 1 || consoleTlsPort > 65_535) {
    throw new TypeError("P0-B Console TLS port is invalid");
  }
  const consoleOrigin = `https://localhost:${consoleTlsPort}`;
  return Object.freeze({
    AGENTPASS_GITHUB_CLIENT_ID: "agentpass-p0b-github-client",
    AGENTPASS_GITHUB_CLIENT_SECRET: "agentpass-p0b-github-secret",
    AGENTPASS_GITHUB_REDIRECT_URI: `${consoleOrigin}/api/auth/bootstrap/github/callback`,
    AGENTPASS_HOSTED_CONSOLE_ONBOARDING_URL: `${consoleOrigin}/onboarding`,
    AGENTPASS_HOSTED_PKCE_KEY_ID: "p0b-hosted-pkce-v1",
    AGENTPASS_HOSTED_PKCE_KEY: Buffer.alloc(32, 0x36).toString("base64url"),
    AGENTPASS_HOSTED_BOOTSTRAP_CSRF_KEY: Buffer.alloc(32, 0x37).toString("base64url"),
    AGENTPASS_HOSTED_WEBAUTHN_RESPONSE_KEY: Buffer.alloc(32, 0x38).toString("base64url")
  });
}

export async function closeP0BHarness({ cloudProcess, consoleProcess, cloudProxy, consoleProxy, database, temp } = {}) {
  await Promise.all([
    closeResource(consoleProxy, P0B_PROXY_CLOSE_TIMEOUT_MS),
    closeResource(cloudProxy, P0B_PROXY_CLOSE_TIMEOUT_MS)
  ]);
  await Promise.all([stopProcess(consoleProcess), stopProcess(cloudProcess)]);
  await closeResource(database, P0B_POOL_CLOSE_TIMEOUT_MS + P0B_DATABASE_QUERY_TIMEOUT_MS + P0B_POOL_CLOSE_TIMEOUT_MS);
  if (temp) await boundedCleanup(() => fsp.rm(temp, { recursive: true, force: true }), P0B_TEMP_CLEANUP_TIMEOUT_MS);
}

export function randomDatabaseName() { return `agentpass_p0b_${process.pid}_${crypto.randomBytes(6).toString("hex")}`.slice(0, 63); }

export function redactP0BDiagnostic(value, secrets = []) {
  let result = String(value ?? "").replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/gu, "?");
  for (const secret of secrets) {
    if (typeof secret === "string" && secret.length >= 4) result = result.replaceAll(secret, "<redacted>");
  }
  result = result.replace(/-----BEGIN [^-]*PRIVATE KEY-----[\s\S]*?-----END [^-]*PRIVATE KEY-----/gu, "<redacted-private-key>");
  result = result.replace(/(postgres(?:ql)?:\/\/[^\s/:@]+:)[^\s@]+(@)/giu, "$1<redacted>$2");
  result = result.replace(/(https?:\/\/[^\s/:@]+:)[^\s@]+(@)/giu, "$1<redacted>$2");
  result = result.replace(/(AGENTPASS_[A-Z0-9_]+=)[^\s]+/gu, "$1<redacted>");
  return result.slice(0, MAX_DIAGNOSTIC_OUTPUT);
}

async function createTrustedCaBundle(directory, files, certificates = []) {
  const contents = [];
  for (const file of files) contents.push(await fsp.readFile(file, "utf8"));
  for (const certificate of certificates.filter(Boolean)) contents.push(certificate);
  const bundle = path.join(directory, "trusted-ca-bundle.pem");
  await fsp.writeFile(bundle, `${contents.join("\n")}\n`, { mode: 0o600, flag: "wx" });
  return bundle;
}

async function dropDisposableDatabase(baseOptions, databaseName) {
  const cleanupPool = new Pool({ ...baseOptions, max: 1, connectionTimeoutMillis: 3_000, idleTimeoutMillis: 3_000 });
  try {
    await boundedCleanup(
      () => cleanupPool.query(`DROP DATABASE ${quoteIdentifier(databaseName)} WITH (FORCE)`),
      P0B_DATABASE_QUERY_TIMEOUT_MS,
      () => forceDestroyPool(cleanupPool)
    );
  } finally {
    await endPool(cleanupPool);
  }
}

async function createRuntimeFiles(directory) {
  const bundle = crypto.generateKeyPairSync("ed25519");
  const capability = crypto.generateKeyPairSync("ed25519");
  const auditAnchor = crypto.generateKeyPairSync("ed25519");
  const promotionEvidence = crypto.generateKeyPairSync("ed25519");
  const refresh = crypto.generateKeyPairSync("ed25519");
  const identity = crypto.generateKeyPairSync("ed25519");
  const agentSession = crypto.generateKeyPairSync("ed25519");
  const qualificationManifest = crypto.generateKeyPairSync("ed25519");
  const possessionReceipt = crypto.generateKeyPairSync("ed25519");
  const controlBundlePrivateKey = path.join(directory, "control-bundle-private.pem");
  const capabilityPrivateKey = path.join(directory, "capability-private.pem");
  const auditAnchorPrivateKey = path.join(directory, "audit-anchor-private.pem");
  const promotionEvidencePrivateKey = path.join(directory, "promotion-evidence-private.pem");
  const refreshPrivateKey = path.join(directory, "refresh-private.pem");
  const identityPublicKey = path.join(directory, "identity-public.pem");
  const agentSessionPrivateKey = path.join(directory, "agent-session-private.pem");
  const qualificationManifestPrivateKey = path.join(directory, "qualification-manifest-private.pem");
  const possessionReceiptPrivateKey = path.join(directory, "possession-receipt-private.pem");
  const processPolicies = path.join(directory, "agent-session-process-policies.json");
  const ownerRecoveryAuthorization = path.join(directory, "owner-recovery-notification-authorization");
  await writePrivate(controlBundlePrivateKey, bundle.privateKey.export({ type: "pkcs8", format: "pem" }));
  await writePrivate(capabilityPrivateKey, capability.privateKey.export({ type: "pkcs8", format: "pem" }));
  await writePrivate(auditAnchorPrivateKey, auditAnchor.privateKey.export({ type: "pkcs8", format: "pem" }));
  await writePrivate(promotionEvidencePrivateKey, promotionEvidence.privateKey.export({ type: "pkcs8", format: "pem" }));
  await writePrivate(refreshPrivateKey, refresh.privateKey.export({ type: "pkcs8", format: "pem" }));
  await fsp.writeFile(identityPublicKey, identity.publicKey.export({ type: "spki", format: "pem" }), { mode: 0o600, flag: "wx" });
  await writePrivate(agentSessionPrivateKey, agentSession.privateKey.export({ type: "pkcs8", format: "pem" }));
  await writePrivate(qualificationManifestPrivateKey, qualificationManifest.privateKey.export({ type: "pkcs8", format: "pem" }));
  await writePrivate(possessionReceiptPrivateKey, possessionReceipt.privateKey.export({ type: "pkcs8", format: "pem" }));
  await writePrivate(processPolicies, `${JSON.stringify({ version: 1, policies: [{ policy_id: "claude-code-v1", release_id: "agentpass-0.18.0", agent_kind: "claude-code", adapter_id: "33333333-3333-4333-8333-333333333333", adapter_versions: ["1.0.0"], status: "enabled" }] })}\n`);
  await writePrivate(ownerRecoveryAuthorization, "p0b-owner-recovery-authorization");
  const nonceKeyring = path.join(directory, "refresh-nonce-keyring.json");
  const refreshNonceKeyId = "refresh-nonce-v1";
  const refreshNonceKey = crypto.randomBytes(32);
  await writePrivate(nonceKeyring, `${JSON.stringify({ version: 1, active_key_id: refreshNonceKeyId, keys: { [refreshNonceKeyId]: refreshNonceKey.toString("base64url") } })}\n`);
  return Object.freeze({
    controlBundlePrivateKey, capabilityPrivateKey, auditAnchorPrivateKey, promotionEvidencePrivateKey,
    refreshPrivateKey, identityPublicKey, nonceKeyring,
    agentSessionPrivateKey, qualificationManifestPrivateKey, possessionReceiptPrivateKey, processPolicies, ownerRecoveryAuthorization,
    controlBundlePublicKeyPem: bundle.publicKey.export({ type: "spki", format: "pem" }).toString(),
    capabilityPublicKeyPem: capability.publicKey.export({ type: "spki", format: "pem" }).toString(),
    auditAnchorPublicKeyPem: auditAnchor.publicKey.export({ type: "spki", format: "pem" }).toString(),
    promotionEvidencePublicKeyPem: promotionEvidence.publicKey.export({ type: "spki", format: "pem" }).toString(),
    agentSessionPublicKeyPem: agentSession.publicKey.export({ type: "spki", format: "pem" }).toString(),
    qualificationManifestPublicKeyPem: qualificationManifest.publicKey.export({ type: "spki", format: "pem" }).toString(),
    possessionReceiptPublicKeyPem: possessionReceipt.publicKey.export({ type: "spki", format: "pem" }).toString(),
    refreshPublicKeyPem: refresh.publicKey.export({ type: "spki", format: "pem" }).toString(),
    refreshNonceKeyId, refreshNonceKey,
    identityPrivateKeyPem: identity.privateKey.export({ type: "pkcs8", format: "pem" }),
    capabilitySecret: crypto.randomBytes(32).toString("base64url"), cursorSecret: crypto.randomBytes(32).toString("base64url"),
    probeSecret: crypto.randomBytes(32).toString("base64url")
  });
}

async function writePrivate(file, value) { await fsp.writeFile(file, value, { mode: 0o600, flag: "wx" }); await fsp.chmod(file, 0o600); }

function quoteIdentifier(value) { return `"${value.replaceAll('"', '""')}"`; }

async function reservePort() {
  const server = net.createServer();
  try {
    await new Promise((resolve, reject) => { server.once("error", reject); server.listen(0, LOOPBACK, resolve); });
  } catch (error) {
    if (isSocketPermissionError(error)) throw new P0BSkip("socket_unavailable", "P0-B real socket transport is unavailable in this environment");
    throw error;
  }
  const port = server.address().port;
  await new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
  return port;
}

export async function listenP0BTestServer(server, { port = 0, host = LOOPBACK } = {}) {
  if (!server || typeof server.listen !== "function") throw new TypeError("P0-B test server is required");
  try {
    await new Promise((resolve, reject) => { server.once("error", reject); server.listen(port, host, resolve); });
  } catch (error) {
    if (isSocketPermissionError(error)) throw new P0BSkip("socket_unavailable", "P0-B real socket transport is unavailable in this environment");
    throw error;
  }
  return server.address();
}

function spawnProcess(command, args, cwd, env) {
  const child = spawn(command, args, { cwd, env, shell: false, detached: process.platform !== "win32", stdio: ["ignore", "pipe", "pipe"] });
  const secrets = Object.entries(env).filter(([key]) => key.startsWith("AGENTPASS_") || key.startsWith("P0B_")).map(([, value]) => value);
  child.p0bDiagnostics = { secrets, stdout: "", stderr: "" };
  child.once("error", (error) => { child.p0bSpawnError = error?.message ?? "unknown"; });
  capture(child.stdout, child.p0bDiagnostics, "stdout");
  capture(child.stderr, child.p0bDiagnostics, "stderr");
  return child;
}

function capture(stream, target, key) {
  if (!stream) return;
  stream.on("data", (chunk) => { target[key] = `${target[key]}${chunk}`.slice(-MAX_CAPTURED_OUTPUT); });
  stream.resume();
}

function processDiagnostic(child) {
  if (!child) return "";
  const state = child.p0bSpawnError ? `spawn_error_${redactP0BDiagnostic(child.p0bSpawnError)}` : child.signalCode ? `signal_${child.signalCode}` : child.exitCode !== null ? `exit_${child.exitCode}` : "running";
  const output = [child.p0bDiagnostics?.stdout, child.p0bDiagnostics?.stderr].filter(Boolean).join("\n");
  const safeOutput = output ? `; output=${redactP0BDiagnostic(output, child.p0bDiagnostics?.secrets)}` : "";
  return `${state}${safeOutput}`;
}

// Reduce child startup output to a reviewed category before it crosses the
// fixture boundary. The raw diagnostics remain redacted and are never emitted
// by the supervisor; only these fixed classes are consumed by browser tests.
export function classifyP0BProcessStartup(child) {
  const output = [child?.p0bDiagnostics?.stdout, child?.p0bDiagnostics?.stderr].filter(Boolean).join("\n");
  if (output.includes("P0B_CLOUD_START_DEPENDENCY_FAILED")) return "dependency_start_failed";
  if (output.includes("P0B_CLOUD_START_CONFIG_FAILED")) return "config_start_failed";
  if (output.includes("P0B_CLOUD_START_POSTGRES_FAILED")) return "postgres_start_failed";
  if (output.includes("P0B_CLOUD_START_SIGNER_FAILED")) return "signer_start_failed";
  if (output.includes("P0B_CLOUD_START_PLATFORM_SESSION_FAILED")) return "platform_session_start_failed";
  if (output.includes("P0B_CLOUD_START_UNKNOWN_FAILED")) return "unknown_start_failed";
  if (/ERR_KMS_PROVIDER_RUNTIME_CONFIG|ERR_KMS_PROVIDER_RUNTIME_SDK|ERR_KMS_PROVIDER_RUNTIME_UNAVAILABLE/u.test(output)) return "kms_start_failed";
  if (/ERR_MODULE_NOT_FOUND|Cannot find package/u.test(output)) return "dependency_start_failed";
  if (/P0-B signer (?:public key|private key|path)/u.test(output)) return "signer_start_failed";
  return "start_failed";
}

async function boundedCleanup(task, timeoutMs, onAbort) {
  const timedOut = Symbol("cleanup_timeout");
  let timer;
  const operation = Promise.resolve().then(task).then(() => true, () => false);
  const timeout = new Promise((resolve) => {
    timer = setTimeout(() => resolve(timedOut), timeoutMs);
  });
  const result = await Promise.race([operation, timeout]);
  clearTimeout(timer);
  if (result === timedOut || result === false) {
    try { onAbort?.(); } catch {}
    return false;
  }
  return true;
}

async function closeResource(resource, timeoutMs) {
  if (!resource || (typeof resource !== "object" && typeof resource !== "function") || typeof resource.close !== "function") return;
  let closePromise = RESOURCE_CLOSE_PROMISES.get(resource);
  if (!closePromise) {
    closePromise = boundedCleanup(() => resource.close(), timeoutMs);
    RESOURCE_CLOSE_PROMISES.set(resource, closePromise);
  }
  await closePromise;
}

async function endPool(pool) {
  if (!pool || typeof pool.end !== "function") return true;
  return boundedCleanup(() => pool.end(), P0B_POOL_CLOSE_TIMEOUT_MS, () => forceDestroyPool(pool));
}

function forceDestroyPool(pool) {
  const clients = new Set([
    ...(Array.isArray(pool?._clients) ? pool._clients : []),
    ...(Array.isArray(pool?._idle) ? pool._idle.map((item) => item?.client).filter(Boolean) : [])
  ]);
  for (const item of pool?._idle ?? []) {
    try { clearTimeout(item?.timeoutId); } catch {}
  }
  for (const client of clients) {
    try { client.connection?.stream?.destroy(); } catch {}
  }
}

function processExited(child) {
  return Boolean(child?.p0bSpawnError) || child?.exitCode != null || child?.signalCode != null;
}

function sendProcessSignal(child, signal) {
  const pid = child?.pid;
  if (Number.isSafeInteger(pid) && pid > 0) {
    if (process.platform !== "win32") {
      try { process.kill(-pid, signal); } catch {}
    }
    try { process.kill(pid, signal); } catch {}
  }
  try { child?.kill?.(signal); } catch {}
}

function waitForProcessExit(child, timeoutMs) {
  if (processExited(child)) return Promise.resolve(true);
  return new Promise((resolve) => {
    let settled = false;
    let timer;
    const finish = (exited) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      child.removeListener?.("exit", onExit);
      child.removeListener?.("error", onError);
      resolve(exited);
    };
    const onExit = () => finish(true);
    const onError = () => finish(processExited(child));
    child.once?.("exit", onExit);
    child.once?.("error", onError);
    if (processExited(child)) {
      finish(true);
      return;
    }
    timer = setTimeout(() => finish(processExited(child)), timeoutMs);
  });
}

async function stopProcess(child) {
  if (!child || typeof child !== "object") return;
  let stopPromise = PROCESS_STOP_PROMISES.get(child);
  if (!stopPromise) {
    stopPromise = (async () => {
      if (processExited(child)) return;
      sendProcessSignal(child, "SIGTERM");
      if (await waitForProcessExit(child, P0B_PROCESS_TERM_TIMEOUT_MS)) return;
      sendProcessSignal(child, "SIGKILL");
      if (!await waitForProcessExit(child, P0B_PROCESS_FORCE_TIMEOUT_MS)) {
        try { child.stdout?.destroy(); } catch {}
        try { child.stderr?.destroy(); } catch {}
        try { child.unref?.(); } catch {}
      }
    })();
    PROCESS_STOP_PROMISES.set(child, stopPromise);
  }
  await stopPromise;
}

async function createTlsProxy({ cert, key, targetPort, port }) {
  const sockets = new Set();
  const upstreams = new Set();
  const server = https.createServer({ cert: await fsp.readFile(cert), key: await fsp.readFile(key), minVersion: "TLSv1.2", requestCert: false }, (request, response) => {
    const externalHost = request.headers.host;
    const headers = { ...request.headers, host: externalHost, "x-forwarded-proto": "https", "x-forwarded-host": externalHost };
    delete headers.connection; delete headers["proxy-connection"]; delete headers["keep-alive"];
    const upstream = http.request({ host: LOOPBACK, port: targetPort, method: request.method, path: request.url, headers }, (incoming) => { response.writeHead(incoming.statusCode ?? 502, incoming.headers); incoming.pipe(response); });
    upstreams.add(upstream);
    upstream.once("close", () => upstreams.delete(upstream));
    upstream.on("error", () => { if (!response.headersSent) response.writeHead(502); response.end(); });
    request.once("aborted", () => upstream.destroy());
    response.once("close", () => { if (!response.writableEnded) upstream.destroy(); });
    request.pipe(upstream);
  });
  server.requestTimeout = 15_000;
  server.headersTimeout = 10_000;
  server.keepAliveTimeout = 1_000;
  server.on("connection", (socket) => { sockets.add(socket); socket.once("close", () => sockets.delete(socket)); });
  try {
    await new Promise((resolve, reject) => { server.once("error", reject); server.listen(port, LOOPBACK, resolve); });
  } catch (error) {
    try { server.close(); } catch {}
    if (isSocketPermissionError(error)) throw new P0BSkip("socket_unavailable", "P0-B real socket transport is unavailable in this environment");
    throw error;
  }
  let closePromise;
  const forceClose = () => {
    try { server.closeIdleConnections?.(); } catch {}
    try { server.closeAllConnections?.(); } catch {}
    for (const upstream of upstreams) {
      try { upstream.destroy(); } catch {}
    }
    for (const socket of sockets) {
      try { socket.destroy(); } catch {}
    }
  };
  return Object.freeze({
    port,
    async close() {
      if (!closePromise) {
        closePromise = (async () => {
          let closeOperation;
          try {
            closeOperation = new Promise((resolve) => server.close(() => resolve()));
          } catch {
            closeOperation = Promise.resolve();
          }
          forceClose();
          await boundedCleanup(closeOperation, P0B_PROXY_CLOSE_TIMEOUT_MS, forceClose);
        })();
      }
      await closePromise;
    }
  });
}

function isSocketPermissionError(error) {
  return error?.code === "EPERM" || error?.code === "EACCES" || /listen\s+EPERM|operation not permitted|permission denied/iu.test(String(error?.message ?? ""));
}

async function waitForHttps(origin, ca, { path: requestPath, headers = {}, expectedStatus = 200, timeoutMs = 20_000, process: child, label = "service" } = {}) {
  const caPem = await fsp.readFile(ca, "utf8");
  const deadline = Date.now() + timeoutMs;
  let lastError;
  while (Date.now() < deadline) {
    if (child?.p0bSpawnError || child?.exitCode !== null || child?.signalCode !== null) {
      const category = classifyP0BProcessStartup(child);
      throw new Error(`P0-B ${label} ${category} before readiness (${processDiagnostic(child)})`);
    }
    try {
      const result = await httpsRequest(new URL(requestPath, origin), { ca: caPem, headers, timeoutMs: 1_500 });
      if (result.status === expectedStatus) return result;
      const readinessCode = safeReadinessCode(result.body);
      lastError = new Error(`status_${result.status}${readinessCode ? `_${readinessCode}` : ""}`);
    } catch (error) { lastError = error; }
    await new Promise((resolve) => setTimeout(resolve, 150));
  }
  const detail = redactP0BDiagnostic(lastError?.message ?? "unavailable");
  const readinessDiagnostic = /^status_\d+_[a-z][a-z0-9_]{0,63}$/u.test(detail) ? detail : "transport_or_timeout";
  const unknownCheckKey = readinessDiagnostic.match(/^status_503_health_unknown_key_([a-z][a-z0-9_]*)$/u)?.[1];
  const readinessMarker = unknownCheckKey !== undefined
    ? `P0B_SAFE_LIFECYCLE_CLOUD_HEALTH_UNKNOWN_KEY_${unknownCheckKey.toUpperCase()}_FAILED`
    : readinessDiagnostic === "status_503_health_unknown_key_metrics"
    ? "P0B_SAFE_LIFECYCLE_CLOUD_HEALTH_UNKNOWN_METRICS_FAILED"
    : readinessDiagnostic === "status_503_health_unknown_key_agent_session_signer"
      ? "P0B_SAFE_LIFECYCLE_CLOUD_HEALTH_UNKNOWN_AGENT_SESSION_FAILED"
      : readinessDiagnostic === "status_503_health_unknown_key_qualification_manifest_signer"
        ? "P0B_SAFE_LIFECYCLE_CLOUD_HEALTH_UNKNOWN_MANIFEST_FAILED"
        : readinessDiagnostic === "status_503_health_unknown_key_possession_receipt_signer"
          ? "P0B_SAFE_LIFECYCLE_CLOUD_HEALTH_UNKNOWN_POSSESSION_FAILED"
          : readinessDiagnostic === "status_503_health_unknown_key_refresh_hint_signer"
            ? "P0B_SAFE_LIFECYCLE_CLOUD_HEALTH_UNKNOWN_REFRESH_FAILED"
            : readinessDiagnostic === "status_503_health_unknown_key_capability_signer"
              ? "P0B_SAFE_LIFECYCLE_CLOUD_HEALTH_UNKNOWN_CAPABILITY_FAILED"
              : readinessDiagnostic === "status_503_health_unknown_key_control_bundle_signer"
                ? "P0B_SAFE_LIFECYCLE_CLOUD_HEALTH_UNKNOWN_CONTROL_BUNDLE_FAILED"
                : readinessDiagnostic === "status_503_health_unknown_key_audit_anchor_signer"
                  ? "P0B_SAFE_LIFECYCLE_CLOUD_HEALTH_UNKNOWN_AUDIT_ANCHOR_FAILED"
                  : readinessDiagnostic === "status_503_health_unknown_key_promotion_evidence_signer"
                    ? "P0B_SAFE_LIFECYCLE_CLOUD_HEALTH_UNKNOWN_PROMOTION_EVIDENCE_FAILED"
    : readinessDiagnostic === "status_503_health_unknown_key_managed_signers"
      ? "P0B_SAFE_LIFECYCLE_CLOUD_HEALTH_UNKNOWN_MANAGED_SIGNERS_FAILED"
      : readinessDiagnostic === "status_503_health_unknown_key_owner_recovery_outbox"
        ? "P0B_SAFE_LIFECYCLE_CLOUD_HEALTH_UNKNOWN_OWNER_OUTBOX_FAILED"
        : readinessDiagnostic === "status_503_health_unknown_key_managed_signer_provider_operations"
          ? "P0B_SAFE_LIFECYCLE_CLOUD_HEALTH_UNKNOWN_PROVIDER_OPERATIONS_FAILED"
          : readinessDiagnostic === "status_503_health_unknown_key_device_audit_inbox"
            ? "P0B_SAFE_LIFECYCLE_CLOUD_HEALTH_UNKNOWN_DEVICE_AUDIT_FAILED"
    : readinessDiagnostic === "status_503_health_unknown_key_outbox"
      ? "P0B_SAFE_LIFECYCLE_CLOUD_HEALTH_UNKNOWN_OUTBOX_FAILED"
      : readinessDiagnostic === "status_503_health_unknown_key_providerOperations"
        ? "P0B_SAFE_LIFECYCLE_CLOUD_HEALTH_UNKNOWN_PROVIDER_OPERATIONS_FAILED"
        : readinessDiagnostic === "status_503_health_unknown_key_deviceAuditInbox"
          ? "P0B_SAFE_LIFECYCLE_CLOUD_HEALTH_UNKNOWN_DEVICE_AUDIT_FAILED"
          : readinessDiagnostic === "status_503_health_database"
    ? "P0B_SAFE_LIFECYCLE_CLOUD_HEALTH_DATABASE_FAILED"
    : readinessDiagnostic === "status_503_health_schema"
      ? "P0B_SAFE_LIFECYCLE_CLOUD_HEALTH_SCHEMA_FAILED"
      : readinessDiagnostic === "status_503_health_pool"
        ? "P0B_SAFE_LIFECYCLE_CLOUD_HEALTH_POOL_FAILED"
        : readinessDiagnostic === "status_503_health_drain"
          ? "P0B_SAFE_LIFECYCLE_CLOUD_HEALTH_DRAIN_FAILED"
          : readinessDiagnostic === "status_503_health_platform_session"
            ? "P0B_SAFE_LIFECYCLE_CLOUD_HEALTH_PLATFORM_SESSION_FAILED"
            : readinessDiagnostic === "status_503_health_platform_promotion"
              ? "P0B_SAFE_LIFECYCLE_CLOUD_HEALTH_PLATFORM_PROMOTION_FAILED"
              : readinessDiagnostic === "status_503_health_signer_set"
                ? "P0B_SAFE_LIFECYCLE_CLOUD_HEALTH_SIGNER_SET_FAILED"
                : readinessDiagnostic === "status_503_health_unknown_key"
                  ? "P0B_SAFE_LIFECYCLE_CLOUD_HEALTH_UNKNOWN_CHECK_FAILED"
                  : readinessDiagnostic === "status_503_health_invalid_readiness_checks"
                    ? "P0B_SAFE_LIFECYCLE_CLOUD_HEALTH_INVALID_READINESS_CHECKS_FAILED"
    : readinessDiagnostic === "status_503_health_invalid_deployment_identity"
      ? "P0B_SAFE_LIFECYCLE_CLOUD_HEALTH_INVALID_DEPLOYMENT_IDENTITY_FAILED"
      : readinessDiagnostic === "status_503_health_invalid_managed_signers"
        ? "P0B_SAFE_LIFECYCLE_CLOUD_HEALTH_INVALID_MANAGED_SIGNERS_FAILED"
        : readinessDiagnostic === "status_503_health_invalid_readiness_report"
          ? "P0B_SAFE_LIFECYCLE_CLOUD_HEALTH_INVALID_REPORT_FAILED"
          : readinessDiagnostic.startsWith("status_503_health_invalid_")
            ? "P0B_SAFE_LIFECYCLE_CLOUD_HEALTH_INVALID_READINESS_FAILED"
    : readinessDiagnostic === "status_503_health_unavailable"
    ? "P0B_SAFE_LIFECYCLE_CLOUD_HEALTH_UNAVAILABLE_FAILED"
    : readinessDiagnostic === "status_503_schema_identity_unavailable"
      ? "P0B_SAFE_LIFECYCLE_CLOUD_SCHEMA_UNAVAILABLE_FAILED"
      : "P0B_SAFE_LIFECYCLE_CLOUD_READINESS_DIAGNOSTIC_FAILED";
  process.stdout.write(`${readinessMarker}\n`);
  throw new Error(`P0-B ${label} readiness failed (${detail || "unavailable"}; ${processDiagnostic(child) || "process_unknown"})`);
}

function safeReadinessCode(body) {
  if (typeof body !== "string" || body.length > 64 * 1024) return null;
  const match = body.match(/"code"\s*:\s*"([a-z][a-z0-9_]{0,63})"/u);
  return match?.[1] ?? null;
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

function decodeUrlComponent(value, label) {
  try {
    const decoded = decodeURIComponent(value);
    if (!decoded) throw new Error("empty");
    return decoded;
  } catch {
    throw new TypeError(`${label} is invalid`);
  }
}
