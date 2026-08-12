import assert from "node:assert/strict";
import https from "node:https";
import fs from "node:fs/promises";
import test from "node:test";
import { Pool } from "pg";

import {
  P0BSkip,
  createVerifiedPostgresPoolOptions,
  createP0BTempDirectory,
  createTestCertificates,
  p0bEnvironment,
  readPostgresCaFile,
  redactP0BDiagnostic,
  requireTrustedHttpsLoopback,
  requireVerifiedPostgresUrl,
  startP0BHarness
} from "./harness.mjs";

test("P0-B accepts only trusted HTTPS loopback origins", () => {
  assert.equal(requireTrustedHttpsLoopback("https://localhost:443/").hostname, "localhost");
  assert.equal(requireTrustedHttpsLoopback("https://[::1]/").hostname, "[::1]");
  for (const value of ["http://localhost/", "https://example.test/", "https://localhost/?x=1", "https://user@localhost/", "https://localhost/#fragment"]) {
    assert.throws(() => requireTrustedHttpsLoopback(value), /trusted HTTPS/);
  }
});

test("P0-B PostgreSQL validation requires verify-full and no extra parameters", () => {
  assert.equal(requireVerifiedPostgresUrl("postgresql://user:secret@db.test/agentpass?sslmode=verify-full").hostname, "db.test");
  for (const value of ["postgresql://user:secret@db.test/agentpass", "postgresql://user:secret@db.test/agentpass?sslmode=require", "postgresql://user:secret@db.test/agentpass?sslmode=verify-full&x=1"]) {
    assert.throws(() => requireVerifiedPostgresUrl(value), /verify-full/);
  }
  assert.throws(() => createVerifiedPostgresPoolOptions(new URL("postgresql://user:secret@db.test/agentpass?sslmode=require")), /verify-full/);
});

test("child environments remove inherited AgentPass secrets and Node injection knobs", () => {
  const env = p0bEnvironment({ PATH: "/bin", AGENTPASS_CLOUD_TOKEN: "do-not-copy", NODE_OPTIONS: "--require evil", NODE_EXTRA_CA_CERTS: "/tmp/ca.pem", HOME: "/tmp" }, { P0B_MARKER: "ok" });
  assert.equal(env.P0B_MARKER, "ok");
  assert.equal(Object.hasOwn(env, "AGENTPASS_CLOUD_TOKEN"), false);
  assert.equal(Object.hasOwn(env, "NODE_OPTIONS"), false);
  assert.equal(Object.hasOwn(env, "NODE_EXTRA_CA_CERTS"), false);
});

test("certificate generation is temporary and creates a localhost CA chain", async (t) => {
  const directory = await createP0BTempDirectory("agentpass-p0b-test-");
  t.after(() => fs.rm(directory, { recursive: true, force: true }));
  const certificates = await createTestCertificates(directory);
  assert.match(await fs.readFile(certificates.caCert, "utf8"), /BEGIN CERTIFICATE/);
  assert.match(await fs.readFile(certificates.key, "utf8"), /BEGIN (?:RSA )?PRIVATE KEY/);
  const mode = (await fs.stat(certificates.key)).mode & 0o777;
  assert.equal(mode, 0o600);
  const ca = await readPostgresCaFile(certificates.caCert);
  assert.equal(ca.file, certificates.caCert);
  assert.match(ca.pem, /BEGIN CERTIFICATE/);
});

test("node-postgres receives explicit CA and hostname verification without connection-string SSL override", async (t) => {
  const ca = "-----BEGIN CERTIFICATE-----\ntrusted-ca\n-----END CERTIFICATE-----\n";
  const options = createVerifiedPostgresPoolOptions("postgresql://user:p%40ss@db.example.test:5433/agentpass?sslmode=verify-full", { ca });
  const pool = new Pool(options);
  t.after(() => pool.end());
  assert.equal(pool.options.connectionString, undefined);
  assert.equal(pool.options.host, "db.example.test");
  assert.equal(pool.options.port, 5433);
  assert.equal(pool.options.user, "user");
  assert.equal(pool.options.password, "p@ss");
  assert.equal(pool.options.ssl.rejectUnauthorized, true);
  assert.equal(pool.options.ssl.ca, ca);
});

test("generated certificate is accepted for localhost and rejected for a different hostname", async (t) => {
  const directory = await createP0BTempDirectory("agentpass-p0b-tls-");
  t.after(() => fs.rm(directory, { recursive: true, force: true }));
  const certificates = await createTestCertificates(directory);
  const server = https.createServer({ cert: await fs.readFile(certificates.cert), key: await fs.readFile(certificates.key) }, (_request, response) => response.end("ok"));
  await new Promise((resolve, reject) => { server.once("error", reject); server.listen(0, "127.0.0.1", resolve); });
  t.after(() => new Promise((resolve) => server.close(() => resolve())));
  const port = server.address().port;
  const ca = await fs.readFile(certificates.caCert, "utf8");
  await assertHttps({ port, ca, servername: "localhost" }, 200);
  await assert.rejects(assertHttps({ port, ca, servername: "wrong.example" }), /hostname|certificate|altname/i);
});

test("PostgreSQL CA files reject writable, private-key, and non-CA material without leaking contents", async (t) => {
  const directory = await createP0BTempDirectory("agentpass-p0b-ca-");
  t.after(() => fs.rm(directory, { recursive: true, force: true }));
  const privateKey = `${directory}/private.pem`;
  await fs.writeFile(privateKey, "-----BEGIN PRIVATE KEY-----\nnever-print-this\n-----END PRIVATE KEY-----\n", { mode: 0o600 });
  await assert.rejects(readPostgresCaFile(privateKey), (error) => error instanceof TypeError && !error.message.includes("never-print-this"));
  const writable = `${directory}/writable.pem`;
  await fs.writeFile(writable, "-----BEGIN CERTIFICATE-----\ninvalid\n-----END CERTIFICATE-----\n", { mode: 0o666 });
  await assert.rejects(readPostgresCaFile(writable), /CA file/);
});

test("diagnostic redaction removes credentials, PEMs, and bounded output", () => {
  const diagnostic = redactP0BDiagnostic("postgresql://user:secret@db/agentpass?sslmode=verify-full -----BEGIN PRIVATE KEY-----secret-----END PRIVATE KEY-----", ["secret"]);
  assert.doesNotMatch(diagnostic, /secret|BEGIN PRIVATE KEY/);
  assert.ok(diagnostic.length <= 2_048);
});

test("missing external dependencies produce an explicit skip without waiting", async () => {
  await assert.rejects(startP0BHarness({ env: { P0B_DISABLE_EXTERNAL: "true" } }), (error) => error instanceof P0BSkip && error.code === "external_disabled");
});

function assertHttps({ port, ca, servername }, expectedStatus) {
  return new Promise((resolve, reject) => {
    const request = https.request({ hostname: "127.0.0.1", port, servername, path: "/", ca, rejectUnauthorized: true }, (response) => {
      response.resume();
      response.once("end", () => expectedStatus === undefined ? resolve(response.statusCode) : response.statusCode === expectedStatus ? resolve(response.statusCode) : reject(new Error(`unexpected status ${response.statusCode}`)));
    });
    request.once("error", reject);
    request.end();
  });
}
