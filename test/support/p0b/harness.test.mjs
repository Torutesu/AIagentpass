import assert from "node:assert/strict";
import fs from "node:fs/promises";
import test from "node:test";

import {
  P0BSkip,
  createP0BTempDirectory,
  createTestCertificates,
  p0bEnvironment,
  requireTrustedHttpsLoopback,
  requireVerifiedPostgresUrl,
  startP0BHarness
} from "./harness.mjs";

test("P0-B accepts only trusted HTTPS loopback origins", () => {
  assert.equal(requireTrustedHttpsLoopback("https://localhost:443/").hostname, "localhost");
  for (const value of ["http://localhost/", "https://example.test/", "https://localhost/?x=1", "https://user@localhost/"]) {
    assert.throws(() => requireTrustedHttpsLoopback(value), /trusted HTTPS/);
  }
});

test("P0-B PostgreSQL validation requires verify-full and no extra parameters", () => {
  assert.equal(requireVerifiedPostgresUrl("postgresql://user:secret@db.test/agentpass?sslmode=verify-full").hostname, "db.test");
  for (const value of ["postgresql://user:secret@db.test/agentpass", "postgresql://user:secret@db.test/agentpass?sslmode=require", "postgresql://user:secret@db.test/agentpass?sslmode=verify-full&x=1"]) {
    assert.throws(() => requireVerifiedPostgresUrl(value), /verify-full/);
  }
});

test("child environments remove inherited AgentPass secrets and Node injection knobs", () => {
  const env = p0bEnvironment({ PATH: "/bin", AGENTPASS_CLOUD_TOKEN: "do-not-copy", NODE_OPTIONS: "--require evil", HOME: "/tmp" }, { P0B_MARKER: "ok" });
  assert.equal(env.P0B_MARKER, "ok");
  assert.equal(Object.hasOwn(env, "AGENTPASS_CLOUD_TOKEN"), false);
  assert.equal(Object.hasOwn(env, "NODE_OPTIONS"), false);
});

test("certificate generation is temporary and creates a localhost CA chain", async (t) => {
  const directory = await createP0BTempDirectory("agentpass-p0b-test-");
  t.after(() => fs.rm(directory, { recursive: true, force: true }));
  const certificates = await createTestCertificates(directory);
  assert.match(await fs.readFile(certificates.caCert, "utf8"), /BEGIN CERTIFICATE/);
  assert.match(await fs.readFile(certificates.key, "utf8"), /BEGIN (?:RSA )?PRIVATE KEY/);
  const mode = (await fs.stat(certificates.key)).mode & 0o777;
  assert.equal(mode, 0o600);
});

test("missing external dependencies produce an explicit skip without waiting", async () => {
  await assert.rejects(startP0BHarness({ env: { P0B_DISABLE_EXTERNAL: "true" } }), (error) => error instanceof P0BSkip && error.code === "external_disabled");
});
