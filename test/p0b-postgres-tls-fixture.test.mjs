import assert from "node:assert/strict";
import { execFile as execFileCallback } from "node:child_process";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { promisify } from "node:util";
import test from "node:test";

import {
  buildAdminUrl,
  createFixtureRoot,
  createTlsMaterial,
  generateCredentials,
  parseArgs,
  startFixture,
  stopFixture
} from "../scripts/p0b/postgres-tls/fixture.mjs";

const execFile = promisify(execFileCallback);

test("P0-B PostgreSQL TLS fixture emits verify-full URL and never puts credentials in the public manifest", async (t) => {
  const directory = await createFixtureRoot("agentpass-p0b-postgres-tls-test-");
  t.after(() => fs.rm(directory, { recursive: true, force: true }));
  const credentials = generateCredentials({ randomBytes: () => Buffer.alloc(32, 0x41) });
  const url = buildAdminUrl({ ...credentials, port: 54321 });
  assert.match(url, /^postgresql:\/\/agentpass_p0b:[^@]+@localhost:54321\/agentpass_p0b\?sslmode=verify-full$/u);
  assert.equal(url.includes(credentials.password), true);
  const publicData = { env_file: path.join(directory, "fixture.env"), ca_file: path.join(directory, "ca.cert.pem"), port: 54321 };
  assert.equal(JSON.stringify(publicData).includes(credentials.password), false);
  assert.equal((await fs.stat(directory)).mode & 0o777, 0o700);
});

test("P0-B certificate has localhost SAN and protected key material", async (t) => {
  const directory = await createFixtureRoot("agentpass-p0b-postgres-tls-cert-");
  t.after(() => fs.rm(directory, { recursive: true, force: true }));
  const files = await createTlsMaterial(directory);
  const { stdout } = await execFile("openssl", ["x509", "-in", files.serverCertificate, "-noout", "-text"]);
  assert.match(stdout, /DNS:localhost/);
  assert.match(stdout, /IP Address:127\.0\.0\.1/);
  assert.equal((await fs.stat(files.serverKey)).mode & 0o777, 0o600);
  assert.equal((await fs.stat(files.serverCertificate)).mode & 0o777, 0o600);
});

test("P0-B CLI parses only PostgreSQL 17 images and requires state for lifecycle commands", () => {
  assert.equal(parseArgs(["start"]).image, "postgres:17-alpine");
  assert.equal(parseArgs(["start", "--image", "registry.example/postgres:17.6-alpine"]).image, "registry.example/postgres:17.6-alpine");
  assert.throws(() => parseArgs(["start", "--image", "postgres:16-alpine"]), /PostgreSQL 17/);
  assert.throws(() => parseArgs(["stop"]), /requires --state-file/);
});

test("P0-B Docker fixture starts with TLS when explicitly requested", async (t) => {
  if (process.env.P0B_POSTGRES_TLS_DOCKER_TEST !== "1") {
    t.skip("set P0B_POSTGRES_TLS_DOCKER_TEST=1 to run the Docker qualification");
    return;
  }
  let fixture;
  try {
    fixture = await startFixture({ timeoutMs: 60_000 });
  } catch (error) {
    if (["docker_missing", "openssl_missing"].includes(error?.code)) {
      t.skip(error.code);
      return;
    }
    throw error;
  }
  t.after(async () => stopFixture(fixture.state_file));
  const environment = await fs.readFile(fixture.env_file, "utf8");
  assert.match(environment, /sslmode=verify-full/);
  assert.doesNotMatch(JSON.stringify(fixture), /POSTGRES_PASSWORD|password|postgresql:\/\/[^\n]*:[^\n@]+@/iu);
  assert.equal(fixture.host, "localhost");
  assert.equal(fixture.database, "agentpass_p0b");
});

test("fixture temp roots are created below the operating system temp directory", async () => {
  const directory = await createFixtureRoot();
  await fs.rm(directory, { recursive: true, force: true });
  assert.equal(path.dirname(directory), os.tmpdir());
});
