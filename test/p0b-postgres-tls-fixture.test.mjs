import assert from "node:assert/strict";
import { execFile as execFileCallback } from "node:child_process";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { promisify } from "node:util";
import test from "node:test";

import {
  buildAdminUrl,
  collectFixtureProvenance,
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

test("collectFixtureProvenance returns only safe Docker and PostgreSQL metadata", async (t) => {
  const fixture = await createProvenanceFixture(t);
  const dockerCalls = [];
  const clientConfigs = [];
  let queryText = "";
  class FakeClient {
    constructor(config) {
      clientConfigs.push(config);
    }

    async connect() {}

    async query(query) {
      queryText = query;
      return {
        rows: [{
          server_version: "17.5 (AgentPass qualification build)",
          server_version_num: "170005",
          ssl: true
        }]
      };
    }

    async end() {}
  }

  const provenance = await collectFixtureProvenance({
    ...fixture,
    Client: FakeClient,
    runDocker: async (args) => {
      dockerCalls.push(args);
      return fixture.manifest.container_id + "\tsha256:" + "b".repeat(64) + "\t" + fixture.startedAt + "\tagentpass.p0b.postgres-tls\t" + fixture.manifest.state_file + "\n";
    }
  });

  assert.deepEqual(provenance, {
    image: fixture.manifest.image,
    image_digest: "sha256:" + "b".repeat(64),
    container_id: fixture.manifest.container_id,
    container_started_at: fixture.startedAt,
    server_version: "17.5"
  });
  assert.equal(dockerCalls.length, 1);
  assert.equal(dockerCalls[0][0], "inspect");
  assert.equal(dockerCalls[0][1], "--format");
  assert.equal(dockerCalls[0][3], fixture.manifest.container_id);
  assert.match(dockerCalls[0][2], /\.Id/u);
  assert.match(dockerCalls[0][2], /\.Image/u);
  assert.match(dockerCalls[0][2], /\.State\.StartedAt/u);
  assert.match(dockerCalls[0][2], /\.Config\.Labels/u);
  assert.doesNotMatch(dockerCalls[0][2], /\.Config\.Env|\.Config\.Mounts|json/u);
  assert.equal(clientConfigs.length, 1);
  assert.equal(clientConfigs[0].ssl.rejectUnauthorized, true);
  assert.equal(clientConfigs[0].ssl.servername, "localhost");
  assert.equal(clientConfigs[0].ssl.ca, "test-ca\n");
  assert.match(queryText, /pg_stat_ssl/u);
  assert.match(queryText, /server_version_num/u);
});

test("collectFixtureProvenance rejects malformed, future, and foreign Docker metadata", async (t) => {
  const fixture = await createProvenanceFixture(t);
  const validDigest = "sha256:" + "b".repeat(64);
  const inspect = (id, startedAt, fixtureLabel = "agentpass.p0b.postgres-tls", stateFile = fixture.manifest.state_file) => (
    id + "\t" + validDigest + "\t" + startedAt + "\t" + fixtureLabel + "\t" + stateFile + "\n"
  );
  const run = (output) => async () => output;
  const noDb = class {
    async connect() {}
    async end() {}
  };

  await assertProvenanceError(
    collectFixtureProvenance({
      ...fixture,
      Client: noDb,
      runDocker: run("malformed")
    }),
    "provenance_container_metadata_invalid"
  );
  await assertProvenanceError(
    collectFixtureProvenance({
      ...fixture,
      Client: noDb,
      runDocker: async () => {
        throw new Error("password=do-not-leak");
      }
    }),
    "provenance_docker_inspect_failed"
  );
  await assertProvenanceError(
    collectFixtureProvenance({
      ...fixture,
      Client: noDb,
      runDocker: run(inspect(fixture.manifest.container_id, new Date(Date.now() + 60_000).toISOString()))
    }),
    "provenance_container_started_in_future"
  );
  await assertProvenanceError(
    collectFixtureProvenance({
      ...fixture,
      Client: noDb,
      runDocker: run(inspect(fixture.manifest.container_id, fixture.startedAt, "other.fixture"))
    }),
    "provenance_ownership_mismatch"
  );
});

test("collectFixtureProvenance rejects manifest and protected environment identity mismatches", async (t) => {
  const fixture = await createProvenanceFixture(t);
  await fs.writeFile(fixture.envFile, [
    "P0B_POSTGRES_ADMIN_URL=" + fixture.adminUrl,
    "AGENTPASS_TEST_POSTGRES_ADMIN_URL=" + fixture.adminUrl,
    "P0B_POSTGRES_CA_FILE=" + fixture.caFile,
    "PGSSLROOTCERT=" + fixture.caFile,
    "P0B_POSTGRES_TLS_STATE_FILE=" + fixture.manifest.state_file,
    "P0B_POSTGRES_TLS_IMAGE=" + fixture.manifest.image,
    "P0B_POSTGRES_TLS_CONTAINER_ID=" + "c".repeat(64),
    ""
  ].join("\n"), { mode: 0o600 });
  await fs.chmod(fixture.envFile, 0o600);

  await assertProvenanceError(
    collectFixtureProvenance({
      ...fixture,
      Client: class {},
      runDocker: async () => ""
    }),
    "invalid_manifest_identity"
  );
});

test("collectFixtureProvenance requires a TLS PostgreSQL 17 connection", async (t) => {
  const fixture = await createProvenanceFixture(t);
  const inspect = async () => fixture.manifest.container_id + "\tsha256:" + "b".repeat(64) + "\t" + fixture.startedAt + "\tagentpass.p0b.postgres-tls\t" + fixture.manifest.state_file + "\n";
  const clientFor = (row) => class {
    constructor(config) {
      this.config = config;
    }

    async connect() {}

    async query() {
      return { rows: [row] };
    }

    async end() {}
  };

  await assertProvenanceError(
    collectFixtureProvenance({
      ...fixture,
      Client: clientFor({ server_version: "17.5", server_version_num: "170005", ssl: false }),
      runDocker: inspect
    }),
    "provenance_postgres_not_tls"
  );
  await assertProvenanceError(
    collectFixtureProvenance({
      ...fixture,
      Client: clientFor({ server_version: "16.4", server_version_num: "160004", ssl: true }),
      runDocker: inspect
    }),
    "provenance_postgres_version_invalid"
  );
});

async function createProvenanceFixture(t) {
  const rootDir = await createFixtureRoot("agentpass-p0b-postgres-tls-provenance-test-");
  t.after(() => fs.rm(rootDir, { recursive: true, force: true }));
  const manifest = {
    schema_version: 1,
    fixture: "agentpass-p0b-postgres-tls",
    status: "ready",
    image: "postgres:17-alpine",
    container_id: "a".repeat(64),
    host: "localhost",
    port: 54_321,
    database: "agentpass_p0b",
    user: "agentpass_p0b",
    root_dir: rootDir,
    state_file: path.join(rootDir, "state.json"),
    env_file: path.join(rootDir, "fixture.env"),
    ca_file: path.join(rootDir, "ca.cert.pem"),
    started_at: new Date(Date.now() - 1_000).toISOString()
  };
  const credentials = {
    user: manifest.user,
    password: "test-password",
    database: manifest.database
  };
  const adminUrl = buildAdminUrl({ ...credentials, port: manifest.port });
  const caFile = manifest.ca_file;
  const environment = [
    "P0B_POSTGRES_ADMIN_URL=" + adminUrl,
    "AGENTPASS_TEST_POSTGRES_ADMIN_URL=" + adminUrl,
    "P0B_POSTGRES_CA_FILE=" + caFile,
    "PGSSLROOTCERT=" + caFile,
    "P0B_POSTGRES_TLS_STATE_FILE=" + manifest.state_file,
    "P0B_POSTGRES_TLS_IMAGE=" + manifest.image,
    "P0B_POSTGRES_TLS_CONTAINER_ID=" + manifest.container_id,
    ""
  ].join("\n");
  await fs.writeFile(caFile, "test-ca\n", { mode: 0o600 });
  await fs.writeFile(manifest.env_file, environment, { mode: 0o600 });
  await fs.chmod(caFile, 0o600);
  await fs.chmod(manifest.env_file, 0o600);
  return { manifest, adminUrl, caFile, envFile: manifest.env_file, startedAt: manifest.started_at };
}

async function assertProvenanceError(promise, code) {
  await assert.rejects(promise, (error) => (
    error?.code === code
    && !/password|test-ca/iu.test(error.message)
    && !error.message.includes("postgresql://")
  ));
}
