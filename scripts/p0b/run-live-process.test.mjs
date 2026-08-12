import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import {
  buildTestEnvironment,
  parseArgs,
  parseProtectedEnvironment,
  readProtectedEnvironment,
  stableReason
} from "./run-live-process.mjs";

const ADMIN_URL = "postgresql://agentpass:password@localhost:5432/agentpass?sslmode=verify-full";
const ENV_CONTENT = [
  `P0B_POSTGRES_ADMIN_URL=${ADMIN_URL}`,
  `AGENTPASS_TEST_POSTGRES_ADMIN_URL=${ADMIN_URL}`,
  "P0B_POSTGRES_CA_FILE=/tmp/p0b/ca.pem",
  "PGSSLROOTCERT=/tmp/p0b/ca.pem",
  "P0B_POSTGRES_TLS_STATE_FILE=/tmp/agentpass-p0b-postgres-tls/state.json",
  "P0B_POSTGRES_TLS_IMAGE=postgres:17-alpine",
  "P0B_POSTGRES_TLS_CONTAINER_ID=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
  ""
].join("\n");

test("protected fixture environment is parsed without shell evaluation", async () => {
  const parsed = parseProtectedEnvironment(ENV_CONTENT);
  assert.equal(parsed.P0B_POSTGRES_ADMIN_URL, ADMIN_URL);
  assert.equal(parsed.P0B_POSTGRES_CA_FILE, "/tmp/p0b/ca.pem");
  assert.throws(() => parseProtectedEnvironment(`${ENV_CONTENT}EVIL=$(touch /tmp/p0b-owned)\n`), /unsupported key/);
  assert.throws(() => parseProtectedEnvironment(ENV_CONTENT.replace("P0B_POSTGRES_CA_FILE=/tmp/p0b/ca.pem", "P0B_POSTGRES_CA_FILE=relative.pem")), /absolute/);
});

test("protected environment file requires owner-only permissions and never returns diagnostics", async () => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), "agentpass-p0b-orchestrator-test-"));
  const file = path.join(directory, "fixture.env");
  try {
    await fs.writeFile(file, ENV_CONTENT, { mode: 0o600 });
    const parsed = await readProtectedEnvironment(file);
    assert.equal(parsed.PGSSLROOTCERT, "/tmp/p0b/ca.pem");
    await fs.chmod(file, 0o640);
    await assert.rejects(readProtectedEnvironment(file), (error) => error.code === "invalid_env_file");
  } finally {
    await fs.rm(directory, { recursive: true, force: true });
  }
});

test("test environment overrides stale external-disable state without printing secrets", () => {
  const env = buildTestEnvironment({ PATH: "/bin", P0B_DISABLE_EXTERNAL: "true" }, { P0B_POSTGRES_ADMIN_URL: ADMIN_URL });
  assert.equal(env.P0B_DISABLE_EXTERNAL, "false");
  assert.equal(env.P0B_POSTGRES_ADMIN_URL, ADMIN_URL);
});

test("diagnostic reason is stable and code-only", () => {
  assert.equal(stableReason({ code: "docker_missing", message: "secret" }), "docker_missing");
  assert.equal(stableReason({ code: "postgres://user:secret@host/db" }), "error");
  assert.equal(stableReason(new Error("secret")), "error");
  assert.deepEqual(parseArgs(["--fixture-timeout-ms", "1200", "--fixture-image", "postgres:17-alpine"]), {
    fixtureTimeoutMs: 1200,
    fixtureImage: "postgres:17-alpine"
  });
});
