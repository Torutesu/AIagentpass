import assert from "node:assert/strict";
import test from "node:test";
import { runExternalPostgresC3Qualification, PostgresExternalQualificationRunnerError } from "./run-postgres-c3-external.mjs";

test("external PostgreSQL runner requires explicit real execution", async () => {
  await assert.rejects(() => runExternalPostgresC3Qualification({ env: {} }), PostgresExternalQualificationRunnerError);
});

test("external PostgreSQL runner rejects local runner and incomplete release binding", async () => {
  await assert.rejects(() => runExternalPostgresC3Qualification({ env: {
    AGENTPASS_POSTGRES_QUALIFICATION_ENABLED: "true",
    AGENTPASS_POSTGRES_QUALIFICATION_EXECUTION: "external",
    AGENTPASS_POSTGRES_QUALIFICATION_REAL_EXECUTION: "true",
    AGENTPASS_POSTGRES_QUALIFICATION_RUNNER_ID: "local-test"
  } }), PostgresExternalQualificationRunnerError);
});
