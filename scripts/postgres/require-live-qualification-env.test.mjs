import assert from "node:assert/strict";
import test from "node:test";

import {
  LivePostgresQualificationEnvironmentError,
  validateLivePostgresQualificationEnvironment,
} from "./require-live-qualification-env.mjs";

const base = Object.freeze({
  AGENTPASS_TEST_DATABASE_URL: "postgresql://test:test@127.0.0.1:5432/agentpass",
  AGENTPASS_TEST_POSTGRES_ADMIN_URL: "postgresql://admin:admin@127.0.0.1:5432/agentpass",
  AGENTPASS_TEST_APP_DATABASE_URL: "postgresql://app:app@127.0.0.1:5432/agentpass",
});

test("requires both admin and application role DSNs", () => {
  assert.throws(() => validateLivePostgresQualificationEnvironment({ ...base, AGENTPASS_TEST_APP_DATABASE_URL: undefined }), LivePostgresQualificationEnvironmentError);
  assert.throws(() => validateLivePostgresQualificationEnvironment({ ...base, AGENTPASS_TEST_POSTGRES_ADMIN_URL: undefined }), LivePostgresQualificationEnvironmentError);
});

test("accepts only PostgreSQL URL schemes and returns no secret-bearing projection", () => {
  const result = validateLivePostgresQualificationEnvironment(base);
  assert.deepEqual(Object.keys(result), ["validated_keys"]);
  assert.deepEqual(result.validated_keys, [
    "AGENTPASS_TEST_DATABASE_URL",
    "AGENTPASS_TEST_POSTGRES_ADMIN_URL",
    "AGENTPASS_TEST_APP_DATABASE_URL",
  ]);
  assert.throws(() => validateLivePostgresQualificationEnvironment({ ...base, AGENTPASS_TEST_APP_DATABASE_URL: "https://example.test/db" }), LivePostgresQualificationEnvironmentError);
});
