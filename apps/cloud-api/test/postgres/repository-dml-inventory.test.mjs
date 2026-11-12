import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

// Live CI tests mostly connect as the `postgres` superuser, so a repository that
// regresses to direct DML against an authority-owned table would still pass
// there and only fail in production under `agentpass_app`. This inventory keeps
// that one invariant: the listed repository sources issue no direct
// INSERT/UPDATE/DELETE against their protected tables (reads and the exact
// authority-function call shapes are intentionally not asserted here).
const SRC = new URL("../../src/", import.meta.url);

const MANAGED_SIGNER_TABLES = [
  "managed_signer_key_lifecycles",
  "managed_signer_keys",
  "managed_signer_key_lifecycle_operations",
  "managed_signer_signing_idempotency",
  "managed_signer_provider_operations"
];

const MAINTENANCE_TABLES = [
  "maintenance_jobs",
  "maintenance_effects",
  "maintenance_results",
  "maintenance_pull_requests",
  "maintenance_receipts"
];

const INVENTORY = [
  ["postgres/agent-session-authority-repository.mjs", ["agent_session_grants", "agent_sessions"]],
  ["postgres/agent-session-lifecycle-repository.mjs", ["agent_session_grants", "agent_sessions"]],
  ["postgres/qualification-grant-batch-repository.mjs", ["agent_session_grants", "agent_sessions"]],
  ["postgres/human-repository.mjs", ["human_sessions", "webauthn_credentials", "upstream_identities"]],
  ["human-auth/identity/postgres-resolver.mjs", ["upstream_identities"]],
  ["identity-bind.mjs", ["upstream_identities"]],
  [
    "postgres/organization-repository.mjs",
    ["organizations", "memberships", "organization_invitations", "human_sessions", "webauthn_challenges"]
  ],
  ["postgres/owner-recovery-repository.mjs", ["webauthn_credentials", "memberships", "human_sessions"]],
  ["postgres/provider-operation-repository.mjs", MANAGED_SIGNER_TABLES],
  ["postgres/provider-operation-maintenance-repository.mjs", MANAGED_SIGNER_TABLES],
  ["postgres/managed-signer-key-lifecycle-repository.mjs", MANAGED_SIGNER_TABLES],
  ["postgres/maintenance-job-repository.mjs", MAINTENANCE_TABLES],
  ["postgres/maintenance-effect-repository.mjs", MAINTENANCE_TABLES],
  ["postgres/maintenance-result-repository.mjs", MAINTENANCE_TABLES],
  ["postgres/maintenance-pull-request-repository.mjs", MAINTENANCE_TABLES],
  ["postgres/maintenance-receipt-repository.mjs", MAINTENANCE_TABLES]
];

function directDml(source, tables) {
  const pattern = new RegExp(
    `\\b(INSERT\\s+INTO|UPDATE|DELETE\\s+FROM)\\s+(?:ONLY\\s+)?(?:public\\.)?"?(${tables.join("|")})"?(?![A-Za-z0-9_])`,
    "giu"
  );
  return [...source.matchAll(pattern)].map((match) => `${match[1].replace(/\s+/gu, " ").toUpperCase()} ${match[2]}`);
}

test("the DML detector recognizes direct writes to a protected table", () => {
  const tables = ["human_sessions"];
  assert.deepEqual(directDml("UPDATE human_sessions SET revoked_at = now()", tables), ["UPDATE human_sessions"]);
  assert.deepEqual(directDml("insert into public.human_sessions (id) values ($1)", tables), ["INSERT INTO human_sessions"]);
  assert.deepEqual(directDml("DELETE FROM\n  human_sessions WHERE id = $1", tables), ["DELETE FROM human_sessions"]);
  assert.deepEqual(directDml("UPDATE human_sessions_archive SET x = 1", tables), []);
  assert.deepEqual(directDml("SELECT public.agentpass_human_session_touch($1::uuid)", tables), []);
});

for (const [file, tables] of INVENTORY) {
  test(`${file} issues no direct DML against ${tables.join(", ")}`, async () => {
    const source = await readFile(new URL(file, SRC), "utf8");
    assert.deepEqual(directDml(source, tables), [], `${file} must route these writes through authority functions`);
  });
}
