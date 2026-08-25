import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import { POSTGRES_SCHEMA_HEAD } from "../../src/postgres/schema-head.mjs";

const root = new URL("../../../../", import.meta.url);
const read = (path) => readFile(new URL(path, root), "utf8");

test("0060 remains the cataloged forward-only first-organization authority migration", async () => {
  const [sql, catalog] = await Promise.all([
    read("contracts/postgres/0060_hosted_first_organization_atomic.sql"),
    read("contracts/catalog-v1.json").then(JSON.parse)
  ]);
  assert.ok(POSTGRES_SCHEMA_HEAD.version >= 60);
  assert.equal(POSTGRES_SCHEMA_HEAD.migrations.find(({ version }) => version === 60)?.name, "0060_hosted_first_organization_atomic.sql");
  assert.match(sql, /^BEGIN;[\s\S]*COMMIT;\s*$/u);
  assert.doesNotMatch(sql, /DROP\s+(?:TABLE|COLUMN|INDEX)|TRUNCATE\s+TABLE/iu);
  const entry = catalog.entries.find(({ id }) => id === "migration.0060_hosted_first_organization_atomic");
  assert.equal(entry?.version, 60);
});

test("0060 derives organization, membership, replay, and audit state in one function", async () => {
  const sql = await read("contracts/postgres/0060_hosted_first_organization_atomic.sql");
  assert.match(sql, /agentpass_hosted_identity_bootstrap_organization_commit_v2\([\s\S]*p_organization_name text,[\s\S]*p_organization_id uuid,[\s\S]*p_membership_id uuid,[\s\S]*p_audit_event_id uuid/u);
  assert.match(sql, /p_request_hash IS DISTINCT FROM sha256\(convert_to\(p_organization_name, 'UTF8'\)\)/u);
  assert.match(sql, /FROM public\.hosted_identity_bootstrap_attempts AS a[\s\S]*FOR UPDATE/u);
  assert.match(sql, /FROM public\.members AS m WHERE m\.id = attempt_row\.member_id FOR UPDATE/u);
  assert.match(sql, /SELECT count\(\*\) INTO membership_count[\s\S]*WHERE m\.member_id = attempt_row\.member_id/u);
  assert.match(sql, /INSERT INTO public\.organizations[\s\S]*INSERT INTO public\.memberships[\s\S]*'owner', 'active'/u);
  assert.match(sql, /INSERT INTO public\.hosted_identity_bootstrap_idempotency[\s\S]*public_result/u);
  assert.match(sql, /INSERT INTO public\.admin_audit_events[\s\S]*UPDATE public\.admin_audit_heads/u);
  assert.match(sql, /SET state = 'webauthn_required', organization_id = organization_row\.id/u);
});

test("0060 replay is canonical and the browser cannot select public or audit payloads", async () => {
  const sql = await read("contracts/postgres/0060_hosted_first_organization_atomic.sql");
  assert.match(sql, /RETURN QUERY SELECT 200, prior_row\.response_json, true/u);
  assert.match(sql, /RETURN QUERY SELECT 201, public_result, false/u);
  assert.match(sql, /jsonb_build_object\([\s\S]*'organization_id', organization_row\.id[\s\S]*'state', 'webauthn_required'/u);
  assert.match(sql, /audit_json := jsonb_build_object\([\s\S]*'source', 'hosted_bootstrap'/u);
  assert.match(sql, /audit_hash := encode\(sha256\(convert_to\(audit_json::text, 'UTF8'\)\), 'hex'\)/u);
  assert.doesNotMatch(sql, /p_public_response|p_role|p_member_id|p_audit_json|p_audit_hash/u);
});

test("0060 replaces legacy runtime EXECUTE with the v2 authority", async () => {
  const [sql, roles, checker] = await Promise.all([
    read("contracts/postgres/0060_hosted_first_organization_atomic.sql"),
    read("scripts/postgres/roles.sql"),
    read("scripts/postgres/role-privilege-check.mjs")
  ]);
  const signature = "agentpass_hosted_identity_bootstrap_organization_commit_v2(bytea,text,bytea,text,uuid,uuid,uuid)";
  assert.doesNotMatch(sql, /agentpass_app|agentpass_backup|agentpass_signer/u);
  assert.match(sql, /REVOKE ALL PRIVILEGES ON FUNCTION public\.agentpass_hosted_identity_bootstrap_organization_commit_v2\([^;]+\) FROM PUBLIC/u);
  assert.ok(roles.includes(`'${signature}'`));
  assert.ok(checker.includes(`('${signature}')`));
  assert.doesNotMatch(roles, /'agentpass_hosted_identity_bootstrap_organization_commit\(bytea,text,bytea,uuid,uuid,jsonb\)'/u);
  assert.doesNotMatch(checker, /\('agentpass_hosted_identity_bootstrap_organization_commit\(bytea,text,bytea,uuid,uuid,jsonb\)'\)/u);
});
