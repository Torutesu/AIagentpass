import assert from "node:assert/strict";
import crypto from "node:crypto";
import { readFile } from "node:fs/promises";
import test from "node:test";

const ROOT = new URL("../../../../", import.meta.url);
const migrationUrl = new URL("contracts/postgres/0109_invitation_authority.sql", ROOT);
const catalogUrl = new URL("contracts/catalog-v1.json", ROOT);
const rolesUrl = new URL("scripts/postgres/roles.sql", ROOT);
const checkerUrl = new URL("scripts/postgres/role-privilege-check.mjs", ROOT);

function compact(value) { return value.replace(/\s+/gu, " "); }

test("0109 exposes invitation SECURITY DEFINER authority functions", async () => {
  const sql = await readFile(migrationUrl, "utf8");
  const names = [
    "agentpass_organization_invitation_create",
    "agentpass_organization_invitation_revoke",
    "agentpass_organization_invitation_reissue",
    "agentpass_organization_invitation_accept",
    "agentpass_organization_invitation_list"
  ];
  assert.equal((sql.match(/CREATE FUNCTION /gu) ?? []).length, 5);
  assert.equal((sql.match(/^SECURITY DEFINER$/gmu) ?? []).length, 5);
  assert.equal((sql.match(/SET search_path = pg_catalog, public/gu) ?? []).length, 5);
  for (const name of names) assert.match(sql, new RegExp(`CREATE FUNCTION public\\.${name}\\(`, "u"));
  assert.match(sql, /GRANT EXECUTE ON FUNCTION public\.agentpass_organization_invitation_accept[\s\S]*TO agentpass_app/u);
  assert.match(sql, /REVOKE ALL PRIVILEGES ON FUNCTION public\.agentpass_organization_invitation_accept[\s\S]*FROM PUBLIC, agentpass_signer, agentpass_backup, agentpass_maintenance/u);
  assert.match(sql, /GRANT EXECUTE ON FUNCTION public\.agentpass_organization_invitation_list[\s\S]*TO agentpass_app/u);
});

test("0109 keeps writes inside authority functions and preserves tenant/actor/CAS checks", async () => {
  const sql = await readFile(migrationUrl, "utf8");
  assert.doesNotMatch(sql, /INSERT INTO public\.(admin_audit_events|outbox_events)/u);
  for (const predicate of [
    "p_organization_id IS NULL",
    "p_actor_member_id IS NULL",
    "p_token_hash IS NULL",
    "octet_length(p_token_hash) <> 32",
    "m.organization_id = p_organization_id",
    "m.member_id = p_actor_member_id",
    "p_expected_version",
    "i.organization_id = p_organization_id",
    "i.revoked_at IS NULL",
    "i.consumed_at IS NULL"
  ]) assert.ok(sql.includes(predicate), `missing predicate: ${predicate}`);
  const acceptStart = sql.indexOf("CREATE FUNCTION public.agentpass_organization_invitation_accept");
  const accept = sql.slice(acceptStart);
  assert.ok(acceptStart >= 0);
  assert.ok(accept.indexOf("INSERT INTO public.memberships") < accept.indexOf("UPDATE public.organization_invitations"));
  assert.match(accept, /INSERT INTO public\.memberships[\s\S]*ON CONFLICT \(organization_id, member_id\) DO UPDATE/u);
  assert.match(accept, /UPDATE public\.organization_invitations[\s\S]*p_token_hash/u);
  assert.match(accept, /agentpass:human:authority:[\s\S]*agentpass:organization:[\s\S]*agentpass:human:sessions:/u);
  assert.match(accept, /membership_id uuid[\s\S]*membership_updated_at timestamptz/u);
});

test("0109 repository-facing return shapes never include a token digest", async () => {
  const sql = compact(await readFile(migrationUrl, "utf8"));
  const returns = sql.split("RETURNS TABLE").slice(1).map((part) => part.slice(0, part.indexOf(") LANGUAGE")));
  assert.equal(returns.length, 5);
  for (const shape of returns) assert.doesNotMatch(shape, /token_hash/iu);
  assert.match(sql, /invitation_consumed_by uuid/);
  assert.match(sql, /membership_role text/);
});

test("0109 is catalog-bound and bootstrap/checker allow all signatures", async () => {
  const [source, catalogText, roles, checker] = await Promise.all([
    readFile(migrationUrl, "utf8"), readFile(catalogUrl, "utf8"), readFile(rolesUrl, "utf8"), readFile(checkerUrl, "utf8")
  ]);
  const catalog = JSON.parse(catalogText);
  const entry = catalog.entries.find((candidate) => candidate?.source === "postgres/0109_invitation_authority.sql");
  assert.ok(entry);
  assert.equal(entry.version, 109);
  assert.equal(entry.sha256, crypto.createHash("sha256").update(source, "utf8").digest("hex"));
  for (const signature of [
    "agentpass_organization_invitation_create(uuid,uuid,bytea,text,uuid,timestamptz,timestamptz)",
    "agentpass_organization_invitation_revoke(uuid,uuid,bigint,timestamptz,uuid,text)",
    "agentpass_organization_invitation_reissue(uuid,uuid,bytea,timestamptz,timestamptz,bigint,uuid)",
    "agentpass_organization_invitation_accept(uuid,uuid,bytea,uuid,timestamptz)",
    "agentpass_organization_invitation_list(uuid,uuid,timestamptz,uuid,integer)"
  ]) {
    assert.ok(roles.includes(`'${signature}'`), `roles.sql missing ${signature}`);
    assert.ok(checker.includes(`('${signature}')`), `role checker missing ${signature}`);
  }
  assert.match(roles, /'organizations', 'memberships', 'organization_invitations'/u);
  assert.doesNotMatch(roles, /GRANT SELECT ON TABLE public\.organizations, public\.memberships, public\.organization_invitations TO agentpass_app/u);
  assert.match(roles, /GRANT SELECT ON TABLE public\.organizations, public\.memberships TO agentpass_app/u);
  const repository = await readFile(new URL("../../src/postgres/organization-repository.mjs", import.meta.url), "utf8");
  assert.doesNotMatch(repository, /(?:INSERT INTO|UPDATE|DELETE FROM)\s+organization_invitations/u);
  assert.doesNotMatch(repository, /(?:INSERT INTO|UPDATE|DELETE FROM)\s+memberships/u);
});
