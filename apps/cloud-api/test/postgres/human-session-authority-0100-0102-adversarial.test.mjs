import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const migrations = {
  switch: new URL("../../../../contracts/postgres/0100_human_session_switch_authority.sql", import.meta.url),
  managedRevoke: new URL("../../../../contracts/postgres/0101_human_session_managed_revoke_authority.sql", import.meta.url),
  revokeOthers: new URL("../../../../contracts/postgres/0102_human_session_revoke_others_authority.sql", import.meta.url),
};
const repository = new URL("../../src/postgres/human-repository.mjs", import.meta.url);
const roles = new URL("../../../../scripts/postgres/roles.sql", import.meta.url);
const privilegeCheck = new URL("../../../../scripts/postgres/role-privilege-check.mjs", import.meta.url);

const signatures = {
  agentpass_human_session_switch: "uuid,bytea,uuid,uuid,uuid,uuid,bytea,bytea,timestamptz,timestamptz,timestamptz,timestamptz,timestamptz,text",
  agentpass_human_session_revoke_managed: "uuid,uuid,uuid,uuid,bigint,timestamptz,text",
  agentpass_human_session_revoke_others: "uuid,uuid,uuid,timestamptz,text",
};

async function read(url) {
  return readFile(url, "utf8");
}

function escaped(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&");
}

function functionBody(sql, name) {
  const start = sql.indexOf(`CREATE FUNCTION public.${name}(`);
  assert.notEqual(start, -1, `missing ${name}`);
  const end = sql.indexOf("\n$$;", start);
  assert.notEqual(end, -1, `unterminated ${name}`);
  return sql.slice(start, end + 4);
}

function assertContainsAll(body, fragments, label) {
  for (const fragment of fragments) {
    assert.match(body, new RegExp(escaped(fragment), "u"), `${label} must contain ${fragment}`);
  }
}

test("0100-0102 use the exact SECURITY DEFINER, search_path, owner, and ACL contract", async () => {
  const [switchSql, managedSql, othersSql, roleSql, checker] = await Promise.all([
    read(migrations.switch),
    read(migrations.managedRevoke),
    read(migrations.revokeOthers),
    read(roles),
    read(privilegeCheck),
  ]);

  for (const [name, sql] of [
    ["agentpass_human_session_switch", switchSql],
    ["agentpass_human_session_revoke_managed", managedSql],
    ["agentpass_human_session_revoke_others", othersSql],
  ]) {
    const signature = signatures[name];
    const functionSignature = `public.${name}`;
    const functionSignaturePattern = `public\\.${escaped(name)}\\(\\s*${signature.split(",").map(escaped).join("\\s*,\\s*")}\\s*\\)`;
    const body = functionBody(sql, name);
    const compactSql = sql.replace(/\s+/gu, " ");
    assert.equal((body.match(/^SECURITY DEFINER$/gmu) ?? []).length, 1, `${name} must be SECURITY DEFINER exactly once`);
    assert.equal((body.match(/^SET search_path = pg_catalog, public$/gmu) ?? []).length, 1, `${name} must pin search_path exactly once`);
    assert.match(compactSql, new RegExp(`ALTER FUNCTION ${functionSignaturePattern} OWNER TO agentpass_migrator;`, "u"));
    assert.match(compactSql, new RegExp(`REVOKE ALL PRIVILEGES ON FUNCTION ${functionSignaturePattern} FROM PUBLIC, agentpass_signer, agentpass_backup, agentpass_maintenance;`, "u"));
    assert.match(compactSql, new RegExp(`GRANT EXECUTE ON FUNCTION ${functionSignaturePattern} TO agentpass_app;`, "u"));
    assert.doesNotMatch(sql, new RegExp(`GRANT EXECUTE ON FUNCTION ${escaped(functionSignature)}[\\s\\S]*?TO (?!agentpass_app\\b)[^;]+;`, "u"));
    assert.match(roleSql, new RegExp(`['"]?${escaped(name)}\\(${escaped(signature)}\\)`, "u"));
    assert.match(checker, new RegExp(`['"]${escaped(name)}\\(${escaped(signature)}\\)['"]`, "u"));
  }
});

test("0100 binds the old bearer and successor to member, tenant, and both authority epochs", async () => {
  const sql = await read(migrations.switch);
  const body = functionBody(sql, "agentpass_human_session_switch");
  assertContainsAll(body, [
    "s.id = p_old_session_id AND s.token_hash = p_old_token_hash",
    "s.member_id = p_member_id AND s.organization_id = p_old_organization_id",
    "s.expires_at > pg_catalog.clock_timestamp()",
    "p_expires_at > old_session.expires_at",
    "m.status = 'active' AND m.role = s.role",
    "o.authority_epoch = s.organization_authority_epoch",
    "m.session_epoch = s.membership_session_epoch",
    "m.organization_id = p_target_organization_id",
    "m.member_id = p_member_id AND m.status = 'active'",
    "target_authority_epoch",
    "target_membership.session_epoch",
    "successor.organization_authority_epoch IS DISTINCT FROM target_authority_epoch",
    "successor.membership_session_epoch IS DISTINCT FROM target_membership.session_epoch",
  ], "0100");
  assert.match(body, /s.revoked_at IS NULL/u);
  assert.match(body, /s.expires_at > pg_catalog\.clock_timestamp\(\)/u);
  assert.match(body, /s\.id = p_old_session_id AND s\.token_hash = p_old_token_hash[\s\S]*?s\.organization_id = p_old_organization_id/u);
  assert.match(body, /successor.organization_id IS DISTINCT FROM p_target_organization_id/u);
});

test("0101 binds the management actor and target to the same tenant and current epochs", async () => {
  const sql = await read(migrations.managedRevoke);
  const body = functionBody(sql, "agentpass_human_session_revoke_managed");
  assertContainsAll(body, [
    "target.id = p_target_session_id",
    "target.member_id = p_member_id",
    "target.organization_id = p_organization_id",
    "target.version = p_expected_version",
    "actor.id = p_actor_session_id",
    "actor.member_id = p_member_id",
    "actor.organization_id = p_organization_id",
    "actor.revoked_at IS NULL",
    "actor_membership.status = 'active'",
    "actor_membership.role = actor.role",
    "actor_organization.authority_epoch = actor.organization_authority_epoch",
    "actor_membership.session_epoch = actor.membership_session_epoch",
    "target_membership.status = 'active'",
    "target_membership.role = target.role",
    "target_organization.authority_epoch = target.organization_authority_epoch",
    "target_membership.session_epoch = target.membership_session_epoch",
  ], "0101");
  assert.match(body, /p_actor_session_id IS NULL OR p_target_session_id IS NULL OR p_actor_session_id = p_target_session_id/u);
  assert.match(body, /target.revoked_at IS NULL/u);
});

test("0102 binds the actor and every revoked target to one tenant and current epochs", async () => {
  const sql = await read(migrations.revokeOthers);
  const body = functionBody(sql, "agentpass_human_session_revoke_others");
  assertContainsAll(body, [
    "s.id = p_actor_session_id",
    "s.member_id = p_member_id",
    "s.organization_id = p_organization_id",
    "s.revoked_at IS NULL",
    "m.status = 'active' AND m.role = s.role",
    "o.authority_epoch = s.organization_authority_epoch AND m.session_epoch = s.membership_session_epoch",
    "target.member_id = p_member_id AND target.organization_id = p_organization_id",
    "target.id <> p_actor_session_id",
    "target.revoked_at IS NULL",
    "m.status = 'active' AND m.role = target.role",
    "o.authority_epoch = target.organization_authority_epoch",
    "m.session_epoch = target.membership_session_epoch",
  ], "0102");
  assert.match(body, /WITH actor AS \([\s\S]*?\), changed AS \(/u);
  assert.match(body, /RETURNING target.id, target.member_id, target.organization_id/u);
});

test("0100-0102 retain explicit lock-order markers before authority mutations", async () => {
  const [switchSql, managedSql, othersSql] = await Promise.all([
    read(migrations.switch),
    read(migrations.managedRevoke),
    read(migrations.revokeOthers),
  ]);
  const switchBody = functionBody(switchSql, "agentpass_human_session_switch");
  const managedBody = functionBody(managedSql, "agentpass_human_session_revoke_managed");
  const othersBody = functionBody(othersSql, "agentpass_human_session_revoke_others");

  for (const body of [switchBody, managedBody, othersBody]) {
    assert.match(body, /pg_advisory_xact_lock\(hashtextextended\('agentpass:organization:' \|\| p_(?:organization_id|old_organization_id|target_organization_id)::text, 0\)\)/u);
    assert.match(body, /pg_advisory_xact_lock\(\s*hashtextextended\(\s*'agentpass:human:sessions:' \|\| p_member_id::text, 0\)\s*\)/u);
  }

  const switchLock = switchBody.indexOf("PERFORM pg_advisory_xact_lock");
  const switchMemberLock = switchBody.indexOf("'agentpass:human:sessions:'", switchLock);
  const organizationRows = switchBody.indexOf("FROM public.organizations AS o", switchMemberLock);
  const oldSessionRows = switchBody.indexOf("FROM public.human_sessions AS s", organizationRows);
  const targetMembershipRows = switchBody.indexOf("FROM public.memberships AS m", oldSessionRows);
  assert.ok(switchLock >= 0 && switchMemberLock > switchLock, "0100 organization lock must precede member lock");
  assert.ok(organizationRows > switchMemberLock, "0100 member lock must precede organization row locks");
  assert.ok(oldSessionRows > organizationRows, "0100 organization row locks must precede old-session row lock");
  assert.ok(targetMembershipRows > oldSessionRows, "0100 old-session row lock must precede target-membership row lock");
  assert.match(switchBody, /WHERE o\.id IN \(p_old_organization_id, p_target_organization_id\)\s+ORDER BY o\.id\s+FOR UPDATE/u);
  assert.match(switchBody, /FOR UPDATE OF s;/u);
  assert.match(switchBody, /FOR UPDATE OF m, o;/u);

  const managedLock = managedBody.indexOf("PERFORM pg_advisory_xact_lock");
  const managedMemberLock = managedBody.indexOf("'agentpass:human:sessions:'", managedLock);
  const managedUpdate = managedBody.indexOf("UPDATE public.human_sessions AS target");
  assert.ok(managedLock >= 0 && managedMemberLock > managedLock && managedUpdate > managedMemberLock, "0101 organization/member locks must precede target mutation");
  assert.match(managedBody, /UPDATE public\.human_sessions AS target[\s\S]*FROM public\.human_sessions AS actor/u);

  const othersLock = othersBody.indexOf("PERFORM pg_advisory_xact_lock");
  const othersMemberLock = othersBody.indexOf("'agentpass:human:sessions:'", othersLock);
  const actorCte = othersBody.indexOf("WITH actor AS");
  const changedCte = othersBody.indexOf("), changed AS (", actorCte);
  const othersUpdate = othersBody.indexOf("UPDATE public.human_sessions AS target", changedCte);
  assert.ok(othersLock >= 0 && othersMemberLock > othersLock && actorCte > othersMemberLock, "0102 organization/member locks must precede actor validation");
  assert.ok(changedCte > actorCte && othersUpdate > changedCte, "0102 actor validation must precede batch mutation");
});

test("the repository routes 0100-0102 through functions and contains no direct human-session DML", async () => {
  const source = await read(repository);
  const methods = [
    ["switchSessionOrganization", "agentpass_human_session_switch"],
    ["revokeManagedSession", "agentpass_human_session_revoke_managed"],
    ["revokeOtherSessions", "agentpass_human_session_revoke_others"],
  ];
  for (const [methodName, functionName] of methods) {
    const start = source.indexOf(`async function ${methodName}`);
    assert.notEqual(start, -1, `missing repository method ${methodName}`);
    const end = source.indexOf("\n  async function ", start + 1);
    const method = source.slice(start, end < 0 ? source.length : end);
    assert.match(method, new RegExp(`public\\.${functionName}\\(`, "u"), `${methodName} must call its authority function`);
    assert.doesNotMatch(method, /\b(?:INSERT\s+INTO|UPDATE|DELETE\s+FROM)\s+(?:public\.)?human_sessions\b/iu, `${methodName} must not issue direct human-session DML`);
  }
});
