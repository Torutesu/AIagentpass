import assert from "node:assert/strict";
import fs from "node:fs/promises";
import path from "node:path";
import test from "node:test";

const ROOT = path.resolve(import.meta.dirname, "../../../../");
const migration = path.join(ROOT, "contracts/postgres/0106_human_lock_order_authority.sql");
const humanRepository = path.join(ROOT, "apps/cloud-api/src/postgres/human-repository.mjs");
const organizationRepository = path.join(ROOT, "apps/cloud-api/src/postgres/organization-repository.mjs");

async function read(file) {
  return fs.readFile(file, "utf8");
}

function body(source, name) {
  const start = source.indexOf(`CREATE FUNCTION public.${name}`);
  assert.notEqual(start, -1, `missing wrapper ${name}`);
  const end = source.indexOf("\n$$;", start);
  assert.notEqual(end, -1, `wrapper ${name} has no body terminator`);
  return source.slice(start, end);
}

function indexInOrder(source, needles, label) {
  let previous = -1;
  for (const needle of needles) {
    const position = source.indexOf(needle);
    assert.ok(position > previous, `${label}: ${needle} must follow the previous lock`);
    previous = position;
  }
}

test("0106 installs wrappers without replacing the reviewed authority bodies", async () => {
  const source = await read(migration);
  for (const legacyName of [
    "agentpass_human_session_create_legacy_0105",
    "agentpass_human_session_create_with_ceiling_legacy_0105",
    "agentpass_human_session_rotate_legacy_0105",
    "agentpass_human_update_credential_label_legacy_0105",
    "agentpass_human_revoke_credential_legacy_0105"
  ]) {
    assert.match(source, new RegExp(`RENAME TO ${legacyName};`, "u"));
    assert.match(source, new RegExp(`ON FUNCTION public\\.${legacyName}\\([\\s\\S]*?FROM PUBLIC, agentpass_app`, "u"));
  }
  for (const publicName of [
    "agentpass_human_session_create",
    "agentpass_human_session_create_with_ceiling",
    "agentpass_human_session_rotate",
    "agentpass_human_update_credential_label",
    "agentpass_human_revoke_credential"
  ]) {
    assert.match(source, new RegExp(`CREATE FUNCTION public\\.${publicName}\\(`, "u"));
    assert.match(source, new RegExp(`GRANT EXECUTE ON FUNCTION public\\.${publicName}\\(`, "u"));
  }
});

test("0106 puts session issue and rotation behind authority -> organization -> session locks", async () => {
  const source = await read(migration);
  for (const name of ["agentpass_human_session_create", "agentpass_human_session_create_with_ceiling", "agentpass_human_session_rotate"]) {
    const current = body(source, name);
    indexInOrder(current, [
      "agentpass:human:authority:",
      "agentpass:organization:",
      "agentpass:human:sessions:",
      "_legacy_0105("
    ], name);
  }
});

test("0106 puts credential mutation behind authority -> organization -> session -> credential locks", async () => {
  const source = await read(migration);
  for (const name of ["agentpass_human_update_credential_label", "agentpass_human_revoke_credential"]) {
    const current = body(source, name);
    indexInOrder(current, [
      "agentpass:human:authority:",
      "agentpass:organization:",
      "agentpass:human:sessions:",
      "agentpass:webauthn:credentials:",
      "_legacy_0105("
    ], name);
  }
  const revoke = body(source, "agentpass_human_revoke_credential");
  assert.match(revoke, /FROM public\.memberships AS m[\s\S]*UNION[\s\S]*FROM public\.platform_sessions AS s/u);
  assert.match(revoke, /ORDER BY scopes\.organization_id/u);
  assert.match(revoke, /UNION\s+SELECT p_organization_id/u);
});

test("repository membership and credential paths carry the same authority prefix", async () => {
  const [human, organization] = await Promise.all([read(humanRepository), read(organizationRepository)]);
  for (const method of ["updateCredentialLabel", "revokeCredential", "createCredentialWithRecentAuth"]) {
    const start = human.indexOf(`async function ${method}`);
    assert.notEqual(start, -1, `missing ${method}`);
    const end = human.indexOf("\n  async function ", start + 1);
    const section = human.slice(start, end < 0 ? human.length : end);
    indexInOrder(section, [
      "lockHumanAuthority(",
      "lockOrganization(",
      "lockSessionSet(",
      "lockCredentialSet("
    ], method);
  }
  assert.match(organization, /async function mutate\([\s\S]*?lockOrder\s*=\s*undefined/u);
  assert.match(organization, /if \(lockOrder\?\.memberId !== undefined\) await lockHumanAuthority\(/u);
  assert.match(organization, /"membership\.role_update"[\s\S]*?\{ memberId \}\);/u);
  assert.match(organization, /"membership\.remove"[\s\S]*?\{ memberId \}\);/u);
  assert.match(organization, /await lockHumanAuthority\(tx, actorId\);[\s\S]*?await lockOrganization\(tx, organizationId\);[\s\S]*?await lockSessionSet\(tx, lockOrder\.memberId\);[\s\S]*?if \(authorization\)/u);
});

test("adversarial lock graph has no prefix inversion for the covered paths", () => {
  const paths = {
    session_issue: ["human-authority", "organization", "session-set", "authority-rows"],
    session_rotation: ["human-authority", "organization", "session-set", "authority-rows"],
    membership_mutation: ["human-authority", "organization", "session-set", "membership-row", "session-rows"],
    credential_revoke: ["human-authority", "organization(s)-ascending", "session-set", "credential-set", "credential-row"],
    credential_invalidation_trigger: ["human-authority", "organization(s)-ascending", "session-set", "session-rows"]
  };
  const rank = new Map([
    ["human-authority", 0],
    ["organization", 1],
    ["organization(s)-ascending", 1],
    ["session-set", 2],
    ["credential-set", 3],
    ["authority-rows", 4],
    ["membership-row", 4],
    ["credential-row", 5],
    ["session-rows", 5]
  ]);
  for (const [name, pathValue] of Object.entries(paths)) {
    const ranks = pathValue.map((lock) => rank.get(lock));
    assert.ok(ranks.every((value) => value !== undefined), `${name} has an unknown lock`);
    assert.deepEqual(ranks, [...ranks].sort((left, right) => left - right), `${name} contains an inversion`);
  }
  // This is a structural adversarial model, not live PostgreSQL proof.
  assert.equal(process.env.AGENTPASS_TEST_DATABASE_URL === undefined, true);
});
