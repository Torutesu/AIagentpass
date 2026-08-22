import assert from "node:assert/strict";
import fs from "node:fs/promises";
import path from "node:path";
import test from "node:test";

const ROOT = path.resolve(import.meta.dirname, "../../../../");
const ORGANIZATION_REPOSITORY = path.join(ROOT, "apps/cloud-api/src/postgres/organization-repository.mjs");
const ROLES_SQL = path.join(ROOT, "scripts/postgres/roles.sql");
const ROLE_CHECKER = path.join(ROOT, "scripts/postgres/role-privilege-check.mjs");
const IDENTITY_BOUNDARY = path.join(ROOT, "contracts/postgres/0105_human_identity_boundary_hardening.sql");
const LOCK_ORDER_BOUNDARY = path.join(ROOT, "contracts/postgres/0106_human_lock_order_authority.sql");
const ORGANIZATION_BOUNDARY = path.join(ROOT, "contracts/postgres/0107_organization_core_authority.sql");
const MEMBERSHIP_BOUNDARY = path.join(ROOT, "contracts/postgres/0108_membership_mutation_authority.sql");
const INVITATION_BOUNDARY = path.join(ROOT, "contracts/postgres/0109_invitation_authority.sql");

const PROTECTED_RELATIONS = Object.freeze([
  "organizations",
  "memberships",
  "organization_invitations"
]);

const AUDIT_RELATIONS = Object.freeze([
  "idempotency_records",
  "admin_audit_heads",
  "admin_audit_events",
  "outbox_events"
]);

const AUTHORITY_ENTRYPOINT_REQUIREMENTS = Object.freeze({
  securityDefiner: true,
  fixedSearchPath: "pg_catalog, public",
  executableBy: "agentpass_app",
  directTableDmlByApp: false,
  auditAndOutboxSameTransaction: true,
  idempotency: "organization_id + principal_id + idempotency_key; same request_hash replays the same response"
});

// This is the migration contract for the eight organization mutations. The
// repository must call these exact entry points and must not retain a direct
// DML fallback around the authority boundary.
const MUTATION_CONTRACTS = Object.freeze([
  {
    method: "createOrganizationWithOwner",
    action: "organization.created",
    targetType: "organization",
    directDml: [],
    functionName: "agentpass_organization_create_with_owner",
    signature: "public.agentpass_organization_create_with_owner(uuid,uuid,uuid,text,text,text,text,timestamptz) RETURNS table",
    requiresAuthorityReduction: false
  },
  {
    method: "renameOrganization",
    action: "organization.renamed",
    targetType: "organization",
    directDml: [],
    functionName: "agentpass_organization_rename",
    signature: "public.agentpass_organization_rename(uuid,uuid,text,bigint) RETURNS table",
    requiresAuthorityReduction: false
  },
  {
    method: "updateMemberRole",
    action: "membership.role_updated",
    targetType: "membership",
    directDml: [],
    functionName: "agentpass_human_membership_role_update",
    signature: "public.agentpass_human_membership_role_update(uuid,uuid,uuid,text,bigint,timestamptz) RETURNS table",
    requiresAuthorityReduction: true
  },
  {
    method: "removeMember",
    action: "membership.removed",
    targetType: "membership",
    directDml: [],
    functionName: "agentpass_human_membership_remove",
    signature: "public.agentpass_human_membership_remove(uuid,uuid,uuid,bigint,timestamptz) RETURNS table",
    requiresAuthorityReduction: true
  },
  {
    method: "createInvitation",
    action: "invitation.created",
    targetType: "invitation",
    directDml: [],
    functionName: "agentpass_organization_invitation_create",
    signature: "public.agentpass_organization_invitation_create(uuid,uuid,bytea,text,uuid,timestamptz,timestamptz) RETURNS table",
    requiresAuthorityReduction: false
  },
  {
    method: "revokeInvitation",
    action: "invitation.revoked",
    targetType: "invitation",
    directDml: [],
    functionName: "agentpass_organization_invitation_revoke",
    signature: "public.agentpass_organization_invitation_revoke(uuid,uuid,bigint,timestamptz,uuid,text) RETURNS table",
    requiresAuthorityReduction: false
  },
  {
    method: "reissueInvitation",
    action: "invitation.reissued",
    targetType: "invitation",
    directDml: [],
    functionName: "agentpass_organization_invitation_reissue",
    signature: "public.agentpass_organization_invitation_reissue(uuid,uuid,bytea,timestamptz,timestamptz,bigint,uuid) RETURNS table",
    requiresAuthorityReduction: false
  },
  {
    method: "acceptInvitation",
    action: "invitation.accepted",
    targetType: "invitation",
    directDml: [],
    functionName: "agentpass_organization_invitation_accept",
    signature: "public.agentpass_organization_invitation_accept(uuid,uuid,bytea,uuid,timestamptz) RETURNS table",
    requiresAuthorityReduction: false
  }
]);

const READ_METHODS = Object.freeze([
  "getOrganization",
  "listOrganizationsForMember",
  "listMembers",
  "listInvitations"
]);

async function read(file) {
  return fs.readFile(file, "utf8");
}

function functionSection(source, name) {
  const start = source.indexOf(`async function ${name}(`);
  assert.notEqual(start, -1, `organization repository is missing ${name}()`);
  const end = source.indexOf("\n  async function ", start + 1);
  return source.slice(start, end === -1 ? source.length : end);
}

function directDml(section) {
  const result = [];
  const pattern = /\b(INSERT\s+INTO|UPDATE|DELETE\s+FROM)\s+(?:public\.)?(organizations|memberships|organization_invitations)\b/giu;
  for (const match of section.matchAll(pattern)) {
    result.push([match[1].split(/\s+/u)[0].toUpperCase(), match[2].toLowerCase()]);
  }
  return result;
}

function relationExcludedFromGenericAppGrant(roles, relation) {
  const grantBlock = roles.match(/c\.relname NOT IN \(([\s\S]*?)\)\n\s*AND left\(c\.relname/u)?.[1] ?? "";
  return grantBlock.includes(`'${relation}'`) || grantBlock.includes(`"${relation}"`);
}

function functionExistsInBoundary(source, functionName) {
  return new RegExp(`(?:CREATE|ALTER|GRANT|REVOKE)[\\s\\S]*?\\b${functionName}\\b`, "u").test(source);
}

test("organization repository exposes the eight mutation surfaces and no protected-table DML is omitted", async () => {
  const source = await read(ORGANIZATION_REPOSITORY);
  assert.equal(new Set(MUTATION_CONTRACTS.map(({ method }) => method)).size, 8);

  for (const contract of MUTATION_CONTRACTS) {
    const section = functionSection(source, contract.method);
    assert.deepEqual(directDml(section), contract.directDml, `${contract.method} direct-DML inventory changed`);
    assert.match(section, new RegExp(`public\\.${contract.functionName}`, "u"), `${contract.method} must call its authority function`);
    assert.match(section, /appendMutationEvents\(/u, `${contract.method} must emit the mutation audit event`);
    assert.match(section, new RegExp(`action:\\s*["']${contract.action}["']`, "u"), `${contract.method} audit action changed`);
    assert.match(section, /mutate\(|acquireIdempotency\(|transaction\(/u, `${contract.method} must stay inside an idempotent transaction`);
    if (contract.requiresAuthorityReduction) {
      assert.match(section, /notifyAuthorityReduction\(/u, `${contract.method} must propagate authority reduction`);
    }
  }
});

test("all repository read surfaces remain DML-free for organization authority relations", async () => {
  const source = await read(ORGANIZATION_REPOSITORY);
  for (const method of READ_METHODS) {
    assert.deepEqual(directDml(functionSection(source, method)), [], `${method} unexpectedly writes an authority relation`);
  }
});

test("the proposed authority-function contract is complete and caller-safe", () => {
  assert.equal(MUTATION_CONTRACTS.length, 8);
  assert.deepEqual(AUTHORITY_ENTRYPOINT_REQUIREMENTS, {
    securityDefiner: true,
    fixedSearchPath: "pg_catalog, public",
    executableBy: "agentpass_app",
    directTableDmlByApp: false,
    auditAndOutboxSameTransaction: true,
    idempotency: "organization_id + principal_id + idempotency_key; same request_hash replays the same response"
  });
  const names = new Set();
  for (const contract of MUTATION_CONTRACTS) {
    assert.equal(names.has(contract.functionName), false, `duplicate authority function ${contract.functionName}`);
    names.add(contract.functionName);
    assert.match(contract.signature, new RegExp(`^public\\.${contract.functionName}\\(.+\\) RETURNS (?:jsonb|table)$`, "u"));
    assert.equal(contract.targetType, "organization" === contract.targetType || "membership" === contract.targetType || "invitation" === contract.targetType ? contract.targetType : "");
    assert.equal(contract.directDml.length, 0);
    assert.equal(contract.requiresAuthorityReduction, contract.method === "updateMemberRole" || contract.method === "removeMember");
  }
});

test("organization authority migrations own all eight mutation entry points", async () => {
  const [identityBoundary, lockOrderBoundary, organizationBoundary, membershipBoundary, invitationBoundary] = await Promise.all([
    read(IDENTITY_BOUNDARY),
    read(LOCK_ORDER_BOUNDARY),
    read(ORGANIZATION_BOUNDARY),
    read(MEMBERSHIP_BOUNDARY),
    read(INVITATION_BOUNDARY)
  ]);
  const source = `${identityBoundary}\n${lockOrderBoundary}`;
  const authoritySource = `${organizationBoundary}\n${membershipBoundary}\n${invitationBoundary}`;
  for (const contract of MUTATION_CONTRACTS) {
    assert.equal(functionExistsInBoundary(source, contract.functionName), false, `${contract.functionName} must not be introduced by 0105/0106`);
    assert.equal(functionExistsInBoundary(authoritySource, contract.functionName), true, `${contract.functionName} is missing from the authority migrations`);
  }
  assert.doesNotMatch(source, /(?:INSERT\s+INTO|UPDATE|DELETE\s+FROM)\s+(?:public\.)?(?:organizations|memberships|organization_invitations)\b/iu);
});

test("app-role ACL and role checker cover the organization authority boundary", async () => {
  const [roles, checker, identityBoundary] = await Promise.all([
    read(ROLES_SQL),
    read(ROLE_CHECKER),
    read(IDENTITY_BOUNDARY)
  ]);

  assert.match(roles, /GRANT SELECT ON TABLE public\.organizations, public\.memberships TO agentpass_app/u);
  assert.match(identityBoundary, /REVOKE INSERT, UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER[\s\S]*public\.organizations, public\.memberships FROM agentpass_app/u);
  assert.match(checker, /app_write_protected_relations\(relname\)[\s\S]*VALUES \('organizations'\), \('memberships'\)/u);

  const missingFromGenericGrant = PROTECTED_RELATIONS.filter((relation) => !relationExcludedFromGenericAppGrant(roles, relation));
  assert.deepEqual(missingFromGenericGrant, []);
  for (const contract of MUTATION_CONTRACTS) {
    assert.match(checker, new RegExp(contract.functionName.replaceAll(".", "\\."), "u"), `${contract.functionName} is missing from the role checker`);
  }
});

test("each mutation contract keeps idempotency, audit, and outbox in one transaction boundary", async () => {
  const source = await read(ORGANIZATION_REPOSITORY);
  const mutate = functionSection(source, "mutate");
  const create = functionSection(source, "createOrganizationWithOwner");
  const accept = functionSection(source, "acceptInvitation");

  assert.match(mutate, /return transaction\(async \(tx\)/u);
  assert.match(mutate, /await acquireIdempotency\(tx/u);
  assert.match(mutate, /await completeIdempotency\(tx/u);
  assert.match(mutate, /await abandonIdempotency\(tx/u);
  assert.match(create, /agentpass_organization_create_with_owner/u);
  assert.match(create, /await completeIdempotency\(tx/u);
  assert.match(accept, /await acquireIdempotency\(tx/u);
  assert.match(accept, /await completeIdempotency\(tx/u);

  const append = functionSection(source, "appendMutationEvents");
  assert.match(append, /INSERT INTO admin_audit_heads/u);
  assert.match(append, /INSERT INTO admin_audit_events/u);
  assert.match(append, /UPDATE admin_audit_heads/u);
  assert.match(append, /INSERT INTO outbox_events/u);
  assert.match(append, /canonicalAuditEvent/u);
  assert.match(append, /canonicalOutboxPayload/u);

  const currentDirectAuditWrites = AUDIT_RELATIONS.filter((relation) => new RegExp(`\\b(?:INSERT\\s+INTO|UPDATE|DELETE\\s+FROM)\\s+${relation}\\b`, "iu").test(source));
  assert.deepEqual(currentDirectAuditWrites, AUDIT_RELATIONS);
});

test("authority-function migration prerequisites are explicit and currently unresolved", async () => {
  const [roles, checker] = await Promise.all([read(ROLES_SQL), read(ROLE_CHECKER)]);
  const requiredFunctionOnlyRelations = [...PROTECTED_RELATIONS, ...AUDIT_RELATIONS];
  const unresolved = requiredFunctionOnlyRelations.filter((relation) => {
    if (relation === "organizations" || relation === "memberships") return false;
    return !relationExcludedFromGenericAppGrant(roles, relation)
      || (relation === "organization_invitations" && !checker.includes("'organization_invitations'"));
  });
  assert.deepEqual(unresolved, [
    "idempotency_records",
    "admin_audit_heads",
    "admin_audit_events",
    "outbox_events"
  ]);
});
