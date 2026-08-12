import assert from "node:assert/strict";
import test from "node:test";

import { createPostgresHumanManagementRepository } from "../src/human-auth/management/postgres-adapter.mjs";

const ids = {
  session: "11111111-1111-4111-8111-111111111111",
  targetSession: "22222222-2222-4222-8222-222222222222",
  member: "33333333-3333-4333-8333-333333333333",
  organization: "44444444-4444-4444-8444-444444444444",
  credential: "AQEBAQEBAQEBAQEBAQEBAQ",
};

const NOW = Date.parse("2026-08-12T12:00:00.000Z");

function credential(overrides = {}) {
  return {
    id: ids.credential,
    member_id: ids.member,
    label: "MacBook",
    transports: ["internal"],
    backup_eligible: false,
    backup_state: false,
    created_at: "2026-08-12T00:00:00.000Z",
    last_used_at: null,
    revoked_at: null,
    version: 1,
    ...overrides,
  };
}

function session(overrides = {}) {
  return {
    session_id: ids.session,
    member_id: ids.member,
    organization_id: ids.organization,
    role: "owner",
    version: 1,
    created_at: "2026-08-12T00:00:00.000Z",
    expires_at: "2026-08-12T13:00:00.000Z",
    last_seen_at: "2026-08-12T11:00:00.000Z",
    idle_expires_at: "2026-08-12T12:30:00.000Z",
    recent_auth_at: null,
    revoked_at: null,
    revoke_reason: null,
    ...overrides,
  };
}

function makeRepository(overrides = {}) {
  const calls = {
    listCredentialMetadataForSession: [],
    updateCredentialLabel: [],
    revokeCredential: [],
    listSafeSessions: [],
    revokeManagedSession: [],
  };
  const base = {
    async listCredentialMetadataForSession(input) {
      calls.listCredentialMetadataForSession.push(input);
      return Object.hasOwn(overrides, "listCredentialMetadataForSession") ? overrides.listCredentialMetadataForSession : [credential()];
    },
    async updateCredentialLabel(input) {
      calls.updateCredentialLabel.push(input);
      return Object.hasOwn(overrides, "updateCredentialLabel") ? overrides.updateCredentialLabel : credential({ label: input.label, version: input.expected_version + 1 });
    },
    async revokeCredential(input) {
      calls.revokeCredential.push(input);
      return Object.hasOwn(overrides, "revokeCredential") ? overrides.revokeCredential : credential({ revoked_at: input.revoked_at, version: input.expected_version + 1 });
    },
    async listSafeSessions(input) {
      calls.listSafeSessions.push(input);
      return Object.hasOwn(overrides, "listSafeSessions") ? overrides.listSafeSessions : [session()];
    },
    async revokeManagedSession(input) {
      calls.revokeManagedSession.push(input);
      return Object.hasOwn(overrides, "revokeManagedSession") ? overrides.revokeManagedSession : session({
        session_id: input.target_session_id,
        revoked_at: input.revoked_at,
        version: input.expected_version + 1,
      });
    },
  };
  return { repository: base, calls };
}

test("requires the complete PostgreSQL management repository and a clock function", () => {
  const methods = [
    "listCredentialMetadataForSession",
    "updateCredentialLabel",
    "revokeCredential",
    "listSafeSessions",
    "revokeManagedSession",
  ];
  for (const missing of methods) {
    const { repository } = repositoryFixtureWithout(missing);
    assert.throws(() => createPostgresHumanManagementRepository({ repository }), /PostgreSQL human repository is invalid/);
  }
  const { repository } = makeRepository();
  assert.throws(() => createPostgresHumanManagementRepository({ repository, now: "not-a-function" }), /now must be a function/);
});

test("paginates credentials and sessions with a bounded, null cursor", async () => {
  const records = [credential({ id: "AQEBAQEBAQEBAQEBAQEBAQ" }), credential({ id: "AgICAgICAgICAgICAgICAg" }), credential({ id: "AwMDAwMDAwMDAwMDAwMDAw" })];
  const { repository, calls } = makeRepository({ listCredentialMetadataForSession: records, listSafeSessions: [session(), session({ session_id: ids.targetSession })] });
  const management = createPostgresHumanManagementRepository({ repository, now: () => NOW });

  const credentials = await management.listCredentials({ session_id: ids.session, member_id: ids.member, organization_id: ids.organization, limit: 2, cursor: "ignored-by-adapter" });
  assert.deepEqual(credentials, { items: records.slice(0, 2), next_cursor: null });
  assert.equal(Object.isFrozen(credentials), true);
  assert.equal(Object.isFrozen(credentials.items), true);
  assert.deepEqual(calls.listCredentialMetadataForSession[0], {
    session_id: ids.session,
    member_id: ids.member,
    organization_id: ids.organization,
    limit: 2,
    cursor: "ignored-by-adapter",
  });

  const sessions = await management.listSessions({ session_id: ids.session, member_id: ids.member, organization_id: ids.organization, limit: 1 });
  assert.equal(sessions.items.length, 1);
  assert.equal(sessions.next_cursor, null);
  assert.deepEqual(calls.listSafeSessions[0], {
    session_id: ids.session,
    member_id: ids.member,
    organization_id: ids.organization,
    limit: 1,
  });

  for (const limit of [0, 101, 1.5, NaN, Infinity]) {
    await assert.rejects(() => management.listCredentials({ limit }), /management page limit is invalid/);
    await assert.rejects(() => management.listSessions({ limit }), /management page limit is invalid/);
  }
});

test("derives session status at the exact expiration boundary and preserves revocation precedence", async () => {
  const { repository } = makeRepository({
    listSafeSessions: [
      session({ session_id: "55555555-5555-4555-8555-555555555555", expires_at: "2026-08-12T12:00:00.000Z" }),
      session({ session_id: "66666666-6666-4666-8666-666666666666", expires_at: "2026-08-12T13:00:00.000Z" }),
      session({ session_id: "77777777-7777-4777-8777-777777777777", expires_at: "2026-08-12T11:00:00.000Z", revoked_at: "2026-08-12T10:00:00.000Z" }),
    ],
  });
  const management = createPostgresHumanManagementRepository({ repository, now: () => NOW });

  const result = await management.listSessions({ limit: 10 });
  assert.deepEqual(result.items.map(({ status }) => status), ["expired", "active", "revoked"]);
  assert.equal(result.items[0].expires_at, "2026-08-12T12:00:00.000Z");
  assert.equal(result.items[2].revoked_at, "2026-08-12T10:00:00.000Z");
});

test("passes rename through and stamps credential and session revocations from one validated clock", async () => {
  let clockCalls = 0;
  const { repository, calls } = makeRepository();
  const management = createPostgresHumanManagementRepository({ repository, now: () => { clockCalls += 1; return NOW; } });

  const renamed = await management.renameCredential({ session_id: ids.session, member_id: ids.member, organization_id: ids.organization, credential_id: ids.credential, label: "Travel Mac", expected_version: 4 });
  assert.equal(renamed.label, "Travel Mac");
  assert.deepEqual(calls.updateCredentialLabel[0], {
    session_id: ids.session,
    member_id: ids.member,
    organization_id: ids.organization,
    credential_id: ids.credential,
    label: "Travel Mac",
    expected_version: 4,
  });

  await management.revokeCredential({ session_id: ids.session, member_id: ids.member, organization_id: ids.organization, credential_id: ids.credential, expected_version: 4, reason: "human_management" });
  assert.equal(calls.revokeCredential[0].revoked_at, "2026-08-12T12:00:00.000Z");
  assert.deepEqual(calls.revokeCredential[0], {
    session_id: ids.session,
    member_id: ids.member,
    organization_id: ids.organization,
    credential_id: ids.credential,
    expected_version: 4,
    reason: "human_management",
    revoked_at: "2026-08-12T12:00:00.000Z",
  });

  await management.revokeSession({ session_id: ids.session, target_session_id: ids.targetSession, member_id: ids.member, organization_id: ids.organization, expected_version: 2, reason: "human_management" });
  assert.deepEqual(calls.revokeManagedSession[0], {
    session_id: ids.session,
    target_session_id: ids.targetSession,
    member_id: ids.member,
    organization_id: ids.organization,
    expected_version: 2,
    reason: "human_management",
    actor_session_id: ids.session,
    revoked_at: "2026-08-12T12:00:00.000Z",
  });
  assert.equal(clockCalls, 2);
});

test("fails closed for invalid clocks and malformed repository list results", async () => {
  for (const invalidClock of [NaN, -1, 1.5, Number.MAX_SAFE_INTEGER + 1, "1700000000000"]) {
    const { repository } = makeRepository();
    const management = createPostgresHumanManagementRepository({ repository, now: () => invalidClock });
    await assert.rejects(() => management.revokeCredential({ expected_version: 1 }), /clock is invalid/);
    await assert.rejects(() => management.listSessions({ limit: 1 }), /clock is invalid/);
  }

  const malformedCredentials = makeRepository({ listCredentialMetadataForSession: null });
  const credentialManagement = createPostgresHumanManagementRepository({ repository: malformedCredentials.repository, now: () => NOW });
  await assert.rejects(() => credentialManagement.listCredentials({ limit: 1 }), /management records are invalid/);

  const malformedSessions = makeRepository({ listSafeSessions: null });
  const sessionManagement = createPostgresHumanManagementRepository({ repository: malformedSessions.repository, now: () => NOW });
  await assert.rejects(() => sessionManagement.listSessions({ limit: 1 }), TypeError);
});

function repositoryFixtureWithout(missing) {
  const { repository } = makeRepository();
  delete repository[missing];
  return { repository };
}
