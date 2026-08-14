import assert from "node:assert/strict";
import crypto from "node:crypto";
import test from "node:test";

import {
  OwnerRecoveryRepositoryError,
  createPostgresOwnerRecoveryRepository
} from "../../src/postgres/owner-recovery-repository.mjs";

const ORG = "11111111-1111-4111-8111-111111111111";
const SUBJECT = "22222222-2222-4222-8222-222222222222";
const REQUEST = "33333333-3333-4333-8333-333333333333";
const RECOVERY_SESSION = "44444444-4444-4444-8444-444444444444";
const AUTHORIZATION = "55555555-5555-4555-8555-555555555555";
const OWNER_ONE = "66666666-6666-4666-8666-666666666666";
const OWNER_TWO = "77777777-7777-4777-8777-777777777777";
const MEMBERSHIP_SUBJECT = "88888888-8888-4888-8888-888888888888";
const MEMBERSHIP_ONE = "99999999-9999-4999-8999-999999999999";
const MEMBERSHIP_TWO = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const CREDENTIAL = Buffer.alloc(32, 0x42);
const PUBLIC_KEY = Buffer.alloc(64, 0x43);
const NOW = new Date("2026-08-14T12:00:00.000Z");
const DELIVERY_BINDING = Object.freeze({ binding_id: "test-owner-recovery", key_version: 3, binding_digest: "a".repeat(64) });

class ScriptedClient {
  constructor(handler) {
    this.handler = handler;
    this.calls = [];
  }

  async query(text, params = []) {
    this.calls.push({ text, params });
    return this.handler(text, params, this.calls) ?? { rows: [], rowCount: 0 };
  }
}

function request(state = "credential_enrolled", version = 4) {
  return {
    organization_id: ORG,
    request_id: REQUEST,
    schema_version: 1,
    kind: "threshold-owner-recovery",
    subject_member_id: SUBJECT,
    creator_member_id: SUBJECT,
    creator_session_id: RECOVERY_SESSION,
    state,
    threshold: 2,
    approved_owner_count: 2,
    approved_at: new Date(NOW - 86_400_000),
    delay_until: new Date(NOW - 3_600_000),
    session_issued_at: new Date(NOW - 1_800_000),
    credential_enrolled_at: new Date(NOW - 900_000),
    activated_at: state === "activated" ? NOW : null,
    expires_at: new Date(NOW.getTime() + 60_000),
    terminal_reason: null,
    version,
    created_at: new Date(NOW - 172_800_000),
    updated_at: NOW
  };
}

function membership(id, memberId, role = "owner") {
  return { id, organization_id: ORG, member_id: memberId, role, status: "active", session_epoch: 7 };
}

function approval(ownerMemberId) {
  return {
    owner_member_id: ownerMemberId,
    owner_membership_session_epoch: 7,
    approved_at: new Date(NOW - 86_400_000),
    invalidated_at: null,
    invalidation_reason: null,
    approval_id: ownerMemberId === OWNER_ONE ? MEMBERSHIP_ONE : MEMBERSHIP_TWO,
    authorization_id: ownerMemberId === OWNER_ONE ? "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb" : "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
  };
}

function recoverySession(stage = "credential_enrolled") {
  return {
    organization_id: ORG,
    recovery_session_id: RECOVERY_SESSION,
    request_id: REQUEST,
    member_id: SUBJECT,
    session_digest: crypto.createHash("sha256").update("recovery-token").digest(),
    stage,
    issued_at: new Date(NOW - 1_800_000),
    expires_at: new Date(NOW.getTime() + 60_000),
    idle_expires_at: new Date(NOW.getTime() + 60_000),
    last_seen_at: NOW,
    credential_id: CREDENTIAL,
    credential_enrolled_at: new Date(NOW - 900_000),
    activation_authorization_id: null,
    activation_authorized_at: null,
    activated_at: null,
    revoked_at: null,
    revoke_reason: null
  };
}

function challenge() {
  return {
    organization_id: ORG,
    challenge_id: AUTHORIZATION,
    recovery_session_id: RECOVERY_SESSION,
    request_id: REQUEST,
    member_id: SUBJECT,
    ceremony: "authentication",
    operation: "human.recovery.activate",
    status: "consuming",
    created_at: new Date(NOW - 30_000),
    expires_at: new Date(NOW.getTime() + 30_000),
    consume_started_at: new Date(NOW - 10_000),
    consumed_at: null,
    failed_at: null,
    verified_credential_id: null,
    authorization_consumed_at: null
  };
}

function activationClient() {
  const rows = {
    request: request(),
    memberships: [membership(MEMBERSHIP_SUBJECT, SUBJECT, "viewer"), membership(MEMBERSHIP_ONE, OWNER_ONE), membership(MEMBERSHIP_TWO, OWNER_TWO)],
    session: recoverySession(),
    approvals: [approval(OWNER_ONE), approval(OWNER_TWO)],
    challenge: challenge()
  };
  return new ScriptedClient((text) => {
    if (text.startsWith("SELECT pg_advisory_xact_lock")) return { rows: [{}], rowCount: 1 };
    if (text.startsWith("SELECT organization_id,request_id,schema_version")) return { rows: [rows.request], rowCount: 1 };
    if (text.startsWith("SELECT owner_member_id FROM owner_recovery_approvals")) return { rows: [{ owner_member_id: OWNER_ONE }, { owner_member_id: OWNER_TWO }], rowCount: 2 };
    if (text.startsWith("SELECT id,organization_id,member_id,role,status,session_epoch")) return { rows: rows.memberships, rowCount: rows.memberships.length };
    if (text.startsWith("SELECT id FROM human_sessions")) return { rows: [], rowCount: 0 };
    if (text.startsWith("SELECT organization_id,recovery_session_id,request_id,member_id,session_digest")) return { rows: [rows.session], rowCount: 1 };
    if (text.startsWith("SELECT organization_id,challenge_id,recovery_session_id")) return { rows: [rows.challenge], rowCount: 1 };
    if (text.startsWith("SELECT owner_member_id,owner_membership_session_epoch")) return { rows: rows.approvals, rowCount: rows.approvals.length };
    if (text.startsWith("SELECT id FROM webauthn_credentials")) return { rows: [{ id: CREDENTIAL }], rowCount: 1 };
    if (text.startsWith("UPDATE webauthn_credentials")) return { rows: [{ id: CREDENTIAL, sign_count: 4, last_used_at: NOW }], rowCount: 1 };
    if (text.startsWith("SET LOCAL")) return { rows: [], rowCount: 0 };
    if (text.startsWith("UPDATE memberships SET session_epoch")) return { rows: [{ session_epoch: 8 }], rowCount: 1 };
    if (text.startsWith("UPDATE human_sessions SET revoked_at")) return { rows: [], rowCount: 0 };
    if (text.startsWith("UPDATE owner_recovery_sessions SET stage='revoked'")) return { rows: [], rowCount: 0 };
    if (text.startsWith("UPDATE owner_recovery_sessions\n      SET stage='activated'")) return { rows: [{ recovery_session_id: RECOVERY_SESSION }], rowCount: 1 };
    if (text.startsWith("UPDATE owner_recovery_requests SET")) return { rows: [request("activated", 5)], rowCount: 1 };
    if (text.startsWith("INSERT INTO owner_recovery_outbox")) return { rows: [{ event_id: "dddddddd-dddd-4ddd-8ddd-dddddddddddd" }], rowCount: 1 };
    return { rows: [], rowCount: 0 };
  });
}

test("exports a closed repository and discards provider diagnostics from errors", async () => {
  const repository = createPostgresOwnerRecoveryRepository({ client: new ScriptedClient(() => { throw new Error("postgresql://user:password@db/private"); }) });
  assert.equal(Object.isFrozen(repository), true);
  assert.equal(typeof repository.activateRecoveryInTransaction, "function");
  await assert.rejects(() => repository.getRequest({ organization_id: ORG, request_id: REQUEST }), (error) => {
    assert.ok(error instanceof OwnerRecoveryRepositoryError);
    assert.equal(error.code, "unavailable");
    assert.equal(Object.hasOwn(error, "cause"), false);
    assert.equal(JSON.stringify(error).includes("postgresql://"), false);
    return true;
  });
});

test("activation composes inside the coordinator transaction while proof is consuming", async () => {
  const client = activationClient();
  const auditCalls = [];
  const repository = createPostgresOwnerRecoveryRepository({
    client,
    deliveryBinding: DELIVERY_BINDING,
    clock: () => NOW,
    appendActivationAudit: async (input) => {
      auditCalls.push(input);
      return { audit_event_id: "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee" };
    }
  });
  const result = await repository.activateRecoveryInTransaction({
    tx: client,
    binding: {
      organization_id: ORG,
      request_id: REQUEST,
      recovery_session_id: RECOVERY_SESSION,
      member_id: SUBJECT,
      challenge_id: AUTHORIZATION,
      credential_id: CREDENTIAL.toString("base64url"),
      completed_at: NOW.toISOString()
    },
    authorization_id: AUTHORIZATION,
    authorization: {
      authorization_id: AUTHORIZATION,
      credential_id: CREDENTIAL.toString("base64url"),
      expected_sign_count: 3,
      sign_count: 4,
      expected_backup_eligible: false,
      expected_backup_state: false,
      credential_device_type: "singleDevice",
      credential_backed_up: false,
      backup_eligible: false,
      backup_state: false
    }
  });
  assert.equal(result.committed, true);
  assert.equal(result.mutation.request.state, "activated");
  assert.equal(auditCalls.length, 1);
  assert.equal(client.calls.some(({ text }) => text.startsWith("UPDATE owner_recovery_webauthn_challenges") && text.includes("authorization_consumed_at")), false);
  assert.equal(client.calls.some(({ text }) => text.includes("SET status='consumed'")), false);
  const counterCall = client.calls.find(({ text }) => text.startsWith("UPDATE webauthn_credentials"));
  assert.ok(counterCall);
  assert.match(counterCall.text, /SET sign_count=\$4,backup_eligible=\$6,backup_state=\$7,last_used_at=\$5/u);
  assert.match(counterCall.text, /sign_count=\$3 AND backup_eligible=\$8 AND backup_state=\$9/u);
  assert.deepEqual(counterCall.params.slice(2), [3, 4, NOW, false, false, false, false]);
  assert.ok(client.calls.findIndex(({ text }) => text.startsWith("SELECT pg_advisory_xact_lock")) < client.calls.findIndex(({ text }) => text.startsWith("UPDATE webauthn_credentials")));
  assert.ok(client.calls.findIndex(({ text }) => text.startsWith("UPDATE webauthn_credentials")) < client.calls.findIndex(({ text }) => text.startsWith("UPDATE memberships SET session_epoch")));
  const transitionCall = client.calls.find(({ text }) => text.startsWith("UPDATE owner_recovery_requests SET"));
  assert.ok(client.calls.indexOf(transitionCall) > client.calls.findIndex(({ text }) => text.startsWith("UPDATE memberships SET session_epoch")));
  assert.match(transitionCall.text, /SET state=\$5/u);
  assert.match(transitionCall.text, /AND state=\$4 RETURNING/u);
  assert.deepEqual(transitionCall.params.slice(0, 5), [ORG, REQUEST, 4, "credential_enrolled", "activated"]);
  const outboxCall = client.calls.find(({ text }) => text.startsWith("INSERT INTO owner_recovery_outbox"));
  assert.match(outboxCall.text, /provider_binding_state,provider_binding_id,provider_key_version,provider_binding_digest/u);
  assert.deepEqual(outboxCall.params.slice(-3), [DELIVERY_BINDING.binding_id, DELIVERY_BINDING.key_version, DELIVERY_BINDING.binding_digest]);
});

test("counter update is exact-CAS, transaction-composable, and confirms committed", async () => {
  const client = new ScriptedClient((text) => text.startsWith("UPDATE webauthn_credentials")
    ? { rows: [{ id: CREDENTIAL, sign_count: 4, last_used_at: NOW }], rowCount: 1 }
    : { rows: [], rowCount: 0 });
  const repository = createPostgresOwnerRecoveryRepository({ client, clock: () => NOW });
  const result = await repository.updateRecoveryCredentialCounterInTransaction({ tx: client, member_id: SUBJECT, credential_id: CREDENTIAL.toString("base64url"), expected_sign_count: 3, sign_count: 4, updated_at: NOW.toISOString() });
  assert.equal(result.committed, true);
  assert.match(client.calls[0].text, /SET sign_count=\$4,last_used_at=\$5/u);
  assert.deepEqual(client.calls[0].params.slice(2), [3, 4, NOW]);
});

test("counter backup metadata is an exact CAS and reports mismatch as conflict", async () => {
  const client = new ScriptedClient((text) => text.startsWith("UPDATE webauthn_credentials")
    ? { rows: [], rowCount: 0 }
    : { rows: [], rowCount: 0 });
  const repository = createPostgresOwnerRecoveryRepository({ client, clock: () => NOW });
  await assert.rejects(() => repository.updateRecoveryCredentialCounterInTransaction({
    tx: client,
    member_id: SUBJECT,
    credential_id: CREDENTIAL.toString("base64url"),
    expected_sign_count: 3,
    sign_count: 4,
    expected_backup_eligible: false,
    expected_backup_state: false,
    backup_eligible: false,
    backup_state: true,
    updated_at: NOW.toISOString()
  }), (error) => error instanceof OwnerRecoveryRepositoryError && error.code === "conflict");
  assert.match(client.calls[0].text, /backup_eligible=\$8 AND backup_state=\$9/u);
  assert.deepEqual(client.calls[0].params.slice(2), [3, 4, NOW, false, true, false, false]);
});

test("credential lookup resolves the session-bound credential when no credential id is supplied", async () => {
  const digest = crypto.createHash("sha256").update("recovery-token").digest();
  const client = new ScriptedClient((text) => {
    if (text.startsWith("SELECT credential_id FROM owner_recovery_sessions")) return { rows: [{ credential_id: CREDENTIAL }], rowCount: 1 };
    if (text.startsWith("SELECT c.id,c.member_id")) return { rows: [{ id: CREDENTIAL, member_id: SUBJECT, public_key: PUBLIC_KEY, sign_count: 0, transports: ["internal"], label: "Recovery", backup_eligible: false, backup_state: false, created_at: NOW, last_used_at: null, revoked_at: null }], rowCount: 1 };
    return { rows: [], rowCount: 0 };
  });
  const repository = createPostgresOwnerRecoveryRepository({ client, clock: () => NOW });
  const result = await repository.findRecoveryCredential({ organization_id: ORG, request_id: REQUEST, recovery_session_id: RECOVERY_SESSION, member_id: SUBJECT, session_digest: digest, now: NOW.toISOString() });
  assert.equal(result.credential_id, CREDENTIAL.toString("base64url"));
  assert.equal(client.calls[0].params[4].equals(digest), true);
});
