import assert from "node:assert/strict";
import test from "node:test";
import { createPostgresHumanRepository } from "../src/postgres/human-repository.mjs";

const ids = Object.freeze({
  session: "11111111-1111-4111-8111-111111111111",
  member: "22222222-2222-4222-8222-222222222222",
  organization: "33333333-3333-4333-8333-333333333333"
});
const credentialBytes = Buffer.alloc(32, 0x44);
const credentialId = credentialBytes.toString("base64url");
const detectedAt = new Date("2026-08-16T01:02:03.000Z");

class QuarantineClient {
  constructor() {
    this.calls = [];
    this.events = [];
  }

  async connect() { return { query: (text, params) => this.query(text, params), release() {} }; }

  async query(text, params = []) {
    this.calls.push({ text, params });
    if (["BEGIN", "COMMIT", "ROLLBACK"].includes(text)) {
      this.events.push(text);
      return { rowCount: 0, rows: [] };
    }
    if (text.startsWith("SELECT * FROM public.agentpass_human_quarantine_credential_clone")) return { rowCount: 1, rows: [{ id: credentialBytes, member_id: ids.member, clone_detected_at: detectedAt }] };
    throw new Error("unexpected SQL in clone quarantine test");
  }
}

test("clone evidence is durably quarantined and propagates authority reduction in one transaction", async () => {
  const client = new QuarantineClient();
  const reductions = [];
  const repository = createPostgresHumanRepository({
    client,
    onAuthorityReduction: async (input) => { reductions.push(input); return { generation: 9 }; }
  });

  assert.equal(await repository.quarantineCredentialClone({
    session_id: ids.session,
    organization_id: ids.organization,
    credential_id: credentialId,
    expected_sign_count: 8,
    observed_sign_count: 8
  }), true);

  assert.deepEqual(client.events, ["BEGIN", "COMMIT"]);
  const mutation = client.calls.find(({ text }) => text.startsWith("SELECT * FROM public.agentpass_human_quarantine_credential_clone"));
  assert.match(mutation.text, /agentpass_human_quarantine_credential_clone/u);
  assert.deepEqual(mutation.params.slice(3), [8, 8]);
  assert.equal(reductions.length, 1);
  assert.equal(reductions[0].tx !== undefined, true);
  assert.equal(reductions[0].reason, "webauthn_clone_detected");
  assert.equal(reductions[0].resource, "credential");
  assert.equal(reductions[0].actor_session_id, ids.session);
  assert.equal(reductions[0].occurred_at, detectedAt.toISOString());
});

test("authority propagation failure rolls clone quarantine back", async () => {
  const client = new QuarantineClient();
  const repository = createPostgresHumanRepository({
    client,
    onAuthorityReduction: async () => { throw new Error("private database detail"); }
  });

  await assert.rejects(() => repository.quarantineCredentialClone({
    session_id: ids.session,
    organization_id: ids.organization,
    credential_id: credentialId,
    expected_sign_count: 8,
    observed_sign_count: 7
  }), /private database detail/u);
  assert.deepEqual(client.events, ["BEGIN", "ROLLBACK"]);
});
