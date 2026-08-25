import assert from "node:assert/strict";
import test from "node:test";

import { createApiTokenRecord } from "../src/auth.mjs";
import { createCloudApi } from "../src/server.mjs";

const ORGANIZATION_ID = "11111111-1111-4111-8111-111111111111";
const DEVICE_ID = "22222222-2222-4222-8222-222222222222";
const PROOF = "99999999-9999-4999-8999-999999999999";
const UPPERCASE_PROOF = "abcdefab-cdef-4abc-8def-abcdefabcdef";
const OTHER_CHALLENGE_ID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const TOKEN = "ap_owner_token_recent_auth_contract_abcdefghijklmnopqrstuvwxyz";
const NOW = Date.parse("2026-08-20T00:00:00.000Z");
const REVOKE_PATH = `/v1/organizations/${ORGANIZATION_ID}/devices/${DEVICE_ID}/revoke`;

function validVerification({ challenge_id = PROOF } = {}) {
  return {
    authenticated_at: NOW,
    challenge_id,
    consumed: true,
    member_id: "owner-1",
    operation: "device.revoke",
    organization_id: ORGANIZATION_ID,
    verified: true
  };
}

function responsePromise() {
  let resolve;
  let reject;
  const completed = new Promise((resolvePromise, rejectPromise) => {
    resolve = resolvePromise;
    reject = rejectPromise;
  });
  const response = {
    headersSent: false,
    destroy(error) {
      reject(error ?? new Error("response destroyed"));
    },
    end(body = Buffer.alloc(0)) {
      resolve({ body: Buffer.from(body).toString("utf8"), headers: this.headers, status: this.status });
    },
    writeHead(status, headers) {
      this.headersSent = true;
      this.headers = headers;
      this.status = status;
    }
  };
  return { completed, response };
}

async function invoke(server, { proof, verifyRecentWebAuthn, store = {} }) {
  const request = {
    headers: {
      authorization: `Bearer ${TOKEN}`,
      "agentpass-recent-auth": proof,
      "content-type": "application/json",
      "idempotency-key": "recent-auth-contract-0001"
    },
    method: "POST",
    socket: { remoteAddress: "127.0.0.1" },
    url: REVOKE_PATH,
    async *[Symbol.asyncIterator]() {
      yield Buffer.from(JSON.stringify({ reason: "contract-test" }));
    }
  };
  const { completed, response } = responsePromise();
  server.emit("request", request, response);
  return { response, ...(await completed), body: JSON.parse((await completed).body) };
}

function createFixture({ verifyRecentWebAuthn, store = {} }) {
  return createCloudApi({
    now: () => NOW,
    store: {
      async appendAdminAuditEvent() {},
      async createRevocation(input) {
        return { revocation_id: "33333333-3333-4333-8333-333333333333", ...input };
      },
      ...store
    },
    tokenRecords: [createApiTokenRecord({
      token: TOKEN,
      tokenId: "recent-auth-contract-token",
      organizationId: ORGANIZATION_ID,
      memberId: "owner-1",
      role: "owner"
    })],
    verifyRecentWebAuthn
  });
}

test("generic recent-auth requires a canonical UUID proof before invoking the verifier", async () => {
  let verifierCalls = 0;
  const server = createFixture({
    verifyRecentWebAuthn: async () => {
      verifierCalls += 1;
      return validVerification();
    }
  });
  assert.equal(server.listening, false);

  for (const proof of [
    "not-a-uuid",
    "00000000-0000-0000-8000-000000000000",
    UPPERCASE_PROOF.toUpperCase()
  ]) {
    const result = await invoke(server, { proof });
    assert.equal(result.status, 401, proof);
    assert.equal(result.body.error.code, "recent_auth_required", proof);
  }
  assert.equal(verifierCalls, 0);
});

test("generic recent-auth requires the verifier challenge_id to equal the proof", async () => {
  let revocations = 0;
  const server = createFixture({
    verifyRecentWebAuthn: async () => validVerification({ challenge_id: OTHER_CHALLENGE_ID }),
    store: {
      async createRevocation(input) {
        revocations += 1;
        return { revocation_id: "33333333-3333-4333-8333-333333333333", ...input };
      }
    }
  });
  assert.equal(server.listening, false);

  const result = await invoke(server, { proof: PROOF });
  assert.equal(result.status, 401);
  assert.equal(result.body.error.code, "recent_auth_failed");
  assert.equal(revocations, 0);
});
