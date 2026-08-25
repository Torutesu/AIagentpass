import assert from "node:assert/strict";
import crypto from "node:crypto";
import test from "node:test";

import {
  AGENT_SESSION_SIGNER_ALGORITHM,
  AGENT_SESSION_SIGNER_ERROR_CODES,
  AGENT_SESSION_SIGNER_MAX_RETIRING_KEYS,
  AGENT_SESSION_SIGNER_MAX_RETIRING_KEY_LIFETIME_MS,
  AGENT_SESSION_SIGNER_PURPOSE,
  AGENT_SESSION_SIGNER_VERIFICATION_KEYS_ENV,
  createHostedAgentSessionGrantSigner,
  parseAgentSessionSignerConfig
} from "../src/agent-session-signer-config.mjs";
import {
  AGENT_SESSION_GRANT_TYPE,
  agentSessionGrantSigningData,
  agentSessionGrantStatementHash
} from "../src/agent-session-grant.mjs";

const NOW = Date.parse("2026-08-13T10:00:00.000Z");
const ACTIVE_ID = "agent-session-2026-08";
const RETIRING_ID = "agent-session-2026-07";
const RETIRING_EXPIRY = "2026-08-20T10:00:00.000Z";
const ids = {
  grant: "11111111-1111-4111-8111-111111111111",
  organization: "22222222-2222-4222-8222-222222222222",
  device: "33333333-3333-4333-8333-333333333333",
  agent: "44444444-4444-4444-8444-444444444444",
  adapter: "55555555-5555-4555-8555-555555555555"
};

const activeKeys = crypto.generateKeyPairSync("ed25519");
const retiringKeys = crypto.generateKeyPairSync("ed25519");
const otherKeys = crypto.generateKeyPairSync("ed25519");

function publicKeyPem(key) {
  return key.publicKey.export({ type: "spki", format: "pem" }).toString();
}

function baseEnv() {
  return {
    AGENTPASS_CLOUD_PROFILE: "hosted",
    AGENTPASS_CLOUD_AGENT_SESSION_TIMEOUT_MS: "5000"
  };
}

function legacyEnv(overrides = {}) {
  return {
    ...baseEnv(),
    AGENTPASS_CLOUD_AGENT_SESSION_KEY_ID: ACTIVE_ID,
    AGENTPASS_CLOUD_AGENT_SESSION_PUBLIC_KEY: publicKeyPem(activeKeys),
    ...overrides
  };
}

function rotationDocument({ activeId = ACTIVE_ID, activePublicKey = publicKeyPem(activeKeys), retiring = [] } = {}) {
  return {
    version: 1,
    active: {
      key_id: activeId,
      algorithm: AGENT_SESSION_SIGNER_ALGORITHM,
      public_key: activePublicKey
    },
    retiring
  };
}

function rotationEnv(options = {}, { includeLegacy = false } = {}) {
  return {
    ...baseEnv(),
    ...(includeLegacy ? {
      AGENTPASS_CLOUD_AGENT_SESSION_KEY_ID: options.activeId ?? ACTIVE_ID,
      AGENTPASS_CLOUD_AGENT_SESSION_PUBLIC_KEY: options.activePublicKey ?? publicKeyPem(activeKeys)
    } : {}),
    [AGENT_SESSION_SIGNER_VERIFICATION_KEYS_ENV]: JSON.stringify(rotationDocument(options))
  };
}

function retiringEntry(overrides = {}) {
  return {
    key_id: RETIRING_ID,
    algorithm: AGENT_SESSION_SIGNER_ALGORITHM,
    public_key: publicKeyPem(retiringKeys),
    expires_at: RETIRING_EXPIRY,
    ...overrides
  };
}

function statement(keyId, overrides = {}) {
  return {
    version: 1,
    grant_id: ids.grant,
    organization_id: ids.organization,
    device_id: ids.device,
    agent_id: ids.agent,
    agent_kind: "claude-code",
    adapter_id: ids.adapter,
    adapter_version: "1.2.3",
    worktree_binding_sha256: "a".repeat(64),
    process_binding_policy_id: "claude-code-v1",
    scope: {
      operations: ["git.commit.sign"],
      repositories: ["/work/project"],
      branches: { allow: ["feature/*"], deny: ["main"] },
      remotes: { allow: ["git@example.test:project.git"], deny: [] }
    },
    max_signatures: 2,
    not_before: "2026-08-13T09:59:00.000Z",
    expires_at: "2026-08-13T10:14:00.000Z",
    control_sequence: 12,
    authority_generation: 7,
    issuer: "agentpass-cloud",
    key_id: keyId,
    ...overrides
  };
}

function signedEnvelope(keyPair, keyId, overrides = {}) {
  const grantStatement = statement(keyId, overrides);
  const bytes = agentSessionGrantSigningData(grantStatement);
  return {
    version: 1,
    type: AGENT_SESSION_GRANT_TYPE,
    statement: grantStatement,
    statement_hash: agentSessionGrantStatementHash(grantStatement),
    signature: crypto.sign(null, bytes, keyPair.privateKey).toString("base64url")
  };
}

function providerFor(keyPair = activeKeys, keyId = ACTIVE_ID, metadataOverrides = {}) {
  return {
    async publicKeyMetadata(input) {
      assert.equal(input.key_id, keyId);
      assert.equal(input.algorithm, AGENT_SESSION_SIGNER_ALGORITHM);
      assert.equal(input.purpose, AGENT_SESSION_SIGNER_PURPOSE);
      assert.equal(input.version, 1);
      return {
        key_id: keyId,
        algorithm: AGENT_SESSION_SIGNER_ALGORITHM,
        public_key: publicKeyPem(keyPair),
        ...metadataOverrides
      };
    },
    async sign(input) {
      assert.equal(input.key_id, keyId);
      assert.equal(input.algorithm, AGENT_SESSION_SIGNER_ALGORITHM);
      assert.equal(input.purpose, AGENT_SESSION_SIGNER_PURPOSE);
      return crypto.sign(null, input.bytes, keyPair.privateKey);
    }
  };
}

test("keeps the legacy single-key hosted configuration compatible", () => {
  const config = parseAgentSessionSignerConfig(legacyEnv(), {}, { now: NOW });
  assert.equal(config.keyId, ACTIVE_ID);
  assert.deepEqual(config.verificationKeys.map(({ key_id, status }) => ({ key_id, status })), [
    { key_id: ACTIVE_ID, status: "active" }
  ]);
  assert.deepEqual(config.retiringVerificationKeys, []);
  assert.equal(Object.hasOwn(config, "verificationKeyRing"), true);
  assert.equal(JSON.stringify(config).includes("PRIVATE KEY"), false);
});

test("parses one active key plus bounded, time-limited retiring verification keys", () => {
  const config = parseAgentSessionSignerConfig(rotationEnv({ retiring: [retiringEntry()] }), {}, { now: NOW });
  assert.equal(config.keyId, ACTIVE_ID);
  assert.equal(config.activeVerificationKey.status, "active");
  assert.deepEqual(config.retiringVerificationKeys.map(({ key_id, status, expires_at }) => ({ key_id, status, expires_at })), [
    { key_id: RETIRING_ID, status: "retiring", expires_at: RETIRING_EXPIRY }
  ]);
  assert.deepEqual(config.verificationKeyRing, {
    version: 1,
    purpose: AGENT_SESSION_SIGNER_PURPOSE,
    active_key_id: ACTIVE_ID,
    keys: config.verificationKeys
  });
  assert.equal(Object.hasOwn(config.activeVerificationKey, "private_key"), false);
});

test("rejects duplicate, ambiguous, expired, unsupported, and unbounded rotation documents", () => {
  const cases = [
    [
      "active and retiring key id collision",
      rotationEnv({ retiring: [retiringEntry({ key_id: ACTIVE_ID })] }),
      AGENT_SESSION_SIGNER_ERROR_CODES.AMBIGUOUS_KEY
    ],
    [
      "active and retiring public key collision",
      rotationEnv({ retiring: [retiringEntry({ public_key: publicKeyPem(activeKeys) })] }),
      AGENT_SESSION_SIGNER_ERROR_CODES.AMBIGUOUS_KEY
    ],
    [
      "duplicate retiring key ids",
      rotationEnv({ retiring: [retiringEntry(), retiringEntry({ expires_at: "2026-08-21T10:00:00.000Z" })] }),
      AGENT_SESSION_SIGNER_ERROR_CODES.DUPLICATE_KEY
    ],
    [
      "retiring entry claiming active status",
      rotationEnv({ retiring: [retiringEntry({ status: "active" })] }),
      AGENT_SESSION_SIGNER_ERROR_CODES.CONFIG
    ],
    [
      "expired retiring key",
      rotationEnv({ retiring: [retiringEntry({ expires_at: "2026-08-13T10:00:00.000Z" })] }),
      AGENT_SESSION_SIGNER_ERROR_CODES.CONFIG
    ],
    [
      "retiring key outside the overlap bound",
      rotationEnv({ retiring: [retiringEntry({ expires_at: new Date(NOW + AGENT_SESSION_SIGNER_MAX_RETIRING_KEY_LIFETIME_MS + 1).toISOString() })] }),
      AGENT_SESSION_SIGNER_ERROR_CODES.CONFIG
    ],
    [
      "unsupported algorithm",
      rotationEnv({ retiring: [retiringEntry({ algorithm: "rsa-sha256" })] }),
      AGENT_SESSION_SIGNER_ERROR_CODES.CONFIG
    ],
    [
      "more than the maximum retiring key count",
      rotationEnv({ retiring: Array.from({ length: AGENT_SESSION_SIGNER_MAX_RETIRING_KEYS + 1 }, (_, index) => retiringEntry({
        key_id: `retiring-${index}`,
        public_key: publicKeyPem(index === 0 ? retiringKeys : crypto.generateKeyPairSync("ed25519")),
        expires_at: `2026-08-${String(20 + index).padStart(2, "0")}T10:00:00.000Z`
      })) }),
      AGENT_SESSION_SIGNER_ERROR_CODES.CONFIG
    ]
  ];
  for (const [label, env, code] of cases) {
    assert.throws(() => parseAgentSessionSignerConfig(env, {}, { now: NOW }), (error) => error.code === code, label);
  }
  assert.throws(() => parseAgentSessionSignerConfig({
    ...baseEnv(),
    [AGENT_SESSION_SIGNER_VERIFICATION_KEYS_ENV]: `{"version":1,"version":1,"active":{"key_id":"${ACTIVE_ID}","algorithm":"ed25519","public_key":${JSON.stringify(publicKeyPem(activeKeys))}},"retiring":[]}`
  }, {}, { now: NOW }), (error) => error.code === AGENT_SESSION_SIGNER_ERROR_CODES.CONFIG);
});

test("rejects legacy active metadata that conflicts with the rotation document", () => {
  const conflicting = rotationEnv({ retiring: [retiringEntry()] }, { includeLegacy: true });
  conflicting.AGENTPASS_CLOUD_AGENT_SESSION_KEY_ID = "wrong-active";
  assert.throws(
    () => parseAgentSessionSignerConfig(conflicting, {}, { now: NOW }),
    (error) => error.code === AGENT_SESSION_SIGNER_ERROR_CODES.AMBIGUOUS_KEY
  );
  assert.throws(
    () => parseAgentSessionSignerConfig({
      ...rotationEnv({ retiring: [retiringEntry()] }),
      AGENTPASS_CLOUD_AGENT_SESSION_KEY_ID: ACTIVE_ID
    }, {}, { now: NOW }),
    (error) => error.code === AGENT_SESSION_SIGNER_ERROR_CODES.AMBIGUOUS_KEY
  );
});

test("checks key reuse across the whole active and retiring verification set", () => {
  assert.throws(
    () => parseAgentSessionSignerConfig(rotationEnv({ retiring: [retiringEntry()] }), { refresh: { keyId: RETIRING_ID } }, { now: NOW }),
    (error) => error.code === AGENT_SESSION_SIGNER_ERROR_CODES.KEY_REUSE
  );
  assert.throws(
    () => parseAgentSessionSignerConfig(rotationEnv({ retiring: [retiringEntry()] }), { bundle: { publicKey: publicKeyPem(retiringKeys) } }, { now: NOW }),
    (error) => error.code === AGENT_SESSION_SIGNER_ERROR_CODES.KEY_REUSE
  );
  assert.throws(
    () => parseAgentSessionSignerConfig(rotationEnv({ retiring: [retiringEntry()] }), { refresh: { publicKey: retiringKeys.privateKey } }, { now: NOW }),
    (error) => error.code === AGENT_SESSION_SIGNER_ERROR_CODES.KEY_REUSE
  );
});

test("uses only the active provider key while verification accepts the overlap", async () => {
  const signer = createHostedAgentSessionGrantSigner({
    provider: providerFor(),
    env: rotationEnv({ retiring: [retiringEntry()] }),
    now: () => NOW
  });
  const activeGrant = await signer.signAgentSessionGrant(statement(ACTIVE_ID));
  assert.deepEqual(signer.verifyAgentSessionGrant(activeGrant, { at: NOW }), activeGrant);

  const retiringGrant = signedEnvelope(retiringKeys, RETIRING_ID);
  assert.deepEqual(signer.verifyAgentSessionGrant(retiringGrant, { at: NOW }), retiringGrant);
  const metadata = await signer.verificationKeyMetadata();
  assert.deepEqual(metadata.keys.map(({ key_id, status }) => ({ key_id, status })), [
    { key_id: ACTIVE_ID, status: "active" },
    { key_id: RETIRING_ID, status: "retiring" }
  ]);
  assert.deepEqual(await signer.verificationKeyMetadata(RETIRING_ID), metadata.keys[1]);
  assert.deepEqual((await signer.health()).verification_key_ids, [ACTIVE_ID, RETIRING_ID]);
});

test("stops accepting a retiring key at expiry and rejects unknown keys", async () => {
  const signer = createHostedAgentSessionGrantSigner({
    provider: providerFor(),
    env: rotationEnv({ retiring: [retiringEntry()] }),
    now: () => NOW
  });
  const retiringGrant = signedEnvelope(retiringKeys, RETIRING_ID);
  const expiry = Date.parse(RETIRING_EXPIRY);
  assert.throws(
    () => signer.verifyAgentSessionGrant(retiringGrant, { at: expiry }),
    (error) => error.code === AGENT_SESSION_SIGNER_ERROR_CODES.KEY_NOT_TRUSTED
  );
  await assert.rejects(
    signer.verificationKeyMetadata(RETIRING_ID, { at: expiry }),
    (error) => error.code === AGENT_SESSION_SIGNER_ERROR_CODES.KEY_NOT_TRUSTED
  );
  assert.throws(
    () => signer.verifyAgentSessionGrant(signedEnvelope(otherKeys, "agent-session-unknown"), { at: NOW }),
    (error) => error.code === AGENT_SESSION_SIGNER_ERROR_CODES.KEY_NOT_TRUSTED
  );
});

test("fails closed on provider/config mismatch and never falls back to a local private key", async () => {
  const mismatched = createHostedAgentSessionGrantSigner({
    provider: providerFor(otherKeys),
    env: rotationEnv({ retiring: [retiringEntry()] }),
    now: () => NOW
  });
  await assert.rejects(mismatched.publicKeyMetadata(), (error) => error.code === AGENT_SESSION_SIGNER_ERROR_CODES.METADATA);
  assert.throws(
    () => parseAgentSessionSignerConfig(rotationEnv({ activePublicKey: activeKeys.privateKey.export({ type: "pkcs8", format: "pem" }).toString() }), {}, { now: NOW }),
    (error) => error.code === AGENT_SESSION_SIGNER_ERROR_CODES.CONFIG
  );
  assert.throws(
    () => createHostedAgentSessionGrantSigner({ env: rotationEnv({ retiring: [retiringEntry()] }), now: () => NOW }),
    (error) => error.code === AGENT_SESSION_SIGNER_ERROR_CODES.CONFIG
  );
});
