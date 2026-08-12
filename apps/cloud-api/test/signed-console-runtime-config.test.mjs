import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import { createApiTokenRecord, generateApiToken } from "../src/auth.mjs";
import { createCloudRuntime, loadRuntimeConfig } from "../src/runtime.mjs";

const CURSOR_SECRET = Buffer.alloc(32, 0x5a).toString("base64url");
const DATABASE_URL = "postgresql://agent:database-secret@db.example.test/agentpass?sslmode=verify-full";
const IDENTIFIER_ISSUER = "agentpass-console";
const IDENTIFIER_AUDIENCE = "agentpass-cloud-session";
const IDENTIFIER_KID = "console-2026-08";

function createFixture({ identityPublicKey, bundlePrivateKey } = {}) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "agentpass-signed-console-runtime-"));
  fs.chmodSync(root, 0o700);
  const dataDir = path.join(root, "data");
  const tokenRecordsPath = path.join(root, "tokens.json");
  const bundlePrivateKeyPath = path.join(root, "bundle-private.pem");
  const identityPublicKeyPath = path.join(root, "console-identity-public.pem");
  const bundlePair = crypto.generateKeyPairSync("ed25519");
  const identityPair = crypto.generateKeyPairSync("ed25519");
  const token = generateApiToken();
  const records = [createApiTokenRecord({
    token,
    organizationId: "11111111-1111-4111-8111-111111111111",
    memberId: "22222222-2222-4222-8222-222222222222",
    role: "owner"
  })];
  const bundlePEM = bundlePrivateKey ?? bundlePair.privateKey.export({ type: "pkcs8", format: "pem" });
  const identityPEM = identityPublicKey ?? identityPair.publicKey.export({ type: "spki", format: "pem" });
  fs.writeFileSync(tokenRecordsPath, JSON.stringify(records), { mode: 0o600 });
  fs.writeFileSync(bundlePrivateKeyPath, bundlePEM, { mode: 0o600 });
  fs.writeFileSync(identityPublicKeyPath, identityPEM, { mode: 0o600 });
  return {
    root,
    tokenRecordsPath,
    bundlePrivateKeyPath,
    identityPublicKeyPath,
    bundlePEM: String(bundlePEM),
    identityPEM: String(identityPEM),
    env: {
      AGENTPASS_CLOUD_PROFILE: "hosted",
      AGENTPASS_CLOUD_BUNDLE_PRIVATE_KEY_PATH: bundlePrivateKeyPath,
      AGENTPASS_CLOUD_PORT: "0",
      AGENTPASS_DATABASE_URL: DATABASE_URL,
      AGENTPASS_CONSOLE_ORIGIN: "https://console.example.test",
      AGENTPASS_WEBAUTHN_RP_ID: "example.test",
      AGENTPASS_HUMAN_CURSOR_SECRET: CURSOR_SECRET,
      AGENTPASS_CAPABILITY_NONCE_SECRET: Buffer.alloc(32, 0x33).toString("base64url"),
      AGENTPASS_IDENTITY_PROVIDER: "chatgpt",
      AGENTPASS_IDENTITY_ASSERTION_ISSUER: IDENTIFIER_ISSUER,
      AGENTPASS_IDENTITY_ASSERTION_AUDIENCE: IDENTIFIER_AUDIENCE,
      AGENTPASS_IDENTITY_ASSERTION_KID: IDENTIFIER_KID,
      AGENTPASS_IDENTITY_ASSERTION_PUBLIC_KEY_PATH: identityPublicKeyPath
    }
  };
}

function removeFixture(fixture) {
  fs.rmSync(fixture.root, { recursive: true, force: true });
}

function fakePostgresRuntime() {
  const noOp = async () => null;
  const humanRepository = {
    createSession: noOp,
    findSessionByTokenHash: noOp,
    updateSessionActivity: noOp,
    revokeSession: noOp,
    listSessions: noOp,
    consumeConsoleIdentityJti: async () => true,
    bindRecentAuth: noOp,
    consumeRecentAuth: noOp,
    listCredentialsForSession: async () => [],
    getRegistrationUser: noOp,
    createCredential: noOp,
    listCredentialMetadataForSession: async () => [],
    updateCredentialLabel: noOp,
    revokeCredential: noOp,
    listSafeSessions: async () => [],
    revokeManagedSession: noOp,
    findCredentialForSession: noOp,
    updateCredentialCounter: noOp
  };
  const organizationRepository = {
    listOrganizationsForMember: async () => [],
    createOrganizationWithOwner: noOp,
    renameOrganization: noOp,
    listMembers: async () => [],
    updateMemberRole: noOp,
    removeMember: noOp,
    listInvitations: async () => [],
    createInvitation: noOp,
    revokeInvitation: noOp,
    acceptInvitation: noOp
  };
  let closed = false;
  return {
    pool: { async query() { return { rows: [], rowCount: 0 }; } },
    humanRepository,
    organizationRepository,
    capabilityAuthorityRepository: {
      async issueCapabilityMetadata() { return null; },
      async listRevokedCapabilityIds() { return []; }
    },
    controlPlaneStore: {},
    sharedControlRepository: {
      async consumeDeviceRequestNonce() { return { accepted: true }; },
      async acquireRateLimit() { return { allowed: true, limit: 120, remaining: 119, retryAfterMs: 0, retryAfterSeconds: 0, resetAt: Date.now() }; }
    },
    async close() { closed = true; },
    wasClosed() { return closed; }
  };
}

test("loadRuntimeConfig fails closed when a production identity assertion setting is missing", () => {
  const fixture = createFixture();
  try {
    const expectedErrors = new Map([
      ["AGENTPASS_IDENTITY_ASSERTION_ISSUER", /requires complete PostgreSQL/],
      ["AGENTPASS_IDENTITY_ASSERTION_AUDIENCE", /requires complete PostgreSQL/],
      ["AGENTPASS_IDENTITY_ASSERTION_KID", /requires complete PostgreSQL/],
      ["AGENTPASS_IDENTITY_ASSERTION_PUBLIC_KEY_PATH", /requires complete PostgreSQL/]
    ]);
    for (const [name, expected] of expectedErrors) {
      const env = { ...fixture.env };
      delete env[name];
      assert.throws(
        () => loadRuntimeConfig(env),
        expected,
        `missing ${name} must be rejected`
      );
    }
  } finally {
    removeFixture(fixture);
  }
});

test("createCloudRuntime rejects an identity public-key file with unsafe mode", async () => {
  const fixture = createFixture();
  try {
    fs.chmodSync(fixture.identityPublicKeyPath, 0o640);
    await assert.rejects(
      createCloudRuntime({ env: fixture.env }),
      /Cloud console identity public key permissions are unsafe/
    );
  } finally {
    removeFixture(fixture);
  }
});

test("createCloudRuntime rejects a symlink at the identity public-key path", async () => {
  const fixture = createFixture();
  const target = path.join(fixture.root, "console-identity-target.pem");
  try {
    fs.renameSync(fixture.identityPublicKeyPath, target);
    fs.symlinkSync(target, fixture.identityPublicKeyPath);
    await assert.rejects(
      createCloudRuntime({ env: fixture.env }),
      /ELOOP|unsafe|symbolic link|too many levels/i
    );
  } finally {
    removeFixture(fixture);
  }
});

test("createCloudRuntime rejects a hardlink at the identity public-key path", async () => {
  const fixture = createFixture();
  const target = path.join(fixture.root, "console-identity-target.pem");
  try {
    fs.renameSync(fixture.identityPublicKeyPath, target);
    fs.linkSync(target, fixture.identityPublicKeyPath);
    await assert.rejects(
      createCloudRuntime({ env: fixture.env }),
      /Cloud console identity public key permissions are unsafe/
    );
  } finally {
    removeFixture(fixture);
  }
});

test("createCloudRuntime rejects a foreign-owner equivalent at the identity public-key boundary", async () => {
  const fixture = createFixture();
  assert.equal(typeof process.getuid, "function", "the runtime owner boundary requires a POSIX uid provider");
  const originalOpenSync = fs.openSync;
  const originalFstatSync = fs.fstatSync;
  const identityDescriptors = new Set();
  try {
    fs.openSync = (file, ...args) => {
      const descriptor = originalOpenSync(file, ...args);
      if (path.resolve(String(file)) === fixture.identityPublicKeyPath) identityDescriptors.add(descriptor);
      return descriptor;
    };
    fs.fstatSync = (descriptor, ...args) => {
      const stat = originalFstatSync(descriptor, ...args);
      if (!identityDescriptors.has(descriptor)) return stat;
      const foreignOwnerStat = Object.create(Object.getPrototypeOf(stat), Object.getOwnPropertyDescriptors(stat));
      Object.defineProperty(foreignOwnerStat, "uid", { value: process.getuid() + 1, configurable: true });
      return foreignOwnerStat;
    };
    await assert.rejects(
      createCloudRuntime({ env: fixture.env }),
      /Cloud console identity public key permissions are unsafe/
    );
  } finally {
    fs.openSync = originalOpenSync;
    fs.fstatSync = originalFstatSync;
    removeFixture(fixture);
  }
});

test("createCloudRuntime rejects non-Ed25519 bundle and console identity keys", async (t) => {
  const rsa = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
  const cases = [
    {
      name: "bundle private key",
      fixture: createFixture({ bundlePrivateKey: rsa.privateKey.export({ type: "pkcs8", format: "pem" }) }),
      expected: /Cloud bundle private key must be Ed25519/
    },
    {
      name: "console identity public key",
      fixture: createFixture({ identityPublicKey: rsa.publicKey.export({ type: "spki", format: "pem" }) }),
      expected: /pinned public key must be Ed25519/
    }
  ];
  for (const value of cases) {
    await t.test(value.name, async () => {
      const postgres = fakePostgresRuntime();
      try {
        await assert.rejects(
          createCloudRuntime({ env: value.fixture.env, postgresFactory: async () => postgres }),
          value.expected
        );
        assert.equal(postgres.wasClosed(), value.name === "console identity public key");
      } finally {
        removeFixture(value.fixture);
      }
    });
  }
});

test("createCloudRuntime rejects broken bundle and console identity PEM", async (t) => {
  const cases = [
    {
      name: "bundle private key",
      fixture: createFixture({ bundlePrivateKey: "-----BEGIN PRIVATE KEY-----\nnot-a-key\n-----END PRIVATE KEY-----\n" }),
      expected: /Cloud bundle private key is invalid/
    },
    {
      name: "console identity public key",
      fixture: createFixture({ identityPublicKey: "-----BEGIN PUBLIC KEY-----\nnot-a-key\n-----END PUBLIC KEY-----\n" }),
      expected: /pinned public key is invalid/
    }
  ];
  for (const value of cases) {
    await t.test(value.name, async () => {
      const postgres = fakePostgresRuntime();
      try {
        await assert.rejects(
          createCloudRuntime({ env: value.fixture.env, postgresFactory: async () => postgres }),
          value.expected
        );
        assert.equal(postgres.wasClosed(), value.name === "console identity public key");
      } finally {
        removeFixture(value.fixture);
      }
    });
  }
});

test("complete production configuration wires only the pinned signedConsoleIdentity boundary", async () => {
  const fixture = createFixture();
  const calls = [];
  const postgres = fakePostgresRuntime();
  const logs = [];
  const logger = {
    info(...args) { logs.push(args); },
    warn(...args) { logs.push(args); },
    error(...args) { logs.push(args); }
  };
  try {
    // Hosted Human Auth has no runtime dependency on the legacy operator
    // bearer database. The profile rejects such a path before composition.
    fs.unlinkSync(fixture.tokenRecordsPath);
    const runtime = await createCloudRuntime({
      env: fixture.env,
      logger,
      postgresFactory: async () => postgres,
      humanAuthFactory: (input) => {
        calls.push(input);
        return {
          api: { async handle() { return { status: 404, body: { error: { code: "not_found", message: "Resource not found" } }, headers: {} }; } },
          humanSession: { async authenticateRequest() { return { session: {} }; } },
          recentAuthService: { async authorize() { return { verified: false }; } }
        };
      }
    });
    assert.equal(calls.length, 1);
    assert.deepEqual(calls[0].signedConsoleIdentity, {
      issuer: IDENTIFIER_ISSUER,
      audience: IDENTIFIER_AUDIENCE,
      keyId: IDENTIFIER_KID,
      publicKey: fixture.identityPEM
    });
    assert.equal(Object.hasOwn(calls[0], "privateKeyPEM"), false);
    assert.equal(Object.hasOwn(calls[0], "databaseUrl"), false);
    assert.equal(Object.hasOwn(runtime.config.humanAuth, "cursorSecret"), false);
    assert.equal(Object.hasOwn(runtime.config.humanAuth, "database"), false);
    assert.equal(runtime.config.tokenRecordsPath, null);
    const serializedConfig = JSON.stringify(runtime.config);
    const serializedLogs = JSON.stringify(logs);
    for (const secret of [DATABASE_URL, CURSOR_SECRET, fixture.bundlePEM]) {
      assert.doesNotMatch(serializedConfig, new RegExp(escapeRegExp(secret)), "secret leaked into runtime config");
      assert.doesNotMatch(serializedLogs, new RegExp(escapeRegExp(secret)), "secret leaked into runtime logs");
    }
    await runtime.listen();
    await runtime.close();
    assert.doesNotMatch(JSON.stringify(logs), new RegExp(escapeRegExp(DATABASE_URL)));
    assert.doesNotMatch(JSON.stringify(logs), new RegExp(escapeRegExp(CURSOR_SECRET)));
  } finally {
    if (!postgres.wasClosed()) await postgres.close();
    removeFixture(fixture);
  }
});

function escapeRegExp(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}
