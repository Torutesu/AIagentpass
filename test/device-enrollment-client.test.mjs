import assert from "node:assert/strict";
import crypto from "node:crypto";
import test from "node:test";

import { canonicalJson } from "../lib/identity.mjs";

import {
  DEVICE_ENROLLMENT_ERRORS,
  DeviceEnrollmentError,
  buildEnrollmentCandidateBinding,
  buildDeviceEnrollmentRequest,
  candidateBindingDigest,
  canonicalEnrollmentProof,
  canonicalEnrollmentProofV2,
  createDeviceEnrollmentClient,
  createV2DeviceEnrollmentClient,
  deviceEnrollmentEvidence,
  recoverDeviceEnrollment,
  verifyDeviceEnrollmentReceipt
} from "../lib/device-enrollment-client.mjs";

const ENROLLMENT = "11111111-1111-4111-8111-111111111111";
const ORGANIZATION = "22222222-2222-4222-8222-222222222222";
const DEVICE = "33333333-3333-4333-8333-333333333333";
const BASE_URL = "https://api.example.test/v1";
const CREDENTIAL = "Abcdefghijklmnopqrstuvwxyz0123456789-_ABCDE";
const CHALLENGE_NONCE = "A".repeat(43);
const CHALLENGE_ID = ENROLLMENT;
const CONTROL_TEST_KEYS = keys("ed25519");
const REFRESH_TEST_KEYS = keys("ed25519");

test("the production factory cannot silently fall back to legacy v1", () => {
  const pair = keys();
  assert.throws(() => createV2DeviceEnrollmentClient(input(pair)), (error) => {
    assert.equal(error.code, DEVICE_ENROLLMENT_ERRORS.INVALID_CONFIG);
    return true;
  });
});

function keys(algorithm = "p256-sha256") {
  const pair = algorithm === "ed25519"
    ? crypto.generateKeyPairSync("ed25519")
    : crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  return {
    ...pair,
    publicPem: pair.publicKey.export({ type: "spki", format: "pem" }).toString()
  };
}

function fingerprint(pair) {
  return `SHA256:${crypto.createHash("sha256").update(pair.publicKey.export({ type: "spki", format: "der" })).digest("base64url")}`;
}

function input(pair, overrides = {}) {
  return {
    baseUrl: BASE_URL,
    proofVersion: 1,
    enrollmentId: ENROLLMENT,
    organizationId: ORGANIZATION,
    deviceId: DEVICE,
    label: "build-mac-01",
    deviceKey: { algorithm: "p256-sha256", spkiPem: pair.publicPem },
    credential: CREDENTIAL,
    keyFingerprint: fingerprint(pair),
    ...overrides
  };
}

function signWith(pair, algorithm = "p256-sha256") {
  return ({ bytes }) => algorithm === "ed25519"
    ? crypto.sign(null, bytes, pair.privateKey)
    : crypto.sign("sha256", bytes, { key: pair.privateKey, dsaEncoding: "ieee-p1363" });
}

function jsonResponse(value, status = 201, headers = {}) {
  const body = JSON.stringify(value);
  return new Response(body, { status, headers: { "content-type": "application/json", ...headers } });
}

function enrolledResponse(pair, extra = {}) {
  const algorithm = pair.publicKey.asymmetricKeyType === "ed25519" ? "ed25519" : "p256-sha256";
  return {
    request_id: "request-123",
    enrollment: {
      version: 1,
      enrollment_id: ENROLLMENT,
      organization_id: ORGANIZATION,
      device_id: DEVICE,
      status: "active",
      key_algorithm: algorithm,
      device_key_epoch: 3,
      control: {
        format_epoch: 2,
        issuer: "cloud-control",
        key_id: "control-v2",
        public_key: CONTROL_TEST_KEYS.publicPem,
        bundle_path: `/v1/organizations/${ORGANIZATION}/bundles/${DEVICE}`,
        refresh_hint: { key_id: "refresh-hint-v1", algorithm: "ed25519", public_key: REFRESH_TEST_KEYS.publicPem }
      }
    },
    ...extra
  };
}

function candidate(pair, overrides = {}) {
  return {
    version: 1,
    enrollment_id: ENROLLMENT,
    organization_id: ORGANIZATION,
    device_id: DEVICE,
    candidate_id: "release-2026-08-13-01",
    artifact_sha256: "a".repeat(64),
    source_commit: "b".repeat(40),
    team_id: "TEAMID1234",
    device_key_fingerprint: fingerprint(pair),
    expires_at: "2099-01-02T03:04:05.000Z",
    ...overrides
  };
}

function possessionReceipt(devicePair, receiptPair, overrides = {}) {
  const { expires_at: _expiresAt, ...candidateStatement } = candidate(devicePair);
  const statement = {
    ...candidateStatement,
    device_key_epoch: 3,
    challenge_nonce_digest: crypto.createHash("sha256").update(CHALLENGE_NONCE).digest("hex"),
    control: {
      format_epoch: 2,
      issuer: "cloud-control",
      key_id: "control-v2",
      public_key: CONTROL_TEST_KEYS.publicPem,
      bundle_path: `/v1/organizations/${ORGANIZATION}/bundles/${DEVICE}`,
      refresh_hint: { key_id: "refresh-hint-v1", algorithm: "ed25519", public_key: REFRESH_TEST_KEYS.publicPem }
    },
    issued_at: "2099-01-02T03:04:05.000Z",
    ...overrides
  };
  const statementBytes = Buffer.from(canonicalJson(statement), "utf8");
  const statementHash = crypto.createHash("sha256").update(statementBytes).digest("hex");
  const signed = Buffer.from(`AgentPass-Cloud-Possession-Receipt-v1\0${statementBytes.toString("utf8")}`);
  return {
    version: 1,
    purpose: "device-enrollment-possession-receipt",
    key_id: "receipt-key-v1",
    algorithm: receiptPair.publicKey.asymmetricKeyType === "ed25519" ? "ed25519" : "p256-sha256",
    statement,
    statement_hash: statementHash,
    signature: receiptPair.publicKey.asymmetricKeyType === "ed25519"
      ? crypto.sign(null, signed, receiptPair.privateKey).toString("base64url")
      : crypto.sign("sha256", signed, { key: receiptPair.privateKey, dsaEncoding: "ieee-p1363" }).toString("base64url")
  };
}

function recoveryInput(pair, receiptPair, overrides = {}) {
  const receipt = possessionReceipt(pair, receiptPair);
  return {
    baseUrl: BASE_URL,
    enrollmentId: ENROLLMENT,
    organizationId: ORGANIZATION,
    deviceId: DEVICE,
    label: "build-mac-01",
    deviceKey: { algorithm: "p256-sha256", spkiPem: pair.publicPem },
    keyFingerprint: fingerprint(pair),
    candidateBinding: candidate(pair),
    requestDigest: "c".repeat(64),
    challengeNonceDigest: crypto.createHash("sha256").update(CHALLENGE_NONCE).digest("hex"),
    possessionReceiptPublicKey: receiptPair.publicPem,
    possessionReceiptKeyId: receipt.key_id,
    signer: signWith(pair),
    ...overrides
  };
}

function resignReceipt(receipt, receiptPair, statement = receipt.statement, extra = {}) {
  const statementBytes = Buffer.from(canonicalJson(statement), "utf8");
  const signed = Buffer.from(`AgentPass-Cloud-Possession-Receipt-v1\0${statementBytes.toString("utf8")}`);
  return {
    ...receipt,
    statement,
    statement_hash: crypto.createHash("sha256").update(statementBytes).digest("hex"),
    signature: crypto.sign(null, signed, receiptPair.privateKey).toString("base64url"),
    ...extra
  };
}

test("builds the exact schema body canonically and never includes credentials", () => {
  const pair = keys();
  const request = buildDeviceEnrollmentRequest({ enrollmentId: ENROLLMENT, organizationId: ORGANIZATION, deviceId: DEVICE, label: "build-mac-01", deviceKey: { algorithm: "p256-sha256", spkiPem: pair.publicPem } });
  assert.deepEqual(JSON.parse(request.body), {
    device_id: DEVICE,
    device_key: { algorithm: "p256-sha256", spki_pem: pair.publicPem },
    enrollment_id: ENROLLMENT,
    label: "build-mac-01",
    organization_id: ORGANIZATION,
    platform: "macos",
    version: 1
  });
  assert.equal(request.body.toString("utf8").startsWith("{"), true);
  assert.equal(request.body.toString("utf8").includes("\n"), false, "canonical JSON contains no physical line breaks");
  assert.equal(request.body.toString("utf8").includes("\\n"), true, "PEM line breaks are escaped public-key data");
  assert.equal(request.body.toString("utf8").includes("PRIVATE KEY"), false);
  assert.match(request.body_digest, /^[0-9a-f]{64}$/);
  assert.equal(request.platform, "macos");
  assert.equal(Object.hasOwn(JSON.parse(request.body), "credential_digest"), false);
});

test("canonicalizes aliases and validates the algorithm against the actual public key", () => {
  const ed = keys("ed25519");
  const request = buildDeviceEnrollmentRequest({
    enrollment_id: ENROLLMENT,
    organization_id: ORGANIZATION,
    device_id: DEVICE,
    label: "agent-host",
    device_key: { algorithm: "ed25519", spki_pem: ed.publicPem }
  });
  assert.equal(request.device_key.algorithm, "ed25519");
  assert.equal(request.device_key.spki_pem, ed.publicPem);
  const p256 = keys();
  assert.throws(() => buildDeviceEnrollmentRequest({ enrollmentId: ENROLLMENT, organizationId: ORGANIZATION, deviceId: DEVICE, label: "agent-host", deviceKey: { algorithm: "ed25519", spkiPem: p256.publicPem } }), (error) => error.code === DEVICE_ENROLLMENT_ERRORS.INVALID_KEY);
});

test("rejects private keys, unknown fields, malformed IDs, unsafe labels, and oversized keys", () => {
  const pair = keys();
  const privatePem = pair.privateKey.export({ type: "pkcs8", format: "pem" }).toString();
  const body = { enrollmentId: ENROLLMENT, organizationId: ORGANIZATION, deviceId: DEVICE, label: "build-mac-01", deviceKey: { algorithm: "p256-sha256", spkiPem: pair.publicPem } };
  assert.throws(() => buildDeviceEnrollmentRequest({ ...body, deviceKey: { algorithm: "p256-sha256", spkiPem: privatePem } }), (error) => error.code === DEVICE_ENROLLMENT_ERRORS.INVALID_KEY);
  assert.throws(() => buildDeviceEnrollmentRequest({ ...body, unexpected: true }), (error) => error.code === DEVICE_ENROLLMENT_ERRORS.INVALID_REQUEST);
  assert.throws(() => buildDeviceEnrollmentRequest({ ...body, organizationId: "not-a-uuid" }), (error) => error.code === DEVICE_ENROLLMENT_ERRORS.INVALID_REQUEST);
  assert.throws(() => buildDeviceEnrollmentRequest({ ...body, label: "\u0000bad" }), (error) => error.code === DEVICE_ENROLLMENT_ERRORS.INVALID_REQUEST);
  assert.throws(() => buildDeviceEnrollmentRequest({ ...body, label: "x".repeat(129) }), (error) => error.code === DEVICE_ENROLLMENT_ERRORS.INVALID_REQUEST);
  assert.throws(() => buildDeviceEnrollmentRequest({ ...body, deviceKey: { algorithm: "p256-sha256", spkiPem: `${pair.publicPem}${"x".repeat(8192)}` } }), (error) => error.code === DEVICE_ENROLLMENT_ERRORS.INVALID_KEY);
});

test("production mode rejects legacy v1 instead of silently falling back", () => {
  const pair = keys();
  assert.throws(() => createDeviceEnrollmentClient({ ...input(pair), requireV2: true }), (error) => {
    assert.equal(error.code, DEVICE_ENROLLMENT_ERRORS.INVALID_CONFIG);
    assert.match(error.message, /proofVersion 2/);
    return true;
  });
});

test("signs proof-of-possession over the exact endpoint and body without a bearer header", async () => {
  const pair = keys();
  let captured;
  const client = createDeviceEnrollmentClient({
    ...input(pair),
    signer: signWith(pair),
    fetchImpl: async (url, init) => {
      captured = { url, init };
      return jsonResponse(enrolledResponse(pair));
    }
  });
  const result = await client.enroll();
  assert.equal(result.status, "enrolled");
  assert.deepEqual(result.evidence, { organization_id: ORGANIZATION, device_id: DEVICE, enrollment_id: ENROLLMENT, device_key_epoch: 3, key_fingerprint: fingerprint(pair) });
  assert.equal(result.organization_id, ORGANIZATION);
  assert.equal(result.control.issuer, "cloud-control");
  assert.equal(result.control.format_epoch, 2);
  assert.equal(result.device_key_epoch, 3);
  assert.equal(result.control.refresh_hint.algorithm, "ed25519");
  assert.equal(JSON.stringify(client.config).includes(CREDENTIAL), false);
  assert.equal(JSON.stringify(result).includes(CREDENTIAL), false);
  assert.equal(captured.url, `${BASE_URL}/enrollments/${ENROLLMENT}`);
  assert.equal(captured.init.method, "POST");
  assert.equal(captured.init.redirect, "error");
  assert.equal(captured.init.headers.authorization, undefined);
  assert.equal(captured.init.headers.Authorization, undefined);
  assert.equal(captured.init.headers["AgentPass-Device"], undefined);
  assert.equal(captured.init.headers["AgentPass-Enrollment-Credential"], CREDENTIAL);
  const body = Buffer.from(captured.init.body);
  const digest = crypto.createHash("sha256").update(body).digest("hex");
  const credentialDigest = crypto.createHash("sha256").update(CREDENTIAL).digest("hex");
  const proof = canonicalEnrollmentProof({ path: `/v1/enrollments/${ENROLLMENT}`, bodyDigest: digest, credentialDigest });
  assert.equal(crypto.verify("sha256", Buffer.from(proof), { key: pair.publicKey, dsaEncoding: "ieee-p1363" }, Buffer.from(captured.init.headers["AgentPass-Enrollment-Signature"], "base64")), true);
  assert.equal(captured.init.headers["content-type"], "application/json");
  assert.equal(captured.init.headers.accept, "application/json");
  assert.equal(body.toString("utf8").includes("PRIVATE KEY"), false);
  assert.equal(JSON.stringify(result).includes("PRIVATE KEY"), false);
});

test("proof verification fails closed when the path or body is substituted", async () => {
  const pair = keys();
  let captured;
  const client = createDeviceEnrollmentClient({
    ...input(pair),
    signer: signWith(pair),
    fetchImpl: async (_url, init) => {
      captured = init;
      return jsonResponse(enrolledResponse(pair));
    }
  });
  await client.enroll();
  const signature = Buffer.from(captured.headers["AgentPass-Enrollment-Signature"], "base64");
  const bodyDigest = crypto.createHash("sha256").update(Buffer.from(captured.body)).digest("hex");
  const credentialDigest = crypto.createHash("sha256").update(CREDENTIAL).digest("hex");
  const differentPath = "/v1/enrollments/44444444-4444-4444-8444-444444444444";
  assert.equal(crypto.verify("sha256", Buffer.from(canonicalEnrollmentProof({ path: differentPath, bodyDigest, credentialDigest })), { key: pair.publicKey, dsaEncoding: "ieee-p1363" }, signature), false);
  assert.equal(crypto.verify("sha256", Buffer.from(canonicalEnrollmentProof({ path: `/v1/enrollments/${ENROLLMENT}`, bodyDigest: "0".repeat(64), credentialDigest })), { key: pair.publicKey, dsaEncoding: "ieee-p1363" }, signature), false);
  assert.equal(crypto.verify("sha256", Buffer.from(canonicalEnrollmentProof({ path: `/v1/enrollments/${ENROLLMENT}`, bodyDigest, credentialDigest: "0".repeat(64) })), { key: pair.publicKey, dsaEncoding: "ieee-p1363" }, signature), false);
});

test("supports the Ed25519 proof profile and verifies the signer against the body key", async () => {
  const pair = keys("ed25519");
  let called = 0;
  const client = createDeviceEnrollmentClient({
    ...input(pair, { deviceKey: { algorithm: "ed25519", spkiPem: pair.publicPem } }),
    signer: (request) => { called += 1; assert.equal(Object.hasOwn(request, "privateKey"), false); return signWith(pair, "ed25519")(request); },
    fetchImpl: async () => jsonResponse(enrolledResponse(pair))
  });
  assert.equal((await client.enroll()).status, "enrolled");
  assert.equal(called, 1);
});

test("does not accept a private key option or leak signer errors", async () => {
  const pair = keys();
  assert.throws(() => createDeviceEnrollmentClient({ ...input(pair), credential: "too-short" }), (error) => error.code === DEVICE_ENROLLMENT_ERRORS.INVALID_CONFIG);
  assert.throws(() => createDeviceEnrollmentClient({ ...input(pair), privateKey: pair.privateKey }), (error) => {
    assert.equal(error.code, DEVICE_ENROLLMENT_ERRORS.INVALID_CONFIG);
    assert.equal(error.message.includes("PRIVATE"), false);
    return true;
  });
  const client = createDeviceEnrollmentClient({
    ...input(pair),
    signer: (request) => {
      assert.equal(Object.hasOwn(request, "credential"), false);
      assert.equal(Object.hasOwn(request, "enrollment_credential"), false);
      assert.match(request.credential_digest, /^[0-9a-f]{64}$/);
      throw new Error(`secret PRIVATE KEY ${pair.privateKey.export({ type: "pkcs8", format: "pem" })}`);
    },
    fetchImpl: async () => { throw new Error("must not be called"); }
  });
  await assert.rejects(() => client.enroll(), (error) => {
    assert.equal(error.code, DEVICE_ENROLLMENT_ERRORS.SIGNER);
    assert.equal(error.message.includes("PRIVATE"), false);
    assert.equal(error.message.includes("BEGIN"), false);
    return true;
  });
});

test("serializes concurrent calls and caches successful one-time enrollment", async () => {
  const pair = keys();
  let calls = 0;
  const client = createDeviceEnrollmentClient({
    ...input(pair),
    signer: signWith(pair),
    fetchImpl: async () => { calls += 1; await new Promise((resolve) => setTimeout(resolve, 2)); return jsonResponse(enrolledResponse(pair)); }
  });
  const [first, second] = await Promise.all([client.enroll(), client.enroll()]);
  assert.deepEqual(first.evidence, second.evidence);
  assert.equal(calls, 1);
  assert.equal(client.status(), "enrolled");
  await client.enroll();
  assert.equal(calls, 1);
});

test("rejects mismatched signer, response identities, key substitution, secrets, duplicates, and unknown fields", async () => {
  const pair = keys();
  const other = keys();
  const mismatchedSigner = createDeviceEnrollmentClient({ ...input(pair), signer: signWith(other), fetchImpl: async () => { throw new Error("not called"); } });
  await assert.rejects(() => mismatchedSigner.enroll(), (error) => error.code === DEVICE_ENROLLMENT_ERRORS.SIGNER);
  const valid = () => enrolledResponse(pair);
  const wrongDevice = valid(); wrongDevice.enrollment.device_id = "44444444-4444-4444-8444-444444444444";
  const wrongOrganization = valid(); wrongOrganization.enrollment.organization_id = "44444444-4444-4444-8444-444444444444";
  const pending = valid(); pending.enrollment.status = "pending";
  const wrongAlgorithm = valid(); wrongAlgorithm.enrollment.key_algorithm = "ed25519";
  const secretField = valid(); secretField.enrollment.control.credential = "should-not-cross-boundary";
  const unknownField = valid(); unknownField.enrollment.unknown = true;
  const missingEpoch = valid(); delete missingEpoch.enrollment.device_key_epoch;
  const substitutedEpoch = valid(); substitutedEpoch.enrollment.device_key_epoch = 0;
  const missingRefreshHint = valid(); delete missingRefreshHint.enrollment.control.refresh_hint;
  const substitutedRefreshHint = valid(); substitutedRefreshHint.enrollment.control.refresh_hint.public_key = substitutedRefreshHint.enrollment.control.public_key;
  for (const responseBody of [wrongDevice, wrongOrganization, pending, wrongAlgorithm, secretField, unknownField, missingEpoch, substitutedEpoch, missingRefreshHint, substitutedRefreshHint]) {
    const client = createDeviceEnrollmentClient({ ...input(pair), signer: signWith(pair), fetchImpl: async () => jsonResponse(responseBody) });
    await assert.rejects(() => client.enroll(), (error) => [DEVICE_ENROLLMENT_ERRORS.BINDING, DEVICE_ENROLLMENT_ERRORS.RESPONSE].includes(error.code));
  }
  const validEnrollment = JSON.stringify(enrolledResponse(pair).enrollment);
  const duplicate = createDeviceEnrollmentClient({ ...input(pair), signer: signWith(pair), fetchImpl: async () => new Response(`{"request_id":"request-123","request_id":"other","enrollment":${validEnrollment}}`, { status: 201 }) });
  await assert.rejects(() => duplicate.enroll(), (error) => error.code === DEVICE_ENROLLMENT_ERRORS.RESPONSE);
});

test("bounds response bytes, rejects redirects/non-201 responses, and never retries", async () => {
  const pair = keys();
  let calls = 0;
  const oversized = createDeviceEnrollmentClient({
    ...input(pair), signer: signWith(pair), maxResponseBytes: 32,
    fetchImpl: async () => { calls += 1; return new Response("x".repeat(33), { status: 201, headers: { "content-length": "33" } }); }
  });
  await assert.rejects(() => oversized.enroll(), (error) => error.code === DEVICE_ENROLLMENT_ERRORS.RESPONSE_TOO_LARGE);
  assert.equal(calls, 1);
  for (const status of [200, 202, 400, 500]) {
    const client = createDeviceEnrollmentClient({ ...input(pair), signer: signWith(pair), fetchImpl: async () => new Response("{}", { status }) });
    await assert.rejects(() => client.enroll(), (error) => error.code === DEVICE_ENROLLMENT_ERRORS.HTTP);
  }
  const redirected = createDeviceEnrollmentClient({ ...input(pair), signer: signWith(pair), fetchImpl: async () => new Response("", { status: 302, headers: { location: "https://evil.example" } }) });
  await assert.rejects(() => redirected.enroll(), (error) => error.code === DEVICE_ENROLLMENT_ERRORS.REDIRECT);
});

test("requires a pinned HTTPS /v1 endpoint and bounded timeout", async () => {
  const pair = keys();
  for (const baseUrl of ["http://api.example.test/v1", "https://user:pass@api.example.test/v1", "https://api.example.test/v1?token=secret", "https://api.example.test/api", "https://api.example.test/v1#fragment"]) {
    assert.throws(() => createDeviceEnrollmentClient({ ...input(pair), baseUrl }), (error) => error.code === DEVICE_ENROLLMENT_ERRORS.INVALID_URL);
  }
  assert.doesNotThrow(() => createDeviceEnrollmentClient({ ...input(pair), baseUrl: "http://127.0.0.1/v1", loopbackTestMode: true, signer: signWith(pair), fetchImpl: async () => jsonResponse(enrolledResponse(pair)) }));
  const timeout = createDeviceEnrollmentClient({ ...input(pair), timeoutMs: 5, signer: signWith(pair), fetchImpl: () => new Promise(() => {}) });
  await assert.rejects(() => timeout.enroll(), (error) => error instanceof DeviceEnrollmentError && error.code === DEVICE_ENROLLMENT_ERRORS.TIMEOUT);
});

test("exposes only the exact non-secret setup evidence", () => {
  const pair = keys();
  const keyFingerprint = fingerprint(pair);
  assert.deepEqual(deviceEnrollmentEvidence({ enrollment_id: ENROLLMENT, organization_id: ORGANIZATION, device_id: DEVICE, device_key_epoch: 2, key_fingerprint: keyFingerprint, private_key: "ignored" }), { organization_id: ORGANIZATION, device_id: DEVICE, enrollment_id: ENROLLMENT, device_key_epoch: 2, key_fingerprint: keyFingerprint });
  assert.throws(() => deviceEnrollmentEvidence({ enrollment_id: ENROLLMENT, organization_id: ORGANIZATION, device_id: DEVICE }), (error) => error.code === DEVICE_ENROLLMENT_ERRORS.BINDING);
});

test("builds a strict candidate binding and rejects replay/substitution fields", () => {
  const pair = keys();
  const binding = buildEnrollmentCandidateBinding(candidate(pair));
  assert.deepEqual(Object.keys(binding).sort(), ["artifact_sha256", "candidate_id", "device_id", "device_key_fingerprint", "enrollment_id", "expires_at", "organization_id", "source_commit", "team_id", "version"].sort());
  assert.equal(candidateBindingDigest(binding), crypto.createHash("sha256").update(JSON.stringify({
    artifact_sha256: "a".repeat(64),
    candidate_id: "release-2026-08-13-01",
    device_id: DEVICE,
    device_key_fingerprint: fingerprint(pair),
    enrollment_id: ENROLLMENT,
    expires_at: "2099-01-02T03:04:05.000Z",
    organization_id: ORGANIZATION,
    source_commit: "b".repeat(40),
    team_id: "TEAMID1234",
    version: 1
  })).digest("hex"));
  for (const bad of [
    { ...candidate(pair), extra: true },
    { ...candidate(pair), source_commit: "B".repeat(40) },
    { ...candidate(pair), team_id: "teamid1234" },
    { ...candidate(pair), expires_at: "2099-01-02T03:04:05Z" },
    { ...candidate(pair), artifact_sha256: "c".repeat(63) }
  ]) assert.throws(() => buildEnrollmentCandidateBinding(bad));
});

test("v2 proof is domain-separated, exact-path, nonce-bound, and candidate-bound", () => {
  const pair = keys();
  const binding = candidate(pair);
  const bodyDigest = "1".repeat(64);
  const credentialDigest = "2".repeat(64);
  const proof = canonicalEnrollmentProofV2({ path: `/v1/enrollments/${ENROLLMENT}`, bodyDigest, credentialDigest, challengeNonce: CHALLENGE_NONCE, candidateBinding: binding });
  assert.equal(proof, `AgentPass-Enrollment-Proof-v2\0POST\n/v1/enrollments/${ENROLLMENT}\n${bodyDigest}\n${credentialDigest}\n${CHALLENGE_NONCE}\n${candidateBindingDigest(binding)}`);
  assert.equal(proof.startsWith("AgentPass-Enrollment-Proof-v2\0"), true);
  assert.throws(() => canonicalEnrollmentProofV2({ path: `/v1/enrollments/${ORGANIZATION}`, bodyDigest, credentialDigest, challengeNonce: CHALLENGE_NONCE, candidateBinding: binding }));
  assert.throws(() => canonicalEnrollmentProofV2({ path: `/v1/enrollments/${ENROLLMENT}?x=1`, bodyDigest, credentialDigest, challengeNonce: CHALLENGE_NONCE, candidateBinding: binding }));
  assert.throws(() => canonicalEnrollmentProofV2({ path: `/v1/enrollments/${ENROLLMENT}`, bodyDigest, credentialDigest, challengeNonce: "A", candidateBinding: binding }));
});

test("v2 client pins the pathname, sends candidate and nonce, and enforces P-256 qualification", async () => {
  const pair = keys();
  const receiptPair = keys("ed25519");
  const receipt = possessionReceipt(pair, receiptPair);
  let captured;
  let receiptReads = 0;
  const client = createDeviceEnrollmentClient({
    ...input(pair),
    proofVersion: 2,
    qualification: "p256-sha256",
    challengeId: CHALLENGE_ID,
    challengeNonce: CHALLENGE_NONCE,
    candidateBinding: candidate(pair),
    possessionReceiptPublicKey: receiptPair.publicPem,
    possessionReceiptKeyId: receipt.key_id,
    signer: signWith(pair),
    fetchImpl: async (url, init) => {
      if (init.method === "GET") {
        receiptReads += 1;
        return receiptReads === 1
          ? new Response("", { status: 401 })
          : jsonResponse({ request_id: "receipt-request-1", receipt }, 200);
      }
      captured = { url, init };
      return jsonResponse(enrolledResponse(pair));
    }
  });
  assert.equal((await client.enroll()).status, "enrolled");
  assert.equal(captured.url, `https://api.example.test/v1/enrollments/${ENROLLMENT}`);
  assert.equal(captured.init.headers["AgentPass-Enrollment-Nonce"], CHALLENGE_NONCE);
  assert.equal(JSON.parse(captured.init.headers["AgentPass-Enrollment-Candidate-Binding"]).candidate_id, "release-2026-08-13-01");
  const v2Body = JSON.parse(captured.init.body.toString("utf8"));
  assert.equal(v2Body.version, 2);
  assert.equal(v2Body.challenge.challenge_id, CHALLENGE_ID);
  assert.equal(client.config.proof_version, 2);
  assert.equal(receiptReads, 2);
  const ed = keys("ed25519");
  assert.throws(() => createDeviceEnrollmentClient({ ...input(ed, { deviceKey: { algorithm: "ed25519", spkiPem: ed.publicPem }, keyFingerprint: fingerprint(ed) }), proofVersion: 2, qualification: "p256-sha256", challengeId: CHALLENGE_ID, challengeNonce: CHALLENGE_NONCE, candidateBinding: candidate(ed), signer: signWith(ed, "ed25519"), fetchImpl: async () => jsonResponse(enrolledResponse(ed)) }), (error) => error.code === DEVICE_ENROLLMENT_ERRORS.INVALID_CONFIG);
});

test("retries a preflight receipt failure without ever retrying the one-time POST", async () => {
  const pair = keys();
  const receiptPair = keys("ed25519");
  const receipt = possessionReceipt(pair, receiptPair);
  let gets = 0;
  let posts = 0;
  const client = createDeviceEnrollmentClient({
    ...input(pair),
    proofVersion: 2,
    qualification: "p256-sha256",
    challengeId: CHALLENGE_ID,
    challengeNonce: CHALLENGE_NONCE,
    candidateBinding: candidate(pair),
    possessionReceiptPublicKey: receiptPair.publicPem,
    possessionReceiptKeyId: receipt.key_id,
    signer: signWith(pair),
    fetchImpl: async (_url, init) => {
      if (init.method === "GET") {
        gets += 1;
        if (gets === 1) throw new TypeError("temporary network failure before POST");
        if (gets === 2) return new Response("", { status: 401 });
        return jsonResponse({ request_id: "receipt-after-post", receipt }, 200);
      }
      posts += 1;
      return jsonResponse(enrolledResponse(pair));
    }
  });
  await assert.rejects(() => client.enroll(), (error) => {
    assert.equal(error.code, DEVICE_ENROLLMENT_ERRORS.RECOVERY_UNPROVEN);
    assert.equal(error.details.phase, "preflight");
    return true;
  });
  assert.equal(client.status(), "ready");
  assert.equal((await client.enroll()).status, "enrolled");
  assert.equal(posts, 1);
  assert.equal(gets, 3);
});

test("does not turn a received HTTP failure into response-loss recovery", async () => {
  const pair = keys();
  const receiptPair = keys("ed25519");
  let gets = 0;
  let posts = 0;
  const client = createDeviceEnrollmentClient({
    ...input(pair),
    proofVersion: 2,
    qualification: "p256-sha256",
    challengeId: CHALLENGE_ID,
    challengeNonce: CHALLENGE_NONCE,
    candidateBinding: candidate(pair),
    possessionReceiptPublicKey: receiptPair.publicPem,
    possessionReceiptKeyId: "receipt-key-v1",
    signer: signWith(pair),
    fetchImpl: async (_url, init) => {
      if (init.method === "GET") { gets += 1; return new Response("", { status: 401 }); }
      posts += 1;
      return new Response("{}", { status: 400 });
    }
  });
  await assert.rejects(() => client.enroll(), (error) => error.code === DEVICE_ENROLLMENT_ERRORS.HTTP);
  assert.equal(gets, 1);
  assert.equal(posts, 1);
  assert.equal(client.status(), "failed");
});

test("reconciles an unusable 201 response without replaying the POST", async () => {
  const pair = keys();
  const receiptPair = keys("ed25519");
  const receipt = possessionReceipt(pair, receiptPair);
  let posts = 0;
  let gets = 0;
  const client = createDeviceEnrollmentClient({
    ...input(pair),
    proofVersion: 2,
    qualification: "p256-sha256",
    challengeId: CHALLENGE_ID,
    challengeNonce: CHALLENGE_NONCE,
    candidateBinding: candidate(pair),
    possessionReceiptPublicKey: receiptPair.publicPem,
    possessionReceiptKeyId: receipt.key_id,
    signer: signWith(pair),
    fetchImpl: async (_url, init) => {
      if (init.method === "GET") {
        gets += 1;
        return gets === 1 ? new Response("", { status: 401 }) : jsonResponse({ request_id: "receipt-malformed-201", receipt }, 200);
      }
      posts += 1;
      return new Response("not-json", { status: 201 });
    }
  });
  const recovered = await client.enroll();
  assert.equal(recovered.status, "enrolled");
  assert.deepEqual(recovered.control, receipt.statement.control);
  assert.equal(posts, 1);
  assert.equal(gets, 2);
});

test("does not retry a response-loss POST and recovers only through a bound receipt", async () => {
  const pair = keys();
  const receiptPair = keys("ed25519");
  const receipt = possessionReceipt(pair, receiptPair);
  let preflight = true;
  let postCalls = 0;
  let getCalls = 0;
  const client = createDeviceEnrollmentClient({
    ...input(pair),
    proofVersion: 2,
    qualification: "p256-sha256",
    challengeId: CHALLENGE_ID,
    challengeNonce: CHALLENGE_NONCE,
    candidateBinding: candidate(pair),
    possessionReceiptPublicKey: receiptPair.publicPem,
    possessionReceiptKeyId: receipt.key_id,
    signer: signWith(pair),
    fetchImpl: async (_url, init) => {
      if (init.method === "GET") {
        getCalls += 1;
        assert.equal(init.headers["AgentPass-Enrollment-Credential"], undefined);
        if (preflight) { preflight = false; return new Response("", { status: 401 }); }
        return jsonResponse({ request_id: "receipt-request-2", receipt }, 200);
      }
      postCalls += 1;
      assert.equal(init.headers["AgentPass-Enrollment-Credential"], CREDENTIAL);
      throw new TypeError("connection closed after Cloud committed the request");
    }
  });
  const recovered = await client.enroll();
  assert.equal(recovered.status, "enrolled");
  assert.equal(recovered.request_id, "receipt-request-2");
  assert.equal(recovered.possession_receipt.statement_hash, receipt.statement_hash);
  assert.equal(JSON.stringify(recovered).includes(CREDENTIAL), false);
  assert.deepEqual(await client.enroll(), recovered);
  assert.equal(postCalls, 1);
  assert.equal(getCalls, 2);
  assert.equal(client.status(), "enrolled");
});

test("a restarted v2 client checks the receipt before submitting a one-time credential", async () => {
  const pair = keys();
  const receiptPair = keys("ed25519");
  const receipt = possessionReceipt(pair, receiptPair);
  let posts = 0;
  const client = createDeviceEnrollmentClient({
    ...input(pair),
    proofVersion: 2,
    qualification: "p256-sha256",
    challengeId: CHALLENGE_ID,
    challengeNonce: CHALLENGE_NONCE,
    candidateBinding: candidate(pair),
    possessionReceiptPublicKey: receiptPair.publicPem,
    possessionReceiptKeyId: receipt.key_id,
    signer: signWith(pair),
    fetchImpl: async (_url, init) => {
      assert.equal(init.method, "GET");
      return jsonResponse({ request_id: "receipt-request-restart", receipt }, 200);
    }
  });
  const recovered = await client.enroll();
  assert.equal(recovered.status, "enrolled");
  assert.deepEqual(recovered.control, receipt.statement.control);
  assert.equal(posts, 0);
});

test("public recovery restores the normal enrollment result through exactly one signed GET", async () => {
  const pair = keys();
  const receiptPair = keys("ed25519");
  const receipt = possessionReceipt(pair, receiptPair);
  const methods = [];
  const calls = [];
  const result = await recoverDeviceEnrollment(recoveryInput(pair, receiptPair, {
    control: receipt.statement.control,
    signer: ({ bytes, body, credential, enrollment_credential: enrollmentCredential, challenge_nonce: challengeNonce }) => {
      assert.equal(body.length, 0);
      assert.equal(credential, undefined);
      assert.equal(enrollmentCredential, undefined);
      assert.equal(challengeNonce, undefined);
      return signWith(pair)({ bytes });
    },
    fetchImpl: async (url, init) => {
      methods.push(init.method);
      calls.push({ url, init });
      assert.equal(init.method, "GET");
      assert.equal(init.body, undefined);
      assert.equal(init.redirect, "error");
      assert.equal(init.headers["AgentPass-Enrollment-Credential"], undefined);
      assert.equal(init.headers["AgentPass-Enrollment-Nonce"], undefined);
      assert.equal(init.headers["AgentPass-Enrollment-Candidate-Binding"], undefined);
      assert.equal(url, `https://api.example.test/v1/organizations/${ORGANIZATION}/devices/${DEVICE}/enrollment-receipt`);
      return jsonResponse({ request_id: "receipt-recovery-1", receipt }, 200);
    }
  }));
  assert.deepEqual(methods, ["GET"]);
  assert.equal(calls.length, 1);
  assert.equal(result.status, "enrolled");
  assert.equal(result.label, "build-mac-01");
  assert.equal(result.platform, "macos");
  assert.equal(result.enrollment_id, ENROLLMENT);
  assert.equal(result.organization_id, ORGANIZATION);
  assert.equal(result.device_id, DEVICE);
  assert.equal(result.key_fingerprint, fingerprint(pair));
  assert.equal(result.request_hash, "c".repeat(64));
  assert.deepEqual(result.control, receipt.statement.control);
  assert.equal(result.server.status, "active");
  assert.equal(result.server.device_key_epoch, receipt.statement.device_key_epoch);
  assert.equal(result.evidence.challenge_nonce_digest, receipt.statement.challenge_nonce_digest);
  assert.equal(result.possession_receipt.statement_hash, receipt.statement_hash);
  assert.equal(JSON.stringify(result).includes(CREDENTIAL), false);
});

test("recovery accepts the persisted public descriptor names and succeeds after invitation expiry", async () => {
  const pair = keys();
  const receiptPair = keys("ed25519");
  const receipt = possessionReceipt(pair, receiptPair);
  const original = recoveryInput(pair, receiptPair);
  const {
    baseUrl: _baseUrl,
    candidateBinding: _candidateBinding,
    challengeNonceDigest: _challengeNonceDigest,
    possessionReceiptPublicKey: _receiptPublicKey,
    possessionReceiptKeyId: _receiptKeyId,
    requestDigest: _requestDigest,
    ...descriptor
  } = original;
  const result = await recoverDeviceEnrollment({
    ...descriptor,
    api_base_url: original.baseUrl,
    candidate_binding: { ...original.candidateBinding, expires_at: "2020-01-01T00:00:00.000Z" },
    challenge_digest: original.challengeNonceDigest,
    request_digest: original.requestDigest,
    verification_algorithm: "ed25519",
    verification_key_id: original.possessionReceiptKeyId,
    verification_public_key: original.possessionReceiptPublicKey,
    fetchImpl: async (_url, init) => {
      assert.equal(init.method, "GET");
      return jsonResponse({ request_id: "receipt-after-expiry", receipt }, 200);
    }
  });
  assert.equal(result.status, "enrolled");
  assert.equal(result.request_hash, original.requestDigest);
  assert.equal(result.possession_receipt.statement.issued_at, "2099-01-02T03:04:05.000Z");
});

test("recovery fails closed for absent receipts and never reaches a POST path", async () => {
  const pair = keys();
  const receiptPair = keys("ed25519");
  for (const status of [401, 404, 200]) {
    let posts = 0;
    let gets = 0;
    await assert.rejects(() => recoverDeviceEnrollment(recoveryInput(pair, receiptPair, {
      fetchImpl: async (_url, init) => {
        if (init.method === "POST") posts += 1;
        if (init.method === "GET") gets += 1;
        assert.equal(init.method, "GET");
        return status === 200 ? jsonResponse({ request_id: "receipt-empty" }, 200) : new Response("", { status });
      }
    })), (error) => error.code === DEVICE_ENROLLMENT_ERRORS.RECOVERY_UNPROVEN);
    assert.equal(posts, 0, `HTTP ${status} must not reach POST`);
    assert.equal(gets, 1);
  }
});

test("recovery binds the signed challenge digest, candidate, device key, control, path, and receipt signer", async () => {
  const pair = keys();
  const receiptPair = keys("ed25519");
  const valid = possessionReceipt(pair, receiptPair);
  const expectedControl = valid.statement.control;
  const digest = valid.statement.challenge_nonce_digest;
  const denied = async (receipt, overrides = {}) => {
    let posts = 0;
    await assert.rejects(() => recoverDeviceEnrollment(recoveryInput(pair, receiptPair, {
      control: expectedControl,
      fetchImpl: async (_url, init) => {
        if (init.method === "POST") posts += 1;
        assert.equal(init.method, "GET");
        return jsonResponse({ request_id: "receipt-recovery-negative", receipt }, 200);
      },
      ...overrides
    })), (error) => error.code === DEVICE_ENROLLMENT_ERRORS.RECOVERY_UNPROVEN);
    assert.equal(posts, 0);
  };

  await denied(valid, { challengeNonceDigest: "f".repeat(64) });
  await denied(resignReceipt(valid, receiptPair, { ...valid.statement, candidate_id: "candidate-substituted" }));
  await denied(resignReceipt(valid, receiptPair, { ...valid.statement, device_key_fingerprint: fingerprint(keys()) }));
  await denied(resignReceipt(valid, receiptPair, { ...valid.statement, organization_id: DEVICE }));
  await denied(resignReceipt(valid, receiptPair, { ...valid.statement, control: { ...valid.statement.control, bundle_path: `/v1/organizations/${ORGANIZATION}/bundles/44444444-4444-4444-8444-444444444444` } }));
  await denied(resignReceipt(valid, receiptPair, { ...valid.statement, control: { ...valid.statement.control, key_id: "control-substituted" } }));
  await denied({ ...valid, key_id: "receipt-rotated" });
  await denied({ ...valid, unknown: true });
  assert.equal(digest, valid.statement.challenge_nonce_digest);
});

test("recovery rejects credentials, challenge nonces, private keys, and unpinned public descriptors", async () => {
  const pair = keys();
  const receiptPair = keys("ed25519");
  const valid = recoveryInput(pair, receiptPair, { fetchImpl: async () => { throw new Error("must not fetch"); } });
  for (const extra of [
    { credential: CREDENTIAL },
    { enrollmentCredential: CREDENTIAL },
    { challengeNonce: CHALLENGE_NONCE },
    { challengeId: CHALLENGE_ID },
    { privateKey: pair.privateKey },
    { unknownDescriptor: true }
  ]) {
    await assert.rejects(() => recoverDeviceEnrollment({ ...valid, ...extra }), (error) => error.code === DEVICE_ENROLLMENT_ERRORS.INVALID_CONFIG);
  }
  for (const baseUrl of ["http://api.example.test/v1", "https://user:pass@api.example.test/v1", "https://api.example.test/v1?token=secret", "https://api.example.test/api", "https://api.example.test/v1#fragment"]) {
    await assert.rejects(() => recoverDeviceEnrollment({ ...valid, baseUrl }), (error) => error.code === DEVICE_ENROLLMENT_ERRORS.INVALID_URL);
  }
  const { requestDigest: _requestDigest, ...withoutDigest } = valid;
  await assert.rejects(() => recoverDeviceEnrollment(withoutDigest), (error) => error.code === DEVICE_ENROLLMENT_ERRORS.INVALID_CONFIG);
  await assert.rejects(() => recoverDeviceEnrollment({ ...valid, requestDigest: "A".repeat(64) }), (error) => error.code === DEVICE_ENROLLMENT_ERRORS.INVALID_CONFIG);
  await assert.rejects(() => recoverDeviceEnrollment({ ...valid, label: "\u0000bad" }), (error) => error.code === DEVICE_ENROLLMENT_ERRORS.INVALID_REQUEST);
  await assert.rejects(() => recoverDeviceEnrollment({ ...valid, keyFingerprint: fingerprint(keys()) }), (error) => error.code === DEVICE_ENROLLMENT_ERRORS.INVALID_CONFIG);
  await assert.rejects(() => recoverDeviceEnrollment({ ...valid, deviceKey: { algorithm: "p256-sha256", spkiPem: pair.privateKey.export({ type: "pkcs8", format: "pem" }).toString() } }), (error) => error.code === DEVICE_ENROLLMENT_ERRORS.INVALID_KEY);
  await assert.rejects(() => recoverDeviceEnrollment({ ...valid, challengeNonceDigest: "A".repeat(64) }), (error) => error.code === DEVICE_ENROLLMENT_ERRORS.INVALID_REQUEST);
});

test("stops honestly when the receipt endpoint cannot prove response-loss recovery", async () => {
  const pair = keys();
  const receiptPair = keys("ed25519");
  let gets = 0;
  let posts = 0;
  const client = createDeviceEnrollmentClient({
    ...input(pair),
    proofVersion: 2,
    qualification: "p256-sha256",
    challengeId: CHALLENGE_ID,
    challengeNonce: CHALLENGE_NONCE,
    candidateBinding: candidate(pair),
    possessionReceiptPublicKey: receiptPair.publicPem,
    possessionReceiptKeyId: "receipt-key-v1",
    signer: signWith(pair),
    fetchImpl: async (_url, init) => {
      if (init.method === "GET") { gets += 1; return new Response("", { status: gets === 1 ? 401 : 404 }); }
      posts += 1;
      throw new Error("response lost");
    }
  });
  await assert.rejects(() => client.enroll(), (error) => {
    assert.equal(error.code, DEVICE_ENROLLMENT_ERRORS.RECOVERY_UNPROVEN);
    assert.equal(error.details.observed_status, 404);
    return true;
  });
  await assert.rejects(() => client.enroll(), (error) => error.code === DEVICE_ENROLLMENT_ERRORS.RECOVERY_UNPROVEN);
  assert.equal(posts, 1);
  assert.equal(gets, 2);
});

test("rejects a receipt signed by the pinned key when its tenant or device binding is substituted", async () => {
  const pair = keys();
  const receiptPair = keys("ed25519");
  const substituted = possessionReceipt(pair, receiptPair, { organization_id: DEVICE });
  let posts = 0;
  const client = createDeviceEnrollmentClient({
    ...input(pair),
    proofVersion: 2,
    qualification: "p256-sha256",
    challengeId: CHALLENGE_ID,
    challengeNonce: CHALLENGE_NONCE,
    candidateBinding: candidate(pair),
    possessionReceiptPublicKey: receiptPair.publicPem,
    possessionReceiptKeyId: substituted.key_id,
    signer: signWith(pair),
    fetchImpl: async (_url, init) => init.method === "GET"
      ? jsonResponse({ request_id: "receipt-request-substituted", receipt: substituted }, 200)
      : (posts += 1, jsonResponse(enrolledResponse(pair)))
  });
  await assert.rejects(() => client.enroll(), (error) => error.code === DEVICE_ENROLLMENT_ERRORS.RECOVERY_UNPROVEN);
  assert.equal(posts, 0);
});

test("fails closed when POST control trust or the pinned receipt signer drifts", async () => {
  const cases = [
    ["control key", (receipt) => ({ ...receipt, statement: { ...receipt.statement, control: { ...receipt.statement.control, key_id: "control-rotated" } } })],
    ["refresh key", (receipt) => ({ ...receipt, statement: { ...receipt.statement, control: { ...receipt.statement.control, refresh_hint: { ...receipt.statement.control.refresh_hint, public_key: keys("ed25519").publicPem } } } })],
    ["bundle path", (receipt) => ({ ...receipt, statement: { ...receipt.statement, control: { ...receipt.statement.control, bundle_path: `/v1/organizations/${ORGANIZATION}/bundles/44444444-4444-4444-8444-444444444444` } } })],
    ["receipt signer rotation", (receipt) => ({ ...receipt, key_id: "receipt-rotated" })]
  ];
  for (const [label, mutate] of cases) {
    const pair = keys();
    const receiptPair = keys("ed25519");
    const receipt = mutate(possessionReceipt(pair, receiptPair));
    // Re-sign a statement mutation with the pinned receipt key so the test
    // reaches the binding comparison rather than failing at the signature.
    if (receipt.statement !== undefined && label !== "receipt signer rotation") {
      const bytes = Buffer.from(`AgentPass-Cloud-Possession-Receipt-v1\0${canonicalJson(receipt.statement)}`);
      receipt.statement_hash = crypto.createHash("sha256").update(canonicalJson(receipt.statement)).digest("hex");
      receipt.signature = crypto.sign(null, bytes, receiptPair.privateKey).toString("base64url");
    }
    let posts = 0;
    const client = createDeviceEnrollmentClient({
      ...input(pair), proofVersion: 2, qualification: "p256-sha256", challengeId: CHALLENGE_ID, challengeNonce: CHALLENGE_NONCE,
      candidateBinding: candidate(pair), possessionReceiptPublicKey: receiptPair.publicPem, possessionReceiptKeyId: "receipt-key-v1", signer: signWith(pair),
      fetchImpl: async (_url, init) => init.method === "GET"
        ? (posts === 0 ? new Response("", { status: 401 }) : jsonResponse({ request_id: `receipt-${label}`, receipt }, 200))
        : (posts += 1, jsonResponse(enrolledResponse(pair)))
    });
    await assert.rejects(() => client.enroll(), (error) => error.code === DEVICE_ENROLLMENT_ERRORS.RECOVERY_UNPROVEN, label);
    assert.equal(posts, 1, label);
  }
});

test("verifies a purpose-separated possession receipt and rejects receipt substitution", () => {
  const pair = keys("ed25519");
  const statement = {
    version: 1,
    enrollment_id: ENROLLMENT,
    organization_id: ORGANIZATION,
    device_id: DEVICE,
    candidate_id: "release-2026-08-13-01",
    artifact_sha256: "a".repeat(64),
    source_commit: "b".repeat(40),
    team_id: "TEAMID1234",
    device_key_fingerprint: fingerprint(keys()),
    device_key_epoch: 3,
    challenge_nonce_digest: crypto.createHash("sha256").update(CHALLENGE_NONCE).digest("hex"),
    control: {
      format_epoch: 2,
      issuer: "cloud-control",
      key_id: "control-v2",
      public_key: CONTROL_TEST_KEYS.publicPem,
      bundle_path: `/v1/organizations/${ORGANIZATION}/bundles/${DEVICE}`,
      refresh_hint: { key_id: "refresh-hint-v1", algorithm: "ed25519", public_key: REFRESH_TEST_KEYS.publicPem }
    },
    issued_at: "2099-01-02T03:04:05.000Z"
  };
  const statementBytes = Buffer.from(canonicalJson(statement), "utf8");
  const receiptHash = crypto.createHash("sha256").update(statementBytes).digest("hex");
  const signed = Buffer.from(`AgentPass-Cloud-Possession-Receipt-v1\0${statementBytes.toString("utf8")}`);
  const receipt = { version: 1, purpose: "device-enrollment-possession-receipt", key_id: "receipt-key-v1", algorithm: "ed25519", statement, statement_hash: receiptHash, signature: crypto.sign(null, signed, pair.privateKey).toString("base64url") };
  const verified = verifyDeviceEnrollmentReceipt(receipt, pair.publicKey.export({ type: "spki", format: "pem" }).toString(), { challengeNonce: CHALLENGE_NONCE, enrollmentId: ENROLLMENT, deviceKeyEpoch: 3 });
  assert.equal(verified.statement_hash, receiptHash);
  const p256Signer = keys();
  const p256ReceiptBytes = Buffer.from(`AgentPass-Cloud-Possession-Receipt-v1\0${statementBytes.toString("utf8")}`);
  const p256Receipt = {
    version: 1,
    purpose: "device-enrollment-possession-receipt",
    key_id: "receipt-p256-v1",
    algorithm: "p256-sha256",
    statement,
    statement_hash: receiptHash,
    signature: crypto.sign("sha256", p256ReceiptBytes, { key: p256Signer.privateKey, dsaEncoding: "ieee-p1363" }).toString("base64url")
  };
  assert.equal(verifyDeviceEnrollmentReceipt(p256Receipt, p256Signer.publicKey.export({ type: "spki", format: "pem" }).toString(), { candidateId: statement.candidate_id }).algorithm, "p256-sha256");
  assert.throws(() => verifyDeviceEnrollmentReceipt({ ...receipt, statement: { ...statement, device_id: ORGANIZATION } }, pair.publicKey.export({ type: "spki", format: "pem" }).toString()));
  assert.throws(() => verifyDeviceEnrollmentReceipt({ ...receipt, unknown: true }, pair.publicKey.export({ type: "spki", format: "pem" }).toString()));
});
