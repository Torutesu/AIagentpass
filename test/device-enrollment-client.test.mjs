import assert from "node:assert/strict";
import crypto from "node:crypto";
import test from "node:test";

import {
  DEVICE_ENROLLMENT_ERRORS,
  DeviceEnrollmentError,
  buildDeviceEnrollmentRequest,
  canonicalEnrollmentProof,
  createDeviceEnrollmentClient,
  deviceEnrollmentEvidence
} from "../lib/device-enrollment-client.mjs";

const ENROLLMENT = "11111111-1111-4111-8111-111111111111";
const ORGANIZATION = "22222222-2222-4222-8222-222222222222";
const DEVICE = "33333333-3333-4333-8333-333333333333";
const BASE_URL = "https://api.example.test/v1";
const CREDENTIAL = "Abcdefghijklmnopqrstuvwxyz0123456789-_ABCDE";

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
  const control = keys("ed25519");
  const refreshHint = keys("ed25519");
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
        public_key: control.publicPem,
        bundle_path: `/v1/organizations/${ORGANIZATION}/bundles/${DEVICE}`,
        refresh_hint: { key_id: "refresh-hint-v1", algorithm: "ed25519", public_key: refreshHint.publicPem }
      }
    },
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
