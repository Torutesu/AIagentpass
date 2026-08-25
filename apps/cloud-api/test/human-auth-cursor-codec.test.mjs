import assert from "node:assert/strict";
import { createHmac } from "node:crypto";
import test from "node:test";

import {
  HUMAN_CURSOR_CODEC_VERSION,
  HUMAN_CURSOR_ERROR_CODES,
  HUMAN_CURSOR_MAX_LENGTH,
  HumanCursorCodecError,
  createHumanCursorCodec
} from "../src/human-auth/pagination/cursor-codec.mjs";

const SECRET = Buffer.from("0123456789abcdef0123456789abcdef", "utf8");
const OTHER_SECRET = Buffer.from("fedcba9876543210fedcba9876543210", "utf8");
const TENANT_ID = "11111111-1111-4111-8111-111111111111";
const OTHER_TENANT_ID = "22222222-2222-4222-8222-222222222222";
const MEMBER_ID = "33333333-3333-4333-8333-333333333333";
const OTHER_MEMBER_ID = "44444444-4444-4444-8444-444444444444";
const RECORD_ID = "55555555-5555-4555-8555-555555555555";
const CREATED_AT = "2026-08-12T00:00:00.123Z";
const BINDING = Object.freeze({ resource: "members", tenant_id: TENANT_ID, member_id: MEMBER_ID });

function input(overrides = {}) {
  return {
    ...BINDING,
    created_at: CREATED_AT,
    id: RECORD_ID,
    direction: "asc",
    ...overrides
  };
}

function unpack(cursor) {
  return JSON.parse(Buffer.from(cursor, "base64url").toString("utf8"));
}

function pack(envelope) {
  return Buffer.from(JSON.stringify(envelope), "utf8").toString("base64url");
}

function invalid(operation, secret = undefined) {
  assert.throws(operation, (error) => {
    assert.ok(error instanceof HumanCursorCodecError);
    assert.equal(error.code, HUMAN_CURSOR_ERROR_CODES.INVALID_CURSOR);
    assert.equal(error.message, "The pagination cursor is invalid");
    assert.equal(error.cause, undefined);
    assert.equal(Object.prototype.hasOwnProperty.call(error, "secret"), false);
    if (secret !== undefined) {
      assert.equal(error.message.includes(secret), false);
      assert.equal(String(error.stack).includes(secret), false);
    }
    return true;
  });
}

test("encodes a deterministic versioned cursor and round-trips its immutable keyset tuple", () => {
  const codec = createHumanCursorCodec({ secret: SECRET });
  const cursor = codec.encode(input());
  const second = codec.encode(input());

  assert.equal(cursor, second);
  assert.match(cursor, /^[A-Za-z0-9_-]+$/u);
  assert.ok(cursor.length <= HUMAN_CURSOR_MAX_LENGTH);
  assert.deepEqual(codec.decode(cursor, BINDING), {
    version: HUMAN_CURSOR_CODEC_VERSION,
    resource: "members",
    tenant_id: TENANT_ID,
    member_id: MEMBER_ID,
    created_at: CREATED_AT,
    id: RECORD_ID,
    direction: "asc"
  });
  assert.equal(Object.isFrozen(codec.decode(cursor, BINDING)), true);
});

test("authenticates the canonical payload with HMAC-SHA256", () => {
  const codec = createHumanCursorCodec({ secret: SECRET });
  const cursor = codec.encode(input());
  const envelope = unpack(cursor);
  const payload = {
    version: envelope.version,
    resource: envelope.resource,
    tenant_id: envelope.tenant_id,
    member_id: envelope.member_id,
    created_at: envelope.created_at,
    id: envelope.id,
    direction: envelope.direction
  };
  const expected = createHmac("sha256", SECRET)
    .update("agentpass:human-api-cursor:v1\u0000", "utf8")
    .update(JSON.stringify(payload), "utf8")
    .digest("base64url");
  assert.equal(envelope.mac, expected);
});

test("binds cursors to resource, tenant, member, and direction", () => {
  const codec = createHumanCursorCodec({ secret: SECRET });
  const cursor = codec.encode(input());

  invalid(() => codec.decode(cursor, { ...BINDING, resource: "organizations" }));
  invalid(() => codec.decode(cursor, { ...BINDING, tenant_id: OTHER_TENANT_ID }));
  invalid(() => codec.decode(cursor, { ...BINDING, member_id: OTHER_MEMBER_ID }));
  invalid(() => codec.decode(cursor, { ...BINDING, direction: "desc" }));
  invalid(() => codec.decode(cursor, { ...BINDING, unexpected: true }));
  invalid(() => codec.decode(cursor));
});

test("rejects a cursor signed by another secret and a tampered keyset field", () => {
  const codec = createHumanCursorCodec({ secret: SECRET });
  const otherCodec = createHumanCursorCodec({ secret: OTHER_SECRET });
  const cursor = codec.encode(input());

  invalid(() => otherCodec.decode(cursor, BINDING), OTHER_SECRET.toString("utf8"));

  const tampered = unpack(cursor);
  tampered.created_at = "2026-08-12T00:00:00.124Z";
  invalid(() => codec.decode(pack(tampered), BINDING), SECRET.toString("utf8"));

  const macTampered = unpack(cursor);
  macTampered.mac = `${macTampered.mac.slice(0, -1)}${macTampered.mac.endsWith("A") ? "B" : "A"}`;
  invalid(() => codec.decode(pack(macTampered), BINDING), SECRET.toString("utf8"));

  for (const mac of ["A".repeat(42), "A".repeat(44)]) {
    invalid(() => codec.decode(pack({ ...unpack(cursor), mac }), BINDING), SECRET.toString("utf8"));
  }
});

test("enforces the exact canonical envelope schema", () => {
  const codec = createHumanCursorCodec({ secret: SECRET });
  const cursor = codec.encode(input());
  const envelope = unpack(cursor);

  invalid(() => codec.decode(pack({ ...envelope, extra: true }), BINDING));

  const withoutId = { ...envelope };
  delete withoutId.id;
  invalid(() => codec.decode(pack(withoutId), BINDING));

  const reordered = {
    resource: envelope.resource,
    version: envelope.version,
    tenant_id: envelope.tenant_id,
    member_id: envelope.member_id,
    created_at: envelope.created_at,
    id: envelope.id,
    direction: envelope.direction,
    mac: envelope.mac
  };
  invalid(() => codec.decode(pack(reordered), BINDING));

  const duplicateMac = JSON.stringify({ ...envelope }).replace(
    `,"mac":${JSON.stringify(envelope.mac)}`,
    `,"mac":${JSON.stringify(envelope.mac)},"mac":${JSON.stringify(envelope.mac)}`
  );
  invalid(() => codec.decode(Buffer.from(duplicateMac, "utf8").toString("base64url"), BINDING));

  const wrongMacType = { ...envelope, mac: 1 };
  invalid(() => codec.decode(pack(wrongMacType), BINDING));
  invalid(() => codec.decode(pack({ ...envelope, version: HUMAN_CURSOR_CODEC_VERSION + 1 }), BINDING));
});

test("rejects malformed, non-canonical, oversized, and invalid-field cursors", () => {
  const codec = createHumanCursorCodec({ secret: SECRET });
  const cursor = codec.encode(input());

  invalid(() => codec.decode("not a cursor", BINDING));
  invalid(() => codec.decode(`${cursor}=`, BINDING));
  invalid(() => codec.decode("A".repeat(HUMAN_CURSOR_MAX_LENGTH + 1), BINDING));

  for (const overrides of [
    { resource: "" },
    { resource: "members/secret" },
    { tenant_id: "not-a-uuid" },
    { id: "not-a-uuid" },
    { created_at: "2026-02-31T00:00:00.123Z" },
    { created_at: "not-a-date" },
    { direction: "forward" }
  ]) {
    invalid(() => codec.encode(input(overrides)));
  }

  invalid(() => codec.encode({ ...input(), extra: true }));
  invalid(() => codec.encode({ ...input(), id: undefined }));
});

test("protects the injected secret from later caller mutation", () => {
  const secret = Buffer.from(SECRET);
  const codec = createHumanCursorCodec({ secret });
  secret.fill(0);
  const cursor = codec.encode(input());
  assert.deepEqual(codec.decode(cursor, BINDING).id, RECORD_ID);
});

test("enforces a configured cursor length ceiling", () => {
  const codec = createHumanCursorCodec({ secret: SECRET, maxLength: 64 });
  invalid(() => codec.encode(input()));
  invalid(() => codec.decode("A".repeat(65), BINDING));
  assert.throws(() => createHumanCursorCodec({ secret: SECRET, maxLength: 513 }), /maxLength/);
});

test("requires an injected non-empty HMAC secret", () => {
  assert.throws(() => createHumanCursorCodec(), /secret/);
  assert.throws(() => createHumanCursorCodec({ secret: "" }), /secret/);
  assert.throws(() => createHumanCursorCodec({ secret: "short-secret" }), /32 bytes/);
  assert.throws(() => createHumanCursorCodec({ secret: 42 }), /secret/);
});
