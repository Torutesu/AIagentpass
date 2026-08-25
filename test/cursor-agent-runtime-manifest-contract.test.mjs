import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import test from "node:test";
import Ajv2020 from "ajv/dist/2020.js";

import { canonicalJson } from "../packages/protocol/src/index.mjs";

const schema = JSON.parse(fs.readFileSync(new URL("../contracts/schemas/cursor-agent-runtime-manifest-v1.schema.json", import.meta.url)));
const vector = JSON.parse(fs.readFileSync(new URL("../contracts/vectors/cursor-agent-runtime-manifest-v1.json", import.meta.url)));
const manifestBytes = Buffer.from(vector.canonical_manifest_base64url, "base64url");
const manifest = JSON.parse(manifestBytes.toString("utf8"));
const domain = "AgentPass-Cursor-Agent-Runtime-Manifest-v1\0";

test("Cursor runtime vector is canonical, schema-valid, and independently signed", () => {
  assert.equal(vector.vector_version, 1);
  assert.deepEqual(manifestBytes, Buffer.from(`${canonicalJson(manifest)}\n`, "utf8"));

  const ajv = new Ajv2020({ allErrors: true, strict: true });
  const validate = ajv.compile(schema);
  assert.equal(validate(manifest), true, ajv.errorsText(validate.errors));

  assert.equal(manifest.signature.key_id, vector.key_id);
  assert.equal(manifest.signature.domain, domain);
  const publicKeyDER = Buffer.from(vector.public_key_der_base64url, "base64url");
  assert.equal(publicKeyDER.length, 44);
  const publicKey = crypto.createPublicKey({ key: publicKeyDER, format: "der", type: "spki" });
  const signedBytes = Buffer.concat([Buffer.from(domain, "utf8"), Buffer.from(canonicalJson(manifest.core), "utf8")]);
  assert.equal(crypto.verify(null, signedBytes, publicKey, Buffer.from(manifest.signature.signature_base64url, "base64url")), true);
});

test("Cursor runtime schema rejects missing required launch files", () => {
  const ajv = new Ajv2020({ allErrors: true, strict: true });
  const validate = ajv.compile(schema);
  const invalid = structuredClone(manifest);
  invalid.core.files = invalid.core.files.filter((entry) => entry.relative_path !== "node");
  assert.equal(validate(invalid), false);
});
