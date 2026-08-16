import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import Ajv2020 from "ajv/dist/2020.js";
import addFormats from "ajv-formats";

import { canonicalJson } from "../packages/protocol/src/index.mjs";

const root = path.resolve(import.meta.dirname, "..");
const fixture = JSON.parse(fs.readFileSync(path.join(root, "test", "fixtures", "agent-signing-capability-v1.json"), "utf8"));

test("Agent signing capability canonical vector matches the Swift contract vector", () => {
  const statementBytes = Buffer.from(canonicalJson(fixture.envelope.statement), "utf8");
  const signedBytes = Buffer.concat([
    Buffer.from(fixture.signature_domain, "utf8"),
    statementBytes
  ]);

  assert.equal(canonicalJson(fixture.envelope.statement), fixture.canonical_statement);
  assert.equal(crypto.createHash("sha256").update(statementBytes).digest("hex"), fixture.statement_hash);
  assert.equal(signedBytes.toString("base64"), fixture.signed_statement_bytes_base64);
  assert.equal(fixture.envelope.statement.organization_id, "11111111-1111-4111-8111-111111111111");
  assert.equal(fixture.envelope.statement.issued_at, "2026-08-16T00:00:00.000Z");
});

test("The vector records the F1 schema-mismatch guard explicitly", () => {
  const schemaDirectory = path.join(root, "contracts", "schemas");
  const envelopeSchema = JSON.parse(fs.readFileSync(path.join(schemaDirectory, "agent-signing-capability-v1.schema.json"), "utf8"));
  const scopeSchema = JSON.parse(fs.readFileSync(path.join(schemaDirectory, "scope-v1.schema.json"), "utf8"));
  const ajv = new Ajv2020({ allErrors: true, strict: true, strictRequired: false });
  addFormats(ajv);
  ajv.addSchema(scopeSchema);
  const validate = ajv.compile(envelopeSchema);
  assert.equal(validate(fixture.envelope), true, "the checked-in schema must carry the signed tenant and issuance fields");
  assert.deepEqual(
    Object.keys(envelopeSchema.$defs.statement.properties).filter((key) => ["organization_id", "issued_at"].includes(key)),
    ["organization_id", "issued_at"]
  );
  assert.ok(envelopeSchema.$defs.statement.required.includes("organization_id"));
  assert.ok(envelopeSchema.$defs.statement.required.includes("issued_at"));
  assert.match(fixture.schema_mismatch, /schema variant.*incompatible/u);
});
