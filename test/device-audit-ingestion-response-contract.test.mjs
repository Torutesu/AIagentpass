import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import Ajv2020 from "ajv/dist/2020.js";
import addFormats from "ajv-formats";

const schema = JSON.parse(fs.readFileSync(path.join(process.cwd(), "contracts/schemas/device-audit-ingestion-response-v1.schema.json"), "utf8"));
const ajv = new Ajv2020({ allErrors: true, strict: true });
addFormats(ajv);
const validate = ajv.compile(schema);
const DEVICE_ID = "11111111-1111-4111-8111-111111111111";
const INBOX_ID = "22222222-2222-4222-8222-222222222222";

test("device audit response contract accepts a queued inbox result without internal fields", () => {
  const response = {
    ingestion: {
      device_id: DEVICE_ID,
      batch_id: `audit-${"a".repeat(64)}`,
      inbox_id: INBOX_ID,
      state: "pending"
    }
  };
  assert.equal(validate(response), true, ajv.errorsText(validate.errors));
  assert.equal(validate({ ingestion: { ...response.ingestion, organization_id: DEVICE_ID } }), false);
});

test("device audit response contract still accepts the committed result", () => {
  const response = {
    ingestion: {
      device_id: DEVICE_ID,
      accepted: [],
      duplicates: [],
      gaps: [],
      head: { last_hash: "b".repeat(64), last_event_id: null, chain_status: "continuous", gap_count: 0 }
    }
  };
  assert.equal(validate(response), true, ajv.errorsText(validate.errors));
});

test("device audit response contract accepts every durable inbox state", () => {
  for (const state of ["pending", "processing", "accepted", "uncertain", "dead_letter"]) {
    assert.equal(validate({ ingestion: { device_id: DEVICE_ID, batch_id: `audit-${"c".repeat(64)}`, inbox_id: INBOX_ID, state } }), true, state);
  }
});
