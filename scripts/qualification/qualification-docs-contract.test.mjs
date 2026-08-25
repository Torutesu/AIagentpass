import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import {
  CLOUD_SIGNER_KMS_PURPOSES,
  CLOUD_SIGNER_KMS_SCENARIOS,
} from "./cloud-signer-kms.mjs";

test("Cloud signer qualification documentation matches the frozen matrix", async () => {
  const source = await readFile(new URL("../../docs/CLOUD_SIGNER_KMS_QUALIFICATION.md", import.meta.url), "utf8");
  const packageJson = JSON.parse(await readFile(new URL("../../package.json", import.meta.url), "utf8"));
  assert.equal(packageJson.scripts["qualification:kms"], "node scripts/qualification/cloud-signer-kms.mjs");
  assert.match(source, new RegExp(`all (?:${CLOUD_SIGNER_KMS_PURPOSES.length}|eight) frozen signer purposes`));
  assert.match(source, new RegExp(`${CLOUD_SIGNER_KMS_PURPOSES.length ** 2} ordered IAM`));
  assert.match(source, new RegExp(`${CLOUD_SIGNER_KMS_PURPOSES.length * CLOUD_SIGNER_KMS_SCENARIOS.length} ordered\\s+purpose/scenario results`));
  assert.doesNotMatch(source, /The seven scenarios/);
  for (const scenario of CLOUD_SIGNER_KMS_SCENARIOS) assert.equal(source.includes(`\`${scenario}\``), true, `missing documented scenario: ${scenario}`);
});
