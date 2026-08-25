import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";

import { assertCloudQualificationSecretScanBoundary, validateCloudProductionQualificationWorkflow } from "./cloud-production-qualification-workflow.mjs";

const workflowPath = path.resolve(".github/workflows/cloud-production-qualification.yml");
const source = fs.readFileSync(workflowPath, "utf8");

test("cloud qualification secret-scans the complete source-bound artifact before upload", () => {
  assert.deepEqual(validateCloudProductionQualificationWorkflow(workflowPath), {
    status: "passed",
    boundary: "pre-upload",
    scanner: "artifact-scan"
  });
});

test("cloud qualification rejects a scan moved after the artifact upload", () => {
  const scanStart = source.indexOf("      - name: Secret-scan every cloud qualification artifact before upload");
  const uploadStart = source.indexOf("      - uses: actions/upload-artifact@", scanStart);
  assert.notEqual(scanStart, -1);
  assert.notEqual(uploadStart, -1);
  const scan = source.slice(scanStart, uploadStart);
  const moved = `${source.slice(0, scanStart)}${source.slice(uploadStart)}\n${scan}`;
  assert.throws(() => assertCloudQualificationSecretScanBoundary(moved), /before upload/u);
});

test("cloud qualification rejects a boundary that omits the dedicated archive scan", () => {
  const withoutArchiveReference = source.replaceAll("operations-evidence.tar", "operations-evidence-redacted.tar");
  assert.throws(() => assertCloudQualificationSecretScanBoundary(withoutArchiveReference), /operations-evidence\.tar/u);
});
