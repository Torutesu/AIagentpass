import fs from "node:fs";
import path from "node:path";

export class CloudProductionQualificationWorkflowError extends Error {
  constructor(message) {
    super(message);
    this.name = "CloudProductionQualificationWorkflowError";
  }
}
function fail(message) {
  throw new CloudProductionQualificationWorkflowError(message);
}

/**
 * The Cloud qualification artifact is later consumed as production evidence
 * and its GitHub archive digest is verified independently during promotion.
 * Keep the upload boundary executable: every file in the artifact tree must
 * be scanned before upload, including the opaque operations archive through
 * the dedicated release artifact scanner.
 */
export function assertCloudQualificationSecretScanBoundary(source) {
  if (typeof source !== "string") fail("workflow source must be a string");
  const prepare = source.indexOf("- name: Prepare immutable qualification artifact");
  const scan = source.indexOf("- name: Secret-scan every cloud qualification artifact before upload");
  const upload = source.indexOf("uses: actions/upload-artifact@");
  if (prepare < 0 || scan < 0 || upload < 0) fail("cloud qualification artifact boundary is incomplete");
  if (!(prepare < scan && scan < upload)) fail("cloud qualification secret scan must run after preparation and before upload");

  const boundary = source.slice(scan, upload);
  for (const required of [
    "node scripts/release/ci-preflight.mjs artifact-scan",
    "operations-evidence.tar",
    "cloud-production-qualification-artifact-scan.json",
    "install -m 0600",
    "node scripts/release/ci-preflight.mjs secret-scan",
    "artifact-scan.json"
  ]) {
    if (!boundary.includes(required)) fail(`cloud qualification secret scan is missing ${required}`);
  }
  return Object.freeze({ status: "passed", boundary: "pre-upload", scanner: "artifact-scan" });
}

export function validateCloudProductionQualificationWorkflow(workflowPath = path.resolve(".github/workflows/cloud-production-qualification.yml")) {
  let source;
  try {
    source = fs.readFileSync(workflowPath, "utf8");
  } catch (error) {
    throw new CloudProductionQualificationWorkflowError(`cannot read cloud qualification workflow: ${error.message}`);
  }
  return assertCloudQualificationSecretScanBoundary(source);
}
