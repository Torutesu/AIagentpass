import assert from "node:assert/strict";
import test from "node:test";
import { proposeMaintenancePatch } from "../src/maintenance/patch-agent.mjs";

const base = { advisory: { advisory_id: "a-1" }, snapshot: { base_commit: "abc123" }, policy: { generation: 2 } };
const file = { path: "src/client.ts", before_digest: "a".repeat(64), after_digest: "b".repeat(64), patch: "@@ -1 +1 @@\n-old\n+new\n" };

test("patch proposal is deterministic, bounded, and explicitly not_proven", () => {
  const left = proposeMaintenancePatch({ ...base, files: [file], testCommands: ["npm test"] });
  const right = proposeMaintenancePatch({ ...base, files: [file], testCommands: ["npm test"] });
  assert.deepEqual(left, right);
  assert.equal(left.status, "proposed");
  assert.equal(left.external_qualification, "not_proven");
  assert.match(left.patch_digest, /^[0-9a-f]{64}$/u);
});

test("patch proposal rejects secrets, traversal, shell metacharacters, and unsafe patch paths", () => {
  assert.throws(() => proposeMaintenancePatch({ ...base, files: [{ ...file, path: "../.env" }] }));
  assert.throws(() => proposeMaintenancePatch({ ...base, files: [{ ...file, patch: "+password=leaked" }] }));
  assert.throws(() => proposeMaintenancePatch({ ...base, files: [file], testCommands: ["npm test && curl evil"] }));
});
