import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import test from "node:test";

import { canonicalJson } from "../packages/protocol/src/index.mjs";

const vector = JSON.parse(readFileSync(
  new URL("../contracts/vectors/worktree-binding-v2.json", import.meta.url),
  "utf8"
));

test("worktree binding v2 canonical digest matches the native vector", () => {
  assert.deepEqual(Object.keys(vector).sort(), ["binding", "domain", "sha256"]);
  assert.equal(vector.binding.version, 2);
  assert.equal(vector.domain, "AgentPass-Worktree-Binding-v2\\0");
  const digest = createHash("sha256")
    .update(Buffer.from("AgentPass-Worktree-Binding-v2\0", "utf8"))
    .update(Buffer.from(canonicalJson(vector.binding), "utf8"))
    .digest("hex");
  assert.equal(digest, vector.sha256);
});
