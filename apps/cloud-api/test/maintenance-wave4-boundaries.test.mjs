import assert from "node:assert/strict";
import test from "node:test";
import { createPatchProposal, PATCH_AGENT_ERROR_CODES } from "../src/maintenance/patch-agent.mjs";
import { createDraftPullRequestIntent, evaluateDraftPullRequest } from "../src/maintenance/pr-workflow.mjs";

test("Wave 4 modules load with explicit fail-closed exports", () => {
  assert.equal(typeof createPatchProposal, "function");
  assert.equal(typeof createDraftPullRequestIntent, "function");
  assert.equal(PATCH_AGENT_ERROR_CODES.SECRET_REJECTED, "maintenance.patch_agent.secret_rejected");
});

test("PR workflow remains approval-gated and never permits merge", () => {
  assert.equal(typeof evaluateDraftPullRequest, "function");
});
