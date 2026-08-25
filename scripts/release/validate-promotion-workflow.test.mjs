import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { validatePromotionWorkflow, validatePromotionWorkflowText } from "./validate-promotion-workflow.mjs";

const workflowPath = path.resolve(".github/workflows/promote-qualified-release.yml");
const source = fs.readFileSync(workflowPath, "utf8");

test("current promotion workflow satisfies the executable static safety contract", () => {
  const result = validatePromotionWorkflow(workflowPath);
  assert.equal(result.ok, true, result.issues.join("\n"));
});

test("rejects duplicate YAML keys instead of silently accepting the last value", () => {
  const result = validatePromotionWorkflowText(source.replace("          MANIFEST_PUBLIC_KEY: ${{ steps.catalog.outputs.public_key }}\n", "          MANIFEST_PUBLIC_KEY: ${{ steps.catalog.outputs.public_key }}\n          MANIFEST_PUBLIC_KEY: duplicate\n"), { workflowPath });
  assert.equal(result.ok, false);
  assert.match(result.issues.join("\n"), /duplicate YAML key/u);
});

test("rejects step-local environment regressions and bad helper paths", () => {
  const withoutKey = source.replace("          MANIFEST_PUBLIC_KEY: ${{ steps.catalog.outputs.public_key }}\n          CANDIDATE_DIR:", "          CANDIDATE_DIR:");
  const badPath = withoutKey.replaceAll("scripts/release/ci-preflight.mjs", "scripts/ci-preflight.mjs");
  const result = validatePromotionWorkflowText(badPath, { workflowPath });
  assert.equal(result.ok, false);
  const issues = result.issues.join("\n");
  assert.match(issues, /MANIFEST_PUBLIC_KEY.*step-local env/u);
  assert.match(issues, /nonexistent scripts\/ci-preflight\.mjs/u);
});

test("rejects publish-before-roundtrip and missing cleanup", () => {
  const roundtrip = "      - name: Re-inspect every uploaded release asset before publishing";
  const publishFirst = source.replace(roundtrip, `      - name: Publish the fully uploaded public release\n        run: gh release edit \"$RELEASE_TAG\" --repo \"$CANONICAL_REPOSITORY\" --draft=false\n\n${roundtrip}`);
  const withoutCleanup = publishFirst.replace(/\n      - name: Remove promotion material[\s\S]*$/u, "\n");
  const result = validatePromotionWorkflowText(withoutCleanup, { workflowPath });
  assert.equal(result.ok, false);
  const issues = result.issues.join("\n");
  assert.match(issues, /roundtrip evidence must be verified before it is uploaded|roundtrip verification must run before publish/u);
  assert.match(issues, /after-publish cleanup/u);
});

test("rejects publishing when the retained round-trip evidence is not re-inspected", () => {
  const withoutRetainedCheck = source.replace(/\n      - name: Re-inspect retained release asset evidence before publishing[\s\S]*?(?=\n      - name: Publish the fully uploaded public release)/u, "\n");
  const result = validatePromotionWorkflowText(withoutRetainedCheck, { workflowPath });
  assert.equal(result.ok, false);
  assert.match(result.issues.join("\n"), /uploaded roundtrip evidence must be re-downloaded/u);
});

test("rejects a promotion workflow that omits either staging verifier", () => {
  const withoutReadiness = source.replace(/\n      - name: Verify exact-candidate staging readiness[\s\S]*?(?=\n      - name: Verify externally reviewed release evidence index operator gate)/u, "\n");
  const result = validatePromotionWorkflowText(withoutReadiness, { workflowPath });
  assert.equal(result.ok, false);
  assert.match(result.issues.join("\n"), /staging readiness.*staging-readiness\.mjs/u);
  assert.match(result.issues.join("\n"), /staging rollback.*staging-rollback\.mjs/u);
});

test("rejects staging evidence inputs that are not step-local", () => {
  const broken = source.replace("          STAGING_BINDING_JSON: ${{ vars.AGENTPASS_STAGING_BINDING_JSON }}\n", "");
  const result = validatePromotionWorkflowText(broken, { workflowPath });
  assert.equal(result.ok, false);
  assert.match(result.issues.join("\n"), /staging readiness: STAGING_BINDING_JSON must be step-local env/u);
});

test("CLI-facing validator reports a missing file without mutating the workspace", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "agentpass-workflow-validator-"));
  try {
    const missing = path.join(root, "missing.yml");
    assert.throws(() => validatePromotionWorkflow(missing), /cannot read promotion workflow/u);
    assert.equal(fs.readdirSync(root).length, 0);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});
