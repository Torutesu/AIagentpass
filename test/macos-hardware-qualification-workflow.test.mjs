import assert from "node:assert/strict";
import fs from "node:fs";
import test from "node:test";
import { resolve } from "node:path";

const root = resolve(import.meta.dirname, "..");
const workflow = fs.readFileSync(resolve(root, ".github/workflows/macos-hardware-qualification.yml"), "utf8");

test("macOS hardware qualification uses protected lane environments", () => {
  assert.match(workflow, /environment: \$\{\{ matrix\.environment \}\}/u);
  assert.match(workflow, /environment: agentpass-macos-apple-silicon/u);
  assert.match(workflow, /environment: agentpass-macos-intel/u);
  assert.match(workflow, /AGENTPASS_QUALIFICATION_EXPECTED_RUNNER_ID: \$\{\{ runner\.name \}\}/u);
});

test("macOS qualification requires a signed probe identity at every boundary", () => {
  assert.match(workflow, /Developer ID Application signing identity is required and invalid/u);
  const entrypoint = fs.readFileSync(resolve(root, "native/macos/scripts/qualification/run-hardware-qualification.sh"), "utf8");
  assert.match(entrypoint, /AGENTPASS_LAUNCHD_HOST_CHILD_PROBE_SIGNING_IDENTITY:\?[^\n]+required/u);
  assert.match(entrypoint, /--launchd-probe-signing-identity/u);
  assert.match(entrypoint, /--nsxpc-probe-signing-identity/u);
  assert.match(entrypoint, /--crash-restart-probe-signing-identity/u);
});

test("macOS qualification executes only the protected installed toolchain", () => {
  assert.match(workflow, /QUALIFICATION_TOOL_ROOT: \/opt\/agentpass\/macos\/qualification-tool/u);
  assert.match(workflow, /verify-installed-toolchain\.mjs/u);
  assert.match(workflow, /QUALIFICATION_TOOL_MANIFEST_FINGERPRINT/u);
  assert.match(workflow, /run: \/opt\/agentpass\/macos\/qualification-tool\/run-hardware-qualification\.sh/u);
  assert.doesNotMatch(workflow, /run: native\/macos\/scripts\/qualification\/run-hardware-qualification\.sh/u);
  assert.doesNotMatch(workflow, /run: node native\/macos\/Qualification\/hardware-qualification\.mjs/u);
});

test("qualification entrypoint rejects local, translated, and virtual execution before probes", () => {
  const entrypoint = fs.readFileSync(resolve(root, "native/macos/scripts/qualification/run-hardware-qualification.sh"), "utf8");
  assert.match(entrypoint, /PROTECTED_TOOL_ROOT="\/opt\/agentpass\/macos\/qualification-tool"/u);
  assert.match(entrypoint, /qualification tool root is not the protected installed toolchain/u);
  assert.match(entrypoint, /sysctl\.proc_translated/u);
  assert.match(entrypoint, /kern\.hv_vmm_present/u);
  assert.match(entrypoint, /AppleSEPManager/u);
  assert.match(entrypoint, /protected physical runner/u);
  assert.match(entrypoint, /macos-latest/u);
});

test("source-bound Swift qualification isolates every SwiftPM cache", () => {
  assert.match(workflow, /Configure reproducible SwiftPM cache and evidence paths/u);
  assert.match(workflow, /CLANG_MODULE_CACHE_PATH=\$NATIVE_SWIFT_ROOT\/module-cache/u);
  assert.match(workflow, /AGENTPASS_DISABLE_SWIFTPM_SANDBOX=1/u);
  for (const option of ["--cache-path", "--config-path", "--security-path", "--scratch-path", "--manifest-cache local"]) {
    assert.match(workflow, new RegExp(option.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"), "u"));
  }
  assert.match(workflow, /swift test --package-path native\/macos --disable-sandbox/u);
  assert.match(workflow, /test-app-bundle\.sh/u);
  const bundleTest = fs.readFileSync(resolve(root, "native/macos/scripts/test-app-bundle.sh"), "utf8");
  assert.match(bundleTest, /AGENTPASS_SWIFT_MODULE_CACHE_PATH/u);
  assert.match(bundleTest, /export CLANG_MODULE_CACHE_PATH=/u);
  assert.match(bundleTest, /AGENTPASS_DISABLE_SWIFTPM_SANDBOX/u);
});

test("Swift qualification evidence binds source, execution identity, and logs", () => {
  assert.match(workflow, /agentpass-native-swift-ci-evidence/u);
  assert.match(workflow, /GITHUB_RUN_ID/u);
  assert.match(workflow, /GITHUB_RUN_ATTEMPT/u);
  assert.match(workflow, /GITHUB_JOB/u);
  assert.match(workflow, /EXPECTED_RUNNER_ID/u);
  assert.match(workflow, /source_commit: evidence\.source\.commit/u);
  assert.match(workflow, /source_tree: evidence\.source\.tree/u);
  assert.match(workflow, /sha256: digest\(file\)/u);
  assert.match(workflow, /Verify source-bound Swift evidence/u);
  assert.match(workflow, /macos-native-swift-\$\{\{ matrix\.architecture \}\}-\$\{\{ inputs\.source_commit \}\}/u);
});
