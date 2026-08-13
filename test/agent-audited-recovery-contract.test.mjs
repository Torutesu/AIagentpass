import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const root = new URL("../", import.meta.url);
const read = (path) => readFile(new URL(path, root), "utf8");

test("audited recovery is a closed v3 pending-prepared-terminal store", async () => {
  const source = await read(
    "native/macos/Sources/AgentPassNativeCore/NativeAgentSessionConsumeRecoveryStore.swift",
  );
  assert.match(source, /private static let version = 3/);
  assert.match(source, /case pending\(NativeAgentSessionConsumeRecoveryEvidence\)/);
  assert.match(source, /case auditPrepared\(NativeAgentSessionConsumeRecoveryPreparedRecord\)/);
  assert.match(source, /case audited\(NativeAgentSessionConsumeRecoveryAuditedRecord\)/);
  assert.match(source, /records\[expected\.recoveryKey\] = \.auditPrepared\(preparedRecord\)/);
  assert.match(source, /records\[expected\.recoveryKey\] = \.audited\(auditedRecord\)/);
  assert.match(source, /try persistLocked\(\)/);
  assert.match(source, /"audit_sha256"/);
  assert.match(source, /"audit_evidence_sha256"/);
  assert.match(source, /"result_sha256"/);
  assert.match(source, /"session_sha256"/);
  for (const forbidden of ["proof_bytes", "private_key", "connection_token", "cloud_lease", "repository_path"]) {
    assert.doesNotMatch(source, new RegExp(`"${forbidden}"`));
  }
});

test("coordinator binds terminal recovery to Cloud result and durable audit receipt", async () => {
  const [coordinator, dependencies, service] = await Promise.all([
    read("native/macos/Sources/AgentPassNativeCore/NativeAgentSessionCoordinator.swift"),
    read("native/macos/Sources/AgentPassNativeCore/NativeAgentSessionDependencies.swift"),
    read("native/macos/Sources/AgentPassNativeService/main.swift"),
  ]);
  assert.match(coordinator, /recoveryStore\.lookupExact\(/);
  assert.match(coordinator, /auditedRecovery\.sessionDigest == sessionDigest/);
  assert.match(coordinator, /throw NativeAgentSessionCoordinatorError\.sessionDenied/);
  assert.match(coordinator, /auditReceipt = try audit\.reconcileAgentSessionActivationAudit/);
  assert.match(coordinator, /auditDigest: auditReceipt\.recordDigest/);
  assert.match(coordinator, /prepareForActivation\([\s\S]*preparedRecord: preparedRecord/);
  assert.match(coordinator, /completeAfterAudit\([\s\S]*auditedRecord: auditedRecord/);
  assert.match(dependencies, /struct NativeAgentSessionAuditReceipt/);
  assert.match(dependencies, /func appendAgentSessionAudit[\s\S]*-> NativeAgentSessionAuditReceipt/);
  assert.match(dependencies, /func reconcileAgentSessionActivationAudit/);
  assert.match(service, /lookupAgentSessionActivationOutcomeAudit\(/);
  assert.match(service, /recordDigest: recordDigest/);
});

test("audited restart cannot recreate in-memory authority", async () => {
  const [coordinator, registry, faultTests] = await Promise.all([
    read("native/macos/Sources/AgentPassNativeCore/NativeAgentSessionCoordinator.swift"),
    read("native/macos/Sources/AgentPassNativeCore/NativeAgentSessionRegistry.swift"),
    read("native/macos/Tests/AgentPassNativeCoreTests/NativeAgentSessionCoordinatorFaultTests.swift"),
  ]);
  const auditedBranch = coordinator.match(
    /if let auditedRecovery = attempt\.auditedRecovery \{([\s\S]*?)\n    \}/,
  )?.[1];
  assert.ok(auditedBranch);
  assert.doesNotMatch(auditedBranch, /registry\.activate/);
  assert.doesNotMatch(auditedBranch, /appendAgentSessionAudit/);
  assert.match(registry, /active authority never survives service restart/);
  assert.match(faultTests, /afterAuditedRestart/);
  assert.match(faultTests, /afterAuditedRestart\.audit\.events\.isEmpty/);
  assert.match(faultTests, /cloud\.commitCount == 1/);
});
