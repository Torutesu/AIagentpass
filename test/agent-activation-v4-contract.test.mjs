import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const root = new URL("../", import.meta.url);
const read = (path) => readFile(new URL(path, root), "utf8");

test("activation recovery v4 is additive and keeps v3 frozen", async () => {
  const source = await read(
    "native/macos/Sources/AgentPassNativeCore/NativeAgentSessionConsumeRecoveryStore.swift",
  );
  assert.match(source, /private static let version = 3/);
  assert.match(source, /class NativeAgentSessionConsumeRecoveryV4Store/);
  assert.match(source, /private static let version = 4/);
  assert.match(source, /case auditPrepared\(NativeAgentSessionConsumeRecoveryV4PreparedRecord\)/);
  assert.match(source, /case commitReceipt\(NativeAgentSessionConsumeRecoveryV4CommitReceipt\)/);
  assert.match(source, /case audited\(NativeAgentSessionConsumeRecoveryV4AuditedTerminalRecord\)/);
  assert.match(source, /case activated/);
  assert.match(source, /case aborted/);
  assert.match(source, /case outcomeUnknown = "outcome_unknown"/);
  assert.match(source, /"transaction_sha256"/);
  assert.match(source, /"commit_receipt_sha256"/);
});

test("staged registry exposes authority only through exact publication", async () => {
  const source = await read(
    "native/macos/Sources/AgentPassNativeCore/NativeAgentSessionRegistry.swift",
  );
  assert.match(source, /func reserveActivation\(/);
  assert.match(source, /func commitActivation\([\s\S]*connectionTokenIdentity:/);
  assert.match(source, /func publishActivation\([\s\S]*connectionTokenIdentity:/);
  assert.match(source, /func abortActivation\(/);
  assert.match(source, /pruneExpiredUnpublished/);
  assert.match(source, /committedActivations\[sessionID\] =/);
  assert.match(source, /entries\[sessionID\] = entry/);
});

test("activation outcomes bind typed transaction and commit receipt digests", async () => {
  const [dependencies, audit, service] = await Promise.all([
    read("native/macos/Sources/AgentPassNativeCore/NativeAgentSessionDependencies.swift"),
    read("native/macos/Sources/AgentPassNativeCore/NativeAudit.swift"),
    read("native/macos/Sources/AgentPassNativeService/main.swift"),
  ]);
  assert.match(dependencies, /sessionActivationAborted = "session_activation_aborted"/);
  assert.match(dependencies, /sessionActivationOutcomeUnknown = "session_activation_outcome_unknown"/);
  assert.match(dependencies, /activationTransactionDigest: Data\?/);
  assert.match(dependencies, /activationCommitReceiptDigest: Data\?/);
  assert.match(audit, /lookupAgentSessionActivationOutcomeAudit/);
  assert.match(service, /reconcileAgentSessionActivationOutcomeAudit/);
});

test("coordinator uses the durable staged activation order", async () => {
  const source = await read(
    "native/macos/Sources/AgentPassNativeCore/NativeAgentSessionCoordinator.swift",
  );
  const reserve = source.indexOf("registry.reserveActivation(");
  const prepare = source.indexOf("activationRecoveryStore.prepareForActivation(", reserve);
  const commit = source.indexOf("registry.commitActivation(", prepare);
  const receipt = source.indexOf("activationRecoveryStore.recordCommitReceipt(", commit);
  const audit = source.indexOf("audit.reconcileAgentSessionActivationOutcomeAudit(", receipt);
  const terminal = source.indexOf("activationRecoveryStore.completeAfterAudit(", audit);
  const publish = source.indexOf("registry.publishActivation(", terminal);
  assert.ok(reserve >= 0);
  assert.ok(reserve < prepare && prepare < commit && commit < receipt);
  assert.ok(receipt < audit && audit < terminal && terminal < publish);
  assert.doesNotMatch(source.slice(reserve, publish), /registry\.activate\(/);
});
