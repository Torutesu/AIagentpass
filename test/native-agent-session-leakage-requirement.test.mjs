import assert from "node:assert/strict";
import fs from "node:fs";
import test from "node:test";

const read = (relativePath) => fs.readFileSync(new URL(`../${relativePath}`, import.meta.url), "utf8");

const protocol = read("native/macos/Sources/AgentPassNativeCore/AgentXPCProtocol.swift");
const denial = read("native/macos/Sources/AgentPassNativeCore/NativeAgentSessionDenial.swift");
const dependencies = read("native/macos/Sources/AgentPassNativeCore/NativeAgentSessionDependencies.swift");
const recovery = read("native/macos/Sources/AgentPassNativeCore/NativeAgentSessionConsumeRecoveryStore.swift");
const service = read("native/macos/Sources/AgentPassNativeService/main.swift");

function between(source, startMarker, endMarker) {
  const start = source.indexOf(startMarker);
  assert.notEqual(start, -1, `missing source marker: ${startMarker}`);
  const end = source.indexOf(endMarker, start + startMarker.length);
  assert.notEqual(end, -1, `missing source marker: ${endMarker}`);
  return source.slice(start, end);
}

function publicFields(source) {
  return [...source.matchAll(/^\s*public let (\w+): ([^\n]+)$/gmu)].map((match) => ({
    name: match[1],
    type: match[2].trim()
  }));
}

function codingKeys(source) {
  const start = source.indexOf("private enum Keys");
  assert.notEqual(start, -1, "DTO must have a private coding-key enum");
  const end = source.indexOf("}", start);
  assert.notEqual(end, -1, "DTO coding-key enum must be closed");
  return [...source.slice(start, end).matchAll(/static let \w+ = "([^"]+)"/gu)].map((match) => match[1]);
}

function assertNoForbiddenPublicNames(label, source) {
  const forbidden = /(?:\bpath\b|\bcwd\b|\bargv\b|\benvironment\b|\benv\b|\bpid\b|audit[_-]?token|credential|private[_-]?key|bearer[_-]?token|access[_-]?token|session[_-]?token|grant|proof)/iu;
  for (const field of publicFields(source)) {
    assert.doesNotMatch(field.name, forbidden, `${label} exposes a forbidden property: ${field.name}`);
  }
  if (source.includes("private enum Keys")) {
    for (const key of codingKeys(source)) {
      assert.doesNotMatch(key, forbidden, `${label} exposes a forbidden coding key: ${key}`);
    }
  }
}

const sessionRequest = between(
  protocol,
  "@objc(AgentPassAgentSessionRequest)",
  "/// The public, correlation-only lease"
);
const statusRequest = between(
  protocol,
  "@objc(AgentPassAgentSessionStatusRequest)",
  "/// Closed session lifecycle values returned by the Agent surface."
);
const closeRequest = between(
  protocol,
  "@objc(AgentPassAgentCloseSessionRequest)",
  "@objc(AgentPassAgentCloseSessionResponse)"
);
const startResponse = between(
  protocol,
  "@objc(AgentPassAgentSessionResponse)",
  "/// Request for a read-only session status snapshot."
);
const statusResponse = between(
  protocol,
  "@objc(AgentPassAgentSessionStatusResponse)",
  "/// A fixed Git commit-sign request."
);
const closeResponse = between(
  protocol,
  "@objc(AgentPassAgentCloseSessionResponse)",
  "/// A dedicated Agent-only XPC surface."
);

test("start/status/close response DTOs have only the frozen opaque shape", () => {
  const expected = [
    {
      label: "start response",
      source: startResponse,
      fields: [
        ["sessionID", "String"],
        ["leaseID", "String"],
        ["processBindingDigest", "Data"],
        ["worktreeBindingDigest", "Data"],
        ["expiresAtMilliseconds", "Int64"],
        ["maxSignatures", "Int"]
      ],
      keys: ["session_id", "lease_id", "process_binding_digest", "worktree_binding_digest", "expires_at_ms", "max_signatures"]
    },
    {
      label: "status response",
      source: statusResponse,
      fields: [
        ["sessionID", "String"],
        ["status", "String"],
        ["expiresAtMilliseconds", "Int64"],
        ["maxSignatures", "Int"],
        ["usedSignatures", "Int"]
      ],
      keys: ["session_id", "status", "expires_at_ms", "max_signatures", "used_signatures"]
    },
    {
      label: "close response",
      source: closeResponse,
      fields: [
        ["sessionID", "String"],
        ["status", "String"],
        ["closedAtMilliseconds", "Int64"]
      ],
      keys: ["session_id", "status", "closed_at_ms"]
    }
  ];

  for (const item of expected) {
    assert.deepEqual(publicFields(item.source).map(({ name, type }) => [name, type]), item.fields, item.label);
    assert.deepEqual(codingKeys(item.source), item.keys, `${item.label} coding keys`);
    assertNoForbiddenPublicNames(item.label, item.source);
  }

  // The only Data values in a lifecycle response are fixed-width SHA-256
  // bindings. IDs are UUID-correlations, and the remaining values are status,
  // timestamps, or bounded counters.
  assert.match(startResponse, /AgentXPCValidation\.digest\(processBindingDigest\)/u);
  assert.match(startResponse, /AgentXPCValidation\.digest\(worktreeBindingDigest\)/u);
  assert.match(statusResponse, /AgentXPCValidation\.sessionStatus\(status\)/u);
  assert.match(statusResponse, /\(0\.\.\.maxSignatures\)\.contains\(usedSignatures\)/u);
  assert.match(closeResponse, /Self\.closedStatus/u);
});

test("the start proof is an inbound one-time handoff, never a public session result", () => {
  assert.deepEqual(publicFields(sessionRequest).map(({ name, type }) => [name, type]), [["bootstrapID", "String"], ["proof", "Data"]]);
  assert.deepEqual(codingKeys(sessionRequest), ["bootstrap_id", "proof"]);
  assert.match(sessionRequest, /maximumProofBytes/u);
  assertNoForbiddenPublicNames("start request", sessionRequest.replace(/\bproof\b/gu, "opaqueHandoff"));

  const endpoint = between(
    service,
    "private final class AgentConnectionEndpoint",
    "private final class AgentListenerDelegate"
  );
  const startMethod = between(endpoint, "func startAgentSession", "func agentSessionStatus");
  assert.match(startMethod, /let proof = request\.proof/u);
  const responseConstruction = between(startMethod, "guard let response = AgentPassAgentSessionResponse", "replyBox.call(response, nil)");
  assert.doesNotMatch(responseConstruction, /\bproof\b|bootstrapID|grant|credential|token/u);
  assert.doesNotMatch(responseConstruction, /path|cwd|argv|environment|env|pid|audit[_-]?token|private[_-]?key/u);
});

test("status and close requests are correlation-only and cannot carry authority material", () => {
  assert.deepEqual(publicFields(statusRequest).map(({ name, type }) => [name, type]), [["sessionID", "String"]]);
  assert.deepEqual(codingKeys(statusRequest), ["session_id"]);
  assertNoForbiddenPublicNames("status request", statusRequest);
  assert.match(statusRequest, /AgentXPCValidation\.uuid\(sessionID\)/u);

  assert.deepEqual(publicFields(closeRequest).map(({ name, type }) => [name, type]), [["sessionID", "String"], ["reason", "String"]]);
  assert.deepEqual(codingKeys(closeRequest), ["session_id", "reason"]);
  assertNoForbiddenPublicNames("close request", closeRequest);
  assert.match(closeRequest, /AgentPassAgentSessionCloseReason\(rawValue: reason\)/u);
});

test("Agent endpoint maps all lifecycle errors to fixed NSError projections", () => {
  const endpoint = between(
    service,
    "private final class AgentConnectionEndpoint",
    "private final class AgentListenerDelegate"
  );
  assert.match(endpoint, /func startAgentSession[\s\S]*coordinator\.start\(bootstrapID: bootstrapID, proof: proof\)/u);
  assert.match(endpoint, /func agentSessionStatus[\s\S]*coordinator\.status\(sessionID: sessionID\)/u);
  assert.match(endpoint, /func closeAgentSession[\s\S]*coordinator\.close\(sessionID: sessionID, reason: reason\)/u);
  assert.match(endpoint, /Self\.denial\(for: error\)\.nsError/u);
  assert.doesNotMatch(endpoint, /error as NSError|error\.localizedDescription|error\.userInfo|String\(describing:/u);
  assert.doesNotMatch(endpoint, /NSError\(domain:|userInfo:\s*\[[\s\S]*request|userInfo:\s*\[[\s\S]*path/u);

  const errorProjection = between(denial, "var nsError: NSError", "/// Alias kept next to `nsError`");
  assert.match(errorProjection, /NSError\([\s\S]*domain: Self\.errorDomain/u);
  assert.match(errorProjection, /userInfo:\s*\[[\s\S]*NSLocalizedDescriptionKey: message[\s\S]*Self\.reasonCodeUserInfoKey: errorCode/u);
  assert.doesNotMatch(errorProjection, /localizedDescription|error\.userInfo|String\(describing:|underlying/u);
  assert.match(denial, /Set\(error\.userInfo\.keys\) == expectedKeys/u);
  assert.match(denial, /let expectedKeys: Set<String> = \[NSLocalizedDescriptionKey, reasonCodeUserInfoKey\]/u);
});

test("audit evidence is an exact secret-free allowlist and is hashed before the frozen audit boundary", () => {
  const binding = between(dependencies, "public struct NativeAgentSessionBinding", "public init(");
  assert.deepEqual(publicFields(binding).map(({ name, type }) => [name, type]), [
    ["agentID", "String"],
    ["deviceID", "String"],
    ["processBindingDigest", "Data"],
    ["ancestryBindingDigest", "Data"],
    ["worktreeBindingDigest", "Data"],
    ["controlSequence", "Int64"],
    ["authorityGeneration", "Int64"],
    ["keyGeneration", "Int64"]
  ]);
  assertNoForbiddenPublicNames("session binding", binding);

  const evidenceImplementation = between(dependencies, "public struct NativeAgentSessionAuditEvidence", "public protocol NativeAgentSessionAuditAppending");
  const evidence = evidenceImplementation.slice(0, evidenceImplementation.indexOf("public init("));
  assert.deepEqual(publicFields(evidence).map(({ name, type }) => [name, type]), [
    ["action", "NativeAgentSessionAuditAction"],
    ["sessionID", "String?"],
    ["requestID", "String?"],
    ["capabilityID", "String?"],
    ["payloadDigest", "Data?"],
    ["binding", "NativeAgentSessionBinding"],
    ["reasonCode", "String?"]
  ]);
  assertNoForbiddenPublicNames("audit evidence", evidence);
  assert.match(evidenceImplementation, /UUID\(uuidString:/u);
  assert.match(evidenceImplementation, /payloadDigest\?\.count == NativeAgentSessionBinding\.digestByteCount/u);
  assert.match(evidenceImplementation, /unicodeScalars\.allSatisfy/u);

  const digestImplementation = between(dependencies, "public func evidenceDigest()", "private static func hex");
  const literalKeys = [...digestImplementation.matchAll(/^\s*"([^"]+)":/gmu)].map((match) => match[1]);
  const optionalKeys = [...digestImplementation.matchAll(/object\["([^"]+)"\]/gu)].map((match) => match[1]);
  assert.deepEqual([...new Set([...literalKeys, ...optionalKeys])], [
    "version",
    "action",
    "agent_id",
    "device_id",
    "process_binding_sha256",
    "ancestry_binding_sha256",
    "worktree_binding_sha256",
    "control_sequence",
    "authority_generation",
    "key_generation",
    "session_id",
    "request_id",
    "capability_id",
    "payload_sha256",
    "reason_code"
  ]);
  for (const key of [...new Set([...literalKeys, ...optionalKeys])]) {
    assert.doesNotMatch(key, /path|cwd|argv|environment|env|pid|audit[_-]?token|proof|grant|credential|private[_-]?key|bearer|session[_-]?token/u, key);
  }
  assert.match(digestImplementation, /NativeStrictJSON\.data\(object\)/u);
  assert.match(digestImplementation, /SHA256\.hash\(data:/u);
  const appendAudit = between(service, "func appendAgentSessionAudit", "private static func lowercaseHexDigest");
  assert.match(appendAudit, /evidence\.evidenceDigest\(\)/u);
  assert.match(appendAudit, /payloadSHA256: evidenceDigest/u);
  assert.match(appendAudit, /reason: evidence\.reasonCode/u);
  assert.doesNotMatch(appendAudit, /localizedDescription|error\.userInfo|String\(describing:|proof|grant|private[_-]?key|credential/u);
});

test("signGitCommit remains deliberately unavailable and cannot reach a signer", () => {
  const endpoint = between(
    service,
    "private final class AgentConnectionEndpoint",
    "private final class AgentListenerDelegate"
  );
  const signMethod = between(endpoint, "func signGitCommit", "func closeAgentSession");
  const signBody = signMethod.slice(signMethod.indexOf("{") + 1);
  assert.match(signMethod, /reply\(nil, unavailableAfterAuthorization\(\)\)/u);
  assert.doesNotMatch(signBody, /AgentPassAgentSignResponse|signGitCommitPayload|runtime\.[A-Za-z]*sign|privateKey|keySelector/u);
  assert.match(protocol, /func signGitCommit\([\s\S]*AgentPassAgentSignResponse\?/u);
  assert.match(service, /signing implementation will be allowed[\s\S]*unavailableAfterAuthorization/u);
});

test("restart recovery persists only Grant and authority digests", () => {
  const evidence = between(
    recovery,
    "public struct NativeAgentSessionConsumeRecoveryEvidence",
    "public struct NativeAgentSessionConsumeRecoveryAuditedRecord"
  );
  assert.deepEqual(publicFields(evidence).map(({ name }) => name), [
    "organizationID",
    "deviceID",
    "agentID",
    "adapterKind",
    "grantProofDigest",
    "processBindingDigest",
    "ancestryBindingDigest",
    "worktreeBindingDigest",
    "controlSequence",
    "authorityGeneration",
    "keyGeneration",
    "recoveryExpiresAtMilliseconds"
  ]);
  assert.doesNotMatch(evidence, /public let (?:proof|path|pid|token|credential|privateKey|bootstrapID|grantID)\b/u);
  const audited = between(
    recovery,
    "public struct NativeAgentSessionConsumeRecoveryAuditedRecord",
    "public enum NativeAgentSessionConsumeRecoveryLookup"
  );
  assert.deepEqual(publicFields(audited).map(({ name }) => name), [
    "evidence",
    "sessionDigest",
    "resultDigest",
    "auditDigest",
    "expiresAtMilliseconds"
  ]);
  assert.doesNotMatch(audited, /public let (?:lease|proof|path|pid|token|credential|privateKey|bootstrapID|grantID|sessionID)\b/u);
  assert.match(recovery, /NativeStrictJSON\.data\(object\)/u);
  assert.match(recovery, /O_NOFOLLOW/u);
  assert.match(recovery, /info\.st_nlink == 1/u);
  assert.match(recovery, /fsync\(descriptor\)/u);
  assert.match(recovery, /renameat\(/u);
  assert.match(recovery, /fsync\(parentFD\)/u);
  assert.doesNotMatch(recovery, /"proof"\s*:|"path"\s*:|"pid"\s*:|"token"\s*:/u);
  assert.match(service, /NativeAgentSessionConsumeRecoveryStore\([\s\S]*session-consume-recovery\.v1\.json/u);
  assert.match(service, /recoveryStore: runtime\.consumeRecoveryStore/u);
});
