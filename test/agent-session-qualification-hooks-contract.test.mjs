import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

function read(relativePath) {
  return fs.readFileSync(path.join(root, relativePath), "utf8");
}

function withoutSwiftComments(source) {
  return source
    .replace(/\/\*[\s\S]*?\*\//gu, "")
    .replace(/\/\/[^\n]*/gu, "");
}

function matchingBrace(source, openIndex) {
  assert.equal(source[openIndex], "{", "expected an opening brace");
  let depth = 0;
  let inString = false;
  let escaped = false;
  for (let index = openIndex; index < source.length; index += 1) {
    const character = source[index];
    if (inString) {
      if (escaped) escaped = false;
      else if (character === "\\") escaped = true;
      else if (character === '"') inString = false;
      continue;
    }
    if (character === '"') {
      inString = true;
      continue;
    }
    if (character === "{") depth += 1;
    if (character === "}") {
      depth -= 1;
      if (depth === 0) return index;
    }
  }
  assert.fail("unterminated Swift brace block");
}

function swiftBlock(source, marker) {
  const markerIndex = source.indexOf(marker);
  assert.notEqual(markerIndex, -1, `${marker} must exist`);
  const openIndex = source.indexOf("{", markerIndex + marker.length);
  assert.notEqual(openIndex, -1, `${marker} must have a body`);
  const closeIndex = matchingBrace(source, openIndex);
  return {
    body: source.slice(openIndex + 1, closeIndex),
    start: markerIndex,
    open: openIndex,
    close: closeIndex,
  };
}

function swiftFunctionBodies(source) {
  const bodies = [];
  const declaration = /\b(?:private\s+|public\s+|internal\s+|fileprivate\s+)?func\s+[A-Za-z_][A-Za-z0-9_]*/gu;
  for (const match of source.matchAll(declaration)) {
    const openIndex = source.indexOf("{", match.index + match[0].length);
    if (openIndex === -1) continue;
    const closeIndex = matchingBrace(source, openIndex);
    bodies.push({
      body: source.slice(openIndex + 1, closeIndex),
      start: match.index,
      open: openIndex,
      close: closeIndex,
    });
  }
  return bodies;
}

const boundaryPath = "native/macos/Sources/AgentPassNativeCore/NativeAgentSessionQualificationFaultConsumer.swift";
const coordinatorPath = "native/macos/Sources/AgentPassNativeCore/NativeAgentSessionCoordinator.swift";
const agentProtocolPath = "native/macos/Sources/AgentPassNativeCore/AgentXPCProtocol.swift";
const servicePath = "native/macos/Sources/AgentPassNativeService/main.swift";

const boundarySource = read(boundaryPath);
const coordinatorSource = read(coordinatorPath);
const agentProtocolSource = read(agentProtocolPath);
const serviceSource = read(servicePath);

const activationBoundaries = [
  ["beforeCloudConsume", "before-cloud-consume"],
  ["afterCloudLeaseVerified", "after-cloud-lease-verified"],
  ["afterAdmissionReserved", "after-admission-reserved"],
  ["afterRecoveryPrepared", "after-recovery-prepared"],
  ["afterHiddenCommit", "after-hidden-commit"],
  ["afterCommitReceipt", "after-commit-receipt"],
  ["afterAuditDurable", "after-audit-durable"],
  ["afterRecoveryTerminal", "after-recovery-terminal"],
  ["afterPublication", "after-publication"],
  ["afterResultEncoded", "after-result-encoded"],
];

test("NativeAgentSessionQualificationBoundary is a closed ten-case enum", () => {
  const clean = withoutSwiftComments(boundarySource);
  const enumBlock = swiftBlock(clean, "public enum NativeAgentSessionQualificationBoundary");
  assert.match(clean, /public enum NativeAgentSessionQualificationBoundary[^\n]*CaseIterable/u);
  const cases = [...enumBlock.body.matchAll(/^\s*case\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*"([^"]+)"/gmu)]
    .map(([, name, rawValue]) => [name, rawValue]);
  assert.deepEqual(cases, activationBoundaries);
  assert.equal(cases.length, 10, "adding a boundary requires a new qualification contract");
});

test("coordinator reaches exactly the first nine boundaries in activation order", () => {
  const clean = withoutSwiftComments(coordinatorSource);
  const calls = [...clean.matchAll(/qualificationFaultConsumer\.reach\(\.([A-Za-z_][A-Za-z0-9_]*)\)/gu)]
    .map(([, boundary]) => boundary);
  assert.deepEqual(calls, activationBoundaries.slice(0, 9).map(([name]) => name));
  assert.doesNotMatch(clean, /qualificationFaultConsumer\.reach\(\.afterResultEncoded\)/u);
});

test("afterResultEncoded is only between successful Agent response construction and reply", () => {
  const cleanService = withoutSwiftComments(serviceSource);
  const startMethod = swiftBlock(cleanService, "func startAgentSession(");
  const responseGuardOffset = startMethod.body.indexOf(
    "guard let response = AgentPassAgentSessionResponse("
  );
  assert.notEqual(responseGuardOffset, -1, "startAgentSession must construct the response DTO");
  const elseOffset = startMethod.body.indexOf("else {", responseGuardOffset);
  assert.ok(elseOffset > responseGuardOffset, "response construction must have a failure branch");
  const failedConstructionEnd = matchingBrace(
    startMethod.body,
    startMethod.body.indexOf("{", elseOffset)
  );
  const reachOffsets = [...cleanService.matchAll(/\.afterResultEncoded\b/gu)]
    .map((match) => match.index)
    .filter((index) => index >= startMethod.start && index <= startMethod.close);
  assert.deepEqual(reachOffsets.length, 1, "the encoded-response boundary must be one-shot at XPC reply");
  const reachOffset = reachOffsets[0] - (startMethod.open + 1);
  assert.ok(
    reachOffset > failedConstructionEnd,
    "afterResultEncoded must run only after successful DTO construction"
  );
  const replyOffset = startMethod.body.indexOf("replyBox.call(response, nil)", reachOffset);
  assert.ok(replyOffset > reachOffset, "afterResultEncoded must run before the successful reply");
  assert.match(
    startMethod.body.slice(reachOffset, replyOffset),
    /catch\s*\{[\s\S]*?coordinator\.abortActivation\(sessionID: activation\.status\.sessionID\)[\s\S]*?throw error/u,
    "a returning hook failure must revoke reply-less authority; injected SIGKILL never returns here"
  );
  assert.equal(
    [...cleanService.matchAll(/\.reach\(\.afterResultEncoded\)/gu)].length,
    1,
    "afterResultEncoded must not be used by another service path"
  );
});

test("Agent XPC DTOs and protocol have no qualification control fields", () => {
  const clean = withoutSwiftComments(agentProtocolSource);
  const agentProtocol = swiftBlock(clean, "public protocol AgentPassAgentXPCProtocol");
  const qualificationField = /\b(?:qualification|fault|scenario|phase)\b/iu;
  assert.doesNotMatch(clean, qualificationField);
  assert.doesNotMatch(agentProtocol.body, qualificationField);
  assert.match(clean, /@objc\(AgentPassAgentBootstrapRequest\)/u);
  assert.match(clean, /@objc\(AgentPassAgentSessionResponse\)/u);
  assert.match(clean, /@objc\(AgentPassAgentSignRequest\)/u);
});

test("normal coordinator construction has a zero-surface no-op qualification path", () => {
  const cleanBoundary = withoutSwiftComments(boundarySource);
  const cleanCoordinator = withoutSwiftComments(coordinatorSource);
  assert.match(
    cleanBoundary,
    /public struct NativeAgentSessionQualificationNoopFaultConsumer\s*:\s*[\s\S]*?NativeAgentSessionQualificationFaultConsuming[\s\S]*?public init\(\)\s*\{\s*\}[\s\S]*?public func reach\(_ boundary: NativeAgentSessionQualificationBoundary\) throws\s*\{\s*\}/u
  );
  assert.match(
    cleanCoordinator,
    /qualificationFaultConsumer\s*:\s*any NativeAgentSessionQualificationFaultConsuming\s*=\s*NativeAgentSessionQualificationNoopFaultConsumer\(\)/u
  );
});

test("service qualification adapter maps only the four coarse scenarios for N3-E3c-2", () => {
  const clean = withoutSwiftComments(serviceSource);
  const mapping = swiftBlock(clean, "private static func boundary(");
  const expectedPairs = [
    ["preCloudKill", "beforeCloudConsume"],
    ["postCloudPreLocalKill", "afterCloudLeaseVerified"],
    ["postActivationPreAuditKill", "afterHiddenCommit"],
    ["postAuditPreReplyLoss", "afterResultEncoded"],
  ];
  for (const [phase, scenario] of expectedPairs) {
    assert.match(
      mapping.body,
      new RegExp(`case\\s+\\.${phase}\\s*:[\\s\\S]*?return\\s+\\.${scenario}\\b`, "u"),
      `${phase} must map to ${scenario}`
    );
  }
  assert.match(
    mapping.body,
    /case\s+\.auditFsyncFailure\s*,\s*\.transportReplyLoss\s*:[\s\S]*?return\s+nil/u,
    "N3-E3c-3 audit/transport scenarios must remain unhandled by this adapter"
  );
  const deferredCases = mapping.body.match(
    /case\s+\.auditFsyncFailure\s*,\s*\.transportReplyLoss[\s\S]*?return\s+nil/u
  )?.[0] ?? "";
  assert.doesNotMatch(deferredCases, /return\s+\.[A-Za-z_][A-Za-z0-9_]*/u);
});

test("fatal qualification action is ordered after an injected controller receipt", () => {
  const candidateSources = [
    [boundaryPath, boundarySource],
    [servicePath, serviceSource],
  ];
  const fatalAction = /\b(?:fatalAction|terminate|kill|exit)\s*\(/u;
  let matchingAdapter = null;
  for (const [file, source] of candidateSources) {
    const clean = withoutSwiftComments(source);
    for (const functionBlock of swiftFunctionBodies(clean)) {
      if (!/\bcontroller\.consume\s*\(/u.test(functionBlock.body)) continue;
      if (!/\breceipt\.outcome\s*==\s*\.injected\b/u.test(functionBlock.body)) continue;
      if (!fatalAction.test(functionBlock.body)) continue;
      matchingAdapter = [file, functionBlock.body];
      break;
    }
    if (matchingAdapter) break;
  }
  assert.ok(
    matchingAdapter,
    "the service qualification adapter must consume the controller receipt before its fatal action"
  );
  const [, body] = matchingAdapter;
  const consumeOffset = body.search(/\bcontroller\.consume\s*\(/u);
  const injectedOffset = body.search(/\breceipt\.outcome\s*==\s*\.injected\b/u);
  const fatalOffset = body.search(fatalAction);
  assert.ok(consumeOffset < injectedOffset, "controller consume must precede receipt inspection");
  assert.ok(injectedOffset < fatalOffset, "fatal action must follow the injected receipt outcome");
  assert.doesNotMatch(
    body.slice(0, injectedOffset),
    fatalAction,
    "no fatal action may occur before the controller reports injected"
  );
});

test("expired qualification configuration is disabled before controller consumption", () => {
  const clean = withoutSwiftComments(serviceSource);
  const reach = swiftFunctionBodies(clean).find(({ body }) =>
    /\bcontroller\.consume\s*\(/u.test(body) && /\bexpiresAtEpochSeconds\b/u.test(body)
  );
  assert.ok(reach, "service adapter reach function must enforce configuration expiry");
  const expiryOffset = reach.body.search(/now\s*<\s*Double\(expiresAtEpochSeconds\)/u);
  const disableOffset = reach.body.search(/controller\.disable\(\)/u);
  const consumeOffset = reach.body.search(/controller\.consume\s*\(/u);
  assert.ok(expiryOffset >= 0 && expiryOffset < disableOffset);
  assert.ok(disableOffset < consumeOffset, "expired control must be disabled before consume");
});
