import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const AUDIT = "native/macos/Sources/AgentPassNativeCore/NativeAudit.swift";
const QUALIFICATION = "native/macos/Sources/AgentPassNativeCore/NativeAgentSessionQualificationFaultConsumer.swift";
const AGENT_PROTOCOL = "native/macos/Sources/AgentPassNativeCore/AgentXPCProtocol.swift";
const SERVICE = "native/macos/Sources/AgentPassNativeService/main.swift";

const read = (relativePath) => fs.readFileSync(path.join(ROOT, relativePath), "utf8");

function withoutSwiftComments(source) {
  return source
    .replace(/\/\*[\s\S]*?\*\//gu, "")
    .replace(/\/\/[^\n]*/gu, "");
}

function matchingBrace(source, openIndex) {
  assert.equal(source[openIndex], "{", "expected a Swift opening brace");
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

function protocolBody(source, name) {
  const marker = `protocol ${name}`;
  return swiftBlock(source, marker).body;
}

const audit = withoutSwiftComments(read(AUDIT));
const qualification = withoutSwiftComments(read(QUALIFICATION));
const agentProtocol = withoutSwiftComments(read(AGENT_PROTOCOL));
const service = withoutSwiftComments(read(SERVICE));

test("NativeAuditLog has a separate injected durability consumer with a no-op default", () => {
  assert.match(
    audit,
    /public protocol NativeAuditDurabilityQualificationFaultConsuming\s*:\s*Sendable\s*\{[\s\S]*?func\s+reachBeforeAgentActivationFsync\(\)\s+throws/u,
  );
  assert.match(
    audit,
    /public struct NativeAuditDurabilityQualificationNoopFaultConsumer[\s\S]*?NativeAuditDurabilityQualificationFaultConsuming[\s\S]*?public init\(\)\s*\{\s*\}[\s\S]*?reachBeforeAgentActivationFsync\(\)\s+throws\s*\{\s*\}/u,
  );
  assert.match(audit, /private let durabilityQualificationFaultConsumer\s*:/u);
  assert.match(
    audit,
    /public init\([\s\S]*?durabilityQualificationFaultConsumer\s*:[\s\S]*?=\s*NativeAuditDurabilityQualificationNoopFaultConsumer\(\)/u,
  );
  assert.doesNotMatch(
    audit,
    /NativeAgentSessionTransportReplyFaultConsuming|transportReplyFaultConsumer|shouldDropEncodedResult/u,
    "the audit writer must not depend on the transport fault plane",
  );
});

test("audit durability injection is after the append write and immediately before fsync", () => {
  const durableAppendBlock = swiftBlock(audit, "private func durableAppend(");
  const durableAppend = durableAppendBlock.body;
  const durableAppendDeclaration = audit.slice(durableAppendBlock.start, durableAppendBlock.open + 1);
  const writeOffset = durableAppend.indexOf("Darwin.write");
  const chmodOffset = durableAppend.indexOf("fchmod(descriptor");
  const hookOffset = durableAppend.search(/try\s+beforeFsync\?\(\)/u);
  const fsyncOffset = durableAppend.indexOf("fsync(descriptor)");
  assert.ok(writeOffset >= 0, "durableAppend must write the record before its durability boundary");
  assert.ok(chmodOffset > writeOffset, "file mode must be applied after the write");
  assert.ok(hookOffset > chmodOffset, "the injected audit fault must run after write preparation");
  assert.ok(fsyncOffset > hookOffset, "the injected audit fault must run before fsync");
  assert.match(durableAppendDeclaration, /beforeFsync\s*:/u);
  assert.match(durableAppend, /try\s+beforeFsync\?\(\)/u);

  const append = swiftBlock(audit, "public func append(").body;
  const exactOperationChecks = [
    ...append.matchAll(/event\.operation\s*==\s*"agent\.session\.session_activated"/gu),
  ];
  assert.equal(
    exactOperationChecks.length,
    2,
    "both the normal append and rotate-then-append paths must use the exact activation operation",
  );
  assert.equal(
    [...append.matchAll(/durabilityQualificationFaultConsumer\.reachBeforeAgentActivationFsync\(\)/gu)].length,
    2,
    "each durable append path must use the injected writer consumer",
  );
  assert.doesNotMatch(
    append,
    /event\.operation\s*\.\s*(?:hasPrefix|contains|starts|localizedCaseInsensitiveCompare)/u,
    "nearby audit operations must not trigger the activation-only hook",
  );
});

test("transport fault control is a distinct no-op dependency", () => {
  const transportProtocol = protocolBody(
    qualification,
    "NativeAgentSessionTransportReplyFaultConsuming",
  );
  assert.match(transportProtocol, /func\s+shouldDropEncodedResult\(\)\s*->\s*Bool/u);
  assert.match(
    qualification,
    /public struct NativeAgentSessionTransportReplyNoopFaultConsumer[\s\S]*?NativeAgentSessionTransportReplyFaultConsuming[\s\S]*?public init\(\)\s*\{\s*\}[\s\S]*?func\s+shouldDropEncodedResult\(\)\s*->\s*Bool\s*\{\s*false\s*\}/u,
  );

  const endpoint = swiftBlock(
    service,
    "private final class AgentConnectionEndpoint:",
  ).body;
  assert.match(
    endpoint,
    /private let transportReplyFaultConsumer\s*:\s*any\s+NativeAgentSessionTransportReplyFaultConsuming/u,
  );
  assert.match(
    endpoint,
    /transportReplyFaultConsumer\s*:\s*any\s+NativeAgentSessionTransportReplyFaultConsuming/u,
  );
  assert.match(endpoint, /self\.transportReplyFaultConsumer\s*=\s*transportReplyFaultConsumer/u);
});

test("transport loss is consumed after successful response encoding and drops only the reply", () => {
  const start = swiftBlock(service, "func startAgentSession(").body;
  const responseOffset = start.indexOf("guard let response = AgentPassAgentSessionResponse(");
  const consumeOffset = start.indexOf("transportReplyFaultConsumer.shouldDropEncodedResult()", responseOffset);
  const replyOffset = start.indexOf("replyBox.call(response, nil)", consumeOffset);
  assert.ok(responseOffset >= 0, "startAgentSession must construct the response DTO");
  assert.ok(consumeOffset > responseOffset, "transport loss must be checked after response encoding");
  assert.ok(replyOffset > consumeOffset, "the normal reply must follow the transport disposition");

  const dropGuardOffset = start.lastIndexOf("guard", consumeOffset);
  const disposition = start.slice(dropGuardOffset, replyOffset);
  assert.match(
    disposition,
    /guard\s+!(?:self\.)?transportReplyFaultConsumer\.shouldDropEncodedResult\(\)\s+else\s*\{\s*return\s*\}/u,
    "an injected transport loss must return without invoking the XPC reply closure",
  );
  assert.doesNotMatch(
    disposition,
    /abortActivation\s*\(/u,
    "transport reply loss must preserve the already-active authority",
  );
  assert.doesNotMatch(
    start.slice(consumeOffset),
    /coordinator\.abortActivation\s*\(/u,
    "no transport-loss path may revoke the activation after response encoding",
  );
});

test("audit and transport adapters are exact, independently bound controller consumers", () => {
  const auditAdapterBlock = swiftBlock(
    service,
    "private final class NativeAgentAuditDurabilityQualificationFaultConsumerAdapter:",
  );
  const transportAdapterBlock = swiftBlock(
    service,
    "private final class NativeAgentTransportReplyQualificationFaultConsumerAdapter:",
  );
  const auditAdapter = service.slice(auditAdapterBlock.start, auditAdapterBlock.close);
  const transportAdapter = service.slice(transportAdapterBlock.start, transportAdapterBlock.close);

  assert.match(auditAdapter, /NativeAuditDurabilityQualificationFaultConsuming/u);
  assert.match(auditAdapter, /values\.scenario\s*==\s*\.auditFsyncFailure\s*&&\s*values\.phase\s*==\s*\.auditFsync/u);
  assert.match(auditAdapter, /NativeAgentQualificationFaultController/u);
  assert.match(auditAdapter, /NativeAgentQualificationRunBinding\(values\.runBindingDigest\)/u);
  assert.match(auditAdapter, /expiresAtEpochSeconds/u);
  assert.match(auditAdapter, /now\s*<\s*Double\(expiresAtEpochSeconds\)/u);
  assert.match(auditAdapter, /controller\.consume\(/u);
  assert.match(auditAdapter, /runBinding:\s*runBinding/u);
  assert.match(auditAdapter, /scenario:\s*\.auditFsyncFailure/u);
  assert.match(auditAdapter, /phase:\s*\.auditFsync/u);
  assert.match(auditAdapter, /receipt\.outcome\s*==\s*\.injected/u);
  assert.doesNotMatch(auditAdapter, /transportReplyLoss|\.transportReply\b/u);

  assert.match(transportAdapter, /NativeAgentSessionTransportReplyFaultConsuming/u);
  assert.match(transportAdapter, /values\.scenario\s*==\s*\.transportReplyLoss\s*&&\s*values\.phase\s*==\s*\.transportReply/u);
  assert.match(transportAdapter, /NativeAgentQualificationFaultController/u);
  assert.match(transportAdapter, /NativeAgentQualificationRunBinding\(values\.runBindingDigest\)/u);
  assert.match(transportAdapter, /expiresAtEpochSeconds/u);
  assert.match(transportAdapter, /now\s*<\s*Double\(expiresAtEpochSeconds\)/u);
  assert.match(transportAdapter, /controller\.consume\(/u);
  assert.match(transportAdapter, /runBinding:\s*runBinding/u);
  assert.match(transportAdapter, /scenario:\s*\.transportReplyLoss/u);
  assert.match(transportAdapter, /phase:\s*\.transportReply/u);
  assert.match(transportAdapter, /receipt\.outcome\s*==\s*\.injected/u);
  assert.doesNotMatch(transportAdapter, /auditFsyncFailure|\.auditFsync\b/u);
});

test("qualification-only consumers are wired separately and disabled mode injects both no-ops", () => {
  const runtime = swiftBlock(service, "private final class QualificationRuntime").body;
  assert.match(
    runtime,
    /auditDurabilityFaultConsumer\s*:\s*any\s+NativeAuditDurabilityQualificationFaultConsuming/u,
  );
  assert.match(
    runtime,
    /transportReplyFaultConsumer\s*:\s*any\s+NativeAgentSessionTransportReplyFaultConsuming/u,
  );
  assert.match(runtime, /NativeAgentAuditDurabilityQualificationFaultConsumerAdapter/u);
  assert.match(runtime, /NativeAgentTransportReplyQualificationFaultConsumerAdapter/u);

  const disabled = service.slice(service.indexOf("case .disabled:"), service.indexOf("case .configured(", service.indexOf("case .disabled:")));
  assert.match(disabled, /auditDurabilityFaultConsumer\s*=\s*NativeAuditDurabilityQualificationNoopFaultConsumer\(\)/u);
  assert.match(disabled, /transportReplyFaultConsumer\s*=\s*NativeAgentSessionTransportReplyNoopFaultConsumer\(\)/u);
  assert.match(
    service,
    /NativeAuditLog\([\s\S]*?durabilityQualificationFaultConsumer:\s*auditDurabilityFaultConsumer/u,
  );
  assert.match(
    service,
    /AgentListenerDelegate\([\s\S]*?transportReplyFaultConsumer:\s*transportReplyFaultConsumer/u,
  );
});

test("production Agent DTOs and selectors contain no audit/transport qualification controls", () => {
  const agentProtocolBody = protocolBody(agentProtocol, "AgentPassAgentXPCProtocol");
  const controlField = /\b(?:qualification|fault|scenario|phase|auditFsync|transportReply)\b/iu;
  assert.doesNotMatch(agentProtocolBody, controlField);
  assert.doesNotMatch(agentProtocol, controlField);
  assert.match(agentProtocol, /@objc\(AgentPassAgentSessionRequest\)/u);
  assert.match(agentProtocol, /@objc\(AgentPassAgentSessionResponse\)/u);
  assert.match(agentProtocol, /func\s+startAgentSession\([^\n]*withReply/u);
  assert.doesNotMatch(
    agentProtocolBody,
    /(?:armFault|readStatus|disarmFault|shouldDropEncodedResult|reachBeforeAgentActivationFsync)/u,
  );
});
