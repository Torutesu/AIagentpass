import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../..");
const contract = JSON.parse(fs.readFileSync(path.join(ROOT, "native/macos/Qualification/native-xpc-contract-v1.json"), "utf8"));
const swift = fs.readFileSync(path.join(ROOT, "native/macos/Sources/AgentPassNativeCore/NativeXPCContract.swift"), "utf8");
const protocol = fs.readFileSync(path.join(ROOT, "native/macos/Sources/AgentPassNativeCore/AgentHostXPCProtocol.swift"), "utf8");
const service = fs.readFileSync(path.join(ROOT, "native/macos/Sources/AgentPassNativeService/main.swift"), "utf8");
const client = fs.readFileSync(path.join(ROOT, "native/macos/Sources/AgentPassNativeClient/main.swift"), "utf8");
const broker = fs.readFileSync(path.join(ROOT, "lib/broker-client.mjs"), "utf8");
const cli = fs.readFileSync(path.join(ROOT, "bin/agentpass.mjs"), "utf8");
const qualificationVerifier = fs.readFileSync(path.join(ROOT, "scripts/release/xpc/verify-xpc-qualification.mjs"), "utf8");

test("Native XPC provenance contract is bound to the frozen Swift fingerprint and all fixed Mach services", () => {
  assert.equal(contract.contract_identifier, "dev.agentpass.native-xpc");
  assert.equal(contract.swift_contract_version, 3);
  assert.match(swift, new RegExp(`contractVersion = ${contract.swift_contract_version}\\b`, "u"));
  assert.match(swift, new RegExp(`frozenFingerprint = "${contract.swift_fingerprint.replace(/[.*+?^${}()|[\\]\\\\]/g, "\\\\$&")}"`, "u"));
  for (const serviceName of Object.values(contract.mach_services)) assert.ok(protocol.includes(`"${serviceName}"`) || service.includes(`"${serviceName}"`) || client.includes(`"${serviceName}"`), serviceName);
});

test("Host-control provenance freezes the separate control selector, DTOs, principal, and CLI route", () => {
  assert.equal(contract.host_control.protocol, "AgentPassHostControlXPCProtocol");
  for (const selector of contract.host_control.selectors) assert.match(swift, new RegExp(selector.replace(/[.*+?^${}()|[\\]\\\\]/g, "\\\\$&"), "u"));
  for (const typeName of [...contract.host_control.request_classes, ...contract.host_control.response_classes]) assert.match(protocol, new RegExp(typeName, "u"));
  assert.match(service, /authorizedControlBundleIdentifier: NativeClientCodeRequirement\.clientBundleID/u);
  assert.match(client, /host-control-close/u);
  assert.match(broker, /native\.host\.close.*host-control-close/u);
  assert.match(cli, /agentpass close|close --session-id/u);
});

test("Provenance source references exist and contract remains closed", () => {
  assert.deepEqual(Object.keys(contract).sort(), ["$id", "$schema", "contract_identifier", "contract_version", "host_control", "mach_services", "source_refs", "swift_contract_version", "swift_fingerprint"].sort());
  for (const sourceRef of contract.source_refs) assert.equal(fs.existsSync(path.join(ROOT, sourceRef)), true, sourceRef);
});

test("The dedicated qualification verifier keeps the production boundary fail-closed", () => {
  for (const required of [
    "candidate_sha256", "source_tree", "artifact_sha256", "run_attempt", "job_id",
    "protected_macos", "kernel_live_audit_token_t", "launchd_mach_nsxpc",
    "dev.agentpass.agent-host", "dev.agentpass.child-git", "denied_before_sign",
    "same_uid_wrong_child", "wrong_team", "wrong_entitlement", "stale_or_reused_audit_token",
    "not_proven", "real_execution"
  ]) assert.match(qualificationVerifier, new RegExp(required.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"), "u"), required);
  assert.doesNotMatch(qualificationVerifier, /promotion-qualified-release|promote-qualified-release/u);
});
