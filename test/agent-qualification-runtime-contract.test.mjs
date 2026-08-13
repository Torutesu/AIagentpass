import assert from "node:assert/strict";
import fs from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

const ROOT = join(fileURLToPath(new URL("..", import.meta.url)));
const read = (relativePath) => fs.readFileSync(join(ROOT, relativePath), "utf8");

const AGENT_PROTOCOL = "native/macos/Sources/AgentPassNativeCore/AgentXPCProtocol.swift";
const QUALIFICATION_PROTOCOL = "native/macos/Sources/AgentPassNativeCore/AgentQualificationXPCProtocol.swift";
const CONTROLLER = "native/macos/Sources/AgentPassNativeCore/NativeAgentQualificationFaultController.swift";
const CONFIGURATION = "native/macos/Sources/AgentPassNativeCore/NativeAgentQualificationConfiguration.swift";
const REQUIREMENT = "native/macos/Sources/AgentPassNativeCore/NativeAgentQualificationCodeRequirement.swift";
const SERVICE = "native/macos/Sources/AgentPassNativeService/main.swift";
const BUILD = "native/macos/scripts/build-app.sh";
const LAUNCHD = "native/macos/Resources/dev.agentpass.native-service.plist";
const EXAMPLE_CONFIG = "native/macos/Resources/native-service.example.json";
const PACKAGE = "native/macos/Package.swift";
const VERIFIER = "scripts/release/n3e/verify-n3e-evidence.mjs";
const SCHEMA = "scripts/release/n3e/n3e-evidence.schema.json";

const INVENTORY = Object.freeze([
  Object.freeze({ scenario: "pre-cloud-kill", phase: "pre-cloud", swiftCase: "preCloudKill", swiftPhase: "preCloud" }),
  Object.freeze({ scenario: "post-cloud-pre-local-kill", phase: "post-cloud-pre-local", swiftCase: "postCloudPreLocalKill", swiftPhase: "postCloudPreLocal" }),
  Object.freeze({ scenario: "post-activation-pre-audit-kill", phase: "post-activation-pre-audit", swiftCase: "postActivationPreAuditKill", swiftPhase: "postActivationPreAudit" }),
  Object.freeze({ scenario: "post-audit-pre-reply-loss", phase: "post-audit-pre-reply", swiftCase: "postAuditPreReplyLoss", swiftPhase: "postAuditPreReply" }),
  Object.freeze({ scenario: "audit-fsync-failure", phase: "audit-fsync", swiftCase: "auditFsyncFailure", swiftPhase: "auditFsync" }),
  Object.freeze({ scenario: "transport-reply-loss", phase: "transport-reply", swiftCase: "transportReplyLoss", swiftPhase: "transportReply" }),
]);

const SCENARIOS = INVENTORY.map(({ scenario }) => scenario);
const PHASES = INVENTORY.map(({ phase }) => phase);

const swiftEnumBody = (source, declaration) => {
  const declarationStart = source.indexOf(declaration);
  assert.notEqual(declarationStart, -1, `${declaration} must exist`);
  const open = source.indexOf("{", declarationStart);
  assert.notEqual(open, -1, `${declaration} must have a body`);
  let depth = 0;
  let inString = false;
  let escaped = false;
  for (let index = open; index < source.length; index += 1) {
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
      if (depth === 0) return source.slice(open + 1, index);
    }
  }
  assert.fail(`${declaration} has an unterminated body`);
};

const swiftEnumValues = (body) => [...body.matchAll(/^\s*case\s+(\w+)\s*=\s*"([^"]+)"/gmu)].map(([, name, value]) => ({ name, value }));

const protocolBody = (source, protocolName) => {
  const marker = `@objc public protocol ${protocolName}`;
  const start = source.indexOf(marker);
  assert.notEqual(start, -1, `${protocolName} must exist`);
  const open = source.indexOf("{", start);
  const close = source.indexOf("\n}", open);
  assert.notEqual(open, -1, `${protocolName} must have a body`);
  assert.notEqual(close, -1, `${protocolName} must have a closing brace`);
  return source.slice(open + 1, close);
};

const selectorNames = (body) => [...body.matchAll(/\bfunc\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(/gu)].map(([, name]) => name);

const quotedArray = (source, declaration) => {
  const match = source.match(new RegExp(`${declaration}\\s*=\\s*Object\\.freeze\\(\\s*\\[([\\s\\S]*?)\\]\\s*\\)`, "u"));
  assert.ok(match, `${declaration} must be a closed array`);
  return [...match[1].matchAll(/["']([^"']+)["']/gu)].map(([, value]) => value);
};

const inventoryObjectKeys = (source, declaration) => {
  const start = source.indexOf(declaration);
  assert.notEqual(start, -1, `${declaration} must exist`);
  const body = source.slice(start, source.indexOf("\n});", start));
  return [...body.matchAll(/^\s*['"]([^'"]+)['"]\s*:\s*Object\.freeze\(/gmu)].map(([, key]) => key);
};

test("Agent XPC selectors are disjoint from qualification control selectors", () => {
  const agentSource = read(AGENT_PROTOCOL);
  const qualificationSource = read(QUALIFICATION_PROTOCOL);
  const agentSelectors = selectorNames(protocolBody(agentSource, "AgentPassAgentXPCProtocol"));
  const qualificationSelectors = selectorNames(protocolBody(qualificationSource, "AgentPassQualificationXPCProtocol"));

  assert.equal(new Set(agentSelectors).size, agentSelectors.length, "Agent selectors must not be duplicated");
  assert.equal(new Set(qualificationSelectors).size, qualificationSelectors.length, "qualification selectors must not be duplicated");
  assert.deepEqual(
    agentSelectors.filter((selector) => qualificationSelectors.includes(selector)),
    [],
    "production Agent XPC must not expose qualification selectors",
  );
  assert.doesNotMatch(protocolBody(agentSource, "AgentPassAgentXPCProtocol"), /qualification|armFault|readStatus|disarmFault/iu);
  assert.doesNotMatch(agentSource, /AgentPassQualificationXPCProtocol|dev\.agentpass\.n3e-qualification|qualification-control/u);
});

test("qualification XPC has exactly three selectors and a closed phase enum", () => {
  const source = read(QUALIFICATION_PROTOCOL);
  const selectors = selectorNames(protocolBody(source, "AgentPassQualificationXPCProtocol"));
  assert.deepEqual(selectors, ["armFault", "readStatus", "disarmFault"]);

  const registeredSelectors = [...source.matchAll(/#selector\(AgentPassQualificationXPCProtocol\.([A-Za-z_][A-Za-z0-9_]*)\(/gu)].map(([, selector]) => selector);
  assert.equal(registeredSelectors.length, 6, "each of the three selectors must register an argument and reply class");
  assert.deepEqual([...new Set(registeredSelectors)], selectors);
  for (const selector of selectors) assert.equal(registeredSelectors.filter((item) => item === selector).length, 2);

  const phaseValues = swiftEnumValues(swiftEnumBody(source, "public enum FaultPhase"));
  assert.deepEqual(phaseValues.map(({ value }) => value), PHASES);
  assert.equal(new Set(phaseValues.map(({ value }) => value)).size, 6);
  assert.match(source, /machServiceName\s*=\s*"dev\.agentpass\.n3e-qualification"/u);
});

test("the six scenario/phase pairs agree across Swift, XPC, and N3-E evidence", () => {
  const controller = read(CONTROLLER);
  const xpc = read(QUALIFICATION_PROTOCOL);
  const verifier = read(VERIFIER);
  const schema = JSON.parse(read(SCHEMA));

  const controllerPhases = swiftEnumValues(swiftEnumBody(controller, "public enum NativeAgentQualificationFaultPhase"));
  assert.deepEqual(controllerPhases.map(({ value }) => value), PHASES);

  const scenarioBody = swiftEnumBody(controller, "public enum NativeAgentQualificationFaultScenario");
  const controllerScenarios = swiftEnumValues(scenarioBody);
  assert.deepEqual(controllerScenarios.map(({ value }) => value), SCENARIOS);

  const mappingBody = controller.match(/public var phase: NativeAgentQualificationFaultPhase\s*\{([\s\S]*?)\n  \}\n\}/u)?.[1] ?? "";
  assert.notEqual(mappingBody, "", "Swift scenarios must map to phases explicitly");
  const mappings = [...mappingBody.matchAll(/case\s+\.(\w+)\s*:\s*\.(\w+)/gu)].map(([, swiftCase, swiftPhase]) => ({ swiftCase, swiftPhase }));
  assert.deepEqual(mappings, INVENTORY.map(({ swiftCase, swiftPhase }) => ({ swiftCase, swiftPhase })));

  const xpcPhases = swiftEnumValues(swiftEnumBody(xpc, "public enum FaultPhase"));
  assert.deepEqual(xpcPhases.map(({ value }) => value), PHASES);

  assert.deepEqual(quotedArray(verifier, "export const REQUIRED_SCENARIOS"), SCENARIOS);
  assert.deepEqual(inventoryObjectKeys(verifier, "const SCENARIO_EVENT_INVENTORY"), SCENARIOS);
  assert.deepEqual(inventoryObjectKeys(verifier, "const SCENARIO_DIGEST_INVENTORY"), SCENARIOS);
  assert.deepEqual(schema.$defs.scenario.properties.name.enum, SCENARIOS);

  for (const { scenario } of INVENTORY) {
    assert.match(verifier, new RegExp(`value\\.name === ['"]${scenario}['"]`, "u"), `${scenario} must have verifier logic`);
  }
});

test("the normal AgentPass app does not bundle an external qualification controller", () => {
  const build = read(BUILD);
  const packageSource = read(PACKAGE);
  const resourceNames = fs.readdirSync(join(ROOT, "native/macos/Resources"));

  assert.doesNotMatch(build, /qualification-controller|AgentPassQualification|NativeAgentQualification/u);
  assert.doesNotMatch(packageSource, /qualification-controller|AgentPassQualificationController/u);
  assert.deepEqual(resourceNames.filter((name) => /qualification-controller/iu.test(name)), []);

  const plist = read(LAUNCHD);
  const machServices = plist.match(/<key>MachServices<\/key><dict>([\s\S]*?)<\/dict>/u)?.[1] ?? "";
  assert.deepEqual([...machServices.matchAll(/<key>([^<]+)<\/key><true\s*\/>/gu)].map(([, name]) => name), [
    "dev.agentpass.native-service",
    "dev.agentpass.agent-session",
    "dev.agentpass.n3e-qualification",
  ]);

  const signedIdentifiers = [...build.matchAll(/sign_item\s+"[^"]+"\s+"([^"]+)"/gu)].map(([, identifier]) => identifier);
  assert.equal(signedIdentifiers.includes("dev.agentpass.qualification-controller"), false);
  assert.equal(signedIdentifiers.includes("dev.agentpass.agent-host"), true);
  assert.equal(signedIdentifiers.includes("dev.agentpass.native-service"), true);
});

test("root-owned service configuration is the only future qualification enablement boundary", () => {
  const service = read(SERVICE);
  const configuration = read(CONFIGURATION);
  const plist = read(LAUNCHD);
  const example = JSON.parse(read(EXAMPLE_CONFIG));

  for (const [swiftName, jsonName] of [
    ["qualificationMode", "qualification_mode"],
    ["qualificationMachServiceName", "qualification_mach_service_name"],
    ["qualificationCandidateSHA256", "qualification_candidate_sha256"],
    ["qualificationSourceCommitSHA256", "qualification_source_commit_sha256"],
    ["qualificationCodeIdentitiesSHA256", "qualification_code_identities_sha256"],
    ["qualificationRunIDSHA256", "qualification_run_id_sha256"],
    ["qualificationExpiresAtEpochSeconds", "qualification_expires_at_epoch_seconds"],
    ["qualificationScenario", "qualification_scenario"],
    ["qualificationPhase", "qualification_phase"],
  ]) {
    assert.match(service, new RegExp(`let ${swiftName}:`, "u"));
    assert.match(service, new RegExp(`case ${swiftName} = "${jsonName}"`, "u"));
  }
  assert.match(configuration, /supplied\.allSatisfy\(\{ \$0 \}\)/u);
  assert.match(configuration, /modeMarker\s*=\s*NativeAgentQualificationMode\.qualification\.rawValue/u);
  assert.match(configuration, /NativeAgentQualificationCodeRequirement\.requirement/u);
  assert.doesNotMatch(configuration, /ProcessInfo\.processInfo\.environment|CommandLine\.arguments/iu);

  assert.match(service, /let data = try loadProtectedFile\(path: path, label: "Native service configuration"\)/u);
  assert.match(service, /owner == 0, permissions & 0o022 == 0/u);
  assert.match(service, /Darwin\.open\(path, O_RDONLY \| O_NOFOLLOW \| O_CLOEXEC\)/u);
  assert.match(service, /\(before\.st_mode & 0o7777\) == 0o600/u);
  assert.match(service, /before\.st_nlink == 1/u);
  assert.match(service, /after\.st_ino == pathState\.st_ino/u);
  assert.match(service, /bytes == expectedData/u);
  assert.match(service, /Set\(object\.keys\)\.isSubset\(of: Set\(CodingKeys\.allCases\.map/u);
  assert.match(service, /guard CommandLine\.arguments\.count == 3, CommandLine\.arguments\[1\] == "--config"/u);

  assert.doesNotMatch(service, /ProcessInfo\.processInfo\.environment|AGENTPASS_[A-Z0-9_]*(?:N3E|QUALIFICATION)|(?:N3E|QUALIFICATION)[A-Z0-9_]*_AGENTPASS/iu);
  assert.match(service, /switch try configuration\.qualificationConfiguration\(\)\.state/u);
  assert.match(service, /case \.disabled:\s*qualificationRuntime = nil/u);
  assert.match(service, /case \.configured\(let values\):\s*qualificationRuntime = try QualificationRuntime/u);
  assert.match(service, /connection\.effectiveUserIdentifier == 0/u);
  assert.match(service, /connection\.setCodeSigningRequirement\(designatedRequirement\)/u);
  assert.match(service, /connection\.exportedInterface = AgentPassQualificationXPCInterface\.make\(\)/u);
  assert.doesNotMatch(service, /CommandLine\.arguments\[[^\]]+\]\s*==\s*"--(?:n3e|qualification|arm-fault|fault-injection)"/iu);

  const argumentsBlock = plist.match(/<key>ProgramArguments<\/key><array>([\s\S]*?)<\/array>/u)?.[1] ?? "";
  assert.deepEqual([...argumentsBlock.matchAll(/<string>([^<]*)<\/string>/gu)].map(([, value]) => value), [
    "agentpass-native-service",
    "--config",
    "/Library/Application Support/AgentPass/native-service.json",
  ]);
  assert.equal(Object.keys(example).some((key) => /qualification|n3e|fault/iu.test(key)), false);
});

test("qualification controller uses a distinct bundle, entitlement, and Developer ID Team binding", () => {
  const source = read(REQUIREMENT);
  const bundleID = source.match(/controllerBundleID\s*=\s*"([^"]+)"/u)?.[1];
  const entitlement = source.match(/controllerEntitlement\s*=\s*"([^"]+)"/u)?.[1];
  assert.equal(bundleID, "dev.agentpass.qualification-controller");
  assert.equal(entitlement, "dev.agentpass.qualification-control");
  assert.notEqual(bundleID, "dev.agentpass.native-client");
  assert.notEqual(bundleID, "dev.agentpass.agent-host");
  assert.notEqual(entitlement, "dev.agentpass.agent-session-client");

  assert.match(source, /anchor apple generic/u);
  assert.match(source, /identifier.*controllerBundleID/u);
  assert.match(source, /certificate leaf\[field\.1\.2\.840\.113635\.100\.6\.1\.13\] exists/u);
  assert.match(source, /certificate leaf\[subject\.OU\].*teamID/u);
  assert.match(source, /entitlement\[.*controllerEntitlement.*\] = true/u);
  assert.match(source, /NativeClientCodeRequirement\.teamID/u);
  assert.doesNotMatch(source, /\*|path\s*=/u);
});
