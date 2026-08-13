import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const QUALIFICATION = path.join(ROOT, "native/macos/Qualification");
const NATIVE_SOURCES = path.join(ROOT, "native/macos/Sources");

const paths = {
  negativeProbe: path.join(NATIVE_SOURCES, "AgentPassNegativeXPCProbe/main.swift"),
  qualificationProtocol: path.join(
    NATIVE_SOURCES,
    "AgentPassNativeCore/AgentQualificationXPCProtocol.swift",
  ),
  qualificationRequirement: path.join(
    NATIVE_SOURCES,
    "AgentPassNativeCore/NativeAgentQualificationCodeRequirement.swift",
  ),
  nativeService: path.join(NATIVE_SOURCES, "AgentPassNativeService/main.swift"),
  controllerInfo: path.join(
    ROOT,
    "native/macos/Resources/AgentPassQualificationController-Info.plist",
  ),
  controllerEntitlements: path.join(
    ROOT,
    "native/macos/Resources/AgentPassQualificationController.entitlements",
  ),
  buildApp: path.join(ROOT, "native/macos/scripts/build-app.sh"),
  buildInstaller: path.join(ROOT, "native/macos/scripts/build-installer.sh"),
  verifyInstaller: path.join(ROOT, "native/macos/scripts/verify-installer-package.sh"),
  bundleTest: path.join(ROOT, "native/macos/scripts/test-app-bundle.sh"),
};

function read(file, label = file) {
  assert.equal(fs.existsSync(file), true, `${label} must exist`);
  const stat = fs.lstatSync(file);
  assert.equal(stat.isFile(), true, `${label} must be a regular file`);
  assert.equal(stat.isSymbolicLink(), false, `${label} must not be a symlink`);
  return fs.readFileSync(file, "utf8");
}

function withoutComments(source) {
  return source
    .replace(/\/\*[\s\S]*?\*\//gu, "")
    .replace(/\/\/[^\n]*/gu, "");
}

function plistEntries(source, label) {
  assert.match(source, /<plist\b[\s\S]*<dict>/u, `${label} must be an XML plist`);
  const body = source.match(/<dict>([\s\S]*?)<\/dict>/u)?.[1];
  assert.ok(body, `${label} must contain a dictionary`);
  const entries = [];
  const entryPattern = /<key>\s*([^<]+?)\s*<\/key>\s*(?:<string>\s*([^<]*?)\s*<\/string>|<true\s*\/>)/gu;
  for (const match of body.matchAll(entryPattern)) {
    entries.push({ key: match[1], value: match[2] === undefined ? true : match[2] });
  }
  return entries;
}

function qualificationScripts() {
  return fs.readdirSync(QUALIFICATION, { withFileTypes: true })
    .filter((entry) => entry.isFile() && entry.name.endsWith(".sh"))
    .map((entry) => ({
      name: entry.name,
      path: path.join(QUALIFICATION, entry.name),
      source: withoutComments(read(path.join(QUALIFICATION, entry.name))),
    }));
}

function findControllerProbeMatrix() {
  const requiredRoleNames = ["approved", "missing-entitlement", "wrong-team"];
  const candidates = qualificationScripts().filter(({ source }) =>
    requiredRoleNames.every((role) => source.includes(role)) &&
    /ad-?hoc/u.test(source) &&
    source.includes("dev.agentpass.qualification-controller") &&
    source.includes("dev.agentpass.qualification-control"),
  );
  assert.ok(
    candidates.length > 0,
    "Qualification must contain a dedicated controller probe matrix with approved, missing-entitlement, wrong-team, and ad-hoc variants",
  );
  return candidates[0];
}

test("qualification negative probe has a fixed command and fixed qualification Mach service", () => {
  const probe = withoutComments(read(paths.negativeProbe, "AgentPassNegativeXPCProbe"));
  const protocol = withoutComments(read(paths.qualificationProtocol, "qualification XPC protocol"));

  assert.match(
    protocol,
    /public\s+static\s+let\s+machServiceName\s*=\s*"dev\.agentpass\.n3e-qualification"/u,
    "the qualification Mach service name must be a closed protocol constant",
  );
  assert.match(
    probe,
    /case\s+"qualification-controller"\s*:/u,
    "the negative probe must expose a dedicated fixed qualification-controller command",
  );
  assert.match(
    probe,
    /NSXPCConnection\s*\(\s*machServiceName:\s*AgentPassQualificationXPCContract\.machServiceName\s*,\s*options:\s*\.privileged/u,
    "the fixed qualification command must connect only to the protocol Mach service",
  );
  assert.match(probe, /readStatus|qualification-health/u, "the fixed probe must exercise an allowlisted qualification selector");

  const commandStart = probe.indexOf('case "qualification-controller"');
  const nextCase = probe.slice(commandStart).search(/\n\s*(?:case|default)\b/u);
  const commandBody = probe.slice(commandStart, nextCase < 0 ? undefined : commandStart + nextCase);
  assert.doesNotMatch(
    commandBody,
    /CommandLine\.arguments\[\d+\]|serviceName\s*:/u,
    "the fixed qualification command must not accept a caller-selected service or identity",
  );
});

test("controller identity and custom entitlement are closed and separate from AgentPass clients", () => {
  const requirement = withoutComments(read(paths.qualificationRequirement, "qualification controller code requirement"));
  const info = read(paths.controllerInfo, "qualification controller Info.plist");
  const entitlements = read(paths.controllerEntitlements, "qualification controller entitlements");

  assert.match(requirement, /controllerBundleID\s*=\s*"dev\.agentpass\.qualification-controller"/u);
  assert.match(requirement, /controllerEntitlement\s*=\s*"dev\.agentpass\.qualification-control"/u);

  const infoValues = new Map(plistEntries(info, "qualification controller Info.plist").map(({ key, value }) => [key, value]));
  assert.equal(infoValues.get("CFBundleIdentifier"), "dev.agentpass.qualification-controller");
  assert.equal(infoValues.get("CFBundleExecutable"), "agentpass-qualification-controller");

  const entitlementEntries = plistEntries(entitlements, "qualification controller entitlements");
  assert.deepEqual(
    entitlementEntries.map(({ key }) => key).sort(),
    ["application-identifier", "com.apple.developer.team-identifier", "dev.agentpass.qualification-control"],
    "the controller must have only its App ID, Team ID, and custom qualification entitlement",
  );
  const entitlementValues = new Map(entitlementEntries.map(({ key, value }) => [key, value]));
  assert.equal(entitlementValues.get("application-identifier"), "$(AppIdentifierPrefix)dev.agentpass.qualification-controller");
  assert.equal(entitlementValues.get("com.apple.developer.team-identifier"), "$(TeamIdentifier)");
  assert.equal(entitlementValues.get("dev.agentpass.qualification-control"), true);
  assert.doesNotMatch(entitlements, /keychain-access-groups|get-task-allow/u);
});

test("controller qualification signing has distinct approved, missing-entitlement, wrong-team, and ad-hoc variants", () => {
  const matrix = findControllerProbeMatrix();
  const source = matrix.source;

  assert.match(source, /codesign/u, `${matrix.name} must sign each probe bundle`);
  assert.match(source, /--entitlements/u, `${matrix.name} must make entitlement presence part of the matrix`);
  assert.match(source, /--sign\s+(?:["']?-|-["']?)/u, `${matrix.name} must include an explicit ad-hoc signature variant`);
  assert.match(source, /wrong[_-]?team|WRONG[_-]?TEAM/u, `${matrix.name} must bind the wrong-team variant to a distinct team identity`);
  assert.match(source, /missing[-_]entitlement[\s\S]{0,1200}(?:codesign|sign)/u, `${matrix.name} must build a missing-entitlement variant`);
  assert.match(source, /dev\.agentpass\.qualification-controller/u);
  assert.match(source, /dev\.agentpass\.qualification-control/u);
  assert.doesNotMatch(source, /keychain-access-groups/u, "controller probe variants must not gain client keychain groups");
});

test("non-root and second-controller connections are denied before qualification authority", () => {
  const controller = withoutComments(read(
    path.join(NATIVE_SOURCES, "AgentPassQualificationController/main.swift"),
    "qualification controller executable",
  ));
  const service = withoutComments(read(paths.nativeService, "native service"));
  const delegateStart = service.indexOf("private final class QualificationListenerDelegate");
  const runtimeStart = service.indexOf("private final class QualificationRuntime", delegateStart);
  assert.ok(delegateStart >= 0 && runtimeStart > delegateStart, "qualification listener delegate must remain identifiable");
  const delegate = service.slice(delegateStart, runtimeStart);

  assert.match(controller, /geteuid\(\)\s*==\s*0/u, "the external controller must require root");
  assert.match(controller, /rootRequired/u, "non-root controller failure must be explicit and bounded");
  assert.match(delegate, /connection\.effectiveUserIdentifier\s*==\s*0/u, "the qualification listener must accept only root peers");
  assert.match(delegate, /private\s+var\s+hasConnection\s*=\s*false/u);
  assert.match(delegate, /guard\s*!hasConnection\s+else\s*\{\s*return\s+false\s*\}/u, "the second controller connection must be rejected");
  assert.match(delegate, /hasConnection\s*=\s*true/u);
  assert.match(delegate, /endpoint\.invalidate\(\)/u);
  assert.match(delegate, /hasConnection\s*=\s*false/u, "the single-controller slot must be released only after invalidation");
});

test("the external controller is excluded from normal AgentPass.app and PKG assembly", () => {
  const controllerNames = /AgentPassQualificationController|agentpass-qualification-controller|dev\.agentpass\.qualification-controller/u;
  const buildApp = read(paths.buildApp, "normal AgentPass.app build script");
  const buildInstaller = read(paths.buildInstaller, "normal AgentPass.pkg build script");
  const verifyInstaller = read(paths.verifyInstaller, "normal AgentPass.pkg verifier");
  const bundleTest = read(paths.bundleTest, "normal AgentPass.app bundle test");

  assert.doesNotMatch(buildApp, controllerNames, "normal AgentPass.app assembly must not mention the qualification controller");
  assert.doesNotMatch(buildInstaller, controllerNames, "normal AgentPass.pkg assembly must not mention the qualification controller");
  assert.match(buildInstaller, /ditto\s+["']?\$APP["']?\s+["']?\$TEMP_DIR\/payload\/AgentPass\.app/u);
  assert.match(verifyInstaller, /AgentPass\.app\|AgentPass\.app\//u, "ordinary PKG verification must constrain payload paths to AgentPass.app");
  assert.doesNotMatch(verifyInstaller, controllerNames, "ordinary PKG verification must not whitelist the external controller");
  assert.match(bundleTest, /QualificationController|qualification-controller/u, "bundle tests must explicitly reject a bundled controller");
});
