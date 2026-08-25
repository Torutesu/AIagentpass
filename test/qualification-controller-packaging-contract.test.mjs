import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const PACKAGE = path.join(ROOT, "native/macos/Package.swift");
const CONTROLLER_SOURCE = path.join(
  ROOT,
  "native/macos/Sources/AgentPassQualificationController/main.swift",
);
const CONTROLLER_CONTRACT = path.join(
  ROOT,
  "native/macos/Sources/AgentPassNativeCore/NativeAgentQualificationControllerManifest.swift",
);
const BUILD_APP = path.join(ROOT, "native/macos/scripts/build-app.sh");
const BUILD_INSTALLER = path.join(ROOT, "native/macos/scripts/build-installer.sh");
const VERIFY_INSTALLER = path.join(ROOT, "native/macos/scripts/verify-installer-package.sh");

const read = (file) => fs.readFileSync(file, "utf8");

function readControllerSource() {
  assert.equal(
    fs.existsSync(CONTROLLER_SOURCE),
    true,
    "the dedicated executable target must have a controller entrypoint",
  );
  return read(CONTROLLER_SOURCE);
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

function commandEnumBody(source) {
  const declaration = source.match(
    /\b(?:private\s+|internal\s+|public\s+|fileprivate\s+)?enum\s+([A-Za-z_][A-Za-z0-9_]*Command)\b[^\{]*\{/u,
  );
  assert.ok(declaration, "controller must define a typed command enum");
  const openIndex = declaration.index + declaration[0].length - 1;
  return source.slice(openIndex + 1, matchingBrace(source, openIndex));
}

test("N3-E2b-1a declares a dedicated external controller executable target", () => {
  const packageSource = read(PACKAGE);
  assert.match(
    packageSource,
    /\.executable\(\s*name:\s*"agentpass-qualification-controller"\s*,\s*targets:\s*\[\s*"AgentPassQualificationController"\s*\]\s*\)/u,
    "the qualification controller must be a separately named executable product",
  );
  assert.match(
    packageSource,
    /\.executableTarget\(\s*name:\s*"AgentPassQualificationController"/u,
    "the qualification controller must have its own executable target",
  );
  readControllerSource();
});

test("N3-E2b-1a keeps the controller out of the app and ordinary product PKG", () => {
  const buildApp = read(BUILD_APP);
  const buildInstaller = read(BUILD_INSTALLER);
  const verifyInstaller = read(VERIFY_INSTALLER);
  const controllerNames = /AgentPassQualificationController|agentpass-qualification-controller/gu;

  assert.doesNotMatch(
    buildApp,
    controllerNames,
    "the normal AgentPass.app build must not install or sign the controller",
  );
  assert.doesNotMatch(
    buildInstaller,
    controllerNames,
    "the ordinary product PKG build must not add the controller",
  );
  assert.match(
    buildInstaller,
    /ditto\s+"\$APP"\s+"\$TEMP_DIR\/payload\/AgentPass\.app"/u,
    "the ordinary product PKG payload must be copied only from AgentPass.app",
  );
  assert.match(
    verifyInstaller,
    /AgentPass\.app\|AgentPass\.app\/\*/u,
    "ordinary product PKG verification must constrain payload paths to AgentPass.app",
  );
  assert.doesNotMatch(
    verifyInstaller,
    controllerNames,
    "ordinary product PKG verification must not whitelist the controller as product content",
  );
});

test("N3-E2b-1a exposes exactly arm, status, and disarm command words", () => {
  const source = withoutSwiftComments(`${read(CONTROLLER_CONTRACT)}\n${readControllerSource()}`);
  const commandBody = commandEnumBody(source);
  const commandCases = [...commandBody.matchAll(/^\s*case\s+([^\n]+)$/gmu)]
    .flatMap(([, declaration]) => declaration.split(","))
    .map((declaration) => declaration.trim().split(/\s|=/u)[0])
    .filter(Boolean)
    .sort();

  assert.deepEqual(commandCases, ["arm", "disarm", "status"]);
  assert.match(source, /(?:switch\s+|Command\s*\(rawValue:)[\s\S]*?(?:\.arm|arm)/u);
  assert.match(source, /(?:switch\s+|Command\s*\(rawValue:)[\s\S]*?(?:\.status|status)/u);
  assert.match(source, /(?:switch\s+|Command\s*\(rawValue:)[\s\S]*?(?:\.disarm|disarm)/u);
  assert.match(
    source,
    /(?:default\s*:\s*(?:throw|return)|guard[\s\S]*?else\s*\{[\s\S]*?(?:throw|return))/u,
    "unknown command words must be rejected by the parser",
  );
});

test("N3-E2b-1a derives identity from protected inputs instead of CLI options", () => {
  const source = withoutSwiftComments(readControllerSource());
  const dynamicIdentityOptions = [
    "mach-service",
    "service",
    "selector",
    "scenario",
    "phase",
    "team",
    "team-id",
    "run",
    "run-id",
    "candidate",
    "candidate-id",
    "candidate-sha256",
  ];

  for (const option of dynamicIdentityOptions) {
    assert.doesNotMatch(
      source,
      new RegExp(`(["'])--${option}(?:[=_\\s"'])`, "u"),
      `controller must not expose --${option} as a caller-controlled option`,
    );
  }
  assert.match(source, /CommandLine\.arguments/u, "the controller must have an explicit command-line boundary");
  assert.match(
    source,
    /(?:root|protected|configuration|manifest)/iu,
    "controller identity must be derived from protected configuration and the signed candidate manifest",
  );
  assert.match(source, /(?:candidate|release)[^\n]{0,80}manifest|manifest[^\n]{0,80}(?:candidate|release)/iu);
});

test("N3-E2b-1a keeps an armed fault bound to one live XPC connection", () => {
  const source = withoutSwiftComments(readControllerSource());
  assert.equal(
    [...source.matchAll(/let\s+client\s*=\s*QualificationClient\(\)/gu)].length,
    1,
    "one controller invocation must create exactly one connection owner",
  );
  const armStart = source.indexOf("case .arm:");
  const statusStart = source.indexOf("case .status:", armStart);
  assert.ok(armStart >= 0 && statusStart > armStart, "arm command block is missing");
  const arm = source.slice(armStart, statusStart);
  assert.match(arm, /writeOutput\(armedOutput\)[\s\S]*while\s+Date\(\)/u);
  assert.match(arm, /client\.status\(statusRequest\)/u);
  assert.match(arm, /finishAfterFired\(client:\s*client/u);
  assert.match(source, /func\s+finishAfterFired\([\s\S]*client\.disarm\(disarmRequest\)/u);
  assert.doesNotMatch(arm, /QualificationClient\(\)/u);
});

test("N3-E2b-1a never persists or accepts a raw qualification run ID", () => {
  const contract = withoutSwiftComments(read(CONTROLLER_CONTRACT));
  const source = withoutSwiftComments(readControllerSource());
  assert.match(contract, /"run_id_sha256"/u);
  assert.doesNotMatch(contract, /run_id_base64/u);
  assert.doesNotMatch(source, /standardInput|readDataToEndOfFile/u);
  assert.match(source, /candidateManifestPath\s*=\s*"\/private\/var\/db\/agentpass-qualification\/controller\/controller-candidate\.json"/u);
  assert.match(source, /candidatePublicKeyPath\s*=\s*"\/private\/var\/db\/agentpass-qualification\/controller\/release-public\.pem"/u);
});
