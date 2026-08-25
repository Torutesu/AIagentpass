import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const ENTITLEMENTS = path.join(
  ROOT,
  "native/macos/Resources/AgentPassQualificationController.entitlements",
);
const SIGN_SCRIPT = path.join(
  ROOT,
  "native/macos/Qualification/build-controller.sh",
);

const readRequired = (file, description) => {
  assert.equal(fs.existsSync(file), true, `${description} must exist`);
  const stat = fs.lstatSync(file);
  assert.equal(stat.isFile(), true, `${description} must be a regular file`);
  assert.equal(stat.isSymbolicLink(), false, `${description} must not be a symlink`);
  return fs.readFileSync(file, "utf8");
};

const uncommentedShell = (source) => source
  .split("\n")
  .filter((line) => !/^\s*#/u.test(line))
  .join("\n");

const plistEntries = (source) => {
  assert.match(source, /<plist\b[^>]*>[\s\S]*<dict>/u, "entitlements must be an XML plist");
  const body = source.match(/<dict>([\s\S]*?)<\/dict>/u)?.[1];
  assert.ok(body, "entitlements must contain a dictionary");

  const entries = [];
  const entryPattern = /<key>\s*([^<]+?)\s*<\/key>\s*(?:<string>\s*([^<]*?)\s*<\/string>|<true\s*\/>)/gu;
  for (const match of body.matchAll(entryPattern)) {
    entries.push({ key: match[1], value: match[2] === undefined ? true : match[2] });
  }
  return entries;
};

const assertHasFlagCase = (source, flag) => {
  assert.match(
    source,
    new RegExp(`(?:^|\\n)\\s*["']?--${flag}["']?\\s*\\)`),
    `signing script must accept --${flag}`,
  );
};

const assertRequiresValue = (source, variable, description) => {
  assert.match(
    source,
    new RegExp(`-n\\s+["']?\\$\\{?${variable}\\}?`),
    `${description} must be required rather than defaulted silently`,
  );
};

test("N3-E2b-1b has a closed qualification-controller entitlement resource", () => {
  const entries = plistEntries(readRequired(ENTITLEMENTS, "qualification-controller entitlement resource"));
  assert.deepEqual(
    entries.map(({ key }) => key).sort(),
    [
      "application-identifier",
      "com.apple.developer.team-identifier",
      "dev.agentpass.qualification-control",
    ],
    "the controller entitlement resource must contain exactly the App ID, Team ID, and qualification-control keys",
  );

  const byKey = new Map(entries.map((entry) => [entry.key, entry.value]));
  assert.equal(
    byKey.get("application-identifier"),
    "$(AppIdentifierPrefix)dev.agentpass.qualification-controller",
  );
  assert.equal(byKey.get("com.apple.developer.team-identifier"), "$(TeamIdentifier)");
  assert.equal(byKey.get("dev.agentpass.qualification-control"), true);

  assert.doesNotMatch(readRequired(ENTITLEMENTS, "qualification-controller entitlement resource"), /keychain-access-groups|get-task-allow/iu);
});

test("N3-E2b-1b uses a separate production-only signing entrypoint", () => {
  const source = uncommentedShell(readRequired(SIGN_SCRIPT, "qualification-controller signing script"));
  assert.equal((fs.statSync(SIGN_SCRIPT).mode & 0o111) !== 0, true, "signing script must be executable");

  for (const flag of ["identity", "profile", "team-id", "app-identifier-prefix", "source-binary", "output"]) {
    assertHasFlagCase(source, flag);
  }
  for (const [variable, description] of [
    ["SIGNING_IDENTITY", "Developer ID signing identity"],
    ["PROFILE", "qualification-controller provisioning profile"],
    ["TEAM_ID", "production Team ID"],
    ["IDENTIFIER_PREFIX", "production application-identifier prefix"],
    ["SOURCE_BINARY", "source controller binary"],
    ["OUTPUT", "external controller output"],
  ]) {
    assertRequiresValue(source, variable, description);
  }

  assert.match(source, /Developer\s+ID\s+Application/iu, "the identity path must be explicitly Developer ID Application signing");
  assert.match(source, /--adhoc[\s|)]/u, "an ad-hoc invocation must be explicitly rejected");
  assert.doesNotMatch(source, /(?:ADHOC\s*=|SIGNING_IDENTITY\s*=\s*["']?-|codesign[^\n]*--sign\s+(?:-|["']-["']))/iu, "the production signing path must not have an ad-hoc success mode");

  assert.match(source, /-f\s+"?\$\{?SOURCE_BINARY\}?|SOURCE_BINARY[\s\S]{0,100}(?:-x|-f)/u, "the source binary must be checked before signing");
  assert.match(source, /OUTPUT[\s\S]{0,180}(?:-e|-L|exists|symlink)/iu, "the output must be protected from overwrite and symlink substitution");
  assert.match(source, /basename[\s\S]{0,160}AgentPassQualificationController\.app/u, "the external output must use a dedicated controller artifact name");
  assert.match(source, /--app[|\s\S]*--pkg|--pkg[|\s\S]*--app/u, "ordinary app and PKG inputs must be explicitly rejected");
  assert.doesNotMatch(source, /(?:pkgbuild|build-app\.sh|build-installer\.sh)/u, "controller signing must not assemble AgentPass.app or the ordinary product PKG");
});

test("N3-E2b-1b validates the production profile before signing", () => {
  const source = uncommentedShell(readRequired(SIGN_SCRIPT, "qualification-controller signing script"));

  assert.match(source, /security\s+cms\s+-D\s+-i/u, "the profile must be decoded and CMS-validated");
  assert.match(source, /plutil\s+-lint/u, "decoded profile plist syntax must be validated");
  for (const field of [
    "TeamIdentifier",
    "ApplicationIdentifierPrefix",
    "application-identifier",
    "com.apple.developer.team-identifier",
    "dev.agentpass.qualification-control",
    "ExpirationDate",
    "ProvisionsAllDevices",
  ]) {
    assert.match(source, new RegExp(field.replace(/[.[\]\\]/gu, "\\$&")), `profile validation must inspect ${field}`);
  }
  assert.match(source, /(?:Time\.parse|date\s+.*ExpirationDate|expiration)[\s\S]{0,180}(?:now|current|expired|greater|before)/iu, "profile expiry must be checked against the current time");
  assert.match(source, /keychain-access-groups[\s\S]{0,180}(?:reject|unexpected|must not|forbidden|!=|exit)/iu, "profile keychain groups must be rejected");
  assert.match(source, /get-task-allow[\s\S]{0,180}(?:reject|unexpected|must not|forbidden|!=|exit)/iu, "profile get-task-allow must be rejected");
  assert.match(source, /ProvisionsAllDevices[\s\S]{0,120}(?:true|Developer ID|distribution)/iu, "profile must be a Developer ID distribution profile");
});

test("N3-E2b-1b signs and independently inspects the external controller identity", () => {
  const source = uncommentedShell(readRequired(SIGN_SCRIPT, "qualification-controller signing script"));

  assert.match(source, /BUNDLE_ID\s*=\s*["']dev\.agentpass\.qualification-controller["']/u);
  assert.match(source, /codesign[\s\S]{0,320}--identifier\s+(?:["']?dev\.agentpass\.qualification-controller|["']?\$\{?BUNDLE_ID\}?)/u);
  assert.match(source, /--options\s+runtime/u, "the controller must use the hardened runtime");
  assert.match(source, /--timestamp/u, "the controller signature must contain a trusted timestamp");
  assert.match(source, /AgentPassQualificationController\.entitlements/u, "the dedicated entitlement resource must feed the signing path");
  assert.match(source, /--entitlements\s+["'][^"']+|--entitlements\s+[^\s]+/u);
  assert.match(source, /--sign\s+["']?\$\{?(?:IDENTITY|SIGNING_IDENTITY)\}?/u, "the controller must be signed with the supplied production identity");

  assert.match(source, /codesign[\s\S]{0,180}--verify[\s\S]{0,120}(?:--strict|--deep)/u, "the output signature must be verified strictly");
  assert.match(source, /codesign[\s\S]{0,220}(?:--requirements|-r-|-[Rr]=)/u, "the designated requirement must be inspected");
  assert.match(source, /codesign[\s\S]{0,220}--entitlements\s+:-/u, "the signed entitlements must be inspected");
  for (const requirementPart of [
    "anchor apple generic",
    "dev.agentpass.qualification-controller",
    "certificate leaf[field.1.2.840.113635.100.6.1.13] exists",
    "certificate leaf[subject.OU]",
    "dev.agentpass.qualification-control",
  ]) {
    assert.match(source, new RegExp(requirementPart.replace(/[.[\]\\]/gu, "\\$&")), `code requirement must bind ${requirementPart}`);
  }
});
