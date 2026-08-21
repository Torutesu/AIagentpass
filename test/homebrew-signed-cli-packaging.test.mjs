import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import test from "node:test";

const root = path.resolve(import.meta.dirname, "..");
const formula = fs.readFileSync(path.join(root, "Formula", "agentpass.rb"), "utf8");
const verifier = fs.readFileSync(path.join(root, "native/macos/scripts/verify-installer-package.sh"), "utf8");

test("Homebrew CLI is visibly distinct from the production dev.agentpass helper", () => {
  assert.match(formula, /system_command\s+"\/usr\/bin\/codesign"[\s\S]*--sign[\s\S]*"-"[\s\S]*--identifier[\s\S]*"dev\.agentpass\.homebrew-evaluation"[\s\S]*bin\/"agentpass"/u);
  assert.doesNotMatch(formula, /--identifier",\s*"dev\.agentpass"/u);
  assert.match(verifier, /SIGNED_CLI="\$APP\/Contents\/MacOS\/agentpass-onboarding"/u);
  assert.match(verifier, /codesign --verify --strict --verbose=2 "\$SIGNED_CLI"/u);
  assert.match(verifier, /CLI_IDENTIFIER=.*Identifier=/u);
  assert.match(verifier, /\[ "\$CLI_IDENTIFIER" == "dev\.agentpass" \]/u);
});

test("macOS recognizes the ad-hoc signed Homebrew wrapper as non-production", { skip: process.platform !== "darwin" }, () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "agentpass-homebrew-cli-"));
  const wrapper = path.join(directory, "agentpass");
  try {
    fs.writeFileSync(wrapper, "#!/bin/sh\nexec /usr/bin/true\n", { mode: 0o755 });
    const signed = spawnSync("/usr/bin/codesign", ["--force", "--sign", "-", "--identifier", "dev.agentpass.homebrew-evaluation", wrapper], { encoding: "utf8" });
    assert.equal(signed.status, 0, `${signed.stdout}\n${signed.stderr}`);
    const verified = spawnSync("/usr/bin/codesign", ["--verify", "--strict", wrapper], { encoding: "utf8" });
    assert.equal(verified.status, 0, `${verified.stdout}\n${verified.stderr}`);
    const details = spawnSync("/usr/bin/codesign", ["-dv", "--verbose=4", wrapper], { encoding: "utf8" });
    assert.equal(details.status, 0, `${details.stdout}\n${details.stderr}`);
    assert.match(`${details.stdout}\n${details.stderr}`, /^Identifier=dev\.agentpass\.homebrew-evaluation$/mu);
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});
