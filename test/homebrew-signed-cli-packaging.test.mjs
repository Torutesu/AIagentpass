import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import test from "node:test";

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
