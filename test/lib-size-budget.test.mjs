import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, readdirSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";

const LIB_DIR = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "lib");

// Soft budget: line-count ceiling per lib module (baseline +20% headroom).
// Growing a module past its ceiling fails this test; split the module or
// raise the budget deliberately here — never silently.
const BUDGET = new Map([
  ["agent-admin.mjs", 111],
  ["agent-launch-contract.mjs", 191],
  ["agent-launch-handoff.mjs", 220],
  ["agent-lifecycle-cli.mjs", 338],
  ["anchor-client.mjs", 165],
  ["anchor.mjs", 2532],
  ["audit-transaction.mjs", 600],
  ["audit.mjs", 240],
  ["broker-client.mjs", 99],
  ["broker.mjs", 588],
  ["browser-cli-handoff.mjs", 722],
  ["capability-state.mjs", 131],
  ["cloud-audit.mjs", 736],
  ["cloud-control.mjs", 525],
  ["config.mjs", 244],
  ["control-bundle-v2.mjs", 755],
  ["device-enrollment-client.mjs", 1320],
  ["device-enrollment-setup-handler.mjs", 620],
  ["device-onboarding-resume.mjs", 972],
  ["git-signing.mjs", 22],
  ["headless-onboarding.mjs", 345],
  ["identity.mjs", 87],
  ["installed-release-receipt.mjs", 335],
  ["integrations.mjs", 543],
  ["macos-atomic-rename.mjs", 350],
  ["native-audit.mjs", 106],
  ["native-bootstrap-runner.mjs", 276],
  ["native-device-enrollment-runner.mjs", 126],
  ["native-setup-handlers.mjs", 98],
  ["onboarding-contract.mjs", 23],
  ["platform-doctor.mjs", 272],
  ["platform-install.mjs", 260],
  ["platform-setup.mjs", 104],
  ["platform-uninstall.mjs", 1163],
  ["platform-user-purge.mjs", 387],
  ["policy.mjs", 64],
  ["recovery.mjs", 334],
  ["release-candidate-identity.mjs", 59],
  ["release-version.mjs", 72],
  ["remote-control.mjs", 214],
  ["setup-browser-connect.mjs", 434],
  ["setup-continue-options.mjs", 76],
  ["setup-finalization-handlers.mjs", 275],
  ["setup-journal.mjs", 551],
  ["setup-orchestrator.mjs", 352],
  ["setup-preflight.mjs", 258],
  ["setup-stdin-delivery.mjs", 249],
  ["small-software-cli.mjs", 117],
]);

describe("lib module size budget", () => {
  for (const [file, ceiling] of BUDGET) {
    it(file + " stays under " + ceiling + " lines", () => {
      const lines = readFileSync(path.join(LIB_DIR, file), "utf8").split("\n").length - 1;
      assert.ok(
        lines <= ceiling,
        file + " grew to " + lines + " lines (budget " + ceiling + "); split the module or adjust the budget map deliberately"
      );
    });
  }

  it("budget map covers every lib module", () => {
    const files = readdirSync(LIB_DIR).filter((f) => f.endsWith(".mjs"));
    for (const f of files) assert.ok(BUDGET.has(f), f + " is missing from the lib size budget map");
  });
});
