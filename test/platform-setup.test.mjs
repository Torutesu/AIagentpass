import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { inspectNativeApplication } from "../lib/platform-setup.mjs";

function applicationFixture(status = "not_registered") {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "agentpass-setup-"));
  const application = path.join(root, "AgentPass.app");
  const manager = path.join(application, "Contents/MacOS/agentpass-native-manager");
  const client = path.join(application, "Contents/Library/HelperTools/AgentPassNativeClient.app/Contents/MacOS/agentpass-native-client");
  fs.mkdirSync(path.dirname(manager), { recursive: true });
  fs.mkdirSync(path.dirname(client), { recursive: true });
  const output = JSON.stringify({ ok: true, status, bundle_path: application, plist_present: true, requires_approval: status === "requires_approval" });
  fs.writeFileSync(manager, `#!/bin/sh\nprintf '%s\\n' '${output}'\n`, { mode: 0o700 });
  fs.writeFileSync(client, "#!/bin/sh\nexit 0\n", { mode: 0o700 });
  return { root, application, manager, client };
}

test("native setup discovers the fixed bridge and service state", () => {
  const value = applicationFixture("requires_approval");
  try {
    const setup = inspectNativeApplication(value.application, { expectedOwner: process.getuid() });
    assert.equal(setup.nativeBroker.client, value.client);
    assert.equal(setup.nativeBroker.manager, value.manager);
    assert.equal(setup.nativeBroker.mach_service, "dev.agentpass.native-service");
    assert.equal(setup.requiresApproval, true);
  } finally { fs.rmSync(value.root, { recursive: true, force: true }); }
});

test("native setup rejects substituted executables and manager output", () => {
  const linked = applicationFixture();
  const target = path.join(linked.root, "replacement");
  try {
    fs.renameSync(linked.client, target);
    fs.symlinkSync(target, linked.client);
    assert.throws(() => inspectNativeApplication(linked.application, { expectedOwner: process.getuid() }), /not trusted/);
  } finally { fs.rmSync(linked.root, { recursive: true, force: true }); }

  const malformed = applicationFixture();
  try {
    fs.writeFileSync(malformed.manager, "#!/bin/sh\necho '{}'\n", { mode: 0o700 });
    assert.throws(() => inspectNativeApplication(malformed.application, { expectedOwner: process.getuid() }), /untrusted service status/);
  } finally { fs.rmSync(malformed.root, { recursive: true, force: true }); }
});
