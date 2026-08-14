import assert from "node:assert/strict";
import { mkdtemp, chmod, link, rm, symlink, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import { verifyW15Evidence } from "./verify-w15-evidence.mjs";

const VALID = Object.freeze({
  version: 1,
  scenarios: ["stale_acknowledgements", "lease_expiry_pending_provider", "retry_suppress_cas", "prune_redrive_cas", "two_worker_exact_binding"],
  race_winner: "retry",
  prune_race_winner: "prune",
  final_state_classes: ["published", "published", "published", "uncertain"],
  accepted_event_digests: ["0123456789abcdef", "1123456789abcdef", "2123456789abcdef"],
  accepted_binding_ids: ["race-matrix-provider", "race-matrix-provider", "race-matrix-provider"],
  max_attempts: 2,
  pending_claims: 0,
  active_leases: 0
});

test("accepts only the closed secret-free W1.5 evidence schema", async (t) => {
  const directory = await mkdtemp(path.join(os.tmpdir(), "agentpass-w15-evidence-"));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const file = path.join(directory, "evidence.json");
  await writeFile(file, `${JSON.stringify(VALID, null, 2)}\n`, { mode: 0o600 });
  const result = await verifyW15Evidence(file);
  assert.match(result.evidence_sha256, /^[0-9a-f]{64}$/u);
  assert.deepEqual({ ...result, evidence_sha256: undefined }, { evidence_sha256: undefined, accepted_event_count: 3, final_state_count: 4 });

  for (const mutation of [
    { ...VALID, organization_id: "11111111-1111-4111-8111-111111111111" },
    { ...VALID, accepted_event_digests: ["11111111-1111-4111-8111-111111111111"] },
    { ...VALID, accepted_binding_ids: ["tenant-derived"] },
    { ...VALID, active_leases: 1 },
    { ...VALID, scenarios: [...VALID.scenarios].reverse() }
  ]) {
    await writeFile(file, `${JSON.stringify(mutation)}\n`, { mode: 0o600 });
    await assert.rejects(verifyW15Evidence(file), (error) => error.code === "invalid_evidence" && !error.message.includes("11111111"));
  }
});

test("rejects links, broad permissions, and oversized files without reflecting paths", async (t) => {
  const directory = await mkdtemp(path.join(os.tmpdir(), "agentpass-w15-evidence-file-"));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const file = path.join(directory, "evidence.json");
  const linkFile = path.join(directory, "evidence-link.json");
  const hardLink = path.join(directory, "evidence-hard.json");
  await writeFile(file, `${JSON.stringify(VALID)}\n`, { mode: 0o600 });
  await symlink(file, linkFile);
  await assert.rejects(verifyW15Evidence(linkFile), (error) => error.code === "invalid_file" && !error.message.includes(directory));
  await link(file, hardLink);
  await assert.rejects(verifyW15Evidence(file), (error) => error.code === "invalid_file");
  await rm(hardLink);
  await chmod(file, 0o644);
  await assert.rejects(verifyW15Evidence(file), (error) => error.code === "invalid_file");
  await chmod(file, 0o600);
  await writeFile(file, "x".repeat(4_097), { mode: 0o600 });
  await assert.rejects(verifyW15Evidence(file), (error) => error.code === "invalid_file");
});
