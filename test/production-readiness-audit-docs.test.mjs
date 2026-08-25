import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";

const root = path.resolve(import.meta.dirname, "..");
const read = (relative) => fs.readFileSync(path.join(root, relative), "utf8");

const audit = read("docs/PRODUCTION_READINESS_AUDIT_2026-08-20.md");
const incident = read("docs/INCIDENT_AND_REVOKE_RUNBOOK.md");
const release = read("docs/RELEASE.md");
const promotionWorkflow = read(".github/workflows/promote-qualified-release.yml");
const qualificationContract = read("docs/qualification/external-qualification-contract.md");
const qualificationRunbook = read("docs/qualification/external-qualification-runbook.md");
const qualificationSchema = JSON.parse(read("docs/qualification/external-qualification-evidence.schema.json"));

test("production-readiness audit has explicit evidence states and external boundary", () => {
  for (const state of ["implemented", "locally-qualified", "source-bound-ci", "externally-qualified", "open"]) {
    assert.equal(audit.includes(`| \`${state}\` |`), true, state);
  }
  assert.match(audit, /not production-ready/u);
  assert.match(audit, /real KMS/u);
  assert.match(audit, /physical hardware/u);
  assert.match(audit, /independent review/u);
});

test("audit maps every external qualification gate to an open, evidence-bound disposition", () => {
  const gates = ["github_actions", "postgresql", "kms", "webauthn", "macos_hardware"];
  assert.deepEqual(Object.keys(qualificationSchema.properties.gates.properties), gates);
  for (const gate of gates) {
    assert.equal(audit.includes(`| \`${gate}\` | \`open\` |`), true, gate);
    assert.equal(qualificationContract.includes(`| \`${gate}\` |`), true, gate);
  }
  assert.match(audit, /does not retain an external qualification\s+envelope/u);
  assert.match(qualificationContract, /aggregate state is `not_run`, `qualified: false`/u);
  assert.match(qualificationRunbook, /terminal `status: completed` with `conclusion: success`/u);
});

test("checklist state columns use only the controlled vocabulary", () => {
  const checklist = audit.slice(audit.indexOf("## Current checkout checklist"), audit.indexOf("## Required evidence record"));
  const allowed = /^(implemented|locally-qualified|source-bound-ci|externally-qualified|open)(?: \(documented\))?$/u;
  const rows = checklist.split("\n")
    .filter((line) => /^\| [^|]+ \| [^|]+ \|/u.test(line))
    .filter((line) => !line.includes("| --- |"))
    .filter((line) => !line.includes("| Current state |"));
  assert.ok(rows.length > 0);
  for (const row of rows) {
    const state = row.split("|")[2].trim().replaceAll("`", "");
    assert.match(state, allowed, `ambiguous or unsupported readiness state: ${state}`);
    assert.doesNotMatch(state, /\bcomplete(?:d)?\b/iu);
  }
});

test("promotion stop conditions retain exact release and qualification bindings", () => {
  for (const value of [
    "postgres-authority-16",
    "postgres-authority-17",
    "postgres-integration",
    "browser-e2e",
    "p0b-live-process",
    "not_proven",
    "source/tree/run/job",
    "Developer ID",
    "Intel/T2",
    "uncertain"
  ]) assert.match(release, new RegExp(value));
});

test("incident runbook covers containment, scoped revoke, uncertain signing, and rollback", () => {
  for (const value of [
    "stop new promotion",
    "agentpass agent revoke",
    "agentpass native revoke-sessions",
    "uncertain",
    "blindly retrying",
    "never rebuild",
    "revocation bound",
    "Required incident record fields"
  ]) assert.match(incident, new RegExp(value, "i"));
});

test("release operator evidence index binds reviewer expiry and executed rollback", () => {
  for (const value of [
    "candidate_id",
    "run_id",
    "run_attempt",
    "job_id",
    "artifact_sha256",
    "reviewer",
    "report_sha256",
    "expires_at",
    "rollback target",
    "status: passed",
    "tested: true",
    "no more than 30 days"
  ]) assert.match(read("docs/runbooks/RELEASE_PROMOTION_RUNBOOK.md"), new RegExp(value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"), "i"));
  assert.match(promotionWorkflow, /Verify externally reviewed release evidence index operator gate/u);
  assert.match(promotionWorkflow, /AGENTPASS_RELEASE_EVIDENCE_INDEX_JSON/u);
  assert.match(promotionWorkflow, /evidence-index\.mjs verify/u);
  assert.match(promotionWorkflow, /release-evidence-index\.json/u);
});

test("readme and planning docs link the dated audit and incident runbook", () => {
  for (const relative of ["README.md", "docs/IMPLEMENTATION_PLAN_2026-08-15.md", "docs/PRODUCTION_HARDENING_PLAN.md"]) {
    const content = read(relative);
    assert.match(content, /PRODUCTION_READINESS_AUDIT_2026-08-20\.md/u, relative);
    assert.match(content, /INCIDENT_AND_REVOKE_RUNBOOK\.md/u, relative);
  }
  for (const relative of [
    "docs/PRODUCTION_READINESS_AUDIT_2026-08-20.md",
    "docs/INCIDENT_AND_REVOKE_RUNBOOK.md"
  ]) assert.equal(fs.existsSync(path.join(root, relative)), true, relative);
});
