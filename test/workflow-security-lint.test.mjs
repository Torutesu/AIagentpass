import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import { parse } from "yaml";

// Structural security lint for every GitHub Actions workflow. It replaces the
// per-workflow regex change-detectors: rules here inspect the parsed YAML, so
// renaming a step or reflowing a comment does not fail them, while removing a
// trigger restriction, an action pin, a protected environment, or a
// publish-before-verify ordering does.

const root = path.resolve(import.meta.dirname, "..");
const workflowDir = path.join(root, ".github", "workflows");
const actionsDir = path.join(root, ".github", "actions");
const load = (file) => parse(fs.readFileSync(file, "utf8"), { uniqueKeys: true, merge: true });

const workflows = new Map(fs.readdirSync(workflowDir)
  .filter((name) => /\.ya?ml$/u.test(name))
  .sort()
  .map((name) => [name, load(path.join(workflowDir, name))]));
const compositeActions = fs.readdirSync(actionsDir, { withFileTypes: true })
  .filter((entry) => entry.isDirectory())
  .flatMap((entry) => ["action.yml", "action.yaml"].map((name) => path.join(actionsDir, entry.name, name)))
  .filter((file) => fs.existsSync(file))
  .map((file) => [path.relative(root, file), load(file)]);

const PINNED_ACTION = /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_./-]+@[0-9a-f]{40}$/u;
const CANONICAL_REPOSITORY = /github\.repository == 'Torutesu\/AIagentpass'/u;
const CANONICAL_REF = /github\.ref == 'refs\/heads\/main'/u;
const RELEASE_MUTATION = /\bgh\s+release\s+(?:create|edit|upload|delete)\b/u;
const SCRIPT_INJECTION = /\$\{\{\s*(?:inputs\.|github\.event\.|github\.head_ref)/u;
const OFFICIAL = (...names) => names.map((name) => `actions/${name}`);

const P0C_LANE_ORDER = [
  "scripts/release/verify-macos-release.sh \"$MANIFEST\"",
  "node scripts/release/generate-hardware-qualification-template.mjs",
  "qualification-device-relay.mjs claim",
  "qualification-input-materializer.mjs materialize",
  "qualification-suite-orchestrator.mjs run)",
  "\"$P0C_RELEASE_TOOL_ROOT/run-p0c-qualification.mjs\"",
  "\"$P0C_RELEASE_TOOL_ROOT/sign-hardware-qualification.mjs\""
];
const POSTGRES_LANE_ORDER = [
  "set -euo pipefail",
  "npm run postgres:require-live-env",
  "node scripts/qualification/backup-pitr-evidence.mjs run"
];

// Per-workflow policy. Every workflow must be listed so a new workflow cannot
// silently bypass classification.
//   triggers            exact set of `on:` events
//   canonicalOnly       every job is guarded to the canonical repository and main
//   persistCredentials  every actions/checkout sets persist-credentials: false
//   permissions         exact workflow-level permissions
//   jobPermissions      exact job-level permissions
//   writePermissions    the only "<scope>.<permission>: write" grants allowed
//   knownUnpinnedActions exact legacy tag references tolerated by the pin rule
//   actions             allowed action repositories (still SHA-pinned)
//   environments        exact protected environment per job (others: none)
//   needs               exact job dependencies
//   secrets             exact secret names a job may reference
//   noSecrets           true: no job may reference secrets; array: these jobs may not
//   noRelease           no job may create/edit/upload/delete a GitHub release
//   stepIf              named steps whose `if:` must match a guard
//   stepOrder           step names that must appear in this order in a job
//   runOrder            run-text anchors whose first occurrences must be ordered
//   forbiddenRun        patterns no run script in the workflow may contain
//   noInputRefs         no step `with.ref` may be taken from workflow inputs
const POLICY = {
  "ci.yml": {
    triggers: ["pull_request", "push"],
    requiredJobs: ["postgres-authority-16", "postgres-authority-17", "postgres-integration", "browser-e2e", "p0b-live-process", "test"],
    environments: {},
    stepIf: [{ job: "browser-e2e", step: "Run dedicated WebAuthn unattended qualification (external bindings required)", guard: CANONICAL_REF }],
    runOrder: [{ job: "test", anchors: ["npm run contracts:validate", "npm test"] }]
  },
  "cloud-image.yml": {
    triggers: ["push", "workflow_dispatch"],
    // Pre-existing tag-pinned third-party actions. Listed exactly so the set
    // cannot grow; pin them to commit SHAs and drop this list.
    knownUnpinnedActions: ["docker/setup-buildx-action@v3", "docker/login-action@v3", "docker/metadata-action@v5", "docker/build-push-action@v6"],
    writePermissions: ["workflow.packages"],
    environments: {}
  },
  "cloud-production-qualification.yml": {
    triggers: ["workflow_dispatch"],
    canonicalOnly: true,
    persistCredentials: true,
    permissions: { contents: "read", actions: "read" },
    environments: { qualify: "production-cloud" }
  },
  "external-qualification-runners.yml": {
    triggers: ["workflow_dispatch"],
    canonicalOnly: true,
    persistCredentials: true,
    permissions: { contents: "read", actions: "read" },
    actions: OFFICIAL("checkout", "setup-node", "upload-artifact", "download-artifact"),
    environments: {
      kms: "external-qualification-kms",
      "platform-auth": "external-qualification-platform-auth",
      webauthn: "external-qualification-webauthn",
      "postgres-authority-16": "external-qualification-postgresql",
      "postgres-authority-17": "external-qualification-postgresql",
      "postgres-gate": "external-qualification-postgresql"
    },
    needs: {
      kms: ["validate"],
      "platform-auth": ["validate"],
      webauthn: ["validate"],
      "postgres-authority-16": ["validate"],
      "postgres-authority-17": ["validate"],
      "postgres-gate": ["validate", "postgres-authority-16", "postgres-authority-17"]
    },
    noSecrets: ["validate", "postgres-gate", "external-qualification-provenance"],
    runOrder: [
      { job: "postgres-authority-16", anchors: POSTGRES_LANE_ORDER },
      { job: "postgres-authority-17", anchors: POSTGRES_LANE_ORDER }
    ]
  },
  "macos-hardware-qualification.yml": {
    triggers: ["workflow_dispatch"],
    canonicalOnly: true,
    persistCredentials: true,
    permissions: { contents: "read" },
    environments: { qualify: "${{ matrix.environment }}" },
    matrixEnvironments: { qualify: ["agentpass-macos-apple-silicon", "agentpass-macos-intel"] },
    // Self-hosted hardware runs only the verified, root-installed toolchain,
    // never qualification entrypoints from the checked-out source tree.
    runOrder: [{ job: "qualify", anchors: ["verify-installed-toolchain.mjs", "/opt/agentpass/macos/qualification-tool/run-hardware-qualification.sh"] }],
    forbiddenRun: [/^\s*(?:node\s+)?native\/macos\/(?:scripts\/qualification\/run-hardware-qualification\.sh|Qualification\/hardware-qualification\.mjs)/mu]
  },
  "p0c-hardware-qualification.yml": {
    triggers: ["workflow_dispatch"],
    canonicalOnly: true,
    persistCredentials: true,
    permissions: { contents: "read", actions: "read" },
    actions: OFFICIAL("checkout", "setup-node", "download-artifact", "upload-artifact"),
    noRelease: true,
    environments: {
      "apple-silicon-qualification": "p0c-hardware-apple-silicon",
      "intel-t2-qualification": "p0c-hardware-intel-t2",
      "aggregate-qualification": "p0c-aggregate"
    },
    needs: {
      "apple-silicon-qualification": ["validate-candidate"],
      "intel-t2-qualification": ["validate-candidate"],
      "aggregate-qualification": ["validate-candidate", "apple-silicon-qualification", "intel-t2-qualification"]
    },
    secrets: {
      "validate-candidate": [],
      "apple-silicon-qualification": ["AGENTPASS_P0C_APPLE_SILICON_OPERATOR_PRIVATE_KEY_BASE64", "QUALIFICATION_DEVICE_CLIENT_CONFIG_B64", "QUALIFICATION_RELAY_REQUEST_B64"],
      "intel-t2-qualification": ["AGENTPASS_P0C_INTEL_T2_OPERATOR_PRIVATE_KEY_BASE64", "QUALIFICATION_DEVICE_CLIENT_CONFIG_B64", "QUALIFICATION_RELAY_REQUEST_B64"],
      "aggregate-qualification": []
    },
    noAlways: ["aggregate-qualification"],
    noInputRefs: true,
    runOrder: [
      { job: "apple-silicon-qualification", anchors: P0C_LANE_ORDER },
      { job: "intel-t2-qualification", anchors: P0C_LANE_ORDER }
    ]
  },
  "promote-qualified-release.yml": {
    triggers: ["workflow_dispatch"],
    canonicalOnly: true,
    persistCredentials: true,
    permissions: { contents: "read", actions: "read" },
    jobPermissions: { promote: { contents: "write", actions: "read" } },
    writePermissions: ["promote.contents"],
    actions: OFFICIAL("checkout", "setup-node", "download-artifact"),
    environments: { promote: "production-release" },
    noSecrets: true,
    // Downloaded candidate and qualification material is data, never code.
    forbiddenRun: [/chmod \+x.*(?:candidate|apple|intel|summary)|bash .*candidate|sh .*candidate|open .*\.pkg/u],
    stepOrder: [{
      job: "promote",
      steps: [
        "Re-run hardware qualification verification against the exact candidate",
        "Verify raw production readiness evidence before release-evidence-index promotion",
        "Verify externally reviewed release evidence index operator gate",
        "Refuse an existing release before creating the public release",
        "Create draft release after every verification gate",
        "Upload only the explicit signed-manifest-bound release list",
        "Materialize the final P0-C release assets",
        "Final P0-C asset gate: secret scan, regular-file/hardlink checks, and SHA256SUMS binding",
        "Upload the verified signed qualification evidence",
        "Re-inspect uploaded P0-C assets before publishing",
        "Re-inspect every uploaded release asset before publishing",
        "Retain release asset round-trip evidence",
        "Re-inspect retained release asset evidence before publishing",
        "Publish the fully uploaded public release"
      ]
    }]
  },
  "release-candidate.yml": {
    triggers: ["workflow_dispatch"],
    canonicalOnly: true,
    persistCredentials: true,
    permissions: { contents: "read", actions: "read" },
    actions: OFFICIAL("checkout", "setup-node", "upload-artifact", "download-artifact"),
    noRelease: true,
    environments: { "signed-candidate": "production-signing" },
    needs: { "signed-candidate": ["verify-source"] },
    noSecrets: ["verify-source"],
    runOrder: [
      {
        job: "signed-candidate",
        anchors: [
          "npm run contracts:validate",
          "node scripts/release/generate-database-migration-manifest.mjs",
          "node scripts/release/generate-release-attestation.mjs",
          "node scripts/release/generate-manifest.mjs",
          "node scripts/release/sign-manifest.mjs"
        ]
      },
      {
        // The CI preflight result is scanned on its own before it is moved out
        // of the candidate tree, and only then is the candidate scanned.
        job: "signed-candidate",
        anchors: [
          "install -m 0600 \"$RUNNER_TEMP/candidate/ci-preflight.json\" \"$ci_preflight_scan_root/ci-preflight.json\"",
          "node scripts/release/ci-preflight.mjs artifact-scan \"$ci_preflight_scan_root\"",
          "install -m 0644 \"$RUNNER_TEMP/candidate/ci-preflight.json\" \"$integrity_dir/ci-preflight.json\"",
          "rm -f \"$RUNNER_TEMP/candidate/ci-preflight.json\"",
          "node scripts/release/ci-preflight.mjs artifact-scan \"$RUNNER_TEMP/candidate\""
        ]
      }
    ]
  },
  "release-preflight.yml": {
    triggers: ["push", "workflow_dispatch"],
    persistCredentials: true,
    permissions: { contents: "read", actions: "read" },
    environments: { "release-preflight": "production" }
  }
};

function triggersOf(workflow) {
  const on = workflow.on;
  if (typeof on === "string") return [on];
  if (Array.isArray(on)) return [...on];
  return Object.keys(on ?? {});
}

const stepsOf = (job) => (Array.isArray(job.steps) ? job.steps : []);
const environmentOf = (job) => (job.environment && typeof job.environment === "object" ? job.environment.name : job.environment);
const needsOf = (job) => (job.needs === undefined ? [] : [job.needs].flat());
const secretNames = (value) => [...new Set([...JSON.stringify(value).matchAll(/\bsecrets\.([A-Za-z0-9_]+)/gu)].map((match) => match[1]))].sort();
const runText = (job) => stepsOf(job).map((step) => (typeof step.run === "string" ? step.run : "")).join("\n");

function collectUses(value, location, found = []) {
  if (Array.isArray(value)) value.forEach((item, index) => collectUses(item, `${location}[${index}]`, found));
  else if (value && typeof value === "object") {
    for (const [key, child] of Object.entries(value)) {
      if (key === "uses") found.push({ location, uses: child });
      else collectUses(child, `${location}.${key}`, found);
    }
  }
  return found;
}

function writeGrants(file, workflow) {
  const grants = [];
  const scan = (permissions, owner) => {
    if (permissions === "write-all") grants.push(`${owner}.*`);
    if (permissions && typeof permissions === "object") {
      for (const [scope, level] of Object.entries(permissions)) if (level === "write") grants.push(`${owner}.${scope}`);
    }
  };
  scan(workflow.permissions, "workflow");
  for (const [name, job] of Object.entries(workflow.jobs ?? {})) scan(job.permissions, name);
  return grants.sort();
}

test("every workflow is classified by the security policy table", () => {
  assert.deepEqual([...workflows.keys()].sort(), Object.keys(POLICY).sort());
});

test("no workflow runs untrusted pull_request_target code", () => {
  for (const [file, workflow] of workflows) {
    assert.ok(!triggersOf(workflow).includes("pull_request_target"), `${file} must not use pull_request_target`);
  }
});

test("every action reference is a local action or pinned to a full commit SHA", () => {
  for (const [file, document] of [...workflows, ...compositeActions]) {
    for (const { location, uses } of collectUses(document, file)) {
      assert.equal(typeof uses, "string", `${location}.uses must be a string`);
      if (uses.startsWith("./") || POLICY[file]?.knownUnpinnedActions?.includes(uses)) continue;
      assert.match(uses, PINNED_ACTION, `${location}.uses must be pinned to a 40-character commit SHA: ${uses}`);
    }
  }
});

test("run scripts never interpolate caller-controlled expressions and no step may fail open", () => {
  for (const [file, workflow] of workflows) {
    for (const [jobName, job] of Object.entries(workflow.jobs ?? {})) {
      assert.notEqual(job["continue-on-error"], true, `${file}:${jobName} must not continue on error`);
      for (const [index, step] of stepsOf(job).entries()) {
        const label = `${file}:${jobName}:${step.name ?? index}`;
        assert.notEqual(step["continue-on-error"], true, `${label} must not continue on error`);
        if (typeof step.run === "string") assert.doesNotMatch(step.run, SCRIPT_INJECTION, `${label} interpolates caller-controlled input into a shell script`);
      }
    }
  }
});

test("write permissions are granted only where the policy allows them", () => {
  for (const [file, workflow] of workflows) {
    assert.deepEqual(writeGrants(file, workflow), [...(POLICY[file].writePermissions ?? [])].sort(), `${file} write permissions`);
  }
});

for (const [file, policy] of Object.entries(POLICY)) {
  test(`${file} matches its trigger, environment, secret, and ordering policy`, () => {
    const workflow = workflows.get(file);
    assert.ok(workflow, `${file} is missing`);
    const jobs = workflow.jobs ?? {};

    assert.deepEqual(triggersOf(workflow).sort(), [...policy.triggers].sort(), `${file} triggers`);
    if (policy.permissions) assert.deepEqual(workflow.permissions, policy.permissions, `${file} workflow permissions`);
    for (const [name, permissions] of Object.entries(policy.jobPermissions ?? {})) {
      assert.deepEqual(jobs[name]?.permissions, permissions, `${file}:${name} permissions`);
    }
    for (const name of policy.requiredJobs ?? []) assert.ok(jobs[name], `${file} must define job ${name}`);

    for (const [name, job] of Object.entries(jobs)) {
      const label = `${file}:${name}`;
      assert.equal(environmentOf(job), policy.environments?.[name], `${label} protected environment`);
      if (policy.canonicalOnly) {
        assert.match(String(job.if ?? ""), CANONICAL_REPOSITORY, `${label} must be limited to the canonical repository`);
        assert.match(String(job.if ?? ""), CANONICAL_REF, `${label} must be limited to refs/heads/main`);
      }
      if (policy.needs?.[name]) assert.deepEqual(needsOf(job).sort(), [...policy.needs[name]].sort(), `${label} needs`);
      if (policy.secrets?.[name]) assert.deepEqual(secretNames(job), [...policy.secrets[name]].sort(), `${label} secrets`);
      if (policy.noSecrets === true || (Array.isArray(policy.noSecrets) && policy.noSecrets.includes(name))) {
        assert.deepEqual(secretNames(job), [], `${label} must not reference secrets`);
      }
      if (policy.noAlways?.includes(name)) assert.doesNotMatch(String(job.if ?? ""), /always\(\)/u, `${label} must not run after a failed dependency`);
      if (policy.noRelease) {
        assert.notEqual(name, "publish", `${file} must not define a publish job`);
        assert.doesNotMatch(runText(job), RELEASE_MUTATION, `${label} must not mutate GitHub releases`);
      }
      for (const pattern of policy.forbiddenRun ?? []) assert.doesNotMatch(runText(job), pattern, `${label} run scripts`);
      for (const step of stepsOf(job)) {
        const uses = typeof step.uses === "string" ? step.uses : "";
        if (policy.actions && !uses.startsWith("./") && uses) {
          assert.ok(policy.actions.includes(uses.split("@")[0]), `${label} uses an unapproved action: ${uses}`);
        }
        if (policy.noInputRefs) assert.doesNotMatch(String(step.with?.ref ?? ""), /\binputs\./u, `${label} must not check out a caller-supplied ref`);
        if (policy.persistCredentials && uses.startsWith("actions/checkout@")) {
          assert.equal(step.with?.["persist-credentials"], false, `${label} checkout must set persist-credentials: false`);
        }
      }
    }

    for (const [name, environments] of Object.entries(policy.matrixEnvironments ?? {})) {
      const include = jobs[name]?.strategy?.matrix?.include ?? [];
      assert.deepEqual(include.map((entry) => entry.environment).sort(), [...environments].sort(), `${file}:${name} matrix environments`);
    }

    for (const { job, step, guard } of policy.stepIf ?? []) {
      const found = stepsOf(jobs[job] ?? {}).find((candidate) => candidate.name === step);
      assert.ok(found, `${file}:${job} is missing step ${step}`);
      assert.match(String(found.if ?? ""), guard, `${file}:${job}:${step} guard`);
    }

    for (const { job, steps } of policy.stepOrder ?? []) {
      const names = stepsOf(jobs[job] ?? {}).map((step) => step.name);
      const positions = steps.map((name) => names.indexOf(name));
      steps.forEach((name, index) => assert.notEqual(positions[index], -1, `${file}:${job} is missing step ${name}`));
      for (let index = 1; index < steps.length; index += 1) {
        assert.ok(positions[index - 1] < positions[index], `${file}:${job}: "${steps[index - 1]}" must run before "${steps[index]}"`);
      }
    }

    for (const { job, anchors } of policy.runOrder ?? []) {
      const text = runText(jobs[job] ?? {});
      const positions = anchors.map((anchor) => text.indexOf(anchor));
      anchors.forEach((anchor, index) => assert.notEqual(positions[index], -1, `${file}:${job} is missing ${anchor}`));
      for (let index = 1; index < anchors.length; index += 1) {
        assert.ok(positions[index - 1] < positions[index], `${file}:${job}: "${anchors[index - 1]}" must run before "${anchors[index]}"`);
      }
    }
  });
}
