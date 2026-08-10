import test from "node:test";
import assert from "node:assert/strict";
import { evaluateSignRequest } from "../lib/policy.mjs";

const policy = {
  repositories: ["/tmp/project"],
  branches: { allow: ["feature/*"], deny: ["main"] },
  remotes: { allow: ["git@github.com:example/*"] }
};

test("allows a matching feature branch and remote", () => {
  assert.deepEqual(evaluateSignRequest({ policy, cwd: "/tmp/project", branch: "feature/auth", remote: "git@github.com:example/project.git" }), { allowed: true, reason: "allowed" });
});

test("denies protected branches", () => {
  assert.equal(evaluateSignRequest({ policy, cwd: "/tmp/project", branch: "main", remote: "git@github.com:example/project.git" }).reason, "branch_denied");
});

test("denies repositories outside the policy", () => {
  assert.equal(evaluateSignRequest({ policy, cwd: "/tmp/other", branch: "feature/auth", remote: "git@github.com:example/project.git" }).reason, "repository_not_allowed");
});
