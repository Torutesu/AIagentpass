import test from "node:test";
import assert from "node:assert/strict";
import { evaluateRequest, evaluateSignRequest } from "../lib/policy.mjs";

const policy = {
  repositories: ["/tmp/project"],
  branches: { allow: ["feature/*"], deny: ["main"] },
  remotes: { allow: ["git@github.com:example/*"] }
};

test("allows a matching feature branch and remote", () => {
  assert.deepEqual(evaluateSignRequest({ policy, cwd: "/tmp/project", branch: "feature/auth", remote: "git@github.com:example/project.git" }), { allowed: true, reason: "allowed", operation: "git.commit.sign" });
});

test("denies protected branches", () => {
  assert.equal(evaluateSignRequest({ policy, cwd: "/tmp/project", branch: "main", remote: "git@github.com:example/project.git" }).reason, "branch_denied");
});

test("denies repositories outside the policy", () => {
  assert.equal(evaluateSignRequest({ policy, cwd: "/tmp/other", branch: "feature/auth", remote: "git@github.com:example/project.git" }).reason, "repository_not_allowed");
});

test("allows a subdirectory of a configured repository", () => {
  assert.equal(evaluateSignRequest({ policy, cwd: "/tmp/project/packages/app", branch: "feature/auth", remote: "git@github.com:example/project.git" }).allowed, true);
});

test("denies revoked requests and unapproved operations", () => {
  assert.equal(evaluateRequest({ policy, cwd: "/tmp/project", branch: "feature/auth", remote: "git@github.com:example/project.git", revoked: true }).reason, "revoked");
  assert.equal(evaluateRequest({ policy, cwd: "/tmp/project", branch: "feature/auth", remote: "git@github.com:example/project.git", operation: "git.push" }).reason, "operation_not_allowed");
});
