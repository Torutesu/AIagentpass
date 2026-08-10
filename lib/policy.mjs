import path from "node:path";

function matchesAny(value, patterns = []) {
  return patterns.some((pattern) => {
    const escaped = pattern.replace(/[.+^${}()|[\]\\]/g, "\\$&").replaceAll("*", ".*");
    return new RegExp(`^${escaped}$`).test(value);
  });
}

export function evaluateSignRequest({ policy, cwd, branch, remote }) {
  const repo = path.resolve(cwd);
  const repositories = policy.repositories ?? [];
  const allowedRepo = repositories.some((configured) => repo === path.resolve(configured));
  if (!allowedRepo) return deny("repository_not_allowed");

  const branches = policy.branches ?? { allow: ["*"] };
  if (branches.deny && matchesAny(branch, branches.deny)) return deny("branch_denied");
  if (branches.allow && !matchesAny(branch, branches.allow)) return deny("branch_not_allowed");

  if (policy.remotes?.allow && !matchesAny(remote ?? "", policy.remotes.allow)) {
    return deny("remote_not_allowed");
  }

  return { allowed: true, reason: "allowed" };
}

function deny(reason) {
  return { allowed: false, reason };
}
