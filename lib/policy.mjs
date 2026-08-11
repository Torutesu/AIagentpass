import path from "node:path";

function matchesAny(value, patterns = []) {
  return patterns.some((pattern) => {
    const escaped = String(pattern).replace(/[.+^${}()|[\]\\]/g, "\\$&").replaceAll("*", ".*");
    return new RegExp(`^${escaped}$`).test(value);
  });
}

function isInside(candidate, root) {
  const relative = path.relative(path.resolve(root), path.resolve(candidate));
  return relative === "" || (!relative.startsWith("..") && !path.isAbsolute(relative));
}

export function evaluateRequest({ policy, cwd, branch = "", remote = "", operation = "git.commit.sign", revoked = false }) {
  if (revoked) return deny("revoked");
  if (policy.session?.required && !policy.session.valid) return deny("session_required");
  const allowedOperations = policy.operations ?? ["git.commit.sign"];
  if (!matchesAny(operation, allowedOperations)) return deny("operation_not_allowed");

  const allowedRepo = (policy.repositories ?? []).some((configured) => isInside(cwd, configured));
  if (!allowedRepo) return deny("repository_not_allowed");

  if (operation === "git.tag.push") {
    const tags = policy.tags ?? { allow: ["*"] };
    if (tags.deny && matchesAny(branch, tags.deny)) return deny("tag_denied");
    if (tags.allow && !matchesAny(branch, tags.allow)) return deny("tag_not_allowed");
  } else {
    const branches = policy.branches ?? { allow: ["*"] };
    if (branches.deny && matchesAny(branch, branches.deny)) return deny("branch_denied");
    if (branches.allow && !matchesAny(branch, branches.allow)) return deny("branch_not_allowed");
  }

  if (policy.remotes?.allow && !matchesAny(remote, policy.remotes.allow)) return deny("remote_not_allowed");
  if (policy.remotes?.deny && matchesAny(remote, policy.remotes.deny)) return deny("remote_denied");
  return { allowed: true, reason: "allowed", operation };
}

export function evaluateSignRequest(context) {
  return evaluateRequest({ ...context, operation: "git.commit.sign" });
}

function deny(reason) { return { allowed: false, reason }; }
