import assert from "node:assert/strict";
import test from "node:test";

import { NOT_PROVEN, verifyBackupRestoreQualification } from "./backup-restore-qualification.mjs";

test("qualification requires candidate-bound evidence and the reviewed schema head", () => {
  assert.equal(NOT_PROVEN.status, "not_proven");
  assert.throws(
    () => verifyBackupRestoreQualification({}, {
      expectedCandidateId: "release-pkg-sha256-" + "a".repeat(64),
      expectedSourceCommit: "b".repeat(40)
    }),
    /invalid_or_unclosed_evidence/u
  );
});
