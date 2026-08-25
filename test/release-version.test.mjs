import assert from "node:assert/strict";
import test from "node:test";

import { compareReleaseVersions, parseReleaseVersion } from "../lib/release-version.mjs";

test("compares release versions without numeric precision loss", () => {
  assert.equal(compareReleaseVersions("1.10.0", "1.9.99"), 1);
  assert.equal(compareReleaseVersions("999999999999999999.0.0", "1000000000000000000.0.0"), -1);
  assert.equal(compareReleaseVersions("2.0.0-rc.2", "2.0.0-rc.10"), -1);
  assert.equal(compareReleaseVersions("2.0.0-rc.1", "2.0.0"), -1);
  assert.equal(compareReleaseVersions("2.0.0", "2.0.0"), 0);
});

test("rejects non-canonical release versions", () => {
  for (const value of ["1.2", "01.2.3", "1.2.3-01", "1.2.3+build", "v1.2.3"]) {
    assert.throws(() => parseReleaseVersion(value), /Invalid release version/);
  }
});

