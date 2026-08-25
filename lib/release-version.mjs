const RELEASE_VERSION = /^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?$/u;

function invalidVersion(value) {
  throw new TypeError(`Invalid release version: ${String(value)}`);
}

function identifier(value) {
  if (/^[0-9]+$/u.test(value)) {
    if (value.length > 1 && value.startsWith("0")) invalidVersion(value);
    return { numeric: true, value };
  }
  return { numeric: false, value };
}

export function parseReleaseVersion(value) {
  if (typeof value !== "string") invalidVersion(value);
  const match = RELEASE_VERSION.exec(value);
  if (!match) invalidVersion(value);
  return Object.freeze({
    major: match[1],
    minor: match[2],
    patch: match[3],
    prerelease: match[4] === undefined ? [] : match[4].split(".").map(identifier)
  });
}

function compareNumber(left, right) {
  return left < right ? -1 : left > right ? 1 : 0;
}

function compareNumericStrings(left, right) {
  if (left.length !== right.length) return left.length < right.length ? -1 : 1;
  return compareNumber(left, right);
}

export function compareReleaseVersions(left, right) {
  const a = parseReleaseVersion(left);
  const b = parseReleaseVersion(right);
  for (const field of ["major", "minor", "patch"]) {
    const result = compareNumericStrings(a[field], b[field]);
    if (result !== 0) return result;
  }
  if (a.prerelease.length === 0 || b.prerelease.length === 0) {
    return compareNumber(a.prerelease.length === 0 ? 1 : 0, b.prerelease.length === 0 ? 1 : 0);
  }
  const length = Math.min(a.prerelease.length, b.prerelease.length);
  for (let index = 0; index < length; index += 1) {
    const first = a.prerelease[index];
    const second = b.prerelease[index];
    if (first.numeric && second.numeric) {
      const result = compareNumericStrings(first.value, second.value);
      if (result !== 0) return result;
    } else if (first.numeric !== second.numeric) {
      return first.numeric ? -1 : 1;
    } else if (first.value !== second.value) {
      return first.value < second.value ? -1 : 1;
    }
  }
  return compareNumber(a.prerelease.length, b.prerelease.length);
}
