/**
 * The protected qualification lane only needs the protocol's canonical JSON
 * byte representation. Keep this dependency local so the installed, root-owned
 * qualification tree never resolves code outside its fixed inventory.
 *
 * This intentionally mirrors packages/protocol's canonicalJson contract:
 * object keys are sorted, arrays retain order, and non-JSON values fail closed.
 */

export class QualificationCanonicalJsonError extends TypeError {}

const fail = (path, message) => {
  throw new QualificationCanonicalJsonError(`invalid JSON at ${path}: ${message}`);
};

const canonicalizeValue = (value, seen, path) => {
  if (value === null) return 'null';
  if (typeof value === 'string' || typeof value === 'boolean') return JSON.stringify(value);
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) fail(path, 'non-finite numbers are not valid JSON');
    return JSON.stringify(value);
  }
  if (typeof value !== 'object') fail(path, 'value is not JSON-serializable');
  if (seen.has(value)) fail(path, 'cyclic values are not valid JSON');
  seen.add(value);

  let result;
  if (Array.isArray(value)) {
    for (let index = 0; index < value.length; index += 1) {
      if (!Object.hasOwn(value, index)) fail(`${path}[${index}]`, 'sparse arrays are not valid JSON');
    }
    const keys = Reflect.ownKeys(value);
    if (keys.some((key) => typeof key !== 'string' || (key !== 'length' && !/^\d+$/u.test(key)))) {
      fail(path, 'arrays may not have symbol or extra properties');
    }
    result = `[${value.map((item, index) => canonicalizeValue(item, seen, `${path}[${index}]`)).join(',')}]`;
  } else {
    const prototype = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null) fail(path, 'only plain objects are valid JSON');
    const keys = Reflect.ownKeys(value);
    if (keys.some((key) => typeof key !== 'string')) fail(path, 'symbol keys are not valid JSON');
    result = `{${keys.sort().map((key) => `${JSON.stringify(key)}:${canonicalizeValue(value[key], seen, `${path}.${key}`)}`).join(',')}}`;
  }
  seen.delete(value);
  return result;
};

export const canonicalJson = (value) => canonicalizeValue(value, new Set(), '$');
export const canonicalize = canonicalJson;
