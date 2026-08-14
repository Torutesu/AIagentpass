import {
  MANAGED_SIGNER_KEY_LIFECYCLE_REPOSITORY_ERROR_CODES as CODES
} from "../../src/postgres/managed-signer-key-lifecycle-repository.mjs";

/** Minimal in-memory lifecycle boundary for runtime composition tests only. */
export function createManagedSignerRepositoryFactory() {
  const snapshots = new Map();
  return function createManagedSignerKeyLifecycleRepository({ purpose, algorithm = "ed25519" } = {}) {
    return Object.freeze({
      async snapshot() {
        const value = snapshots.get(purpose);
        if (!value) throw Object.assign(new Error("not initialized"), { code: CODES.NOT_INITIALIZED });
        return value;
      },
      async initialize({ snapshot }) {
        const existing = snapshots.get(purpose);
        if (existing) return existing;
        if (snapshot?.purpose !== purpose || snapshot?.algorithm !== algorithm) throw new Error("invalid snapshot");
        snapshots.set(purpose, snapshot);
        return snapshot;
      },
      async reserveSignature() { throw new Error("signing is outside this runtime composition test"); },
      async startSignature() { throw new Error("signing is outside this runtime composition test"); },
      async commitSignature() { throw new Error("signing is outside this runtime composition test"); },
      async markSignatureUncertain() { throw new Error("signing is outside this runtime composition test"); },
      async reconcileSignature() { throw new Error("signing is outside this runtime composition test"); }
    });
  };
}
