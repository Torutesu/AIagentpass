export class SessionAuthorityInvalidatedError extends Error {
  constructor() {
    super("The session authority was invalidated while loading");
    this.name = "SessionAuthorityInvalidatedError";
  }
}

export type SessionAuthority<T extends object> = Readonly<{
  get(signal?: AbortSignal): Promise<T>;
  replace(value: T): void;
  clear(expected?: T): void;
}>;

/**
 * Owns one in-memory session generation for all Console consumers.
 *
 * The loader deliberately has no caller AbortSignal. A component may stop
 * waiting without cancelling the shared transport used by other components.
 * Explicit invalidation fences an in-flight result so stale authority can
 * neither be returned nor repopulate the cache.
 */
export function createSessionAuthority<T extends object>(loader: () => Promise<T>): SessionAuthority<T> {
  if (typeof loader !== "function") throw new TypeError("session loader is required");

  let value: T | undefined;
  let pending: Promise<T> | undefined;
  let generation = 0;

  const get = (signal?: AbortSignal): Promise<T> => {
    throwIfAborted(signal);
    if (value !== undefined) return Promise.resolve(value);
    if (pending === undefined) {
      const startedGeneration = generation;
      const current = Promise.resolve().then(loader);
      const shared = current.then((loaded) => {
        if (generation !== startedGeneration) throw new SessionAuthorityInvalidatedError();
        value = Object.freeze(loaded);
        if (pending === shared) pending = undefined;
        return value;
      });
      pending = shared;
      void shared.catch(() => {
        if (pending === shared) pending = undefined;
      });
    }
    return waitFor(pending, signal);
  };

  const clear = (expected?: T): void => {
    if (expected !== undefined && value !== expected) return;
    generation += 1;
    value = undefined;
    pending = undefined;
  };

  const replace = (next: T): void => {
    if (!next || typeof next !== "object") throw new TypeError("session value is required");
    generation += 1;
    value = Object.freeze(next);
    pending = undefined;
  };

  return Object.freeze({ get, replace, clear });
}

function abortError(): DOMException {
  return new DOMException("The operation was aborted", "AbortError");
}

function throwIfAborted(signal?: AbortSignal): void {
  if (signal?.aborted) throw abortError();
}

function waitFor<T>(promise: Promise<T>, signal?: AbortSignal): Promise<T> {
  throwIfAborted(signal);
  if (signal === undefined) return promise;
  return new Promise<T>((resolve, reject) => {
    const onAbort = () => reject(abortError());
    signal.addEventListener("abort", onAbort, { once: true });
    promise.then((result) => {
      signal.removeEventListener("abort", onAbort);
      resolve(result);
    }, (error: unknown) => {
      signal.removeEventListener("abort", onAbort);
      reject(error);
    });
  });
}
