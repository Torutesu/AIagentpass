const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const PROVIDER = /^[a-z][a-z0-9._-]{0,63}$/;
const ROLE = new Set(["owner", "admin", "auditor", "viewer"]);
const CONTROL_CHARACTERS = /[\u0000-\u001f\u007f]/;
const ASSERTION_KEYS = ["version", "issued_at", "expires_at"];
const INPUT_KEYS = ["provider", "subject", "organization_id"];
const CONTEXT_KEYS = new Set(["now", "origin"]);
const RESOLVE_QUERY = "SELECT * FROM public.agentpass_human_identity_resolve($1::text,$2::text,$3::uuid)";

export const IDENTITY_RESOLVER_ERROR_CODES = Object.freeze({
  RESOLUTION_FAILED: "identity_resolution_failed"
});

const PUBLIC_FAILURE_MESSAGE = "Identity resolution failed";
const DEFAULT_ASSERTION_TTL_MS = 30_000;
const MIN_ASSERTION_TTL_MS = 1_000;
const MAX_ASSERTION_TTL_MS = 60_000;
const MAX_SUBJECT_BYTES = 512;
const MAX_CLOCK_SKEW_MS = 5_000;

/**
 * Deliberately constant for every public resolution and assertion failure.
 * Database/provider details are never exposed through this error.
 */
export class IdentityResolutionError extends Error {
  constructor(status = 401) {
    super(PUBLIC_FAILURE_MESSAGE);
    this.name = "IdentityResolutionError";
    this.code = IDENTITY_RESOLVER_ERROR_CODES.RESOLUTION_FAILED;
    this.status = status;
  }
}

/**
 * Resolve a server-verified upstream identity against durable PostgreSQL
 * membership state. The returned assertion is an in-process capability:
 * callers cannot construct a valid equivalent value, and successful
 * verification consumes it exactly once.
 *
 * The resolver accepts only {provider, subject, organization_id}. In
 * particular, member_id and role are always read from PostgreSQL and are
 * never accepted from the caller.
 */
export function createPostgresIdentityResolver({
  client,
  now = () => Date.now(),
  assertionTtlMs = DEFAULT_ASSERTION_TTL_MS
} = {}) {
  if (!client || typeof client.query !== "function") throw new TypeError("database client is invalid");
  if (typeof now !== "function") throw new TypeError("now must be a function");
  if (!Number.isSafeInteger(assertionTtlMs) || assertionTtlMs < MIN_ASSERTION_TTL_MS || assertionTtlMs > MAX_ASSERTION_TTL_MS) {
    throw new TypeError("assertion TTL is invalid");
  }

  // WeakMap retains no assertion after the caller drops it. The value is
  // deleted before returning a principal so the capability is one-use.
  const capabilities = new WeakMap();

  async function resolveIdentity(input) {
    let request;
    try {
      request = parseInput(input);
    } catch { throw publicFailure(401); }
    let result;
    try {
      result = await client.query(RESOLVE_QUERY, [request.provider, request.subject, request.organization_id]);
    } catch { throw publicFailure(503); }
    if (!result || result.rowCount !== 1 || !Array.isArray(result.rows) || result.rows.length !== 1) {
      throw publicFailure(401);
    }
    try {
      const identity = normalizeIdentityRow(result.rows[0], request);
      const issuedAt = clock(now());
      if (issuedAt > Number.MAX_SAFE_INTEGER - assertionTtlMs) throw new Error("assertion expiry is unsafe");
      const assertion = Object.freeze({ version: 1, issued_at: issuedAt, expires_at: issuedAt + assertionTtlMs });
      capabilities.set(assertion, Object.freeze({ ...identity, issued_at: issuedAt, expires_at: assertion.expires_at }));
      return assertion;
    } catch { throw publicFailure(503); }
  }

  function verifyAssertion(assertion, context = {}) {
    try {
      if (!plain(context) || Object.keys(context).some((key) => !CONTEXT_KEYS.has(key))) throw new Error("context is invalid");
      const current = clock(context.now === undefined ? now() : context.now);
      if (!plain(assertion) || !exactKeys(assertion, ASSERTION_KEYS)) throw new Error("assertion is invalid");

      const capability = capabilities.get(assertion);
      if (!capability || assertion.version !== 1 || assertion.issued_at !== capability.issued_at || assertion.expires_at !== capability.expires_at) {
        throw new Error("assertion capability is invalid");
      }
      if (capability.issued_at > current + MAX_CLOCK_SKEW_MS || capability.expires_at <= current) {
        capabilities.delete(assertion);
        throw new Error("assertion is expired");
      }

      capabilities.delete(assertion);
      return Object.freeze({
        provider: capability.provider,
        subject: capability.subject,
        member_id: capability.member_id,
        membership_id: capability.membership_id,
        organization_id: capability.organization_id,
        role: capability.role,
        assertion_expires_at: capability.expires_at
      });
    } catch (error) {
      if (error instanceof IdentityResolutionError) throw error;
      throw publicFailure();
    }
  }

  return Object.freeze({
    resolveIdentity,
    verifyAssertion,
    // This adapter shape lets the existing human-session service consume the
    // capability without knowing how the upstream provider is stored.
    identityAdapter: Object.freeze({ verify: verifyAssertion }),
    assertionTtlMs
  });
}

function parseInput(input) {
  if (!plain(input) || !exactKeys(input, INPUT_KEYS)) throw new Error("identity input is invalid");
  const provider = boundedProvider(input.provider);
  return Object.freeze({
    provider,
    subject: boundedSubject(input.subject),
    organization_id: boundedUuid(input.organization_id)
  });
}

function normalizeIdentityRow(row, request) {
  if (!plain(row) || row.provider !== request.provider || !boundedUuidValue(row.member_id) || !boundedUuidValue(row.membership_id) || !boundedUuidValue(row.organization_id) || row.organization_id.toLowerCase() !== request.organization_id || row.subject !== request.subject || !ROLE.has(row.role)) {
    throw new Error("identity row is invalid");
  }
  return Object.freeze({
    provider: request.provider,
    subject: row.subject,
    member_id: row.member_id.toLowerCase(),
    membership_id: row.membership_id.toLowerCase(),
    organization_id: row.organization_id.toLowerCase(),
    role: row.role
  });
}

function boundedProvider(value) {
  if (typeof value !== "string" || !PROVIDER.test(value) || value !== value.toLowerCase()) throw new Error("provider is invalid");
  return value;
}

function boundedSubject(value) {
  if (typeof value !== "string" || value.length < 1 || Buffer.byteLength(value, "utf8") > MAX_SUBJECT_BYTES || CONTROL_CHARACTERS.test(value)) throw new Error("subject is invalid");
  return value;
}

function boundedUuid(value) {
  if (!boundedUuidValue(value)) throw new Error("UUID is invalid");
  return value.toLowerCase();
}

function boundedUuidValue(value) {
  return typeof value === "string" && UUID.test(value);
}

function clock(value) {
  if (!Number.isSafeInteger(value) || value < 0) throw new Error("clock is invalid");
  return value;
}

function publicFailure(status = 401) {
  return new IdentityResolutionError(status);
}

function plain(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value) && Object.getPrototypeOf(value) === Object.prototype;
}

function exactKeys(value, expected) {
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  return actual.length === wanted.length && actual.every((key, index) => key === wanted[index]);
}
