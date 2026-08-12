const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const IDENTIFIER = /^[a-z_][a-z0-9_]*$/;
const TABLES = new Set([
  "memberships", "devices", "device_enrollments", "agents", "policies", "revocations",
  "capabilities", "bundle_heads", "bundle_acknowledgements", "device_audit_events",
  "idempotency_records", "admin_audit_events", "webauthn_challenges"
]);
const PRIMARY_KEYS = new Map([
  ["memberships", "id"], ["devices", "id"], ["device_enrollments", "id"], ["agents", "id"],
  ["policies", "id"], ["revocations", "id"], ["capabilities", "id"], ["bundle_heads", "device_id"],
  ["bundle_acknowledgements", "device_id"], ["device_audit_events", "event_id"], ["idempotency_records", "idempotency_key"],
  ["admin_audit_events", "id"], ["webauthn_challenges", "id"]
]);
const DEFAULT_ORDER_COLUMNS = new Set(["created_at", "updated_at", "received_at", "expires_at", "sequence", "id", "last_seen_at", "applied_at"]);
const UPDATED_AT_TABLES = new Set(["memberships", "devices", "agents"]);

export class PostgresRepositoryError extends Error {
  constructor(code, message, details = undefined, cause = undefined) {
    super(message, cause === undefined ? undefined : { cause });
    this.name = "PostgresRepositoryError";
    this.code = code;
    if (details !== undefined) this.details = details;
    if (cause !== undefined) this.cause = cause;
  }
}

export class TenantScopeError extends PostgresRepositoryError {
  constructor(message = "organization_id is required for tenant-scoped access") {
    super("ERR_TENANT_SCOPE", message);
    this.name = "TenantScopeError";
  }
}

export function assertTenantId(organizationId) {
  if (typeof organizationId !== "string" || !UUID.test(organizationId)) throw new TenantScopeError("organization_id must be a UUID");
  return organizationId;
}

export function createTenantRepository({ client, organizationId } = {}) {
  assertClient(client);
  const tenantId = assertTenantId(organizationId);
  const select = async ({ table, columns = ["*"], where = undefined, params = [], orderBy = undefined, limit = undefined, forUpdate = false } = {}) => {
    const safeTable = tableName(table);
    const safeColumns = columnList(columns);
    const values = [tenantId];
    const clauses = ["organization_id = $1"];
    if (where !== undefined) {
      if (typeof where !== "string" || where.trim().length === 0) throw new PostgresRepositoryError("ERR_QUERY", "where must be a non-empty SQL predicate");
      if (!Array.isArray(params)) throw new PostgresRepositoryError("ERR_QUERY", "where parameters must be an array");
      clauses.push(shiftPlaceholders(where.trim(), 1, params.length));
      values.push(...params);
    } else if (params.length > 0) throw new PostgresRepositoryError("ERR_QUERY", "where parameters require a where predicate");
    const order = normalizeOrder(orderBy, safeTable);
    const boundedLimit = normalizeLimit(limit);
    const text = `SELECT ${safeColumns} FROM ${quoteIdentifier(safeTable)} WHERE ${clauses.join(" AND ")}${order ? ` ORDER BY ${order}` : ""}${boundedLimit === undefined ? "" : ` LIMIT ${boundedLimit}`}${forUpdate ? " FOR UPDATE" : ""}`;
    return client.query(text, values);
  };

  const findById = async ({ table, id, columns = ["*"], forUpdate = false } = {}) => {
    const safeTable = tableName(table);
    const key = PRIMARY_KEYS.get(safeTable) ?? "id";
    if (typeof id !== "string" || id.length < 1 || id.length > 1024) throw new PostgresRepositoryError("ERR_IDENTIFIER_VALUE", "resource id is invalid");
    return select({ table: safeTable, columns, where: `${quoteIdentifier(key)} = $1`, params: [id], limit: 1, forUpdate });
  };

  const insert = async ({ table, values, returning = ["*"] } = {}) => {
    const safeTable = tableName(table);
    if (!values || typeof values !== "object" || Array.isArray(values)) throw new PostgresRepositoryError("ERR_QUERY", "insert values must be an object");
    if (Object.prototype.hasOwnProperty.call(values, "organization_id") || Object.prototype.hasOwnProperty.call(values, "organizationId")) throw new TenantScopeError("organization_id is assigned by the tenant repository");
    const entries = Object.entries(values).sort(([a], [b]) => a.localeCompare(b));
    if (entries.length === 0) throw new PostgresRepositoryError("ERR_QUERY", "insert values cannot be empty");
    for (const [column] of entries) assertColumn(column);
    const columns = ["organization_id", ...entries.map(([column]) => column)];
    const params = [tenantId, ...entries.map(([, value]) => value)];
    const placeholders = params.map((_, index) => `$${index + 1}`).join(", ");
    return client.query(`INSERT INTO ${quoteIdentifier(safeTable)} (${columns.map(quoteIdentifier).join(", ")}) VALUES (${placeholders}) RETURNING ${columnList(returning)}`, params);
  };

  const updateById = async ({ table, id, values, expectedVersion, returning = ["*"] } = {}) => {
    const safeTable = tableName(table);
    const key = PRIMARY_KEYS.get(safeTable) ?? "id";
    if (typeof id !== "string" || id.length < 1 || id.length > 1024) throw new PostgresRepositoryError("ERR_IDENTIFIER_VALUE", "resource id is invalid");
    if (!values || typeof values !== "object" || Array.isArray(values)) throw new PostgresRepositoryError("ERR_QUERY", "update values must be an object");
    if (Object.keys(values).some((column) => column === "organization_id" || column === "version")) throw new TenantScopeError("organization_id and version are managed by the tenant repository");
    const entries = Object.entries(values).sort(([a], [b]) => a.localeCompare(b));
    if (entries.length === 0) throw new PostgresRepositoryError("ERR_QUERY", "update values cannot be empty");
    for (const [column] of entries) assertColumn(column);
    const params = [tenantId, id, ...entries.map(([, value]) => value)];
    const assignments = entries.map(([column], index) => `${quoteIdentifier(column)} = $${index + 3}`);
    const clauses = [`organization_id = $1`, `${quoteIdentifier(key)} = $2`];
    if (expectedVersion !== undefined) {
      if (!Number.isSafeInteger(expectedVersion) || expectedVersion < 1) throw new PostgresRepositoryError("ERR_VERSION", "expectedVersion must be a positive safe integer");
      params.push(expectedVersion);
      clauses.push(`version = $${params.length}`);
      assignments.push("version = version + 1");
    }
    if (UPDATED_AT_TABLES.has(safeTable)) assignments.push("updated_at = clock_timestamp()");
    return client.query(`UPDATE ${quoteIdentifier(safeTable)} SET ${assignments.join(", ")} WHERE ${clauses.join(" AND ")} RETURNING ${columnList(returning)}`, params);
  };

  const queryTenant = async ({ text, params = [], organizationPlaceholder = "$1" } = {}) => {
    if (typeof text !== "string" || text.trim().length === 0) throw new PostgresRepositoryError("ERR_QUERY", "tenant query text is required");
    if (!Array.isArray(params)) throw new PostgresRepositoryError("ERR_QUERY", "tenant query parameters must be an array");
    if (typeof organizationPlaceholder !== "string" || !/^\$[1-9][0-9]*$/.test(organizationPlaceholder)) throw new PostgresRepositoryError("ERR_QUERY", "organization placeholder is invalid");
    if (!/^\s*SELECT\b/i.test(text)) throw new PostgresRepositoryError("ERR_QUERY", "raw tenant queries are read-only; use insert or updateById for writes");
    const organizationParameter = organizationPlaceholder.slice(1);
    if (!new RegExp(`\\borganization_id\\s*=\\s*\\$${organizationParameter}\\b`, "i").test(text)) throw new TenantScopeError("tenant query must bind organization_id to the repository tenant");
    return client.query(text, [tenantId, ...params]);
  };

  const transaction = (fn) => withTransaction(client, async (transactionClient) => fn(createTenantRepository({ client: transactionClient, organizationId: tenantId })));

  return Object.freeze({ organizationId: tenantId, select, list: select, findById, insert, updateById, queryTenant, transaction });
}

export function createTenantRepositoryFactory({ client } = {}) {
  assertClient(client);
  return Object.freeze({ forOrganization: (organizationId) => createTenantRepository({ client, organizationId }) });
}

export async function withTransaction(client, operation) {
  assertClient(client);
  if (typeof operation !== "function") throw new PostgresRepositoryError("ERR_TRANSACTION", "transaction operation must be a function");
  // pg.Pool#query does not reserve a connection between BEGIN and COMMIT.
  // Acquire one checked-out client for the complete transaction whenever the
  // supplied database handle is a pool; already-checked-out clients and test
  // doubles continue through the same path without an extra acquisition.
  if (typeof client.connect === "function" && typeof client.release !== "function") {
    const transactionClient = await client.connect();
    try {
      return await withTransaction(transactionClient, operation);
    } finally {
      transactionClient.release();
    }
  }
  let began = false;
  try {
    await client.query("BEGIN", []);
    began = true;
    const result = await operation(client);
    await client.query("COMMIT", []);
    began = false;
    return result;
  } catch (error) {
    if (began) {
      try { await client.query("ROLLBACK", []); }
      catch (rollbackError) { throw new PostgresRepositoryError("ERR_TRANSACTION_ROLLBACK", "transaction failed and rollback failed", { rollbackError: rollbackError.message }, error); }
    }
    throw error;
  }
}

function assertClient(client) {
  if (!client || typeof client.query !== "function") throw new PostgresRepositoryError("ERR_DB_CLIENT", "database client must provide query(text, params)");
}

function tableName(table) {
  if (typeof table !== "string" || !TABLES.has(table)) throw new PostgresRepositoryError("ERR_TABLE", "table is not an approved tenant-scoped table", { table });
  return table;
}

function assertColumn(column) {
  if (typeof column !== "string" || !IDENTIFIER.test(column)) throw new PostgresRepositoryError("ERR_COLUMN", "column identifier is invalid", { column });
}

function columnList(columns) {
  if (columns === "*") return "*";
  if (!Array.isArray(columns) || columns.length === 0) throw new PostgresRepositoryError("ERR_COLUMN", "at least one selected column is required");
  for (const column of columns) {
    if (column === "*") return "*";
    assertColumn(column);
  }
  return columns.map(quoteIdentifier).join(", ");
}

function quoteIdentifier(identifier) {
  assertColumn(identifier);
  return `"${identifier}"`;
}

function shiftPlaceholders(text, offset, parameterCount) {
  const placeholders = [...text.matchAll(/\$(\d+)/g)].map((match) => Number(match[1]));
  if (placeholders.some((number) => number < 1 || number > parameterCount)) throw new PostgresRepositoryError("ERR_QUERY", "where placeholder is outside the supplied parameter list");
  const unique = new Set(placeholders);
  if (unique.size !== parameterCount || Array.from({ length: parameterCount }, (_, index) => index + 1).some((number) => !unique.has(number))) throw new PostgresRepositoryError("ERR_QUERY", "where placeholders must be contiguous and match supplied parameters");
  return text.replace(/\$(\d+)/g, (_, number) => `$${Number(number) + offset}`);
}

function normalizeOrder(orderBy, table) {
  if (orderBy === undefined || orderBy === null) return undefined;
  if (typeof orderBy === "string") orderBy = { column: orderBy, direction: "ASC" };
  if (!orderBy || typeof orderBy !== "object" || !DEFAULT_ORDER_COLUMNS.has(orderBy.column)) throw new PostgresRepositoryError("ERR_ORDER", "order column is not approved");
  const direction = String(orderBy.direction ?? "ASC").toUpperCase();
  if (direction !== "ASC" && direction !== "DESC") throw new PostgresRepositoryError("ERR_ORDER", "order direction is invalid");
  const tieBreaker = PRIMARY_KEYS.get(table) ?? "id";
  return `${quoteIdentifier(orderBy.column)} ${direction}, ${quoteIdentifier(tieBreaker)} ${direction}`;
}

function normalizeLimit(limit) {
  if (limit === undefined || limit === null) return undefined;
  if (!Number.isSafeInteger(limit) || limit < 1 || limit > 1000) throw new PostgresRepositoryError("ERR_LIMIT", "limit must be an integer between 1 and 1000");
  return limit;
}
