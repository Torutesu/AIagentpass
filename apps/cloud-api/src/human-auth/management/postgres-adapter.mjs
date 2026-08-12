import { createHash } from "node:crypto";

import { HUMAN_CURSOR_ERROR_CODES } from "../pagination/cursor-codec.mjs";

const DEFAULT_PAGE_SIZE = 25;
const MAX_PAGE_SIZE = 100;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu;
const BASE64URL = /^[A-Za-z0-9_-]+$/u;

export const HUMAN_MANAGEMENT_CURSOR_ERROR_CODES = Object.freeze({
  INVALID_CURSOR: HUMAN_CURSOR_ERROR_CODES.INVALID_CURSOR
});

/**
 * Adapts the PostgreSQL human repository to the management API. `cursorCodec`
 * is deliberately injected here, at the management boundary, so this adapter
 * owns resource/scope binding and the repository only receives a validated
 * immutable keyset position.
 */
export function createPostgresHumanManagementRepository({ repository, cursorCodec, now = () => Date.now() } = {}) {
  if (!repository || typeof repository.listCredentialMetadataForSession !== "function" || typeof repository.updateCredentialLabel !== "function" || typeof repository.revokeCredential !== "function" || typeof repository.listSafeSessions !== "function" || typeof repository.revokeManagedSession !== "function") throw new TypeError("PostgreSQL human repository is invalid");
  if (cursorCodec !== undefined && (!cursorCodec || typeof cursorCodec.encode !== "function" || typeof cursorCodec.decode !== "function")) throw new TypeError("cursorCodec must expose encode() and decode()");
  if (typeof now !== "function") throw new TypeError("now must be a function");

  return Object.freeze({ listCredentials, renameCredential, revokeCredential, listSessions, revokeSession });

  async function listCredentials(input = {}) {
    const pageInput = pagination(input);
    const position = decodeCursor(pageInput.cursor, input, "credentials", cursorCodec);
    const records = await repository.listCredentialMetadataForSession(repositoryInput(input, pageInput, position));
    return page(records, pageInput.limit, "credentials", input);
  }

  async function renameCredential(input) {
    return repository.updateCredentialLabel(input);
  }

  async function revokeCredential(input) {
    return repository.revokeCredential({ ...input, revoked_at: timestamp(), authority_reduction: true, actor_session_id: input.session_id });
  }

  async function listSessions(input = {}) {
    const pageInput = pagination(input);
    const position = decodeCursor(pageInput.cursor, input, "sessions", cursorCodec);
    const records = await repository.listSafeSessions(repositoryInput(input, pageInput, position));
    const current = clock();
    return page(records.map((record) => ({
      ...record,
      status: record.revoked_at ? "revoked" : Date.parse(record.expires_at) <= current ? "expired" : "active"
    })), pageInput.limit, "sessions", input);
  }

  async function revokeSession(input) {
    return repository.revokeManagedSession({
      ...input,
      actor_session_id: input.session_id,
      target_session_id: input.target_session_id,
      revoked_at: timestamp(),
      authority_reduction: true
    });
  }

  function timestamp() { return new Date(clock()).toISOString(); }
  function clock() { const value = now(); if (!Number.isSafeInteger(value) || value < 0) throw new TypeError("clock is invalid"); return value; }

  function page(records, limit, resource, scope) {
    if (!Array.isArray(records)) throw new TypeError("management records are invalid");
    const items = records.slice(0, limit);
    const hasMore = records.length > limit;
    let next_cursor = null;
    if (hasMore) {
      if (cursorCodec === undefined) throw new TypeError("cursorCodec is required for a non-terminal management page");
      const last = items.at(-1);
      try {
        next_cursor = cursorCodec.encode({
          resource,
          tenant_id: requiredUuid(scope.organization_id, "organization_id"),
          member_id: requiredUuid(scope.member_id, "member_id"),
          created_at: cursorTimestamp(last?.created_at),
          id: resource === "sessions" ? requiredUuid(last?.session_id ?? last?.id, "session_id") : credentialCursorId(last?.id ?? last?.credential_id),
          direction: "asc"
        });
      } catch (error) {
        throw invalidCursor(error);
      }
      if (typeof next_cursor !== "string" || next_cursor.length < 1 || next_cursor.length > 512 || !BASE64URL.test(next_cursor)) throw invalidCursor();
    }
    return Object.freeze({ items: Object.freeze(items), next_cursor });
  }
}

function pagination(input) {
  const limit = input?.limit === undefined ? DEFAULT_PAGE_SIZE : input.limit;
  if (!Number.isSafeInteger(limit) || limit < 1 || limit > MAX_PAGE_SIZE) throw new TypeError("management page limit is invalid");
  const cursor = input?.cursor;
  if (cursor !== undefined && (typeof cursor !== "string" || cursor.length < 1 || cursor.length > 512 || !BASE64URL.test(cursor))) throw invalidCursor();
  return Object.freeze({ limit, ...(cursor === undefined ? {} : { cursor }) });
}

function repositoryInput(input, pageInput, position) {
  const { cursor: _cursor, ...scope } = input ?? {};
  return {
    ...scope,
    limit: pageInput.limit,
    ...(position === undefined ? {} : { after_created_at: position.created_at, after_id: position.id })
  };
}

function decodeCursor(cursor, scope, resource, cursorCodec) {
  if (cursor === undefined) return undefined;
  if (cursorCodec === undefined) throw invalidCursor();
  try {
    const decoded = cursorCodec.decode(cursor, {
      resource,
      tenant_id: requiredUuid(scope?.organization_id, "organization_id"),
      member_id: requiredUuid(scope?.member_id, "member_id"),
      direction: "asc"
    });
    if (!decoded || decoded.resource !== resource || decoded.direction !== "asc") throw invalidCursor();
    return {
      created_at: cursorTimestamp(decoded.created_at),
      id: requiredUuid(decoded.id, "cursor id")
    };
  } catch (error) {
    throw invalidCursor(error);
  }

}

function credentialCursorId(value) {
  if (typeof value !== "string" || !BASE64URL.test(value) || value.includes("=")) throw new TypeError("credential id is invalid");
  const bytes = Buffer.from(value, "base64url");
  if (bytes.length < 16 || bytes.length > 1024 || bytes.toString("base64url") !== value) throw new TypeError("credential id is invalid");
  const digest = createHash("sha256").update(bytes).digest("hex");
  // The codec intentionally carries UUID keyset IDs. Credential IDs are
  // arbitrary WebAuthn byte strings, so the first 128 bits of SHA-256 form a
  // deterministic UUID anchor with collision resistance equivalent to the
  // UUID identifiers used by the other cursor resources. PostgreSQL derives
  // the same anchor from the immutable bytea ID before keyset comparison.
  return `${digest.slice(0, 8)}-${digest.slice(8, 12)}-4${digest.slice(13, 16)}-8${digest.slice(17, 20)}-${digest.slice(20, 32)}`;
}

function cursorTimestamp(value) {
  const date = value instanceof Date ? new Date(value.getTime()) : new Date(value);
  if (!Number.isFinite(date.getTime())) throw new TypeError("cursor timestamp is invalid");
  return date.toISOString();
}

function requiredUuid(value, field) {
  if (typeof value !== "string" || !UUID.test(value)) throw new TypeError(`${field} is invalid`);
  return value.toLowerCase();
}

function invalidCursor(cause = undefined) {
  const error = new Error("The pagination cursor is invalid", { cause });
  error.code = HUMAN_MANAGEMENT_CURSOR_ERROR_CODES.INVALID_CURSOR;
  return error;
}
