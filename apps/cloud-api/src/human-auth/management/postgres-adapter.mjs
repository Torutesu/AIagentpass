export function createPostgresHumanManagementRepository({ repository, now = () => Date.now() } = {}) {
  if (!repository || typeof repository.listCredentialMetadataForSession !== "function" || typeof repository.updateCredentialLabel !== "function" || typeof repository.revokeCredential !== "function" || typeof repository.listSafeSessions !== "function" || typeof repository.revokeManagedSession !== "function") throw new TypeError("PostgreSQL human repository is invalid");
  if (typeof now !== "function") throw new TypeError("now must be a function");

  return Object.freeze({ listCredentials, renameCredential, revokeCredential, listSessions, revokeSession });

  async function listCredentials(input) {
    const items = await repository.listCredentialMetadataForSession(input);
    return page(items, input.limit);
  }

  async function renameCredential(input) {
    return repository.updateCredentialLabel(input);
  }

  async function revokeCredential(input) {
    return repository.revokeCredential({ ...input, revoked_at: timestamp() });
  }

  async function listSessions(input) {
    const records = await repository.listSafeSessions(input);
    const current = clock();
    return page(records.map((record) => ({
      ...record,
      status: record.revoked_at ? "revoked" : Date.parse(record.expires_at) <= current ? "expired" : "active"
    })), input.limit);
  }

  async function revokeSession(input) {
    return repository.revokeManagedSession({
      ...input,
      actor_session_id: input.session_id,
      target_session_id: input.target_session_id,
      revoked_at: timestamp()
    });
  }

  function timestamp() { return new Date(clock()).toISOString(); }
  function clock() { const value = now(); if (!Number.isSafeInteger(value) || value < 0) throw new TypeError("clock is invalid"); return value; }
}

function page(records, limit) {
  if (!Array.isArray(records)) throw new TypeError("management records are invalid");
  if (!Number.isSafeInteger(limit) || limit < 1 || limit > 100) throw new TypeError("management page limit is invalid");
  return Object.freeze({ items: Object.freeze(records.slice(0, limit)), next_cursor: null });
}
