export class FakePgClient {
  constructor({ applied = [], dirty = [], schemaMigrationsExists = true, migrationAttemptsExists = false, failWhen = undefined } = {}) {
    this.calls = [];
    this.applied = structuredClone(applied);
    this.dirty = structuredClone(dirty);
    this.schemaMigrationsExists = schemaMigrationsExists;
    this.migrationAttemptsExists = migrationAttemptsExists;
    this.failWhen = failWhen;
    this.inTransaction = false;
    this.snapshots = [];
  }

  async query(text, params = []) {
    this.calls.push({ text, params: structuredClone(params) });
    if (this.failWhen?.(text, params, this.calls.length)) throw this.failWhen(text, params, this.calls.length);
    if (text === "BEGIN") {
      this.inTransaction = true;
      this.snapshots.push({ applied: structuredClone(this.applied), dirty: structuredClone(this.dirty), schemaMigrationsExists: this.schemaMigrationsExists });
      return { rows: [], rowCount: 0 };
    }
    if (text === "COMMIT") {
      this.inTransaction = false;
      this.snapshots.pop();
      return { rows: [], rowCount: 0 };
    }
    if (text === "ROLLBACK") {
      const snapshot = this.snapshots.pop();
      if (snapshot) Object.assign(this, structuredClone(snapshot));
      this.inTransaction = false;
      return { rows: [], rowCount: 0 };
    }
    if (text.startsWith("SELECT pg_advisory_xact_lock")) return { rows: [{ locked: true }], rowCount: 1 };
    if (text.startsWith("SELECT version, checksum FROM schema_migrations")) {
      if (!this.schemaMigrationsExists) throw missingRelation("schema_migrations");
      return { rows: structuredClone(this.applied), rowCount: this.applied.length };
    }
    if (text.startsWith("SELECT version, checksum, status, finished_at FROM schema_migration_attempts")) {
      if (!this.migrationAttemptsExists) throw missingRelation("schema_migration_attempts");
      return { rows: structuredClone(this.dirty), rowCount: this.dirty.length };
    }
    if (text.startsWith("INSERT INTO schema_migrations")) {
      this.schemaMigrationsExists = true;
      this.applied.push({ version: params[0], checksum: params[1] });
      return { rows: [], rowCount: 1 };
    }
    return { rows: [], rowCount: 0 };
  }
}

export function missingRelation(relation) {
  const error = new Error(`relation "${relation}" does not exist`);
  error.code = "42P01";
  return error;
}
