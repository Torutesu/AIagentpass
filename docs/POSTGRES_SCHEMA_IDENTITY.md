# PostgreSQL schema identity

Hosted readiness measures the live PostgreSQL schema in one `REPEATABLE READ
READ ONLY` transaction. The measured snapshot is version 2 and includes:

- relations, RLS flags, owners, and ACLs;
- column defaults, generated/identity flags;
- constraint validation and deferrability;
- index validity and access method;
- sequence parameters and ownership;
- policy command, mode, and roles;
- object ACLs and default privileges;
- the applied migration ledger.

The connection's resolved `search_path` must contain only `pg_catalog` and
`public`; hostile or unexpected schemas fail closed. The transaction is rolled
back before the connection is returned to the pool. If rollback cannot be
confirmed, the connection is destroyed.

`database_schema_digest` is the digest of this live snapshot. It is distinct
from `schema_digest`, which identifies the candidate migration manifest. A
promotion must provide fresh `agentpass.database-schema-evidence` containing
the live digest, deployment/source binding, measurement ID, and the
`repeatable_read` isolation claim.

Hosted startup is fail-closed at the listener boundary: a deployment with a
missing or partial deployment identity, or without the exact 32-byte
`AGENTPASS_OPERATIONAL_PROBE_SECRET`, must not expose the Cloud API or its
operational endpoints. Readiness also rejects partial identity objects rather
than treating `ready: true` as sufficient. The operational token is forbidden
in the evaluation profile so it cannot be silently ignored there.

Focused tests do not replace PostgreSQL 16/17 qualification. Release approval
still requires the real-DB RLS, policy, default, sequence, ACL, migration-race,
timeout, and rollback-failure matrix.
