# PostgreSQL 0011 cutover preflight

Migration `0011_control_plane_hosted_cutover.sql` closes tenant-attribution gaps that existed in the legacy schema. Before 0011, `created_by` proved that a member existed, but did not prove that the member belonged to the row's organization. Applying a validated composite foreign key directly can therefore abort on an otherwise historically legal database.

The cutover is intentionally staged:

1. Run the read-only preflight against the database that will be migrated.
2. Repair or quarantine every reported row. Do not rewrite attribution without an approved data-owner decision and an audit record.
3. Apply migration 0011. Its internal preflight is a second fail-closed check. The new composite foreign keys are installed as `NOT VALID`, so new writes are protected while historical data is being reviewed.
4. Run the preflight with `--validate`. This runs all four tenant foreign-key validations in one transaction. A failure rolls the validation transaction back and leaves the constraints `NOT VALID`.

```sh
export AGENTPASS_DATABASE_URL='postgresql://USER:PASSWORD@HOST/DATABASE?sslmode=verify-full'
node scripts/postgres/preflight-0011.mjs

# Apply the reviewed migration with the normal PostgreSQL migration runner.
# Do not bypass the runner or edit schema_migrations by hand.

node scripts/postgres/preflight-0011.mjs --validate
```

The preflight only prints counts by table; it never prints member IDs, database URLs, credentials, or row contents. The stable blocking diagnostic is:

`AGENTPASS_0011_PREFLIGHT_CROSS_TENANT_CREATED_BY`

Its remediation is to repair or quarantine the listed rows so `created_by` is a member of the same organization, rerun the preflight, and retry migration 0011. Database connection failures and post-migration validation failures also use stable `AGENTPASS_0011_PREFLIGHT_*` diagnostics and fail closed.

The migration itself contains the same query and diagnostic so an operator who accidentally invokes 0011 without the external preflight still receives an actionable rollback instead of a generic composite-FK error.
