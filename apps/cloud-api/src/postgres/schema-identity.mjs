import crypto from "node:crypto";
import { canonicalJson } from "../../../../packages/protocol/src/index.mjs";

export const POSTGRES_SCHEMA_IDENTITY_QUERY = `
WITH tables AS (
  SELECT n.nspname AS schema_name, c.relname AS relation_name, c.relkind, pg_catalog.pg_get_userbyid(c.relowner) AS owner,
    c.relrowsecurity, c.relforcerowsecurity, c.relacl
  FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
  WHERE n.nspname NOT LIKE 'pg_%' AND n.nspname <> 'information_schema' AND c.relkind IN ('r','p','v','m','S')
), columns AS (
  SELECT n.nspname AS schema_name, c.relname AS relation_name, a.attname AS column_name, a.attnum, pg_catalog.format_type(a.atttypid, a.atttypmod) AS data_type, a.attnotnull,
    a.atthasdef, a.attidentity, a.attgenerated, pg_catalog.pg_get_expr(d.adbin, d.adrelid) AS default_expression
  FROM pg_attribute a JOIN pg_class c ON c.oid = a.attrelid JOIN pg_namespace n ON n.oid = c.relnamespace
    LEFT JOIN pg_attrdef d ON d.adrelid = a.attrelid AND d.adnum = a.attnum
  WHERE a.attnum > 0 AND NOT a.attisdropped AND n.nspname NOT LIKE 'pg_%' AND n.nspname <> 'information_schema'
), constraints AS (
  SELECT n.nspname AS schema_name, c.relname AS relation_name, con.conname AS constraint_name, con.contype, pg_get_constraintdef(con.oid, true) AS definition,
    con.convalidated, con.condeferrable, con.condeferred, con.connoinherit
  FROM pg_constraint con JOIN pg_class c ON c.oid = con.conrelid JOIN pg_namespace n ON n.oid = c.relnamespace
  WHERE n.nspname NOT LIKE 'pg_%' AND n.nspname <> 'information_schema'
), indexes AS (
  SELECT n.nspname AS schema_name, c.relname AS relation_name, i.relname AS index_name, pg_get_indexdef(i.oid) AS definition,
    am.amname AS access_method, x.indisunique, x.indisprimary, x.indisexclusion, x.indisvalid, x.indisready, x.indislive
  FROM pg_index x JOIN pg_class c ON c.oid = x.indrelid JOIN pg_class i ON i.oid = x.indexrelid JOIN pg_namespace n ON n.oid = c.relnamespace JOIN pg_am am ON am.oid = i.relam
  WHERE n.nspname NOT LIKE 'pg_%' AND n.nspname <> 'information_schema'
), functions AS (
  SELECT n.nspname AS schema_name, p.proname AS function_name, pg_get_function_identity_arguments(p.oid) AS arguments, pg_get_functiondef(p.oid) AS definition,
    pg_catalog.pg_get_userbyid(p.proowner) AS owner, p.proacl, p.prosecdef, p.proleakproof, p.provolatile, p.proparallel, p.proconfig
  FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
  WHERE n.nspname NOT LIKE 'pg_%' AND n.nspname <> 'information_schema'
), triggers AS (
  SELECT n.nspname AS schema_name, c.relname AS relation_name, t.tgname AS trigger_name, pg_get_triggerdef(t.oid, true) AS definition, t.tgenabled
  FROM pg_trigger t JOIN pg_class c ON c.oid = t.tgrelid JOIN pg_namespace n ON n.oid = c.relnamespace
  WHERE NOT t.tgisinternal AND n.nspname NOT LIKE 'pg_%' AND n.nspname <> 'information_schema'
), policies AS (
  SELECT n.nspname AS schema_name, c.relname AS relation_name, p.polname AS policy_name, p.polpermissive, p.polcmd, p.polroles,
    pg_get_expr(p.polqual, p.polrelid) AS using_expression, pg_get_expr(p.polwithcheck, p.polrelid) AS check_expression
  FROM pg_policy p JOIN pg_class c ON c.oid = p.polrelid JOIN pg_namespace n ON n.oid = c.relnamespace
  WHERE n.nspname NOT LIKE 'pg_%' AND n.nspname <> 'information_schema'
), schemas AS (
  SELECT n.nspname AS schema_name, pg_catalog.pg_get_userbyid(n.nspowner) AS owner, n.nspacl
  FROM pg_namespace n
  WHERE n.nspname NOT LIKE 'pg_%' AND n.nspname <> 'information_schema'
), sequences AS (
  SELECT n.nspname AS schema_name, c.relname AS sequence_name, pg_catalog.pg_get_userbyid(c.relowner) AS owner,
    s.seqstart, s.seqincrement, s.seqmin, s.seqmax, s.seqcache, s.seqcycle, pg_catalog.format_type(s.seqtypid, NULL) AS data_type, c.relacl,
    own_n.nspname AS owned_by_schema, own_c.relname AS owned_by_relation, own_a.attname AS owned_by_column
  FROM pg_sequence s JOIN pg_class c ON c.oid = s.seqrelid JOIN pg_namespace n ON n.oid = c.relnamespace
    LEFT JOIN pg_depend dep ON dep.objid = c.oid AND dep.deptype = 'a'
    LEFT JOIN pg_class own_c ON own_c.oid = dep.refobjid
    LEFT JOIN pg_namespace own_n ON own_n.oid = own_c.relnamespace
    LEFT JOIN pg_attribute own_a ON own_a.attrelid = dep.refobjid AND own_a.attnum = dep.refobjsubid
  WHERE n.nspname NOT LIKE 'pg_%' AND n.nspname <> 'information_schema'
), object_acls AS (
  SELECT n.nspname AS schema_name, c.relname AS object_name,
    CASE WHEN c.relkind = 'S' THEN 'sequence' ELSE 'table' END AS object_type,
    pg_catalog.pg_get_userbyid(c.relowner) AS owner, bool_and(c.relacl IS NULL) AS acl_is_null,
    COALESCE(jsonb_agg(jsonb_build_object(
      'grantor', pg_catalog.pg_get_userbyid(ax.grantor),
      'grantee', CASE WHEN ax.grantee = 0 THEN 'PUBLIC' ELSE pg_catalog.pg_get_userbyid(ax.grantee) END,
      'privilege', ax.privilege_type, 'is_grantable', ax.is_grantable
    ) ORDER BY ax.grantor, ax.grantee, ax.privilege_type) FILTER (WHERE ax.grantor IS NOT NULL), '[]'::jsonb) AS acl
  FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
    LEFT JOIN LATERAL pg_catalog.aclexplode(c.relacl) ax ON true
  WHERE n.nspname NOT LIKE 'pg_%' AND n.nspname <> 'information_schema' AND c.relkind IN ('r','p','v','m','S')
  -- aclitem[] has no portable GROUP BY implementation on PostgreSQL 17.
  -- The relation has one relacl value, so aggregate only its NULL predicate
  -- while grouping on stable scalar identity fields.
  GROUP BY n.nspname, c.relname, c.relkind, c.relowner
), default_privileges AS (
  SELECT pg_catalog.pg_get_userbyid(d.defaclrole) AS grantor_role,
    NULLIF(ns.nspname, '') AS schema_name,
    CASE d.defaclobjtype WHEN 'r' THEN 'table' WHEN 'S' THEN 'sequence' WHEN 'f' THEN 'function' WHEN 'T' THEN 'type' WHEN 'n' THEN 'schema' ELSE d.defaclobjtype::text END AS object_type,
    CASE WHEN ax.grantee = 0 THEN 'PUBLIC' ELSE pg_catalog.pg_get_userbyid(ax.grantee) END AS grantee,
    ax.privilege_type AS privilege, ax.is_grantable
  FROM pg_default_acl d
    LEFT JOIN pg_namespace ns ON ns.oid = NULLIF(d.defaclnamespace, 0)
    CROSS JOIN LATERAL pg_catalog.aclexplode(d.defaclacl) ax
), migration_ledger AS (
  SELECT version, checksum FROM public.schema_migrations ORDER BY version
)
SELECT jsonb_build_object(
  'version', 2,
  'schemas', COALESCE((SELECT jsonb_agg(to_jsonb(s) ORDER BY schema_name) FROM schemas s), '[]'::jsonb),
  'tables', COALESCE((SELECT jsonb_agg(to_jsonb(t) ORDER BY schema_name, relation_name, relkind) FROM tables t), '[]'::jsonb),
  'columns', COALESCE((SELECT jsonb_agg(to_jsonb(c) ORDER BY schema_name, relation_name, attnum) FROM columns c), '[]'::jsonb),
  'constraints', COALESCE((SELECT jsonb_agg(to_jsonb(c) ORDER BY schema_name, relation_name, constraint_name) FROM constraints c), '[]'::jsonb),
  'indexes', COALESCE((SELECT jsonb_agg(to_jsonb(i) ORDER BY schema_name, relation_name, index_name) FROM indexes i), '[]'::jsonb),
  'sequences', COALESCE((SELECT jsonb_agg(to_jsonb(s) ORDER BY schema_name, sequence_name) FROM sequences s), '[]'::jsonb),
  'functions', COALESCE((SELECT jsonb_agg(to_jsonb(f) ORDER BY schema_name, function_name, arguments) FROM functions f), '[]'::jsonb),
  'triggers', COALESCE((SELECT jsonb_agg(to_jsonb(t) ORDER BY schema_name, relation_name, trigger_name) FROM triggers t), '[]'::jsonb),
  'policies', COALESCE((SELECT jsonb_agg(to_jsonb(p) ORDER BY schema_name, relation_name, policy_name) FROM policies p), '[]'::jsonb),
  'object_acls', COALESCE((SELECT jsonb_agg(to_jsonb(a) ORDER BY schema_name, object_type, object_name) FROM object_acls a), '[]'::jsonb),
  'default_privileges', COALESCE((SELECT jsonb_agg(to_jsonb(d) ORDER BY grantor_role, schema_name, object_type, grantee, privilege) FROM default_privileges d), '[]'::jsonb)
  , 'migration_ledger', COALESCE((SELECT jsonb_agg(to_jsonb(m) ORDER BY version) FROM migration_ledger m), '[]'::jsonb)
) AS snapshot`;

const MAX_SNAPSHOT_BYTES = 4 * 1024 * 1024;

export function postgresSchemaIdentityDigest(snapshot) {
  if (!snapshot || typeof snapshot !== "object" || Array.isArray(snapshot)) throw new TypeError("schema snapshot is invalid");
  const bytes = Buffer.from(canonicalJson(snapshot), "utf8");
  if (bytes.length > MAX_SNAPSHOT_BYTES) throw new TypeError("schema snapshot is too large");
  return crypto.createHash("sha256").update(bytes).digest("hex");
}

export async function measurePostgresSchemaIdentity({ client, expectedDigest } = {}) {
  if (!client || typeof client.query !== "function" || typeof expectedDigest !== "string" || !/^[0-9a-f]{64}$/u.test(expectedDigest)) return Object.freeze({ ok: false, code: "schema_identity_unconfigured", digest: null });
  let began = false;
  let result;
  try {
    await client.query("BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY");
    began = true;
    const searchPath = await client.query("SELECT pg_catalog.current_setting('search_path', false) AS raw_search_path, pg_catalog.current_schemas(false) AS resolved_search_path");
    const resolved = searchPath?.rows?.[0]?.resolved_search_path;
    if (!Array.isArray(resolved) || resolved.some((schema) => !["pg_catalog", "public"].includes(schema))) throw new Error("unsafe search_path");
    await client.query("SET LOCAL search_path TO pg_catalog, public");
    const queryResult = await client.query(POSTGRES_SCHEMA_IDENTITY_QUERY);
    const snapshot = queryResult?.rows?.[0]?.snapshot;
    const parsed = typeof snapshot === "string" ? JSON.parse(snapshot) : snapshot;
    const digest = postgresSchemaIdentityDigest(parsed);
    result = { ok: digest === expectedDigest, code: digest === expectedDigest ? "verified" : "schema_identity_mismatch", digest, destroy: false };
  } catch {
    result = { ok: false, code: "schema_identity_unavailable", digest: null, destroy: false };
  } finally {
    if (began) {
      try { await client.query("ROLLBACK"); } catch {
        result = { ok: false, code: "schema_identity_unavailable", digest: null, destroy: true };
      }
    }
  }
  return Object.freeze(result);
}
