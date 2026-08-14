import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const migrationUrl = new URL("../../../../contracts/postgres/0044_platform_promotion_approvals.sql", import.meta.url);

test("0044 is a forward-only transactional deployment-scoped approval schema", async () => {
  const sql = await readFile(migrationUrl, "utf8");

  assert.match(sql.trim(), /^BEGIN;[\s\S]*COMMIT;$/u);
  assert.doesNotMatch(sql, /DROP\s+(?:TABLE|COLUMN|INDEX)|TRUNCATE\s+TABLE|ALTER\s+TABLE/iu);
  assert.doesNotMatch(sql, /organization_id/iu);
  assert.match(sql, /CREATE TABLE platform_promotion_approvals[\s\S]*approval_id uuid PRIMARY KEY/u);
  assert.match(sql, /deployment_id text NOT NULL[\s\S]*environment text NOT NULL[\s\S]*candidate_id text NOT NULL/u);
  assert.match(sql, /source_commit text NOT NULL[\s\S]*source_tree text NOT NULL[\s\S]*product_pkg_sha256 text NOT NULL[\s\S]*image_digest text NOT NULL[\s\S]*sbom_sha256 text NOT NULL/u);
  assert.match(sql, /qualification_report_digests text\[\] NOT NULL[\s\S]*array_ndims\(qualification_report_digests\) = 1[\s\S]*cardinality\(qualification_report_digests\) BETWEEN 1 AND 16[\s\S]*agentpass_platform_promotion_approval_sorted_unique_array/u);
  assert.match(sql, /release_manifest_schema_version integer NOT NULL[\s\S]*CHECK \(release_manifest_schema_version = 4\)[\s\S]*release_manifest_sha256 text NOT NULL/u);
  assert.match(sql, /policy_id text NOT NULL[\s\S]*policy_version integer NOT NULL[\s\S]*approval_version integer NOT NULL[\s\S]*decision text NOT NULL[\s\S]*CHECK \(decision = 'approved'\)/u);
});

test("0044 derives the environment quorum and enforces matching private evidence cardinality", async () => {
  const sql = await readFile(migrationUrl, "utf8");

  assert.match(sql, /quorum_required integer GENERATED ALWAYS AS \([\s\S]*WHEN 'production' THEN 2[\s\S]*WHEN 'staging' THEN 1[\s\S]*\) STORED/u);
  assert.match(sql, /quorum_satisfied boolean GENERATED ALWAYS AS \([\s\S]*cardinality\(platform_principal_ids\) >= CASE environment/u);
  assert.match(sql, /authorization_evidence_digests text\[\] NOT NULL[\s\S]*cardinality\(authorization_evidence_digests\) BETWEEN 1 AND 16[\s\S]*cardinality\(authorization_evidence_digests\) = cardinality\(platform_principal_ids\)/u);
  assert.match(sql, /CHECK \(quorum_satisfied IS TRUE\)/u);
  assert.match(sql, /CREATE FUNCTION agentpass_platform_promotion_approval_sorted_unique_array[\s\S]*item COLLATE "C" <= previous COLLATE "C"[\s\S]*RETURN false/u);
  assert.match(sql, /UNIQUE \(deployment_id, environment, candidate_id, approval_version\)/u);
});

test("0044 derives a domain-separated record digest and makes approvals immutable", async () => {
  const sql = await readFile(migrationUrl, "utf8");

  assert.match(sql, /AgentPass-Platform-Promotion-Approval-v1/u);
  assert.match(sql, /whitespace-free, lexicographically-keyed JSON/u);
  assert.doesNotMatch(sql, /SELECT jsonb?_build_object\(/u);
  assert.match(sql, /'\{"approval_id":'[\s\S]*',"version":'/u);
  assert.match(sql, /sha256\(convert_to\(/u);
  assert.match(sql, /record_digest text GENERATED ALWAYS AS \([\s\S]*agentpass_platform_promotion_approval_record_digest\([\s\S]*\) STORED/u);
  assert.match(sql, /CREATE FUNCTION agentpass_guard_platform_promotion_approval_immutable\(\)[\s\S]*TG_OP = 'DELETE'[\s\S]*platform promotion approvals are immutable after insert/u);
  assert.match(sql, /CREATE TRIGGER platform_promotion_approvals_immutable[\s\S]*BEFORE UPDATE OR DELETE/u);
  assert.match(sql, /decision text NOT NULL[\s\S]*CHECK \(decision = 'approved'\)/u);
  assert.doesNotMatch(sql, /status\s+text|pending/iu);
});

test("0044 keeps authorization arrays out of the public summary and adds exact lookup indexes", async () => {
  const sql = await readFile(migrationUrl, "utf8");
  const publicView = sql.slice(sql.indexOf("CREATE VIEW platform_promotion_approvals_public"));

  assert.match(sql, /CREATE VIEW platform_promotion_approvals_public[\s\S]*record_digest[\s\S]*FROM platform_promotion_approvals/u);
  assert.doesNotMatch(publicView, /platform_principal_ids|authorization_evidence_digests/iu);
  assert.match(sql, /CREATE INDEX platform_promotion_approvals_expiry[\s\S]*ON platform_promotion_approvals \(expires_at/u);
  assert.match(sql, /CREATE INDEX platform_promotion_approvals_candidate[\s\S]*candidate_id/u);
});

test("0044 has the expected migration filename and content checksum shape", async () => {
  const sql = await readFile(migrationUrl, "utf8");

  assert.equal(migrationUrl.pathname.endsWith("/0044_platform_promotion_approvals.sql"), true);
  assert.match(sql, /BEGIN;[\s\S]*COMMIT;/u);
});
