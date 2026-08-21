export type DeploymentReadiness = Readonly<{
  version: 1;
  ready: boolean;
  status: string;
  code: string;
  deploymentIdentity: Readonly<{
    version: 1;
    configured: true;
    ready: true;
    sourceCommit: string;
    sourceTree: string;
    imageDigest: string;
    deploymentId: string;
    revision: string;
    schemaDigest: string;
    catalogDigest: string;
    databaseSchemaDigest: string;
  }>;
}>;

const ROOT_KEYS = ["version", "ready", "status", "code", "deployment_identity"];
const IDENTITY_KEYS = ["version", "configured", "ready", "source_commit", "source_tree", "image_digest", "deployment_id", "revision", "schema_digest", "catalog_digest", "database_schema_digest"];
const SHA = /^[0-9a-f]{40}$/u;
const DIGEST = /^[0-9a-f]{64}$/u;
const IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u;

export class DeploymentReadinessParseError extends Error {
  constructor(path: string, reason: string) {
    super(`Invalid deployment readiness at ${path}: ${reason}`);
    this.name = "DeploymentReadinessParseError";
  }
}

export function parseDeploymentReadiness(value: unknown): DeploymentReadiness {
  const root = record(value, "$", ROOT_KEYS);
  if (root.version !== 1 || typeof root.ready !== "boolean" || typeof root.status !== "string" || typeof root.code !== "string") fail("$", "root fields");
  const identity = record(root.deployment_identity, "$.deployment_identity", IDENTITY_KEYS);
  if (identity.version !== 1 || identity.configured !== true || identity.ready !== true
    || !stringMatch(identity.source_commit, SHA) || !stringMatch(identity.source_tree, SHA)
    || typeof identity.image_digest !== "string" || !/^sha256:[0-9a-f]{64}$/u.test(identity.image_digest)
    || !stringMatch(identity.deployment_id, IDENTIFIER) || !stringMatch(identity.revision, IDENTIFIER)
    || !stringMatch(identity.schema_digest, DIGEST) || !stringMatch(identity.catalog_digest, DIGEST) || !stringMatch(identity.database_schema_digest, DIGEST)) {
    fail("$.deployment_identity", "identity fields");
  }
  return Object.freeze({
    version: 1,
    ready: root.ready,
    status: root.status,
    code: root.code,
    deploymentIdentity: Object.freeze({
      version: 1,
      configured: true,
      ready: true,
      sourceCommit: identity.source_commit,
      sourceTree: identity.source_tree,
      imageDigest: identity.image_digest,
      deploymentId: identity.deployment_id,
      revision: identity.revision,
      schemaDigest: identity.schema_digest,
      catalogDigest: identity.catalog_digest,
      databaseSchemaDigest: identity.database_schema_digest,
    }),
  });
}

function record(value: unknown, path: string, required: string[]): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) fail(path, "object required");
  const result = value as Record<string, unknown>;
  const keys = Object.keys(result);
  if (keys.some((key) => !required.includes(key)) || required.some((key) => !Object.hasOwn(result, key))) fail(path, "unknown or missing field");
  return result;
}

function stringMatch(value: unknown, pattern: RegExp): value is string {
  return typeof value === "string" && pattern.test(value);
}

function fail(path: string, reason: string): never {
  throw new DeploymentReadinessParseError(path, reason);
}
