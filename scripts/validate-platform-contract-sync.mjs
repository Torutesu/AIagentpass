import fs from "node:fs";
import path from "node:path";
import { pathToFileURL } from "node:url";

import Ajv2020 from "ajv/dist/2020.js";
import addFormats from "ajv-formats";

const repositoryRoot = path.resolve(import.meta.dirname, "..");

export const PLATFORM_CONTRACT_SYNC = Object.freeze({
  openapi: "openapi/platform-v1.json",
  catalog: "catalog-v1.json",
  vector: "vectors/platform-promotion-request-digest-v1.json",
  authorizedPromotionPath: "/api/platform/v1/promotions",
  legacyHostedPaths: Object.freeze([
    "/v1/platform/promotions",
    "/v1/platform/promotions/replay"
  ]),
  platformPaths: Object.freeze({
    "/api/platform/v1/sessions/challenges": "createPlatformSessionChallenge",
    "/api/platform/v1/sessions": "verifyPlatformSessionAssertion",
    "/api/platform/v1/sessions/revoke": "revokeCurrentPlatformSession",
    "/api/platform/v1/promotions": "issuePlatformPromotion"
  }),
  schemaFixtures: Object.freeze({
    "platform-promotion-issue-request-v1.schema.json": Object.freeze([
      "platform-promotion-issue-request.contract.json"
    ]),
    "platform-promotion-issue-result-v1.schema.json": Object.freeze([
      "platform-promotion-issue-result.contract.json"
    ]),
    "platform-promotion-issue-envelope-v1.schema.json": Object.freeze([
      "platform-promotion-issue-201.contract.json",
      "platform-promotion-issue-200-retry.contract.json"
    ])
  }),
  catalogEntries: Object.freeze({
    "schema.platform-promotion-issue-request-v1": Object.freeze({
      source: "schemas/platform-promotion-issue-request-v1.schema.json",
      requiredFixtures: Object.freeze([
        "contracts/fixtures/platform-promotion-issue-request.contract.json",
        "contracts/vectors/platform-promotion-request-digest-v1.json"
      ]),
      implementationRefs: Object.freeze([
        "contracts/openapi/platform-v1.json",
        "test/platform-promotion-issue-contract.test.mjs"
      ])
    }),
    "schema.platform-promotion-issue-result-v1": Object.freeze({
      source: "schemas/platform-promotion-issue-result-v1.schema.json",
      requiredFixtures: Object.freeze([
        "contracts/fixtures/platform-promotion-issue-result.contract.json"
      ]),
      implementationRefs: Object.freeze([
        "contracts/openapi/platform-v1.json",
        "apps/cloud-api/src/platform-promotion-http-contract.mjs",
        "test/platform-promotion-issue-contract.test.mjs"
      ])
    }),
    "schema.platform-promotion-issue-envelope-v1": Object.freeze({
      source: "schemas/platform-promotion-issue-envelope-v1.schema.json",
      requiredFixtures: Object.freeze([
        "contracts/fixtures/platform-promotion-issue-201.contract.json",
        "contracts/fixtures/platform-promotion-issue-200-retry.contract.json"
      ]),
      implementationRefs: Object.freeze([
        "contracts/openapi/platform-v1.json",
        "apps/cloud-api/src/platform-promotion-http-contract.mjs",
        "test/platform-promotion-issue-contract.test.mjs"
      ])
    })
  })
});

const REQUIRED_EXTERNAL_SCHEMA_REFS = Object.freeze(new Map([
  ["PlatformSessionAssertion", "platform-session-assertion-v1.schema.json"],
  ["PlatformSessionHttpAssertionResponse", "platform-session-http-assertion-response-v1.schema.json"],
  ["PlatformPromotionIssueRequest", "platform-promotion-issue-request-v1.schema.json"],
  ["PlatformPromotionIssueResult", "platform-promotion-issue-result-v1.schema.json"],
  ["PlatformPromotionIssueEnvelope", "platform-promotion-issue-envelope-v1.schema.json"]
]));

const EXPECTED_PLATFORM_SCHEMA_COMPONENTS = Object.freeze({
  PlatformPromotionIssueRequest: "platform-promotion-issue-request-v1.schema.json",
  PlatformPromotionIssueResult: "platform-promotion-issue-result-v1.schema.json",
  PlatformPromotionIssueEnvelope: "platform-promotion-issue-envelope-v1.schema.json"
});

function fail(message) {
  throw new Error(`platform contract sync failed: ${message}`);
}

function readJson(filePath) {
  try {
    return JSON.parse(fs.readFileSync(filePath, "utf8"));
  } catch (error) {
    fail(`${path.relative(repositoryRoot, filePath)} is not valid JSON (${error.message})`);
  }
}

function readText(filePath) {
  try {
    return fs.readFileSync(filePath, "utf8");
  } catch (error) {
    fail(`${path.relative(repositoryRoot, filePath)} is not readable (${error.message})`);
  }
}

function exactKeys(value, expected, label) {
  if (!value || typeof value !== "object" || Array.isArray(value)) fail(`${label} must be an object`);
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  if (JSON.stringify(actual) !== JSON.stringify(wanted)) {
    fail(`${label} keys drifted: expected ${wanted.join(",")}, found ${actual.join(",")}`);
  }
}

function exactArray(actual, expected, label) {
  if (JSON.stringify(actual) !== JSON.stringify(expected)) {
    fail(`${label} drifted: expected ${JSON.stringify(expected)}, found ${JSON.stringify(actual)}`);
  }
}

function refBasename(reference) {
  if (typeof reference !== "string" || !reference.startsWith("../schemas/")) return undefined;
  return path.basename(reference.split("#", 1)[0]);
}

function assertSchemaReference(reference, expectedName, label) {
  if (refBasename(reference) !== expectedName) fail(`${label} must reference ${expectedName}`);
}

function assertNoLegacyHostedRoutes(value, label) {
  const serialized = typeof value === "string" ? value : JSON.stringify(value);
  for (const legacyPath of PLATFORM_CONTRACT_SYNC.legacyHostedPaths) {
    if (serialized.includes(legacyPath)) fail(`${label} reintroduces hosted legacy route ${legacyPath}`);
  }
}

/**
 * Validate source-level Hosted route composition independently of the JSON
 * contract files. This is exported so regression tests can mutate the route
 * inventory without changing files in the working tree.
 */
export function validateHostedPlatformRouteInventory({
  runtimeSource,
  promotionHttpSource,
  runtimePromotionPaths,
  runtimeSessionPaths
} = {}) {
  if (typeof runtimeSource !== "string") fail("Hosted runtime source is missing");
  if (typeof promotionHttpSource !== "string") fail("Platform promotion HTTP source is missing");
  if (!runtimeSource.includes("createPlatformPromotionHttpApi")) fail("Hosted runtime does not compose the authorized promotion HTTP boundary");
  if (!runtimeSource.includes("platformPromotionHttpApi")) fail("Hosted runtime does not expose the authorized promotion HTTP seam");
  for (const forbidden of ["createPlatformPromotionIssuanceService", "platformPromotionIssuanceService", "handlePlatformPromotion"]) {
    if (new RegExp(`\\b${forbidden}\\b`, "u").test(runtimeSource)) {
      fail(`Hosted runtime composes evaluation-only legacy symbol ${forbidden}`);
    }
  }
  if (!promotionHttpSource.includes("PLATFORM_AUTHORIZED_PROMOTION_ISSUE_PATH")) {
    fail("Platform promotion HTTP source is not bound to the authorized path constant");
  }
  exactKeys(runtimePromotionPaths, ["issue"], "Hosted promotion route inventory");
  if (runtimePromotionPaths.issue !== PLATFORM_CONTRACT_SYNC.authorizedPromotionPath) {
    fail(`Hosted promotion route must be ${PLATFORM_CONTRACT_SYNC.authorizedPromotionPath}`);
  }
  const uniqueSessionPaths = [...new Set(Object.values(runtimeSessionPaths ?? {}))].sort();
  exactArray(uniqueSessionPaths, [
    "/api/platform/v1/sessions",
    "/api/platform/v1/sessions/challenges",
    "/api/platform/v1/sessions/revoke"
  ], "Hosted Platform Session route inventory");
  return true;
}

function validatePlatformOpenApi(document, schemas) {
  if (document.openapi !== "3.1.0") fail("platform OpenAPI must use 3.1.0");
  assertNoLegacyHostedRoutes(document, "Platform OpenAPI");
  exactArray(Object.keys(document.paths ?? {}).sort(), Object.keys(PLATFORM_CONTRACT_SYNC.platformPaths).sort(), "Platform OpenAPI path inventory");
  for (const [route, operationId] of Object.entries(PLATFORM_CONTRACT_SYNC.platformPaths)) {
    const methods = document.paths[route];
    exactKeys(methods, ["post"], `Platform OpenAPI ${route}`);
    if (methods.post.operationId !== operationId) fail(`${route} operationId drifted`);
  }
  const components = document.components?.schemas ?? {};
  for (const [component, schemaName] of Object.entries(EXPECTED_PLATFORM_SCHEMA_COMPONENTS)) {
    assertSchemaReference(components[component]?.$ref, schemaName, `Platform OpenAPI component ${component}`);
    if (!schemas.has(schemaName)) fail(`Platform OpenAPI component ${component} references absent ${schemaName}`);
  }
  assertSchemaReference(
    document.paths["/api/platform/v1/sessions"].post.requestBody?.content?.["application/json"]?.schema?.$ref,
    "platform-session-assertion-v1.schema.json",
    "Platform Session assertion request body"
  );
  assertSchemaReference(components.PlatformSessionHttpAssertionResponse?.$ref, "platform-session-http-assertion-response-v1.schema.json", "Platform Session assertion response component");
  assertSchemaReference(
    document.paths[PLATFORM_CONTRACT_SYNC.authorizedPromotionPath].post.requestBody?.content?.["application/json"]?.schema?.$ref,
    EXPECTED_PLATFORM_SCHEMA_COMPONENTS.PlatformPromotionIssueRequest,
    "Platform promotion request body"
  );
  for (const responseName of ["PlatformPromotionIssued", "PlatformPromotionRetried"]) {
    const response = document.components?.responses?.[responseName]?.content?.["application/json"]?.schema;
    if (response?.$ref !== "#/components/schemas/PlatformPromotionIssueEnvelope") {
      fail(`Platform OpenAPI response ${responseName} must use PlatformPromotionIssueEnvelope`);
    }
  }
  const operation = document.paths[PLATFORM_CONTRACT_SYNC.authorizedPromotionPath].post;
  if (operation["x-agentpass-request-binding"]?.["canonical-form"] !== "canonical-json({candidate_id,deployment_id,environment,idempotency_key,operation,organization_id,promotion_id})") {
    fail("Platform promotion canonical binding drifted from the digest vector");
  }
  return true;
}

function validateCatalog(catalog, contractsRoot) {
  const entries = new Map((catalog.entries ?? []).map((entry) => [entry.id, entry]));
  for (const [id, expected] of Object.entries(PLATFORM_CONTRACT_SYNC.catalogEntries)) {
    const entry = entries.get(id);
    if (!entry) fail(`catalog is missing ${id}`);
    if (entry.source !== expected.source) fail(`${id} source drifted`);
    for (const reference of expected.requiredFixtures) {
      if (!entry.compatibility_fixtures?.includes(reference)) fail(`${id} is missing compatibility fixture ${reference}`);
    }
    for (const reference of expected.implementationRefs) {
      if (!entry.implementation_refs?.includes(reference)) fail(`${id} is missing implementation reference ${reference}`);
    }
    if (!fs.existsSync(path.join(contractsRoot, expected.source))) fail(`${id} source file is absent`);
  }

  const platformDocument = readJson(path.join(contractsRoot, PLATFORM_CONTRACT_SYNC.openapi));
  for (const componentName of REQUIRED_EXTERNAL_SCHEMA_REFS.keys()) {
    const schemaName = REQUIRED_EXTERNAL_SCHEMA_REFS.get(componentName);
    const entry = [...entries.values()].find((candidate) => candidate.source === `schemas/${schemaName}`);
    if (!entry) fail(`catalog has no schema entry for Platform OpenAPI component ${componentName}`);
    if (!fs.existsSync(path.join(contractsRoot, entry.source))) fail(`${entry.id} source file is absent`);
    const catalogOpenApiAnchor = `contracts/${PLATFORM_CONTRACT_SYNC.openapi}`;
    if (!entry.implementation_refs?.includes(catalogOpenApiAnchor)) {
      fail(`${entry.id} is not anchored to ${catalogOpenApiAnchor}`);
    }
  }
  for (const [route, operation] of Object.entries(platformDocument.paths)) {
    if (!operation.post?.operationId) fail(`Platform OpenAPI ${route} has no operationId for catalog synchronization`);
  }
  return true;
}

function createSchemaValidator(contractsRoot) {
  const validator = new Ajv2020({ allErrors: true, strict: true, strictRequired: false });
  addFormats(validator);
  const schemaRoot = path.join(contractsRoot, "schemas");
  for (const name of fs.readdirSync(schemaRoot).filter((item) => item.endsWith(".schema.json")).sort()) {
    validator.addSchema(readJson(path.join(schemaRoot, name)));
  }
  return validator;
}

function validateFixtures(contractsRoot, schemas) {
  const validator = createSchemaValidator(contractsRoot);
  for (const [schemaName, fixtureNames] of Object.entries(PLATFORM_CONTRACT_SYNC.schemaFixtures)) {
    const schema = schemas.get(schemaName);
    if (!schema) fail(`fixture mapping references absent ${schemaName}`);
    const validate = validator.getSchema(schema.$id);
    if (!validate) fail(`Ajv could not load ${schemaName}`);
    for (const fixtureName of fixtureNames) {
      const fixture = readJson(path.join(contractsRoot, "fixtures", fixtureName));
      if (!validate(fixture)) fail(`${fixtureName} does not satisfy ${schemaName}: ${validator.errorsText(validate.errors, { separator: "; " })}`);
    }
  }
  const issued = readJson(path.join(contractsRoot, "fixtures/platform-promotion-issue-201.contract.json"));
  const retried = readJson(path.join(contractsRoot, "fixtures/platform-promotion-issue-200-retry.contract.json"));
  if (issued.promotion?.replayed !== false || retried.promotion?.replayed !== true) fail("promotion issue fixtures do not represent 201/200 replay semantics");
  const issuedPublic = { ...issued.promotion, replayed: undefined };
  const retriedPublic = { ...retried.promotion, replayed: undefined };
  delete issuedPublic.replayed;
  delete retriedPublic.replayed;
  if (JSON.stringify(issuedPublic) !== JSON.stringify(retriedPublic)) fail("201 and 200 promotion fixtures drifted in their public result");
  return true;
}

async function validateDigestVector(contractsRoot, root) {
  const vector = readJson(path.join(contractsRoot, PLATFORM_CONTRACT_SYNC.vector));
  exactKeys(vector, ["canonical_form", "input", "request_digest_sha256", "type", "version"], "Platform digest vector");
  if (vector.version !== 1 || vector.type !== "agentpass.platform-promotion-request-digest-vector") fail("Platform digest vector identity drifted");
  if (vector.canonical_form !== "canonical-json({candidate_id,deployment_id,environment,idempotency_key,operation,organization_id,promotion_id})") fail("Platform digest vector canonical form drifted");
  if (!/^[0-9a-f]{64}$/u.test(vector.request_digest_sha256)) fail("Platform digest vector digest is not a SHA-256 hex value");
  exactKeys(vector.input, ["candidate_id", "deployment_id", "environment", "idempotency_key", "operation", "organization_id", "promotion_id"], "Platform digest vector input");
  const implementation = await import(pathToFileURL(path.join(root, "apps/cloud-api/src/platform-promotion-http-contract.mjs")).href);
  const calculated = implementation.platformPromotionAuthorizationRequestDigest({
    promotion_id: vector.input.promotion_id,
    deployment_id: vector.input.deployment_id,
    environment: vector.input.environment,
    candidate_id: vector.input.candidate_id,
    idempotency_key: vector.input.idempotency_key
  }, { organizationId: vector.input.organization_id, operation: vector.input.operation });
  if (calculated !== vector.request_digest_sha256) fail(`Platform digest vector does not match implementation: expected ${calculated}, found ${vector.request_digest_sha256}`);
  if (implementation.PLATFORM_AUTHORIZED_PROMOTION_ISSUE_PATH !== PLATFORM_CONTRACT_SYNC.authorizedPromotionPath) fail("implementation authorized promotion path drifted");
  if (implementation.PLATFORM_PROMOTION_OPERATIONS.issue !== vector.input.operation) fail("implementation issue operation drifted from digest vector");
  return true;
}

export async function validatePlatformContractSync({ root = repositoryRoot, contractsRoot = path.join(root, "contracts") } = {}) {
  const platformDocument = readJson(path.join(contractsRoot, PLATFORM_CONTRACT_SYNC.openapi));
  const catalog = readJson(path.join(contractsRoot, PLATFORM_CONTRACT_SYNC.catalog));
  const schemas = new Map();
  for (const schemaName of Object.keys(PLATFORM_CONTRACT_SYNC.schemaFixtures)) {
    schemas.set(schemaName, readJson(path.join(contractsRoot, "schemas", schemaName)));
  }
  validatePlatformOpenApi(platformDocument, schemas);
  validateCatalog(catalog, contractsRoot);
  validateFixtures(contractsRoot, schemas);
  await validateDigestVector(contractsRoot, root);

  const promotionImplementation = await import(pathToFileURL(path.join(root, "apps/cloud-api/src/platform-promotion-http-api.mjs")).href);
  const sessionImplementation = await import(pathToFileURL(path.join(root, "apps/cloud-api/src/platform-session-http-api.mjs")).href);
  const runtimeSource = readText(path.join(root, "apps/cloud-api/src/runtime.mjs"));
  const promotionHttpSource = readText(path.join(root, "apps/cloud-api/src/platform-promotion-http-api.mjs"));
  validateHostedPlatformRouteInventory({
    runtimeSource,
    promotionHttpSource,
    runtimePromotionPaths: promotionImplementation.PLATFORM_PROMOTION_HTTP_PATHS,
    runtimeSessionPaths: sessionImplementation.PLATFORM_SESSION_HTTP_PATHS
  });

  return Object.freeze({
    authorized_promotion_path: PLATFORM_CONTRACT_SYNC.authorizedPromotionPath,
    platform_openapi_paths: Object.keys(platformDocument.paths).length,
    synchronized_schema_entries: Object.keys(PLATFORM_CONTRACT_SYNC.catalogEntries).length,
    synchronized_fixtures: Object.values(PLATFORM_CONTRACT_SYNC.schemaFixtures).reduce((total, names) => total + names.length, 0),
    digest_vector: PLATFORM_CONTRACT_SYNC.vector,
    hosted_legacy_routes: "absent"
  });
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? "").href) {
  try {
    const report = await validatePlatformContractSync();
    process.stdout.write(`validated Platform contract sync: ${JSON.stringify(report)}\n`);
  } catch (error) {
    process.stderr.write(`${error.message}\n`);
    process.exitCode = 1;
  }
}
