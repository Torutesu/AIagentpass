import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import {
  PLATFORM_CONTRACT_SYNC,
  validateHostedPlatformRouteInventory,
  validatePlatformContractSync
} from "../scripts/validate-platform-contract-sync.mjs";

const repositoryRoot = path.resolve(import.meta.dirname, "..");
const contractsRoot = path.join(repositoryRoot, "contracts");

function copyContracts() {
  const temporaryRoot = fs.mkdtempSync(path.join(os.tmpdir(), "agentpass-platform-contract-sync-"));
  const temporaryContracts = path.join(temporaryRoot, "contracts");
  fs.cpSync(contractsRoot, temporaryContracts, { recursive: true });
  return { temporaryRoot, temporaryContracts };
}

test("Platform OpenAPI, catalog, schemas, fixtures, digest vector, and hosted route inventory are synchronized", async () => {
  const report = await validatePlatformContractSync();
  assert.deepEqual(report, {
    authorized_promotion_path: "/api/platform/v1/promotions",
    platform_openapi_paths: 4,
    synchronized_schema_entries: 3,
    synchronized_fixtures: 4,
    digest_vector: "vectors/platform-promotion-request-digest-v1.json",
    hosted_legacy_routes: "absent"
  });
});

test("validator rejects a reintroduced hosted legacy route in Platform OpenAPI", async () => {
  const { temporaryRoot, temporaryContracts } = copyContracts();
  try {
    const file = path.join(temporaryContracts, PLATFORM_CONTRACT_SYNC.openapi);
    const document = JSON.parse(fs.readFileSync(file, "utf8"));
    document.paths[PLATFORM_CONTRACT_SYNC.legacyHostedPaths[0]] = { post: { operationId: "legacyPromotion" } };
    fs.writeFileSync(file, `${JSON.stringify(document, null, 2)}\n`);
    await assert.rejects(
      validatePlatformContractSync({ contractsRoot: temporaryContracts, root: repositoryRoot }),
      /reintroduces hosted legacy route/u
    );
  } finally {
    fs.rmSync(temporaryRoot, { recursive: true, force: true });
  }
});

test("validator rejects a hosted runtime downgrade even when evaluation code remains available", () => {
  assert.throws(
    () => validateHostedPlatformRouteInventory({
      runtimeSource: "createPlatformPromotionHttpApi(); platformPromotionHttpApi; platformPromotionIssuanceService;",
      promotionHttpSource: "PLATFORM_AUTHORIZED_PROMOTION_ISSUE_PATH",
      runtimePromotionPaths: { issue: PLATFORM_CONTRACT_SYNC.authorizedPromotionPath },
      runtimeSessionPaths: {
        challenge: "/api/platform/v1/sessions/challenges",
        assertion: "/api/platform/v1/sessions",
        revoke: "/api/platform/v1/sessions/revoke"
      }
    }),
    /evaluation-only legacy symbol platformPromotionIssuanceService/u
  );
});

test("validator rejects implementation route constants that point back to the legacy path", () => {
  assert.throws(
    () => validateHostedPlatformRouteInventory({
      runtimeSource: "createPlatformPromotionHttpApi(); platformPromotionHttpApi;",
      promotionHttpSource: "PLATFORM_AUTHORIZED_PROMOTION_ISSUE_PATH",
      runtimePromotionPaths: { issue: PLATFORM_CONTRACT_SYNC.legacyHostedPaths[0] },
      runtimeSessionPaths: {
        challenge: "/api/platform/v1/sessions/challenges",
        assertion: "/api/platform/v1/sessions",
        revoke: "/api/platform/v1/sessions/revoke"
      }
    }),
    /Hosted promotion route must be \/api\/platform\/v1\/promotions/u
  );
});

test("validator rejects a catalog fixture anchor drift", async () => {
  const { temporaryRoot, temporaryContracts } = copyContracts();
  try {
    const file = path.join(temporaryContracts, PLATFORM_CONTRACT_SYNC.catalog);
    const catalog = JSON.parse(fs.readFileSync(file, "utf8"));
    const entry = catalog.entries.find((item) => item.id === "schema.platform-promotion-issue-envelope-v1");
    entry.compatibility_fixtures = entry.compatibility_fixtures.filter((item) => !item.endsWith("platform-promotion-issue-200-retry.contract.json"));
    fs.writeFileSync(file, `${JSON.stringify(catalog, null, 2)}\n`);
    await assert.rejects(
      validatePlatformContractSync({ contractsRoot: temporaryContracts, root: repositoryRoot }),
      /missing compatibility fixture contracts\/fixtures\/platform-promotion-issue-200-retry\.contract\.json/u
    );
  } finally {
    fs.rmSync(temporaryRoot, { recursive: true, force: true });
  }
});

test("validator rejects digest vector drift instead of silently accepting a new preimage", async () => {
  const { temporaryRoot, temporaryContracts } = copyContracts();
  try {
    const file = path.join(temporaryContracts, PLATFORM_CONTRACT_SYNC.vector);
    const vector = JSON.parse(fs.readFileSync(file, "utf8"));
    vector.input.idempotency_key = "promotion-issue-0002";
    fs.writeFileSync(file, `${JSON.stringify(vector, null, 2)}\n`);
    await assert.rejects(
      validatePlatformContractSync({ contractsRoot: temporaryContracts, root: repositoryRoot }),
      /does not match implementation/u
    );
  } finally {
    fs.rmSync(temporaryRoot, { recursive: true, force: true });
  }
});
