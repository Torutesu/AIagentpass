import test from "node:test";
import assert from "node:assert/strict";
import { createMaintenanceService, MAINTENANCE_ERROR_CODES } from "../src/maintenance/index.mjs";
import { createFakeClock, createFakeProvider, createFakeRepository, createFakeUuid } from "./support/deterministic.mjs";
test("maintenance uses deterministic operation identity and reserve/inspect", async () => { const provider = createFakeProvider(); const service = createMaintenanceService({ profile: "test", repository: createFakeRepository(), provider, clock: createFakeClock(10), uuid: createFakeUuid(["op-1"]) }); const { operationId } = await service.reservePlan({ advisory: "a" }); assert.equal(operationId, "op-1"); assert.equal((await service.inspectPlan(operationId)).status, "reserved"); assert.deepEqual(provider.calls.map((call) => call.method), ["reserveOperation", "inspectOperation"]); });
test("maintenance hosted profile cannot use fakes", () => { assert.throws(() => createMaintenanceService({ profile: "hosted", repository: createFakeRepository(), provider: createFakeProvider(), clock: createFakeClock(), uuid: createFakeUuid() }), { code: MAINTENANCE_ERROR_CODES.INVALID_CONFIGURATION }); });
