import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const openapi = JSON.parse(fs.readFileSync(path.join(root, "contracts/openapi/human-v1.json"), "utf8"));

test("Human OpenAPI freezes the exact WebAuthn registration HTTP contract", () => {
  const options = openapi.paths["/webauthn/registration/options"].post;
  const verify = openapi.paths["/webauthn/registration/verify"].post;

  assert.equal(options.requestBody.$ref, "#/components/requestBodies/WebAuthnRegistrationOptions");
  assert.equal(verify.requestBody.$ref, "#/components/requestBodies/WebAuthnRegistrationVerify");
  assert.equal(options["x-agentpass-runtime-path"], "/api/auth/webauthn/registration/options");
  assert.equal(verify["x-agentpass-runtime-path"], "/api/auth/webauthn/registration/verify");
  assert.deepEqual(Object.keys(options.responses).sort(), ["200", "400", "401", "403", "409", "428", "429", "503"]);
  assert.deepEqual(Object.keys(verify.responses).sort(), ["201", "400", "401", "403", "409", "422", "428", "429", "503"]);
  assert.equal(Object.hasOwn(verify.responses, "200"), false);
  assert.equal(options.parameters.some((parameter) => parameter.$ref.endsWith("/IdempotencyKey")), false);
  assert.equal(verify.parameters.some((parameter) => parameter.$ref.endsWith("/IdempotencyKey")), false);
  assert.equal(options.parameters[0].$ref, "#/components/parameters/CsrfToken");
  assert.equal(options.parameters[1].$ref, "#/components/parameters/RecentAuthForCredentialRegistration");
  assert.equal(openapi.components.parameters.CsrfToken.name, "AgentPass-CSRF");
  assert.deepEqual(openapi.components.parameters.CsrfToken.schema, { type: "string", minLength: 43, maxLength: 43, pattern: "^[A-Za-z0-9_-]{43}$" });
  assert.equal(openapi.components.parameters.RecentAuthForCredentialRegistration.required, false);
});

test("registration schemas reject caller authority and unknown browser fields", () => {
  const schemas = openapi.components.schemas;
  const options = schemas.WebAuthnRegistrationOptionsRequest;
  const verify = schemas.WebAuthnRegistrationVerifyRequest;
  const credential = schemas.WebAuthnBrowserRegistrationCredential;
  const response = credential.properties.response;

  assert.deepEqual(options.required, ["organization_id"]);
  assert.equal(options.additionalProperties, false);
  assert.deepEqual(verify.required, ["organization_id", "challenge_id", "credential"]);
  assert.equal(verify.additionalProperties, false);
  assert.equal(credential.additionalProperties, false);
  assert.deepEqual(credential.required, ["id", "rawId", "response", "type", "clientExtensionResults"]);
  assert.equal(credential.properties.type.const, "public-key");
  assert.equal(credential.properties.clientExtensionResults.maxProperties, 32);
  assert.equal(response.additionalProperties, false);
  assert.deepEqual(response.required, ["clientDataJSON", "attestationObject"]);
  assert.deepEqual(response.properties.transports.items.enum, ["ble", "cable", "hybrid", "internal", "nfc", "smart-card", "usb"]);
  assert.equal(response.properties.transports.uniqueItems, true);
  for (const forbidden of ["member_id", "role", "rp_id", "origin", "public_key", "sign_count", "authorization_id"]) {
    assert.equal(Object.hasOwn(options.properties, forbidden), false);
    assert.equal(Object.hasOwn(verify.properties, forbidden), false);
    assert.equal(Object.hasOwn(credential.properties, forbidden), false);
    assert.equal(Object.hasOwn(response.properties, forbidden), false);
  }
});

test("registration success responses expose only public completion metadata", () => {
  const schemas = openapi.components.schemas;
  assert.deepEqual(schemas.WebAuthnRegistrationOptionsResponse.required, ["challenge_id", "options"]);
  assert.equal(schemas.WebAuthnRegistrationOptionsResponse.additionalProperties, false);
  assert.deepEqual(schemas.WebAuthnRegistrationVerifiedResponse.required, ["credential_id", "registered_at"]);
  assert.equal(schemas.WebAuthnRegistrationVerifiedResponse.additionalProperties, false);
  assert.deepEqual(Object.keys(schemas.WebAuthnRegistrationVerifiedResponse.properties).sort(), ["credential_id", "registered_at"]);
});
