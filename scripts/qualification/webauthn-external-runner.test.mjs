import assert from "node:assert/strict";
import test from "node:test";
import { WebAuthnExternalQualificationError, runExternalWebAuthnQualification } from "./run-webauthn-external.mjs";

test("external WebAuthn runner requires explicit real execution", async () => {
  await assert.rejects(() => runExternalWebAuthnQualification({ env: {} }), WebAuthnExternalQualificationError);
});

test("external WebAuthn runner rejects local identity and incomplete deployment binding", async () => {
  await assert.rejects(() => runExternalWebAuthnQualification({ env: {
    AGENTPASS_WEBAUTHN_QUALIFICATION_ENABLED: "true",
    AGENTPASS_WEBAUTHN_QUALIFICATION_EXECUTION: "external",
    AGENTPASS_WEBAUTHN_QUALIFICATION_REAL_EXECUTION: "true",
    AGENTPASS_WEBAUTHN_QUALIFICATION_RUNNER_ID: "local-test"
  } }), WebAuthnExternalQualificationError);
});
