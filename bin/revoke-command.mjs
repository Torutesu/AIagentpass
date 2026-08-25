import { brokerRequest as defaultBrokerRequest } from "../lib/broker-client.mjs";

/**
 * Execute the user-facing emergency revoke command without ever exposing
 * authority-bearing material. Native mode must invalidate the protected
 * broker sessions; it must not silently write the legacy user-state flag.
 */
export async function revokeOperations({
  config,
  configDir,
  loadState,
  saveState,
  audit,
  brokerRequest = defaultBrokerRequest,
  now = () => new Date().toISOString(),
}) {
  if (config?.native_broker?.enabled === true) {
    await brokerRequest(
      { operation: "native.session.revoke" },
      { native: config.native_broker },
    );
    return Object.freeze({ version: 1, mode: "native", revoked: true });
  }

  const state = loadState(configDir);
  const generation = (state.generation ?? 0) + 1;
  saveState({
    ...state,
    revoked: true,
    generation,
    revoked_at: now(),
  }, configDir);
  audit({ operation: "control.revoke", decision: "allow", generation }, configDir);
  return Object.freeze({ version: 1, mode: "local", revoked: true, generation });
}
