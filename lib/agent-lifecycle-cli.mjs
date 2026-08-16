const OPERATIONS = new Set(["launch", "close"]);

export const AGENT_LIFECYCLE_UNAVAILABLE = "AGENT_LIFECYCLE_NOT_AVAILABLE";

export function unavailableAgentLifecycle(operation) {
  if (!OPERATIONS.has(operation)) throw new TypeError("agent lifecycle operation is invalid");
  return Object.freeze({
    ok: false,
    operation,
    error: Object.freeze({
      code: AGENT_LIFECYCLE_UNAVAILABLE,
      message: "The process-bound Agent lifecycle is not available in this build"
    })
  });
}
