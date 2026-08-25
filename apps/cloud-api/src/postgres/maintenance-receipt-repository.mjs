/** Append-only maintenance receipt authority adapter. */
export function createMaintenanceReceiptRepository({ db } = {}) {
  if (!db || typeof db.query !== "function") throw new TypeError("db.query is required");
  return Object.freeze({
    saveReceipt: async (input) => {
      const { rows } = await db.query("SELECT public.agentpass_record_maintenance_receipt($1) AS result", [input]);
      return rows?.[0]?.result ?? null;
    }
  });
}
