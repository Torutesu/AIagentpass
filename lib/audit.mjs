import fs from "node:fs";
import { auditPath } from "./config.mjs";

export function audit(event, dir) {
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  const record = { timestamp: new Date().toISOString(), ...event };
  fs.appendFileSync(auditPath(dir), `${JSON.stringify(record)}\n`, { mode: 0o600 });
}
