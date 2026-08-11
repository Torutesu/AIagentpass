import net from "node:net";
import fs from "node:fs";
import { spawn } from "node:child_process";
import { socketPath } from "./config.mjs";

export function brokerRequest(request, { timeoutMs = 5000, socket = socketPath(), native = null } = {}) {
  if (native?.enabled) return nativeBrokerRequest(request, native, timeoutMs);
  return new Promise((resolve, reject) => {
    const client = net.createConnection(socket);
    let response = "";
    const timer = setTimeout(() => {
      client.destroy();
      reject(new Error("AgentPass broker request timed out"));
    }, timeoutMs);

    client.setEncoding("utf8");
    client.on("connect", () => client.end(`${JSON.stringify(request)}\n`));
    client.on("data", (chunk) => {
      response += chunk;
      if (response.length > 16 * 1024 * 1024) client.destroy(new Error("Broker response is too large"));
    });
    client.on("error", (error) => {
      clearTimeout(timer);
      reject(new Error(`AgentPass broker unavailable: ${error.message}`));
    });
    client.on("end", () => {
      clearTimeout(timer);
      try {
        const parsed = JSON.parse(response.trim());
        if (!parsed.ok) reject(new Error(parsed.error || "Broker denied the request"));
        else resolve(parsed);
      } catch (error) {
        reject(new Error(`Invalid broker response: ${error.message}`));
      }
    });
  });
}

function nativeBrokerRequest(request, native, timeoutMs) {
  const stat = fs.lstatSync(native.client);
  if (!stat.isFile() || stat.isSymbolicLink() || (stat.mode & 0o022) !== 0) throw new Error("Native broker client permissions are unsafe");
  return new Promise((resolve, reject) => {
    const commands = { ping: "ping", "native.public-key": "public-key", "native.audit.status": "audit-status", "native.audit.public-key": "audit-public-key", "native.audit.checkpoint": "audit-checkpoint", "native.session.approval-public-key": "approval-public-key", "native.session.start": "session-start", "native.session.revoke": "session-revoke", "native.session.validate": "session-validate", "native.control.apply": "control-apply", "native.control.status": "control-status", "native.control.validate": "control-validate" };
    const command = commands[request.operation] ?? "sign";
    const child = spawn(native.client, ["--service", native.mach_service, command], {
      stdio: ["pipe", "pipe", "pipe"],
      env: { PATH: "/usr/bin:/bin:/usr/sbin:/sbin" }
    });
    let output = "", errors = "", settled = false;
    const finish = (callback) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      callback();
    };
    const timer = setTimeout(() => {
      child.kill("SIGKILL");
      finish(() => reject(new Error("Native broker request timed out")));
    }, timeoutMs);
    child.stdout.setEncoding("utf8");
    child.stderr.setEncoding("utf8");
    child.stdout.on("data", (chunk) => {
      output += chunk;
      if (output.length > 16 * 1024 * 1024) child.kill("SIGKILL");
    });
    child.stderr.on("data", (chunk) => { if (errors.length < 64 * 1024) errors += chunk; });
    child.on("error", (error) => finish(() => reject(new Error(`Native broker unavailable: ${error.message}`))));
    child.on("close", () => finish(() => {
      try {
        const parsed = JSON.parse(output.trim());
        if (!parsed.ok) reject(new Error(parsed.error || "Native broker denied the request"));
        else resolve(parsed);
      } catch (error) {
        reject(new Error(`Invalid native broker response: ${error.message}${errors.trim() ? ` (${errors.trim()})` : ""}`));
      }
    }));
    child.stdin.end(`${JSON.stringify(request)}\n`);
  });
}
