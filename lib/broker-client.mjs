import net from "node:net";
import { socketPath } from "./config.mjs";

export function brokerRequest(request, { timeoutMs = 5000, socket = socketPath() } = {}) {
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
