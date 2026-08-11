import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { secureMkdir } from "./config.mjs";

export function createAgentIdentity(configDir, name = "coding-agent") {
  const id = crypto.randomUUID();
  const directory = path.join(configDir, "agents");
  secureMkdir(directory);
  const { privateKey, publicKey } = crypto.generateKeyPairSync("ed25519");
  const privatePath = path.join(directory, `${id}.pem`);
  fs.writeFileSync(privatePath, privateKey.export({ type: "pkcs8", format: "pem" }), { mode: 0o600 });
  return {
    id,
    name,
    private_path: privatePath,
    public_key: publicKey.export({ type: "spki", format: "pem" }).toString()
  };
}

export function createAuditIdentity(configDir) {
  const directory = path.join(configDir, "audit");
  secureMkdir(directory);
  const { privateKey, publicKey } = crypto.generateKeyPairSync("ed25519");
  const privatePath = path.join(directory, "checkpoint.pem");
  fs.writeFileSync(privatePath, privateKey.export({ type: "pkcs8", format: "pem" }), { flag: "wx", mode: 0o600 });
  return {
    private_path: privatePath,
    public_key: publicKey.export({ type: "spki", format: "pem" }).toString()
  };
}

export function signRequest(request, privatePath) {
  const stat = fs.lstatSync(privatePath);
  const uid = process.getuid?.();
  if (!stat.isFile() || stat.isSymbolicLink()) throw new Error("Agent identity key must be a regular file");
  if (uid !== undefined && stat.uid !== uid) throw new Error("Agent identity key is not owned by the current user");
  if ((stat.mode & 0o077) !== 0) throw new Error("Agent identity key permissions are too permissive");
  const unsigned = { ...request };
  delete unsigned.signature;
  const signature = crypto.sign(null, Buffer.from(canonicalJson(unsigned)), fs.readFileSync(privatePath));
  return { ...unsigned, signature: signature.toString("base64") };
}

export function verifyRequestIdentity(request, config, replayCache = new Map(), now = Date.now()) {
  if (typeof request.agent_id !== "string" || typeof request.signature !== "string") throw new Error("Signed agent identity is required");
  if (!Number.isFinite(request.timestamp_ms) || Math.abs(now - request.timestamp_ms) > 60_000) throw new Error("Agent request timestamp is outside the allowed window");
  if (typeof request.nonce !== "string" || request.nonce.length < 32) throw new Error("Agent request nonce is invalid");
  purgeReplayCache(replayCache, now);
  if (replayCache.has(request.nonce)) throw new Error("Agent request replay detected");
  const identity = config.agents?.find((agent) => agent.id === request.agent_id);
  if (!identity) throw new Error("Unknown agent identity");
  const unsigned = { ...request };
  delete unsigned.signature;
  const valid = crypto.verify(null, Buffer.from(canonicalJson(unsigned)), identity.public_key, Buffer.from(request.signature, "base64"));
  if (!valid) throw new Error("Agent request signature is invalid");
  if (replayCache.size >= 10_000) throw new Error("Agent replay cache capacity exceeded");
  replayCache.set(request.nonce, now + 120_000);
  return identity;
}

export function canonicalJson(value) {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (value && typeof value === "object") {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(",")}}`;
  }
  return JSON.stringify(value);
}

function purgeReplayCache(cache, now) {
  for (const [nonce, expires] of cache) if (expires <= now) cache.delete(nonce);
}
