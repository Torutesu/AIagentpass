import fs from "node:fs";
import path from "node:path";

export function readGitSigningInvocation(signArgs) {
  if (!Array.isArray(signArgs) || signArgs.length === 0) throw new Error("Missing Git signing invocation");
  const candidate = signArgs.at(-1);
  if (typeof candidate !== "string" || candidate.startsWith("-") || !path.isAbsolute(candidate)) throw new Error("Git signing payload must be an absolute file path");
  const stat = fs.lstatSync(candidate);
  const uid = process.getuid?.();
  if (!stat.isFile() || stat.isSymbolicLink()) throw new Error("Git signing payload must be a regular file");
  if (uid !== undefined && stat.uid !== uid) throw new Error("Git signing payload is not owned by the current user");
  if (stat.size === 0 || stat.size > 8 * 1024 * 1024) throw new Error("Git signing payload size is invalid");
  return { payloadPath: candidate, payload: fs.readFileSync(candidate), brokerArgs: signArgs.slice(0, -1) };
}

export function writeGitSignature(payloadPath, signature) {
  fs.writeFileSync(`${payloadPath}.sig`, signature, { flag: "wx", mode: 0o600 });
}
