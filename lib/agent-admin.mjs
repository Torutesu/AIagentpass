import fs from "node:fs";
import path from "node:path";
import { audit } from "./audit.mjs";
import { loadConfig, saveConfig, secureMkdir } from "./config.mjs";
import { createAgentIdentity } from "./identity.mjs";

export function addAgent(name, configDir) {
  validateName(name);
  const config = version4(configDir);
  const identity = createAgentIdentity(configDir, name);
  saveConfig({ ...config, agents: [...config.agents, publicIdentity(identity, scopeFromConfig(config))] }, configDir);
  audit({ operation: "agent.add", decision: "allow", agent_id: identity.id, agent_name: name }, configDir);
  return identity;
}

export function setDefaultAgent(id, configDir) {
  const config = version4(configDir);
  requireAgent(config, id);
  saveConfig({ ...config, default_agent_id: id }, configDir);
  audit({ operation: "agent.set-default", decision: "allow", agent_id: id }, configDir);
}

export function revokeAgent(id, configDir) {
  const config = version4(configDir);
  const identity = requireAgent(config, id);
  if (config.agents.length === 1) throw new Error("Cannot revoke the only enrolled agent");
  if (config.default_agent_id === id) throw new Error("Select a different default agent before revoking this one");
  saveConfig({ ...config, agents: config.agents.filter((agent) => agent.id !== id) }, configDir);
  archivePrivateKey(id, configDir);
  audit({ operation: "agent.revoke", decision: "allow", agent_id: id, agent_name: identity.name }, configDir);
}

export function rotateAgent(id, configDir) {
  const config = version4(configDir);
  const previous = requireAgent(config, id);
  const identity = createAgentIdentity(configDir, previous.name);
  const agents = config.agents.map((agent) => agent.id === id ? publicIdentity(identity, agent.scope) : agent);
  saveConfig({ ...config, agents, default_agent_id: config.default_agent_id === id ? identity.id : config.default_agent_id }, configDir);
  archivePrivateKey(id, configDir);
  audit({ operation: "agent.rotate", decision: "allow", previous_agent_id: id, agent_id: identity.id, agent_name: identity.name }, configDir);
  return identity;
}

export function setAgentScope(id, scope, configDir) {
  const config = version4(configDir);
  const identity = requireAgent(config, id);
  validateScope(scope);
  const agents = config.agents.map((agent) => agent.id === id ? { ...agent, scope } : agent);
  saveConfig({ ...config, agents }, configDir);
  audit({ operation: "agent.scope", decision: "allow", agent_id: id, agent_name: identity.name, scope }, configDir);
}

function archivePrivateKey(id, configDir) {
  const source = path.join(configDir, "agents", `${id}.pem`);
  if (!fs.existsSync(source)) return;
  const revoked = path.join(configDir, "agents", "revoked");
  secureMkdir(revoked);
  fs.renameSync(source, path.join(revoked, `${id}.${Date.now()}.pem`));
}

function version4(configDir) {
  const config = loadConfig(configDir);
  if (config.version < 4) throw new Error("Configuration version 4 is required; run agentpass migrate");
  return config;
}

function requireAgent(config, id) {
  const identity = config.agents.find((agent) => agent.id === id);
  if (!identity) throw new Error(`Unknown agent identity: ${id}`);
  return identity;
}

function validateName(name) {
  if (typeof name !== "string" || !name.trim() || name.length > 64 || /[\x00-\x1f\x7f]/.test(name)) throw new Error("Agent name must contain 1-64 printable characters");
}

function publicIdentity(identity, scope) {
  return { id: identity.id, name: identity.name, public_key: identity.public_key, scope };
}

function scopeFromConfig(config) {
  return {
    operations: [...config.operations],
    repositories: [...config.repositories],
    branches: structuredClone(config.branches ?? { allow: ["*"] }),
    remotes: structuredClone(config.remotes ?? { allow: ["*"] })
  };
}

function validateScope(scope) {
  if (!scope || ![scope.operations, scope.repositories, scope.branches?.allow, scope.remotes?.allow].every((value) => Array.isArray(value) && value.length > 0)) throw new Error("Agent scope requires operations, repositories, branches, and remotes");
}
