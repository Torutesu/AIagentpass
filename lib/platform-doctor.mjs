import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { configPath, defaultConfigDir, loadConfig } from "./config.mjs";
import { inspectNativeApplication } from "./platform-setup.mjs";

export const DOCTOR_SCHEMA_VERSION = 1;
export const DOCTOR_STATES = Object.freeze(["healthy", "action_required", "degraded", "blocked"]);

const STATE_WEIGHT = Object.freeze({ healthy: 0, action_required: 1, degraded: 2, blocked: 3 });
const FIXED_APPLICATION = "/Applications/AgentPass.app";
const FIXED_CLIENT = `${FIXED_APPLICATION}/Contents/Library/HelperTools/AgentPassNativeClient.app/Contents/MacOS/agentpass-native-client`;
const FIXED_MANAGER = `${FIXED_APPLICATION}/Contents/MacOS/agentpass-native-manager`;

function commandRunner(command, args) {
  return spawnSync(command, args, {
    encoding: "utf8",
    env: { PATH: "/usr/bin:/bin:/usr/sbin:/sbin" },
    timeout: 15_000,
    maxBuffer: 1024 * 1024
  });
}

function check(id, state, summary, remediation = null, detail = undefined) {
  if (!DOCTOR_STATES.includes(state)) throw new Error(`Invalid doctor state: ${state}`);
  return {
    id,
    state,
    severity: state === "blocked" ? "error" : state === "degraded" ? "warning" : "info",
    summary,
    ...(remediation ? { remediation } : {}),
    ...(detail !== undefined ? { detail } : {})
  };
}

function safeDetail(verbose, value) { return verbose ? value : undefined; }

function commandCheck(run, id, command, args, summary, remediation, verbose) {
  const result = run(command, args);
  if (result.status !== 0) return check(id, "blocked", `${summary} is unavailable`, remediation, safeDetail(verbose, result.stderr?.trim() || result.stdout?.trim()));
  return check(id, "healthy", summary, null, safeDetail(verbose, result.stdout?.trim()));
}

function appCodeIdentity(run, application, expectedTeamId, verbose) {
  const verify = run("/usr/bin/codesign", ["--verify", "--deep", "--strict", application]);
  if (verify.status !== 0) return check("app.code_signature", "blocked", "AgentPass application signature is invalid", "Reinstall AgentPass from a verified production release.", safeDetail(verbose, verify.stderr?.trim()));
  const assessment = run("/usr/sbin/spctl", ["--assess", "--type", "execute", "--verbose=4", application]);
  if (assessment.status !== 0) return check("app.gatekeeper", "blocked", "Gatekeeper rejected AgentPass", "Reinstall a Developer ID-signed and notarized AgentPass release.", safeDetail(verbose, assessment.stderr?.trim()));
  if (expectedTeamId) {
    const details = run("/usr/bin/codesign", ["-dv", "--verbose=4", application]);
    const combined = `${details.stdout ?? ""}\n${details.stderr ?? ""}`;
    const actual = combined.match(/^TeamIdentifier=([A-Z0-9]{10})$/m)?.[1];
    if (details.status !== 0 || actual !== expectedTeamId) return check("app.team_id", "blocked", "AgentPass Apple Team ID does not match the pinned value", "Remove the substituted application and reinstall from the pinned release channel.", safeDetail(verbose, actual ?? "missing"));
  }
  return check("app.code_identity", "healthy", expectedTeamId ? "Application signature, Gatekeeper, and Team ID are valid" : "Application signature and Gatekeeper assessment are valid", null, safeDetail(verbose, application));
}

function integrationCheck(client, projectDir, verbose) {
  if (!client) return check("integration.agent", "action_required", "No agent integration was selected for diagnosis", "Run `agentpass doctor --client claude-code|cursor --project DIR`.");
  if (!projectDir) return check("integration.agent", "blocked", "Agent integration diagnosis requires a project", "Pass an absolute existing project with --project.");
  const relative = client === "claude-code" ? ".mcp.json" : client === "cursor" ? path.join(".cursor", "mcp.json") : null;
  if (!relative) return check("integration.agent", "blocked", "Unsupported agent integration", "Use --client claude-code or --client cursor.");
  let root;
  try { root = fs.realpathSync(projectDir); } catch { return check("integration.agent", "blocked", "Project directory is unavailable", "Choose an existing project directory."); }
  const file = path.join(root, relative);
  if (!fs.existsSync(file)) return check("integration.agent", "action_required", `${client} is not connected to AgentPass`, `Run \`agentpass setup --client ${client} --project PROJECT --execute\`.`);
  try {
    const stat = fs.lstatSync(file);
    const uid = process.getuid?.();
    if (!stat.isFile() || stat.isSymbolicLink() || stat.size > 1024 * 1024 || (uid !== undefined && stat.uid !== uid)) throw new Error("unsafe integration file");
    const document = JSON.parse(fs.readFileSync(file, "utf8"));
    const server = document?.mcpServers?.agentpass;
    if (server?.command !== process.execPath || !Array.isArray(server.args) || server.args.length !== 1 || server.env?.AGENTPASS_PROJECT_DIR !== root) throw new Error("AgentPass MCP entry does not match this installation");
    return check("integration.agent", "healthy", `${client} is connected to AgentPass`, null, safeDetail(verbose, file));
  } catch (error) {
    return check("integration.agent", "blocked", `${client} integration is invalid or unsafe`, `Preview and reapply \`agentpass setup --client ${client} --project PROJECT\`.`, safeDetail(verbose, error.message));
  }
}

export async function runProductionDoctor(options = {}, dependencies = {}) {
  const platform = dependencies.platform ?? process.platform;
  const architecture = dependencies.architecture ?? process.arch;
  const nodeVersion = dependencies.nodeVersion ?? process.versions.node;
  const run = dependencies.run ?? commandRunner;
  const now = dependencies.now ?? (() => new Date());
  const inspectApplication = dependencies.inspectApplication ?? inspectNativeApplication;
  const configDirectory = options.configDir ?? defaultConfigDir;
  const application = options.application ?? FIXED_APPLICATION;
  const verbose = options.verbose === true;
  const checks = [];

  const nodeMajor = Number(nodeVersion.split(".")[0]);
  checks.push(check("runtime.node", nodeMajor >= 20 ? "healthy" : "blocked", nodeMajor >= 20 ? "Supported Node.js runtime is active" : "Node.js 20 or newer is required", nodeMajor >= 20 ? null : "Install a supported Node.js release.", safeDetail(verbose, nodeVersion)));
  checks.push(check("runtime.platform", platform === "darwin" ? "healthy" : "blocked", platform === "darwin" ? "macOS production platform detected" : "Production native mode requires macOS", platform === "darwin" ? null : "Use evaluation mode or run on a supported Mac.", safeDetail(verbose, `${platform}/${architecture}`)));
  checks.push(commandCheck(run, "runtime.git", "/usr/bin/git", ["--version"], "Git is available", "Install the supported macOS Git tools.", verbose));
  checks.push(check("runtime.ssh_keygen", fs.existsSync("/usr/bin/ssh-keygen") ? "healthy" : "blocked", fs.existsSync("/usr/bin/ssh-keygen") ? "OpenSSH signing helper is available" : "OpenSSH signing helper is unavailable", fs.existsSync("/usr/bin/ssh-keygen") ? null : "Restore /usr/bin/ssh-keygen from macOS."));

  let config = null;
  if (!fs.existsSync(configPath(configDirectory))) {
    checks.push(check("config.local", "action_required", "AgentPass local policy is not initialized", "Run `agentpass init` in the intended repository."));
  } else {
    try {
      config = loadConfig(configDirectory);
      checks.push(check("config.local", "healthy", "Local policy is valid and securely stored", null, safeDetail(verbose, configDirectory)));
    } catch (error) {
      checks.push(check("config.local", "blocked", "Local policy is invalid or unsafe", "Inspect permissions and restore a known-good AgentPass configuration.", safeDetail(verbose, error.message)));
    }
  }

  let nativeApplication = null;
  if (platform === "darwin" && fs.existsSync(application)) {
    try {
      nativeApplication = inspectApplication(application, { expectedOwner: options.expectedAppOwner ?? 0 });
      checks.push(check("app.layout", "healthy", "Production native application layout is trusted", null, safeDetail(verbose, application)));
      checks.push(appCodeIdentity(run, application, options.expectedTeamId, verbose));
      checks.push(check("service.registration", nativeApplication.serviceStatus === "enabled" ? "healthy" : "action_required", nativeApplication.serviceStatus === "enabled" ? "Native service is registered and enabled" : nativeApplication.requiresApproval ? "Native service requires macOS approval" : "Native service is not registered", nativeApplication.serviceStatus === "enabled" ? null : nativeApplication.requiresApproval ? "Approve AgentPass in System Settings > General > Login Items, then rerun doctor." : "Run `agentpass native daemon-register` after setup."));
    } catch (error) {
      checks.push(check("app.layout", "blocked", "Production native application is invalid or substituted", "Reinstall AgentPass using the verified production installer.", safeDetail(verbose, error.message)));
    }
  } else if (platform === "darwin") {
    checks.push(check("app.layout", "action_required", "Production native application is not installed", "Verify and install the signed/notarized PKG with `agentpass install`."));
  }

  if (platform === "darwin") {
    const receipt = run("/usr/sbin/pkgutil", ["--pkg-info", "dev.agentpass.installer"]);
    checks.push(check("package.receipt", receipt.status === 0 ? "healthy" : "action_required", receipt.status === 0 ? "Production installer receipt is present" : "Production installer receipt is missing", receipt.status === 0 ? null : "Install AgentPass through the verified production PKG.", safeDetail(verbose, receipt.stdout?.trim() || receipt.stderr?.trim())));
  }

  if (config?.native_broker) {
    const fixed = config.native_broker.enabled === true && config.native_broker.client === FIXED_CLIENT && config.native_broker.manager === FIXED_MANAGER && config.native_broker.mach_service === "dev.agentpass.native-service" && (options.expectedTeamId === undefined || config.native_broker.team_id === options.expectedTeamId);
    checks.push(check("config.native_bridge", fixed ? "healthy" : "blocked", fixed ? "Local policy selects the fixed native bridge" : "Native bridge configuration is not the production fixed path", fixed ? null : "Run `agentpass setup --client ... --execute` after reinstalling the production application."));
    if (fixed && dependencies.nativeStatus) {
      try {
        const status = await dependencies.nativeStatus(config.native_broker);
        const operational = status?.health?.ok === true || status?.ok === true;
        checks.push(check("service.health", operational ? "healthy" : "degraded", operational ? "Native signing service is operational" : "Native signing service reported degraded health", operational ? null : "Run `agentpass native status` and follow the reported remediation.", safeDetail(verbose, status)));
      } catch (error) {
        checks.push(check("service.health", "blocked", "Native signing service is unreachable", "Confirm daemon approval and run `agentpass native status`.", safeDetail(verbose, error.message)));
      }
    } else if (fixed) {
      checks.push(check("service.health", nativeApplication?.serviceStatus === "enabled" ? "degraded" : "action_required", "Native service health was not queried", "Run `agentpass native status` for protected-state verification."));
    }
  } else if (config) {
    checks.push(check("config.native_bridge", "degraded", "Evaluation broker mode is configured", "Install and set up the production native service for the hardware-backed XPC boundary."));
  }

  checks.push(integrationCheck(options.client, options.projectDir, verbose));
  const state = checks.reduce((worst, item) => STATE_WEIGHT[item.state] > STATE_WEIGHT[worst] ? item.state : worst, "healthy");
  return {
    schema_version: DOCTOR_SCHEMA_VERSION,
    state,
    ok: state === "healthy",
    generated_at: now().toISOString(),
    mode: config?.native_broker?.enabled ? "production-native" : "evaluation",
    checks,
    summary: Object.fromEntries(DOCTOR_STATES.map((value) => [value, checks.filter((item) => item.state === value).length])),
    host: verbose ? { platform, architecture, node: nodeVersion, hostname: os.hostname() } : { platform, architecture }
  };
}
