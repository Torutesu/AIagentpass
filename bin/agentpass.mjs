#!/usr/bin/env node
import fs from "node:fs";
import crypto from "node:crypto";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";
import { addAgent, revokeAgent, rotateAgent, setAgentScope, setDefaultAgent } from "../lib/agent-admin.mjs";
import { anchorPendingCheckpoints, verifyStoredAnchorReceipts } from "../lib/anchor-client.mjs";
import { audit, createAuditCheckpoint, publicKeyFingerprint, verifyAudit, verifyAuditCheckpoints } from "../lib/audit.mjs";
import { brokerRequest } from "../lib/broker-client.mjs";
import { anchorReceiptPath, auditPath, controlBundlePath, defaultConfigDir, loadConfig, loadSession, loadState, saveConfig, saveSession, saveState, socketPath } from "../lib/config.mjs";
import { canonicalJson, createAgentIdentity, createAuditIdentity, signRequest } from "../lib/identity.mjs";
import { installIntegration, integrationPlan, integrationRemovalPlan, removeIntegration } from "../lib/integrations.mjs";
import { readGitSigningInvocation, writeGitSignature } from "../lib/git-signing.mjs";
import { evaluateAgentRequest } from "../lib/policy.mjs";
import { executeProductionInstall, prepareProductionInstall, removeStagedProductionInstall, stageProductionInstall, verifyProductionInstall } from "../lib/platform-install.mjs";
import { runProductionDoctor } from "../lib/platform-doctor.mjs";
import { inspectNativeApplication } from "../lib/platform-setup.mjs";
import { createNativeBootstrapRunner } from "../lib/native-bootstrap-runner.mjs";
import { createNativeDeviceEnrollmentRunner } from "../lib/native-device-enrollment-runner.mjs";
import { createNativeSetupHandlers } from "../lib/native-setup-handlers.mjs";
import { createDeviceEnrollmentSetupHandler } from "../lib/device-enrollment-setup-handler.mjs";
import { connectSetupInBrowser, normalizeConsoleBaseUrl } from "../lib/setup-browser-connect.mjs";
import { parseSetupContinueOptions } from "../lib/setup-continue-options.mjs";
import { parseControlBundleJson } from "../lib/control-bundle-v2.mjs";
import { executeProductionUninstall, planProductionUninstall } from "../lib/platform-uninstall.mjs";
import { runUserStatePurge } from "../lib/platform-user-purge.mjs";
import { parseEnrollmentInvitation, publicSetupFailure, publicSetupResult, readHeadlessOnboarding, validateHeadlessEnrollmentBaseUrl } from "../lib/headless-onboarding.mjs";
import { prepareSetupPreflight, publicSetupPreflightFailure, serializeSetupPreflightHandoff } from "../lib/setup-preflight.mjs";
import { readInstalledReleaseReceipt, verifyInstalledReleaseReceipt } from "../lib/installed-release-receipt.mjs";
import { createSetupOrchestrator } from "../lib/setup-orchestrator.mjs";
import { TEST_COMMIT_VERIFICATION_MARKER, createCompleteSetupHandler, createEditorConnectedHandler, createTestCommitVerifiedHandler } from "../lib/setup-finalization-handlers.mjs";
import { SETUP_STATES, SetupJournalError, createSetupJournal, loadSetupJournal } from "../lib/setup-journal.mjs";
import { generateRecoveryIdentity, recoveryPolicyToAnchorPolicy, signAnchorRecoveryAuthorization, signRecoveryRequest, verifyAnchorRecoveryApprovals, verifyRecoveryThreshold } from "../lib/recovery.mjs";
import { applyControlBundle, controlKeyFingerprint, fetchControlBundle, generateControlKeyPair, loadControlBundle, signControlBundle } from "../lib/remote-control.mjs";

const [, , command, ...args] = process.argv;

function shellWord(value) {
  const word = String(value);
  return /^[A-Za-z0-9_./:@%+=,-]+$/.test(word) ? word : `'${word.replaceAll("'", `'"'"'`)}'`;
}

function usage() {
  console.log(`AgentPass 0.18.0

Commands:
  install --manifest FILE --signature FILE --public-key FILE
          --fingerprint SHA256:PIN --team-id TEAMID [--execute]
                    verify and optionally install the production macOS package
  setup status
  setup prepare --json
                    emit a public, candidate-bound local setup handoff
  setup continue [--execute]
  setup continue --execute --browser --console-url HTTPS_URL --enrollment-url HTTPS_URL
  setup continue --execute --enrollment-url HTTPS_URL --enrollment-stdin
                    advance exactly one verified, crash-resumable setup state
  setup --client claude-code|cursor --team-id TEAMID [--project DIR] [--execute]
                    configure the native bridge and project MCP integration
  init              create a secure local policy
  migrate           upgrade an older policy to signed-agent format
  status            show policy and revocation status
  check             evaluate the current repository
  doctor [--client claude-code|cursor] [--project DIR] [--team-id TEAMID] [--verbose]
                    diagnose production installation without changing state
  uninstall [--project DIR] [--team-id TEAMID] [--execute] [--system]
                    remove integrations/app registration while preserving all protected state
  broker ping       verify that the signing broker is running
  broker install    install and start the macOS LaunchAgent
  broker stop       stop the macOS LaunchAgent
  native status     verify protected native audit and broker health
  native public-key print the native Git signing public key
  native audit-key  print the native audit checkpoint public key
  native checkpoint create a protected native audit checkpoint
  native audit-rotate archive a full protected native audit segment
  native audit-evidence-rotate archive protected checkpoint/receipt evidence
  native key-lifecycle-status inspect protected key lifecycle state
  native key-stage ROLE stage a new git_signing, audit_checkpoint, or session_approval generation
  native key-activate ROLE GENERATION --reason TEXT
                    approve and activate a staged service key
  native key-abort ROLE GENERATION --reason TEXT
                    approve deletion of a staged service key
  native key-delete audit_checkpoint GENERATION --reason TEXT --retention SECONDS --proof FILE
                    permanently delete an externally archived retired service key
  native recovery-request ROLE
                    emit an exact host recovery request for offline signing
  native recovery-install --request FILE --policy FILE --authorization FILE...
                    install an offline-authorized replacement with local presence
  native recovery-prepare --request FILE --policy FILE --authorization FILE...
                    prepare canonical anchor authorization for audit-key recovery
  native recovery-anchor-install --evidence FILE
                    install threshold-approved schema-v3 audit recovery evidence
  native anchor-push push the next protected checkpoint to the native anchor
  native anchor-status verify protected native anchor receipts
  native session-approval-key  create/print the human-presence approval key
  native revoke-sessions       immediately invalidate protected native sessions
  native daemon-register       register the bundled privileged service
  native daemon-unregister     unregister the bundled privileged service
  native daemon-status         inspect Service Management registration
  native daemon-open-settings  open macOS Login Items settings
  agent list        list enrolled agent identities
  agent add NAME    enroll a new agent identity
  agent set-default ID
  agent scope ID    replace per-agent authorization scope
  agent rotate ID   replace an agent identity key
  agent revoke ID   revoke an identity (--confirm REVOKE)
  integrate CLIENT  preview Claude Code or Cursor MCP setup
  integrate CLIENT --install [--project DIR]
                    install project-scoped MCP setup without replacing other servers
  integrate CLIENT --remove [--execute] [--project DIR]
                    remove only the matching AgentPass MCP entry (dry run by default)
  setup-macos       show Secure Enclave setup (use --execute to run)
  install-hook      install a policy-enforcing pre-push hook
  push-check        evaluate a pre-push request
  session start     issue a short-lived agent session token
  revoke            immediately deny all operations
  restore           re-enable operations after revocation
  git-sign [args]   send a signing request to the broker
  audit [--verify]  print or verify audit logs and checkpoints
  audit checkpoint  sign the current audit head
  audit public-key  print the checkpoint verification key
  audit anchor trust --url HTTPS_URL --tenant TENANT --key PUBLIC_KEY
  audit anchor push
  audit anchor status
  control keygen DIR
  control trust PUBLIC_KEY [--url HTTPS_URL]
  control sign       create an offline-signed control bundle
  control source URL configure the native HTTPS distribution URL
  control apply FILE verify and install a control bundle
  control fetch      fetch and install the configured HTTPS bundle
  control status     inspect active remote revocation state
  recovery keygen DIR --signer ID
                    create an offline Ed25519 recovery identity
  recovery sign --request FILE --key FILE --signer ID
                    sign one canonical recovery request offline
  recovery verify --request FILE --policy FILE --authorization FILE...
                    verify a threshold of offline authorizations
  recovery anchor-sign --authorization FILE --key FILE --signer ID [--output FILE]
                    sign one canonical anchor-v3 recovery authorization
  recovery anchor-policy --policy FILE [--output FILE]
                    emit the canonical policy pinned during anchor enrollment
  recovery anchor-verify --authorization FILE --policy FILE --approval FILE...
                    verify and emit canonical anchor-v3 recovery evidence
`);
}

function git(gitArgs, optional = false) {
  const result = spawnSync("git", gitArgs, { encoding: "utf8" });
  if (result.status !== 0) {
    if (optional) return "";
    throw new Error(result.stderr.trim() || `git ${gitArgs.join(" ")} failed`);
  }
  return result.stdout.trim();
}

function strictInstallFlags() {
  const values = new Map();
  const allowed = new Set(["--manifest", "--signature", "--public-key", "--fingerprint", "--team-id"]);
  for (let index = 0; index < args.length; index += 1) {
    const argument = args[index];
    if (argument === "--execute") continue;
    if (!allowed.has(argument) || values.has(argument) || index + 1 >= args.length || args[index + 1].startsWith("--")) {
      throw new Error("Usage: agentpass install --manifest FILE --signature FILE --public-key FILE --fingerprint SHA256:PIN --team-id TEAMID [--execute]");
    }
    values.set(argument, args[index + 1]);
    index += 1;
  }
  for (const flag of allowed) if (!values.has(flag)) throw new Error(`Install requires ${flag}`);
  return values;
}

function installProduction() {
  const flags = strictInstallFlags();
  const inputs = prepareProductionInstall({
    manifest: path.resolve(flags.get("--manifest")),
    signature: path.resolve(flags.get("--signature")),
    publicKey: path.resolve(flags.get("--public-key")),
    fingerprint: flags.get("--fingerprint"),
    teamId: flags.get("--team-id")
  });
  const verifier = fileURLToPath(new URL("../scripts/release/verify-macos-release.sh", import.meta.url));
  const stager = fileURLToPath(new URL("../scripts/release/stage-release.mjs", import.meta.url));
  const staged = stageProductionInstall(inputs, stager);
  try {
    const plan = verifyProductionInstall(staged, verifier);
    const publicPlan = { ...plan, package: path.join(path.dirname(inputs.manifest), path.basename(plan.package)), stagingDirectory: undefined };
    if (!args.includes("--execute")) {
      console.log(JSON.stringify({ ...publicPlan, installed: false, dryRun: true, next: "rerun this command as root with --execute" }, null, 2));
      return;
    }
    const installed = executeProductionInstall(plan);
    console.log(JSON.stringify({ ...publicPlan, installed: installed.installed, installerOutput: installed.installerOutput, dryRun: false }, null, 2));
  } finally {
    removeStagedProductionInstall(staged.stagingDirectory);
  }
}

function readEnrollmentInvitationStdin() {
  const chunks = []; let total = 0;
  while (true) {
    const chunk = Buffer.alloc(4096);
    const count = fs.readSync(0, chunk, 0, chunk.length, null);
    if (count === 0) break;
    total += count;
    if (total > 16 * 1024) throw new Error("Enrollment invitation exceeds 16 KiB");
    chunks.push(chunk.subarray(0, count));
  }
  const parsed = parseControlBundleJson(Buffer.concat(chunks), { maxBytes: 16 * 1024, maxDepth: 8 });
  return parseEnrollmentInvitation(parsed);
}

async function continueNativeSetup() {
  const flags = parseSetupContinueOptions(args.slice(1));
  const journal = loadSetupJournal();
  if (!flags.execute) {
    console.log(JSON.stringify(publicSetupResult(await createSetupOrchestrator({ journal }).preview()), null, 2));
    return;
  }
  if (process.platform !== "darwin") throw new Error("Native AgentPass setup is supported only on macOS");
  if (process.getuid?.() === 0) throw new Error("Run setup as the interactive user, not root");
  const config = loadConfig();
  const state = journal.status().state;
  const enrollmentMode = flags.browser || flags.enrollmentStdin;
  if ((state === "service_keys_activated") !== enrollmentMode) {
    throw new Error(state === "service_keys_activated"
      ? "At service_keys_activated, use the browser-assisted command or the explicit stdin recovery path"
      : "Browser and stdin enrollment options are accepted only at service_keys_activated");
  }
  const enrollmentBaseUrl = flags.enrollmentUrl === undefined ? undefined : validateHeadlessEnrollmentBaseUrl(flags.enrollmentUrl);
  const consoleBaseUrl = flags.consoleUrl === undefined ? undefined : normalizeConsoleBaseUrl(flags.consoleUrl);
  const teamId = config.native_broker?.team_id;
  if (typeof teamId !== "string") throw new Error("Native bridge configuration has no pinned Apple Team ID; rerun agentpass setup --team-id TEAMID");
  const application = inspectNativeApplication(undefined, { expectedTeamId: teamId });
  if (config.native_broker?.client !== application.client || config.native_broker?.manager !== application.manager || config.native_broker?.mach_service !== "dev.agentpass.native-service") throw new Error("Native bridge configuration does not match the verified AgentPass application");
  const enrollmentRunner = enrollmentMode ? createNativeDeviceEnrollmentRunner({ servicePath: application.service }) : undefined;
  let enrollmentInvitation;
  if (flags.enrollmentStdin) enrollmentInvitation = readEnrollmentInvitationStdin();
  if (flags.browser) {
    const receipt = readInstalledReleaseReceipt();
    const preflight = await prepareSetupPreflight({
      readInstalledReleaseReceipt: () => receipt,
      verifyInstalledRelease: () => verifyInstalledReleaseReceipt(),
      nativeRunner: enrollmentRunner
    });
    const controller = new AbortController();
    const abort = () => controller.abort();
    process.once("SIGINT", abort);
    process.once("SIGTERM", abort);
    try {
      enrollmentInvitation = await connectSetupInBrowser({
        consoleBaseUrl,
        cloudBaseUrl: enrollmentBaseUrl,
        preflight,
        signal: controller.signal
      });
    } finally {
      process.removeListener("SIGINT", abort);
      process.removeListener("SIGTERM", abort);
    }
  }
  const registerService = (context) => {
    let inspected = inspectNativeApplication(undefined, { expectedTeamId: teamId });
    if (inspected.serviceStatus !== "enabled") {
      const result = spawnSync(inspected.manager, ["register"], { encoding: "utf8", env: { PATH: "/usr/bin:/bin:/usr/sbin:/sbin" } });
      if (result.status !== 0) throw Object.assign(new Error("Native service registration failed"), { code: "SERVICE_REGISTRATION_FAILED" });
      inspected = inspectNativeApplication(undefined, { expectedTeamId: teamId });
    }
    if (inspected.serviceStatus !== "enabled") throw Object.assign(new Error("Approve AgentPass in System Settings, then continue setup"), { code: "SERVICE_APPROVAL_REQUIRED" });
    return { evidence: { version: 1, from_state: context.current_state, to_state: context.target_state, action: context.action.id, operation_id: context.operation_id, outcome: "completed", proof: { service: "dev.agentpass.native-service", status: "enabled" } } };
  };
  let runner;
  const nativeHandlers = () => {
    runner ??= createNativeBootstrapRunner({
      clientPath: application.client,
      servicePath: application.service
    });
    return createNativeSetupHandlers({ runner });
  };
  const handlers = {
    verify_app: (context) => ({ evidence: { version: 1, from_state: context.current_state, to_state: context.target_state, action: context.action.id, operation_id: context.operation_id, outcome: "already_completed", proof: { application: application.application, verification: "developer_id_gatekeeper_team_pinned" } } }),
    initialize_local_config: (context) => {
      if (config.version !== 4) throw Object.assign(new Error("Local configuration version is not supported"), { code: "CONFIG_VERSION_MISMATCH" });
      return { evidence: { version: 1, from_state: context.current_state, to_state: context.target_state, action: context.action.id, operation_id: context.operation_id, outcome: "already_completed", proof: { directory: defaultConfigDir, config_version: 4 } } };
    },
    select_native_bridge: (context) => ({ evidence: { version: 1, from_state: context.current_state, to_state: context.target_state, action: context.action.id, operation_id: context.operation_id, outcome: "already_completed", proof: { bridge: "production_native", client: application.client, manager: application.manager } } }),
    register_service: registerService,
    start_bootstrap: (context) => nativeHandlers().start_bootstrap(context),
    enroll_approval_key: (context) => nativeHandlers().enroll_approval_key(context),
    activate_service_keys: (context) => nativeHandlers().activate_service_keys(context)
  };
  const onboarding = config.setup_onboarding;
  const verifyCurrentCommit = () => {
    if (!onboarding?.server?.env?.AGENTPASS_PROJECT_DIR) throw Object.assign(new Error("Setup onboarding project is unavailable"), { code: "ONBOARDING_PROJECT_MISSING" });
    const project = onboarding.server.env.AGENTPASS_PROJECT_DIR;
    const commit = git(["-C", project, "rev-parse", "--verify", "HEAD^{commit}"]);
    const verified = spawnSync("git", ["-C", project, "verify-commit", commit], { encoding: "utf8", env: { PATH: "/usr/bin:/bin:/usr/sbin:/sbin" } });
    if (verified.status !== 0) throw Object.assign(new Error("Current Git commit is not cryptographically verified"), { code: "TEST_COMMIT_NOT_VERIFIED" });
    return { commit, verification: TEST_COMMIT_VERIFICATION_MARKER };
  };
  if (journal.status().state === "device_enrolled") handlers.connect_editor = createEditorConnectedHandler({ onboarding });
  if (journal.status().state === "editor_connected") handlers.verify_test_commit = createTestCommitVerifiedHandler({ verifierResult: verifyCurrentCommit() });
  if (journal.status().state === "test_commit_verified") handlers.complete_setup = createCompleteSetupHandler({ priorVerificationProof: verifyCurrentCommit() });
  if (enrollmentInvitation) {
    nativeHandlers();
    handlers.enroll_device = createDeviceEnrollmentSetupHandler({
      runner: enrollmentRunner,
      provisionControl: (input) => runner.provisionControl(input),
      restartService: async () => {
        const environment = { PATH: "/usr/bin:/bin:/usr/sbin:/sbin" };
        const unregister = spawnSync(application.manager, ["unregister"], { encoding: "utf8", env: environment });
        if (unregister.status !== 0 && !/not.registered|not found|does not exist/i.test(`${unregister.stdout ?? ""}\n${unregister.stderr ?? ""}`)) throw Object.assign(new Error("Native service unregister failed during control provisioning"), { code: "SERVICE_RESTART_FAILED" });
        const register = spawnSync(application.manager, ["register"], { encoding: "utf8", env: environment });
        if (register.status !== 0) throw Object.assign(new Error("Native service registration failed during control provisioning"), { code: "SERVICE_RESTART_FAILED" });
        const inspected = inspectNativeApplication(undefined, { expectedTeamId: teamId });
        if (inspected.serviceStatus !== "enabled") throw Object.assign(new Error("Native service requires approval after control provisioning"), { code: "SERVICE_APPROVAL_REQUIRED" });
        await brokerRequest({ operation: "native.control.refresh" }, { native: config.native_broker, timeoutMs: 30_000 });
        return { status: "enabled", control_refreshed: true };
      },
      invitation: enrollmentInvitation,
      baseUrl: enrollmentBaseUrl,
      loadConfig,
      saveConfig
    });
  }
  const result = await createSetupOrchestrator({ journal, handlers }).execute();
  console.log(JSON.stringify(publicSetupResult(result), null, 2));
}

async function setupNativeBridgeUnsafe() {
  if (args[0] === "status") {
    if (args.length !== 1) throw new Error("Usage: agentpass setup status");
    const result = readHeadlessOnboarding();
    console.log(JSON.stringify(result.ok ? result.status : result.error, null, 2));
    if (!result.ok) process.exitCode = 1;
    return;
  }
  if (args[0] === "continue") return continueNativeSetup();
  if (process.platform !== "darwin") throw new Error("Native AgentPass setup is supported only on macOS");
  if (process.getuid?.() === 0) throw new Error("Run setup as the interactive user, not root");
  const allowed = new Set(["--client", "--project", "--team-id"]);
  const flags = new Map();
  for (let index = 0; index < args.length; index += 1) {
    const argument = args[index];
    if (argument === "--execute") continue;
    if (!allowed.has(argument) || flags.has(argument) || index + 1 >= args.length || args[index + 1].startsWith("--")) {
      throw new Error("Usage: agentpass setup --client claude-code|cursor --team-id TEAMID [--project DIR] [--execute]");
    }
    flags.set(argument, args[index + 1]);
    index += 1;
  }
  const clientName = flags.get("--client") ?? "claude-code";
  const teamId = flags.get("--team-id");
  if (typeof teamId !== "string" || !/^[A-Z0-9]{10}$/.test(teamId)) throw new Error("setup requires --team-id with the pinned 10-character Apple Team ID");
  const project = path.resolve(flags.get("--project") ?? process.cwd());
  const application = inspectNativeApplication(undefined, { expectedTeamId: teamId });
  const config = loadConfig();
  const mcpServer = fileURLToPath(new URL("../adapters/mcp-server/bin/agentpass-mcp.mjs", import.meta.url));
  const integration = integrationPlan({ client: clientName, projectDir: project, nodePath: process.execPath, mcpServerPath: mcpServer });
  const preview = installIntegration(integration);
  const initialExecuteCommand = ["agentpass", "setup", "--client", clientName, "--team-id", teamId, "--project", project, "--execute"].map(shellWord).join(" ");
  if (!args.includes("--execute")) {
    console.log(JSON.stringify({ version: 1, dryRun: true, native: application, integration: preview, next: ["agentpass setup status", initialExecuteCommand] }, null, 2));
    return;
  }
  const next = ["agentpass setup status", "agentpass setup continue --execute"];
  const configured = { ...config, native_broker: { ...application.nativeBroker, team_id: teamId }, setup_onboarding: integration };
  saveConfig(configured);
  try {
    const installed = installIntegration(integration, { dryRun: false });
    const journal = createSetupJournal();
    const record = (target) => {
      if (SETUP_STATES.indexOf(journal.status().state) < SETUP_STATES.indexOf(target)) journal.transition(target);
    };
    record("app_verified");
    record("local_config_initialized");
    record("native_bridge_selected");
    if (application.serviceStatus === "enabled") record("service_registered");
    console.log(JSON.stringify({ version: 1, dryRun: false, configured: true, native: application, integration: installed, setup_journal: journal.status(), next }, null, 2));
  } catch (error) {
    saveConfig(config);
    throw error;
  }
}

async function setupNativeBridge() {
  if (args[0] === "prepare") return setupPrepare();
  try {
    return await setupNativeBridgeUnsafe();
  } catch (error) {
    const current = readHeadlessOnboarding();
    const status = current.ok && current.status.initialized ? current.status : undefined;
    console.log(JSON.stringify(publicSetupFailure(error, status), null, 2));
    process.exitCode = 1;
  }
}

async function setupPrepare() {
  if (args.length !== 2 || args[0] !== "prepare" || args[1] !== "--json") {
    throw new Error("Usage: agentpass setup prepare --json");
  }
  try {
    // The receipt is the only durable public release identity retained after
    // the signed installer has completed. Re-read it through the protected
    // root on both sides of preflight, and independently inspect the current
    // app bundle before asking the native service for its public P-256 key.
    const receipt = readInstalledReleaseReceipt();
    const application = inspectNativeApplication(undefined, { expectedTeamId: receipt.team_id });
    const nativeRunner = createNativeDeviceEnrollmentRunner({ servicePath: application.service });
    const handoff = await prepareSetupPreflight({
      readInstalledReleaseReceipt: () => receipt,
      verifyInstalledRelease: () => verifyInstalledReleaseReceipt(),
      nativeRunner
    });
    process.stdout.write(serializeSetupPreflightHandoff(handoff));
  } catch (error) {
    process.stdout.write(`${JSON.stringify(publicSetupPreflightFailure(error))}\n`);
    process.exitCode = 1;
  }
}

async function uninstallProduction() {
  const allowed = new Set(["--project", "--team-id", "--confirm"]); const flags = new Map(); const switches = new Set();
  for (let index = 0; index < args.length; index += 1) {
    const argument = args[index];
    if (["--execute", "--system", "--purge-user-state"].includes(argument)) {
      if (switches.has(argument)) throw new Error("Usage: agentpass uninstall [--project DIR] [--team-id TEAMID] [--execute] [--system] | agentpass uninstall --purge-user-state [--confirm PURGE_USER_STATE] [--execute]");
      switches.add(argument); continue;
    }
    if (!allowed.has(argument) || flags.has(argument) || index + 1 >= args.length || args[index + 1].startsWith("--")) throw new Error("Usage: agentpass uninstall [--project DIR] [--team-id TEAMID] [--execute] [--system] | agentpass uninstall --purge-user-state [--confirm PURGE_USER_STATE] [--execute]");
    flags.set(argument, args[++index]);
  }
  if (switches.has("--purge-user-state")) {
    if (switches.has("--system") || flags.has("--project") || flags.has("--team-id")) throw new Error("--purge-user-state cannot be combined with system uninstall options");
    const execute = switches.has("--execute");
    const config = execute ? loadConfig() : null;
    const result = await runUserStatePurge({ execute, confirm: flags.get("--confirm"), native: config?.native_broker, agentId: config?.default_agent_id, requestNative: brokerRequest });
    if (!switches.has("--execute")) {
      console.log(JSON.stringify({ ...result, next: "agentpass uninstall --purge-user-state --confirm PURGE_USER_STATE --execute" }, null, 2));
      return;
    }
    console.log(JSON.stringify(result, null, 2));
    return;
  }
  if (flags.has("--confirm")) throw new Error("--confirm is valid only with --purge-user-state");
  const system = switches.has("--system");
  const configuredTeamId = system ? undefined : loadConfig().native_broker?.team_id;
  const teamId = flags.get("--team-id") ?? configuredTeamId;
  if (typeof teamId !== "string" || !/^[A-Z0-9]{10}$/.test(teamId)) throw new Error("uninstall requires the pinned 10-character Apple Team ID");
  const project = path.resolve(flags.get("--project") ?? process.cwd());
  const mcpServer = fileURLToPath(new URL("../adapters/mcp-server/bin/agentpass-mcp.mjs", import.meta.url));
  const integrations = system ? [] : ["claude-code", "cursor"].map((client) => ({ client, projectDir: project, nodePath: process.execPath, mcpServerPath: mcpServer }));
  const plan = planProductionUninstall({ integrations, includeUser: !system, expectedTeamId: teamId });
  if (!switches.has("--execute")) {
    console.log(JSON.stringify({ ...plan, next: system ? "rerun as root with --system --execute" : "rerun with --execute; then run the reported system command" }, null, 2));
    return;
  }
  const result = executeProductionUninstall(plan, { execute: true, scope: system ? "system" : "user", includeUser: !system, expectedTeamId: teamId });
  console.log(JSON.stringify({ ...result, system_removal_required: !system && plan.requiresRoot, system_command: !system && plan.requiresRoot ? `sudo agentpass uninstall --system --team-id ${teamId} --execute` : null }, null, 2));
}

function init() {
  const dir = defaultConfigDir;
  if (fs.existsSync(path.join(dir, "config.json"))) throw new Error(`Already initialized: ${dir}`);
  const repository = git(["rev-parse", "--show-toplevel"], true) || process.cwd();
  const origin = git(["remote", "get-url", "origin"], true);
  const identity = createAgentIdentity(dir, process.env.AGENTPASS_AGENT ?? "coding-agent");
  const auditIdentity = createAuditIdentity(dir);
  const operations = ["git.commit.sign"];
  const repositories = [path.resolve(repository)];
  const branches = { allow: ["feature/*", "fix/*", "chore/*"], deny: ["main", "master", "production"] };
  const remotes = { allow: origin ? [origin] : [] };
  saveConfig({
    version: 4,
    agent: { name: process.env.AGENTPASS_AGENT ?? "coding-agent" },
    agents: [{ id: identity.id, name: identity.name, public_key: identity.public_key, scope: { operations, repositories, branches, remotes } }],
    default_agent_id: identity.id,
    operations,
    repositories,
    branches,
    remotes,
    signing: { key: path.join(defaultConfigDir, "keys", "id_git_sign"), provider: "/usr/lib/ssh-keychain.dylib" },
    audit_signing: { public_key: auditIdentity.public_key },
    session: { required: true, ttl_seconds: 3600 }
  }, dir);
  saveState({ revoked: false, generation: 0 }, dir);
  audit({ operation: "config.init", decision: "allow", agent: process.env.AGENTPASS_AGENT ?? "coding-agent" }, dir);
  console.log(`Initialized ${dir}`);
}

function migrate() {
  const config = loadConfig();
  if (config.version >= 4) throw new Error("Configuration is already at version 4");
  const identity = config.version >= 3 ? null : createAgentIdentity(defaultConfigDir, config.agent?.name ?? "coding-agent");
  const auditIdentity = createAuditIdentity(defaultConfigDir);
  const policy = scopeFromPolicy(config);
  const previousTtl = Number(config.session?.ttl_seconds);
  const ttlSeconds = Number.isFinite(previousTtl) ? Math.max(60, Math.min(previousTtl, 86400)) : 3600;
  const migrated = {
    ...config,
    version: 4,
    agents: (identity ? [{ id: identity.id, name: identity.name, public_key: identity.public_key }] : config.agents).map((agent) => ({ ...agent, scope: agent.scope ?? policy })),
    default_agent_id: identity ? identity.id : config.default_agent_id,
    operations: policy.operations,
    repositories: policy.repositories,
    branches: policy.branches,
    remotes: policy.remotes,
    audit_signing: { public_key: auditIdentity.public_key },
    session: { ...config.session, ttl_seconds: ttlSeconds, required: true }
  };
  saveConfig(migrated);
  audit({ operation: "config.migrate", decision: "allow", from_version: config.version, to_version: 4, agent_id: identity?.id ?? config.default_agent_id }, defaultConfigDir);
  console.log("Migrated to configuration version 4. Restart the AgentPass broker.");
}

function context(config) {
  const root = git(["rev-parse", "--show-toplevel"]);
  const supplied = process.env.AGENTPASS_SESSION;
  const session = loadSession(supplied);
  const agentId = process.env.AGENTPASS_AGENT_ID ?? config.default_agent_id;
  const sessionValid = isSessionValid(session, supplied, agentId);
  return {
    cwd: root,
    branch: git(["branch", "--show-current"], true) || "HEAD",
    remote: git(["remote", "get-url", "origin"], true),
    revoked: loadState().revoked,
    policy: { ...config, session: { ...config.session, valid: sessionValid } }
  };
}

function isSessionValid(session, supplied, agentId) {
  return Boolean(session && supplied && session.agent_id === agentId && crypto.createHash("sha256").update(supplied).digest("hex") === session.token_hash && Date.now() < Date.parse(session.expires_at) && session.generation === loadState().generation);
}

async function sessionStart() {
  const config = loadConfig();
  const agentFlag = args.indexOf("--agent");
  const agentId = agentFlag >= 0 ? args[agentFlag + 1] : (process.env.AGENTPASS_AGENT_ID ?? config.default_agent_id);
  if (!config.agents?.some((agent) => agent.id === agentId)) throw new Error("Cannot create a session for an unknown agent identity");
  const ttlArgument = args.slice(1).find((value, index, values) => value !== "--agent" && values[index - 1] !== "--agent");
  const ttl = Math.max(60, Math.min(Number(ttlArgument ?? config.session?.ttl_seconds ?? 3600), 86400));
  if (!Number.isFinite(ttl)) throw new Error("Session TTL must be a number of seconds");
  if (config.native_broker?.enabled) {
    const result = await brokerRequest({ operation: "native.session.start", agent_id: agentId, ttl_seconds: ttl }, { native: config.native_broker, timeoutMs: 120_000 });
    const issued = JSON.parse(Buffer.from(result.stdout_base64, "base64").toString("utf8"));
    if (typeof issued.token !== "string" || typeof issued.expires_at !== "string" || issued.agent_id !== agentId) throw new Error("Native service returned an invalid session");
    console.log(issued.token);
    console.error(`Session expires at ${issued.expires_at}`);
    return;
  }
  const token = crypto.randomBytes(32).toString("base64url");
  const state = loadState();
  const expiresAt = new Date(Date.now() + ttl * 1000).toISOString();
  saveSession({ token_hash: crypto.createHash("sha256").update(token).digest("hex"), expires_at: expiresAt, generation: state.generation, agent_id: agentId });
  audit({ operation: "session.start", decision: "allow", expires_at: expiresAt, generation: state.generation, agent_id: agentId }, defaultConfigDir);
  console.log(token);
  console.error(`Session expires at ${expiresAt}`);
}

function check() {
  const config = loadConfig();
  const identity = selectedAgent(config);
  const result = evaluateAgentRequest({ ...context(config), operation: "git.commit.sign" }, identity);
  audit({ operation: "git.commit.sign", decision: result.allowed ? "allow" : "deny", reason: result.reason, cwd: process.cwd() }, defaultConfigDir);
  console.log(JSON.stringify(result, null, 2));
  if (!result.allowed) process.exitCode = 1;
}

function status() {
  const config = loadConfig();
  const state = loadState();
  console.log(JSON.stringify({
    version: config.version,
    agent: config.agent,
    agents: config.agents?.map((agent) => ({ id: agent.id, name: agent.name, default: agent.id === config.default_agent_id })),
    operations: config.operations,
    repositories: config.repositories,
    revoked: state.revoked,
    generation: state.generation,
    audit: auditPath(),
    audit_key_fingerprint: config.audit_signing?.public_key ? publicKeyFingerprint(config.audit_signing.public_key) : null
  }, null, 2));
}

function revoke() {
  const config = loadConfig();
  if (config.native_broker?.enabled) throw new Error("User-state revoke does not control the native service; use `agentpass native revoke-sessions`");
  const state = loadState();
  saveState({ ...state, revoked: true, generation: (state.generation ?? 0) + 1, revoked_at: new Date().toISOString() });
  audit({ operation: "control.revoke", decision: "allow", generation: state.generation + 1 }, defaultConfigDir);
  console.log("All AgentPass operations revoked.");
}

function restore() {
  const config = loadConfig();
  if (config.native_broker?.enabled) throw new Error("User-state restore does not control the native service; start a new protected native session instead");
  if (args[0] !== "--confirm" || args[1] !== "RESTORE") throw new Error("Restoring requires: agentpass restore --confirm RESTORE");
  const state = loadState();
  saveState({ ...state, revoked: false, generation: (state.generation ?? 0) + 1, restored_at: new Date().toISOString() });
  audit({ operation: "control.restore", decision: "allow", generation: state.generation + 1 }, defaultConfigDir);
  console.log("AgentPass operations restored.");
}

async function doctor() {
  const allowed = new Set(["--client", "--project", "--team-id"]);
  const flags = new Map();
  for (let index = 0; index < args.length; index += 1) {
    const argument = args[index];
    if (argument === "--verbose") continue;
    if (!allowed.has(argument) || flags.has(argument) || index + 1 >= args.length || args[index + 1].startsWith("--")) {
      throw new Error("Usage: agentpass doctor [--client claude-code|cursor] [--project DIR] [--team-id TEAMID] [--verbose]");
    }
    flags.set(argument, args[index + 1]);
    index += 1;
  }
  const expectedTeamId = flags.get("--team-id") ?? process.env.AGENTPASS_RELEASE_TEAM_ID;
  if (expectedTeamId !== undefined && !/^[A-Z0-9]{10}$/.test(expectedTeamId)) throw new Error("Doctor Team ID must contain 10 uppercase letters or digits");
  const report = await runProductionDoctor({
    client: flags.get("--client"),
    projectDir: flags.has("--project") ? path.resolve(flags.get("--project")) : undefined,
    expectedTeamId,
    verbose: args.includes("--verbose")
  }, {
    nativeStatus: async (native) => {
      const health = await brokerRequest({ operation: "ping" }, { native, timeoutMs: 10_000 });
      const auditResult = await brokerRequest({ operation: "native.audit.status" }, { native, timeoutMs: 30_000 });
      return { health, audit: JSON.parse(Buffer.from(auditResult.stdout_base64, "base64").toString("utf8")) };
    }
  });
  console.log(JSON.stringify(report, null, 2));
  if (!report.ok) process.exitCode = 1;
}

function setupMacos() {
  if (process.platform !== "darwin") throw new Error("Secure Enclave setup is currently supported only on macOS");
  const commands = [
    "sc_auth create-ctk-identity -l agentpass-git-sign -k p-256-ne -t none",
    "mkdir -p ~/.agentpass/keys",
    "cd ~/.agentpass/keys && ssh-keygen -w /usr/lib/ssh-keychain.dylib -K -N \"\"",
    "mv ~/.agentpass/keys/id_ecdsa_sk_rk ~/.agentpass/keys/id_git_sign",
    "mv ~/.agentpass/keys/id_ecdsa_sk_rk.pub ~/.agentpass/keys/id_git_sign.pub"
  ];
  if (!args.includes("--execute")) {
    console.log(commands.join("\n"));
    console.log("\nDry run only. Re-run with --execute after reviewing the commands.");
    return;
  }
  const keyDir = path.join(defaultConfigDir, "keys");
  if (!args.includes("--force") && (fs.existsSync(path.join(keyDir, "id_git_sign")) || fs.existsSync(path.join(keyDir, "id_git_sign.pub")))) {
    throw new Error("AgentPass signing key already exists; use --force only if you intend to replace it");
  }
  if (args.includes("--force")) {
    const backup = `${Date.now()}.bak`;
    for (const file of ["id_git_sign", "id_git_sign.pub"]) {
      const target = path.join(keyDir, file);
      if (fs.existsSync(target)) fs.renameSync(target, `${target}.${backup}`);
    }
  }
  let result = spawnSync("sc_auth", ["create-ctk-identity", "-l", "agentpass-git-sign", "-k", "p-256-ne", "-t", "none"], { stdio: "inherit" });
  if (result.status !== 0) throw new Error("Setup command failed: sc_auth");
  fs.mkdirSync(keyDir, { recursive: true, mode: 0o700 });
  result = spawnSync("/usr/bin/ssh-keygen", ["-w", "/usr/lib/ssh-keychain.dylib", "-K", "-N", ""], { stdio: "inherit", cwd: keyDir });
  if (result.status !== 0) throw new Error("Setup command failed: ssh-keygen");
  fs.renameSync(path.join(keyDir, "id_ecdsa_sk_rk"), path.join(keyDir, "id_git_sign"));
  fs.renameSync(path.join(keyDir, "id_ecdsa_sk_rk.pub"), path.join(keyDir, "id_git_sign.pub"));
  fs.chmodSync(path.join(keyDir, "id_git_sign"), 0o600);
  fs.chmodSync(path.join(keyDir, "id_git_sign.pub"), 0o644);
  console.log("Secure Enclave-backed SSH signing key created.");
}

function installHook() {
  const root = git(["rev-parse", "--show-toplevel"]);
  const hook = path.join(root, ".git", "hooks", "pre-push");
  if (fs.existsSync(hook) && !args.includes("--force")) throw new Error(`${hook} exists; use --force to replace it`);
  const wrapper = fileURLToPath(new URL("./agentpass-pre-push.mjs", import.meta.url));
  fs.writeFileSync(hook, `#!/bin/sh\nexec /usr/bin/env node ${JSON.stringify(wrapper)} "$@"\n`, { mode: 0o755 });
  fs.chmodSync(hook, 0o755);
  console.log(`Installed ${hook}`);
}

async function pushCheck() {
  const config = loadConfig();
  const state = loadState();
  const remote = args[0] ?? "origin";
  const remoteUrl = args[1] ?? git(["remote", "get-url", remote], true);
  const lines = fs.readFileSync(0, "utf8").trim().split("\n").filter(Boolean);
  const refs = lines.length ? lines : [`local 0000000 refs/heads/${git(["branch", "--show-current"], true)} 0000000`];
  const identity = selectedAgent(config);
  let sessionValid;
  let controlValid = true;
  if (config.native_broker?.enabled) {
    const [sessionResponse, controlResponse] = await Promise.all([
      brokerRequest({ operation: "native.session.validate", agent_id: identity.id, session: process.env.AGENTPASS_SESSION ?? null }, { native: config.native_broker }),
      brokerRequest({ operation: "native.control.validate", agent_id: identity.id }, { native: config.native_broker })
    ]);
    const sessionStatus = JSON.parse(Buffer.from(sessionResponse.stdout_base64, "base64").toString("utf8"));
    const controlStatus = JSON.parse(Buffer.from(controlResponse.stdout_base64, "base64").toString("utf8"));
    sessionValid = sessionStatus.valid === true;
    controlValid = controlStatus.valid === true;
  } else {
    sessionValid = isSessionValid(loadSession(process.env.AGENTPASS_SESSION), process.env.AGENTPASS_SESSION, identity.id);
  }
  const results = refs.map((line) => {
    const [, , remoteRef] = line.split(/\s+/);
    const isTag = remoteRef?.startsWith("refs/tags/");
    const operation = isTag ? "git.tag.push" : "git.push";
    const branch = (remoteRef ?? `refs/heads/${git(["branch", "--show-current"], true)}`).replace(/^refs\/(heads|tags)\//, "");
    const agentId = identity.id;
    const requestContext = { policy: { ...config, session: { ...config.session, valid: sessionValid } }, cwd: git(["rev-parse", "--show-toplevel"]), branch, remote: remoteUrl, operation, revoked: config.native_broker?.enabled ? !controlValid : state.revoked };
    const result = evaluateAgentRequest(requestContext, identity);
    audit({ operation, decision: result.allowed ? "allow" : "deny", reason: result.reason, branch, remote: remoteUrl }, defaultConfigDir);
    return { operation, branch, ...result };
  });
  console.log(JSON.stringify(results, null, 2));
  if (results.some((result) => !result.allowed)) process.exitCode = 1;
}

async function gitSign(signArgs = args) {
  const config = loadConfig();
  const { payloadPath, payload, brokerArgs } = readGitSigningInvocation(signArgs);
  const agentId = selectedAgent(config).id;
  const privatePath = path.join(defaultConfigDir, "agents", `${agentId}.pem`);
  const capability = config.control_v2 ? readCapabilityInput() : undefined;
  const request = signRequest({
    request_id: crypto.randomUUID(),
    operation: "git.commit.sign",
    cwd: process.cwd(),
    sign_args: brokerArgs,
    payload_base64: payload.toString("base64"),
    session: process.env.AGENTPASS_SESSION ?? null,
    agent_id: agentId,
    timestamp_ms: Date.now(),
    nonce: crypto.randomBytes(24).toString("base64url"),
    ...(capability ? { capability } : {})
  }, privatePath);
  const response = await brokerRequest(request, { timeoutMs: 30000, native: config.native_broker });
  writeGitSignature(payloadPath, Buffer.from(response.stdout_base64, "base64"));
}

function readCapabilityInput() {
  const file = process.env.AGENTPASS_CAPABILITY_PATH;
  if (typeof file !== "string" || !path.isAbsolute(file)) throw new Error("ControlBundle v2 requires AGENTPASS_CAPABILITY_PATH to name an absolute capability file");
  const stat = fs.lstatSync(file);
  const uid = process.getuid?.();
  if (!stat.isFile() || stat.isSymbolicLink() || stat.size < 2 || stat.size > 256 * 1024 || (stat.mode & 0o077) !== 0 || (uid !== undefined && stat.uid !== uid)) throw new Error("Capability file permissions are unsafe");
  let capability;
  try { capability = JSON.parse(fs.readFileSync(file, "utf8")); } catch { throw new Error("Capability file is not valid JSON"); }
  if (!capability || typeof capability !== "object" || Array.isArray(capability)) throw new Error("Capability file must contain an object");
  return capability;
}

function selectedAgent(config) {
  const agentId = process.env.AGENTPASS_AGENT_ID ?? config.default_agent_id;
  const identity = config.agents?.find((agent) => agent.id === agentId);
  if (!identity) throw new Error("Selected agent identity is not enrolled");
  return identity;
}

async function brokerPing() {
  const config = loadConfig();
  const response = await brokerRequest({ operation: "ping" }, { native: config.native_broker });
  console.log(JSON.stringify(response, null, 2));
}

async function nativeManage() {
  const action = args[0];
  if (action === "key-delete" && (args.length !== 9 || args[1] !== "audit_checkpoint" || !/^[1-9]\d*$/.test(args[2]) || args[3] !== "--reason" || !args[4] || args[5] !== "--retention" || !/^[1-9]\d*$/.test(args[6]) || args[7] !== "--proof")) {
    throw new Error("Usage: agentpass native key-delete audit_checkpoint GENERATION --reason TEXT --retention SECONDS --proof FILE");
  }
  const config = loadConfig();
  if (!config.native_broker?.enabled) throw new Error("Native broker is not configured");
  if (["daemon-register", "daemon-unregister", "daemon-status", "daemon-open-settings"].includes(action)) {
    const manager = config.native_broker.manager ?? path.join(path.dirname(config.native_broker.client), "agentpass-native-manager");
    const stat = fs.lstatSync(manager);
    const currentUid = process.getuid?.();
    if (!stat.isFile() || stat.isSymbolicLink() || (stat.mode & 0o022) !== 0 || (currentUid !== undefined && stat.uid !== currentUid && stat.uid !== 0)) throw new Error("Native manager executable permissions are unsafe");
    const managerAction = { "daemon-register": "register", "daemon-unregister": "unregister", "daemon-status": "status", "daemon-open-settings": "open-settings" }[action];
    const result = spawnSync(manager, [managerAction], { encoding: "utf8", env: { PATH: "/usr/bin:/bin:/usr/sbin:/sbin" } });
    if (result.status !== 0) throw new Error(result.stderr.trim() || result.stdout.trim() || "Native service management failed");
    console.log(JSON.stringify(JSON.parse(result.stdout.trim()), null, 2));
  } else if (action === "status") {
    const health = await brokerRequest({ operation: "ping" }, { native: config.native_broker });
    const auditResult = await brokerRequest({ operation: "native.audit.status" }, { native: config.native_broker });
    console.log(JSON.stringify({ health, audit: JSON.parse(Buffer.from(auditResult.stdout_base64, "base64").toString("utf8")) }, null, 2));
  } else if (action === "public-key") {
    const result = await brokerRequest({ operation: "native.public-key" }, { native: config.native_broker });
    console.log(result.public_key);
  } else if (action === "audit-key") {
    const result = await brokerRequest({ operation: "native.audit.public-key" }, { native: config.native_broker });
    console.log(result.public_key);
  } else if (action === "checkpoint") {
    const result = await brokerRequest({ operation: "native.audit.checkpoint" }, { native: config.native_broker, timeoutMs: 30_000 });
    console.log(JSON.stringify(JSON.parse(Buffer.from(result.stdout_base64, "base64").toString("utf8")), null, 2));
  } else if (action === "audit-rotate") {
    const result = await brokerRequest({ operation: "native.audit.rotate" }, { native: config.native_broker, timeoutMs: 30_000 });
    console.log(JSON.stringify(JSON.parse(Buffer.from(result.stdout_base64, "base64").toString("utf8")), null, 2));
  } else if (action === "audit-evidence-rotate") {
    if (args.length !== 1) throw new Error("native audit-evidence-rotate does not accept arguments");
    const result = await brokerRequest({ operation: "native.audit.evidence.rotate" }, { native: config.native_broker, timeoutMs: 30_000 });
    console.log(JSON.stringify(JSON.parse(Buffer.from(result.stdout_base64, "base64").toString("utf8")), null, 2));
  } else if (action === "key-lifecycle-status") {
    if (args.length !== 1) throw new Error("native key-lifecycle-status does not accept arguments");
    const result = await brokerRequest({ operation: "native.key-lifecycle.status" }, { native: config.native_broker, timeoutMs: 30_000 });
    console.log(JSON.stringify(JSON.parse(Buffer.from(result.stdout_base64, "base64").toString("utf8")), null, 2));
  } else if (action === "key-stage") {
    if (args.length !== 2 || !["git_signing", "audit_checkpoint", "session_approval"].includes(args[1])) throw new Error("Usage: agentpass native key-stage git_signing|audit_checkpoint|session_approval");
    const result = await brokerRequest({ operation: "native.key.stage", role: args[1] }, { native: config.native_broker, timeoutMs: 30_000 });
    console.log(JSON.stringify(JSON.parse(Buffer.from(result.stdout_base64, "base64").toString("utf8")), null, 2));
  } else if (action === "key-activate") {
    if (args.length !== 5 || !["git_signing", "audit_checkpoint", "session_approval"].includes(args[1]) || !/^[1-9]\d*$/.test(args[2]) || args[3] !== "--reason" || !args[4]) throw new Error("Usage: agentpass native key-activate ROLE GENERATION --reason TEXT");
    const result = await brokerRequest({ operation: "native.key.activate", role: args[1], generation: Number(args[2]), reason: args[4] }, { native: config.native_broker, timeoutMs: 120_000 });
    console.log(JSON.stringify(JSON.parse(Buffer.from(result.stdout_base64, "base64").toString("utf8")), null, 2));
  } else if (action === "key-abort") {
    if (args.length !== 5 || !["git_signing", "audit_checkpoint"].includes(args[1]) || !/^[1-9]\d*$/.test(args[2]) || args[3] !== "--reason" || !args[4]) throw new Error("Usage: agentpass native key-abort git_signing|audit_checkpoint GENERATION --reason TEXT");
    const result = await brokerRequest({ operation: "native.key.abort", role: args[1], generation: Number(args[2]), reason: args[4] }, { native: config.native_broker, timeoutMs: 120_000 });
    console.log(JSON.stringify(JSON.parse(Buffer.from(result.stdout_base64, "base64").toString("utf8")), null, 2));
  } else if (action === "key-delete") {
    const proof = readCanonicalJsonFile(path.resolve(args[8]), 16 * 1024, "Lifecycle deletion proof");
    const result = await brokerRequest({ operation: "native.key.delete", role: args[1], generation: Number(args[2]), reason: args[4], minimum_retention_seconds: Number(args[6]), proof }, { native: config.native_broker, timeoutMs: 120_000 });
    console.log(JSON.stringify(JSON.parse(Buffer.from(result.stdout_base64, "base64").toString("utf8")), null, 2));
  } else if (action === "recovery-request") {
    if (args.length !== 2 || !["git_signing", "audit_checkpoint", "session_approval"].includes(args[1])) throw new Error("Usage: agentpass native recovery-request ROLE");
    const result = await brokerRequest({ operation: "native.recovery.request", role: args[1] }, { native: config.native_broker, timeoutMs: 30_000 });
    const response = JSON.parse(Buffer.from(result.stdout_base64, "base64").toString("utf8"));
    const request = Buffer.from(response.request_base64, "base64");
    if (request.length === 0 || request.length > 16 * 1024 || request.toString("base64") !== response.request_base64) throw new Error("Native service returned invalid recovery request bytes");
    process.stdout.write(request);
    process.stdout.write("\n");
  } else if (action === "recovery-install") {
    const flags = strictRecoveryFlags(args.slice(1), ["--request", "--policy", "--authorization"], new Set(["--authorization"]));
    const request = readCanonicalJsonFile(path.resolve(flags.get("--request")[0]), 16 * 1024, "Recovery request");
    const policy = readCanonicalJsonFile(path.resolve(flags.get("--policy")[0]), 256 * 1024, "Recovery policy");
    const authorizations = flags.get("--authorization").map((file) => readCanonicalJsonFile(path.resolve(file), 16 * 1024, "Recovery authorization"));
    verifyRecoveryThreshold(request, authorizations, policy);
    const evidence = Buffer.from(canonicalJson({
      authorizations_base64: authorizations.map((value) => Buffer.from(canonicalJson(value)).toString("base64")),
      policy_base64: Buffer.from(canonicalJson(policy)).toString("base64"),
      request_base64: Buffer.from(canonicalJson(request)).toString("base64"),
      version: 1
    }));
    const result = await brokerRequest({ operation: "native.recovery.install", evidence_base64: evidence.toString("base64") }, { native: config.native_broker, timeoutMs: 120_000 });
    console.log(JSON.stringify(JSON.parse(Buffer.from(result.stdout_base64, "base64").toString("utf8")), null, 2));
  } else if (action === "recovery-prepare") {
    const flags = strictRecoveryFlags(args.slice(1), ["--request", "--policy", "--authorization"], new Set(["--authorization"]));
    const request = readCanonicalJsonFile(path.resolve(flags.get("--request")[0]), 16 * 1024, "Recovery request");
    if (request.role !== "audit_checkpoint") throw new Error("native recovery-prepare is only for audit_checkpoint; use native recovery-install for this role");
    const policy = readCanonicalJsonFile(path.resolve(flags.get("--policy")[0]), 256 * 1024, "Recovery policy");
    const authorizations = flags.get("--authorization").map((file) => readCanonicalJsonFile(path.resolve(file), 16 * 1024, "Recovery authorization"));
    verifyRecoveryThreshold(request, authorizations, policy);
    const evidence = Buffer.from(canonicalJson({
      authorizations_base64: authorizations.map((value) => Buffer.from(canonicalJson(value)).toString("base64")),
      policy_base64: Buffer.from(canonicalJson(policy)).toString("base64"),
      request_base64: Buffer.from(canonicalJson(request)).toString("base64"),
      version: 1
    }));
    const result = await brokerRequest({ operation: "native.recovery.prepare", evidence_base64: evidence.toString("base64") }, { native: config.native_broker, timeoutMs: 30_000 });
    const response = JSON.parse(Buffer.from(result.stdout_base64, "base64").toString("utf8"));
    const authorization = Buffer.from(response.anchor_authorization_base64 ?? "", "base64");
    if (!authorization.length || authorization.length > 32 * 1024 || authorization.toString("base64") !== response.anchor_authorization_base64) throw new Error("Native service returned invalid anchor recovery authorization bytes");
    const parsed = JSON.parse(authorization.toString("utf8"));
    if (canonicalJson(parsed) !== authorization.toString("utf8")) throw new Error("Native service returned noncanonical anchor recovery authorization");
    process.stdout.write(authorization);
    process.stdout.write("\n");
  } else if (action === "recovery-anchor-install") {
    const flags = strictRecoveryFlags(args.slice(1), ["--evidence"]);
    const evidence = readCanonicalJsonFile(path.resolve(flags.get("--evidence")[0]), 512 * 1024, "Anchor recovery evidence");
    const evidenceBytes = Buffer.from(canonicalJson(evidence));
    const result = await brokerRequest({ operation: "native.recovery.anchor.install", evidence_base64: evidenceBytes.toString("base64") }, { native: config.native_broker, timeoutMs: 120_000 });
    console.log(JSON.stringify(JSON.parse(Buffer.from(result.stdout_base64, "base64").toString("utf8")), null, 2));
  } else if (action === "anchor-push") {
    const result = await brokerRequest({ operation: "native.audit.anchor.push" }, { native: config.native_broker, timeoutMs: 30_000 });
    console.log(JSON.stringify(JSON.parse(Buffer.from(result.stdout_base64, "base64").toString("utf8")), null, 2));
  } else if (action === "anchor-status") {
    const result = await brokerRequest({ operation: "native.audit.anchor.status" }, { native: config.native_broker, timeoutMs: 30_000 });
    console.log(JSON.stringify(JSON.parse(Buffer.from(result.stdout_base64, "base64").toString("utf8")), null, 2));
  } else if (action === "session-approval-key") {
    const result = await brokerRequest({ operation: "native.session.approval-public-key" }, { native: config.native_broker, timeoutMs: 30_000 });
    console.log(result.public_key);
  } else if (action === "revoke-sessions") {
    const result = await brokerRequest({ operation: "native.session.revoke" }, { native: config.native_broker });
    console.log(JSON.stringify(JSON.parse(Buffer.from(result.stdout_base64, "base64").toString("utf8")), null, 2));
  } else {
    throw new Error("Unknown native command");
  }
}

async function controlManage() {
  const action = args[0];
  if (action === "keygen") {
    if (!args[1]) throw new Error("Control key generation requires an output directory");
    console.log(JSON.stringify(generateControlKeyPair(path.resolve(args[1])), null, 2));
    return;
  }
  if (action === "sign") {
    const privateFile = requiredFlag("--key");
    const sequence = Number(requiredFlag("--sequence"));
    const expiresAt = requiredFlag("--expires");
    const revokedAgents = repeatedFlag("--revoke-agent");
    const bundle = signControlBundle({ sequence, expiresAt, globalRevoked: args.includes("--global-revoke"), revokedAgents }, path.resolve(privateFile));
    console.log(JSON.stringify(bundle, null, 2));
    return;
  }

  const config = loadConfig();
  const native = config.native_broker?.enabled === true;
  if (action === "source") {
    if (!native) throw new Error("Control source is only used by the native broker; local mode configures it with control trust --url");
    if (!args[1]) throw new Error("Control source requires an HTTPS URL");
    const url = new URL(args[1]);
    if (url.protocol !== "https:") throw new Error("Native control source must use HTTPS");
    saveConfig({ ...config, native_broker: { ...config.native_broker, control_url: url.toString() } });
    console.log(JSON.stringify({ url: url.toString(), trust: "root-owned native policy" }, null, 2));
  } else if (action === "trust") {
    if (native) throw new Error("Native control trust is defined only by the root-owned service policy; update it through the operator provisioning flow");
    if (!args[1]) throw new Error("Control trust requires a public key file");
    const publicKey = fs.readFileSync(path.resolve(args[1]), "utf8");
    const urlIndex = args.indexOf("--url");
    const refreshIndex = args.indexOf("--refresh");
    const url = urlIndex >= 0 ? args[urlIndex + 1] : undefined;
    const refreshSeconds = refreshIndex >= 0 ? Number(args[refreshIndex + 1]) : 60;
    const control = { required: true, public_key: publicKey };
    if (url) Object.assign(control, { url, refresh_seconds: refreshSeconds });
    const newFingerprint = controlKeyFingerprint(publicKey);
    const currentFingerprint = config.control?.public_key ? controlKeyFingerprint(config.control.public_key) : null;
    if (currentFingerprint && currentFingerprint !== newFingerprint && !(args.includes("--confirm") && args.includes("ROTATE_TRUST"))) throw new Error("Replacing the control trust root requires --confirm ROTATE_TRUST");
    saveConfig({ ...config, control });
    const existingBundle = controlBundlePath();
    if (currentFingerprint !== newFingerprint && fs.existsSync(existingBundle)) fs.renameSync(existingBundle, `${existingBundle}.${Date.now()}.untrusted.bak`);
    audit({ operation: "control.trust", decision: "allow", key_fingerprint: newFingerprint, previous_key_fingerprint: currentFingerprint, url: url ?? null }, defaultConfigDir);
    console.log(JSON.stringify({ fingerprint: newFingerprint, url: url ?? null }, null, 2));
    console.error("Install a signed control bundle, then restart the broker.");
  } else if (action === "apply") {
    if (!args[1]) throw new Error("Control apply requires a bundle file");
    const bundle = readJsonFile(path.resolve(args[1]), 256 * 1024);
    if (native) {
      const result = await brokerRequest({ operation: "native.control.apply", bundle }, { native: config.native_broker, timeoutMs: 30_000 });
      console.log(JSON.stringify(JSON.parse(Buffer.from(result.stdout_base64, "base64").toString("utf8")), null, 2));
      return;
    }
    const verified = applyControlBundle(bundle, config, defaultConfigDir);
    audit({ operation: "control.apply", decision: "allow", sequence: verified.sequence, expires_at: verified.expires_at, global_revoked: verified.global_revoked, revoked_agents: verified.revoked_agents }, defaultConfigDir);
    console.log(JSON.stringify(verified, null, 2));
  } else if (action === "fetch") {
    const sourceURL = native ? config.native_broker.control_url : config.control?.url;
    if (!sourceURL) throw new Error("No remote control HTTPS URL is configured");
    if (native) {
      const result = await brokerRequest({ operation: "native.control.refresh" }, { native: config.native_broker, timeoutMs: 30_000 });
      console.log(JSON.stringify(JSON.parse(Buffer.from(result.stdout_base64, "base64").toString("utf8")), null, 2));
      return;
    }
    const bundle = await fetchControlBundle(sourceURL);
    const verified = applyControlBundle(bundle, config, defaultConfigDir);
    audit({ operation: "control.fetch", decision: "allow", sequence: verified.sequence, expires_at: verified.expires_at }, defaultConfigDir);
    console.log(JSON.stringify(verified, null, 2));
  } else if (action === "status") {
    if (native) {
      const result = await brokerRequest({ operation: "native.control.status" }, { native: config.native_broker });
      const status = JSON.parse(Buffer.from(result.stdout_base64, "base64").toString("utf8"));
      console.log(JSON.stringify({ ...status, source_url: config.native_broker.control_url ?? null }, null, 2));
      return;
    }
    if (!config.control) {
      console.log(JSON.stringify({ configured: false }, null, 2));
      return;
    }
    const bundle = loadControlBundle(config, defaultConfigDir);
    console.log(JSON.stringify({ configured: true, fingerprint: controlKeyFingerprint(config.control.public_key), url: config.control.url ?? null, bundle }, null, 2));
  } else {
    throw new Error("Unknown control command");
  }
}

function requiredFlag(flag) {
  const index = args.indexOf(flag);
  if (index < 0 || !args[index + 1]) throw new Error(`Missing required ${flag} value`);
  return args[index + 1];
}

function repeatedFlag(flag) {
  const values = [];
  for (let index = 0; index < args.length; index += 1) if (args[index] === flag && args[index + 1]) values.push(args[index + 1]);
  return values;
}

function readJsonFile(file, maxBytes) {
  const stat = fs.lstatSync(file);
  if (!stat.isFile() || stat.isSymbolicLink() || stat.size <= 0 || stat.size > maxBytes) throw new Error("JSON input must be a bounded regular file");
  try { return JSON.parse(fs.readFileSync(file, "utf8")); }
  catch { throw new Error(`Invalid JSON file: ${file}`); }
}

function recoveryManage() {
  const action = args[0];
  if (action === "keygen") {
    if (args.length !== 4 || args[2] !== "--signer") throw new Error("Usage: agentpass recovery keygen DIR --signer ID");
    const identity = generateRecoveryIdentity(path.resolve(args[1]), args[3]);
    writeCanonicalJson({ signer_id: identity.signer_id, public_file: identity.public_file, fingerprint: identity.fingerprint });
    console.error(`Recovery private key created at ${identity.private_file}; keep it offline.`);
    return;
  }
  if (action === "sign") {
    const flags = strictRecoveryFlags(args.slice(1), ["--request", "--key", "--signer"]);
    const request = readCanonicalJsonFile(path.resolve(flags.get("--request")[0]), 16 * 1024, "Recovery request");
    const authorization = signRecoveryRequest(request, path.resolve(flags.get("--key")[0]), flags.get("--signer")[0]);
    writeCanonicalJson(authorization);
    return;
  }
  if (action === "verify") {
    const flags = strictRecoveryFlags(args.slice(1), ["--request", "--policy", "--authorization"], new Set(["--authorization"]));
    const request = readCanonicalJsonFile(path.resolve(flags.get("--request")[0]), 16 * 1024, "Recovery request");
    const policy = readCanonicalJsonFile(path.resolve(flags.get("--policy")[0]), 256 * 1024, "Recovery policy");
    const authorizations = flags.get("--authorization").map((file) => readCanonicalJsonFile(path.resolve(file), 16 * 1024, "Recovery authorization"));
    writeCanonicalJson(verifyRecoveryThreshold(request, authorizations, policy));
    return;
  }
  if (action === "anchor-sign") {
    const flags = strictRecoveryFlags(args.slice(1), ["--authorization", "--key", "--signer"], new Set(), new Set(["--output"]));
    const authorization = readCanonicalJsonFile(path.resolve(flags.get("--authorization")[0]), 32 * 1024, "Anchor recovery authorization");
    const approval = signAnchorRecoveryAuthorization(authorization, path.resolve(flags.get("--key")[0]), flags.get("--signer")[0]);
    writeCanonicalJson(approval, flags.get("--output")?.[0]);
    return;
  }
  if (action === "anchor-policy") {
    const flags = strictRecoveryFlags(args.slice(1), ["--policy"], new Set(), new Set(["--output"]));
    const policy = readCanonicalJsonFile(path.resolve(flags.get("--policy")[0]), 256 * 1024, "Recovery policy");
    writeCanonicalJson(recoveryPolicyToAnchorPolicy(policy), flags.get("--output")?.[0]);
    return;
  }
  if (action === "anchor-verify") {
    const flags = strictRecoveryFlags(args.slice(1), ["--authorization", "--policy", "--approval"], new Set(["--approval"]));
    const authorization = readCanonicalJsonFile(path.resolve(flags.get("--authorization")[0]), 32 * 1024, "Anchor recovery authorization");
    const policy = readCanonicalJsonFile(path.resolve(flags.get("--policy")[0]), 256 * 1024, "Recovery policy");
    const approvals = flags.get("--approval").map((file) => readCanonicalJsonFile(path.resolve(file), 16 * 1024, "Anchor recovery approval"));
    writeCanonicalJson(verifyAnchorRecoveryApprovals(authorization, policy, approvals));
    return;
  }
  throw new Error("Unknown recovery command");
}

function strictRecoveryFlags(values, required, repeated = new Set(), optional = new Set()) {
  if (values.length === 0 || values.length % 2 !== 0) throw new Error("Recovery command flags require a value");
  const allowed = new Set([...required, ...optional]);
  const parsed = new Map();
  for (let index = 0; index < values.length; index += 2) {
    const flag = values[index];
    const value = values[index + 1];
    if (!allowed.has(flag) || !value || value.startsWith("--")) throw new Error(`Unknown or missing recovery flag: ${flag}`);
    if (parsed.has(flag) && !repeated.has(flag)) throw new Error(`Duplicate recovery flag: ${flag}`);
    parsed.set(flag, [...(parsed.get(flag) ?? []), value]);
  }
  for (const flag of required) if (!parsed.has(flag)) throw new Error(`Missing required ${flag} value`);
  return parsed;
}

function readCanonicalJsonFile(file, maxBytes, label) {
  let descriptor;
  try {
    const before = fs.lstatSync(file);
    if (before.isSymbolicLink()) throw new Error();
    descriptor = fs.openSync(file, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW ?? 0));
    const stat = fs.fstatSync(descriptor);
    if (!stat.isFile() || stat.nlink !== 1 || stat.size <= 0 || stat.size > maxBytes) throw new Error();
    const buffer = Buffer.allocUnsafe(maxBytes + 1);
    let total = 0;
    while (total < buffer.length) {
      const count = fs.readSync(descriptor, buffer, total, buffer.length - total, null);
      if (count === 0) break;
      total += count;
    }
    if (total === 0 || total > maxBytes) throw new Error();
    let text;
    try { text = new TextDecoder("utf-8", { fatal: true }).decode(buffer.subarray(0, total)); }
    catch { throw new Error(`${label} must contain valid UTF-8 canonical JSON`); }
    let value;
    try { value = JSON.parse(text); }
    catch { throw new Error(`${label} must contain valid canonical JSON`); }
    const canonical = canonicalJson(value);
    if (text !== canonical && text !== `${canonical}\n`) throw new Error(`${label} must contain canonical JSON`);
    return value;
  } catch (error) {
    if (error.message?.startsWith(label)) throw error;
    throw new Error(`${label} must be a bounded, single-link regular file`);
  } finally {
    if (descriptor !== undefined) fs.closeSync(descriptor);
  }
}

function writeCanonicalJson(value, outputFile) {
  const bytes = `${canonicalJson(value)}\n`;
  if (outputFile === undefined) {
    process.stdout.write(bytes);
    return;
  }
  const file = path.resolve(outputFile);
  let descriptor;
  try {
    descriptor = fs.openSync(file, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | (fs.constants.O_NOFOLLOW ?? 0), 0o600);
    fs.writeFileSync(descriptor, bytes, { encoding: "utf8" });
    fs.fsyncSync(descriptor);
  } catch (error) {
    throw new Error(`Recovery output file must not already exist and must be safely creatable: ${file}`);
  } finally {
    if (descriptor !== undefined) fs.closeSync(descriptor);
  }
}

function agentManage() {
  const action = args[0];
  if (action === "list") {
    const config = loadConfig();
    console.log(JSON.stringify(config.agents.map((agent) => ({ id: agent.id, name: agent.name, default: agent.id === config.default_agent_id, fingerprint: publicKeyFingerprint(agent.public_key), scope: agent.scope ?? null })), null, 2));
    return;
  }
  if (action === "add") {
    const identity = addAgent(args[1], defaultConfigDir);
    console.log(JSON.stringify({ id: identity.id, name: identity.name }, null, 2));
  } else if (action === "set-default") {
    setDefaultAgent(args[1], defaultConfigDir);
    console.log(`Default agent set to ${args[1]}.`);
  } else if (action === "scope") {
    const scope = parseAgentScope(args.slice(2));
    setAgentScope(args[1], scope, defaultConfigDir);
    console.log(JSON.stringify(scope, null, 2));
  } else if (action === "rotate") {
    const identity = rotateAgent(args[1], defaultConfigDir);
    console.log(JSON.stringify({ previous_id: args[1], id: identity.id, name: identity.name }, null, 2));
  } else if (action === "revoke") {
    if (args[2] !== "--confirm" || args[3] !== "REVOKE") throw new Error("Agent revocation requires: agentpass agent revoke ID --confirm REVOKE");
    revokeAgent(args[1], defaultConfigDir);
    console.log(`Agent ${args[1]} revoked.`);
  } else {
    throw new Error("Unknown agent command");
  }
  console.error("Broker configuration changed. Restart it before the next signing request.");
}

function integrateAgent() {
  const client = args[0];
  let projectValue = process.cwd();
  let projectSet = false;
  let install = false;
  let remove = false;
  let execute = false;
  for (let index = 1; index < args.length; index += 1) {
    if (args[index] === "--install" && !install) install = true;
    else if (args[index] === "--remove" && !remove) remove = true;
    else if (args[index] === "--execute" && !execute) execute = true;
    else if (args[index] === "--project" && !projectSet && args[index + 1] && !args[index + 1].startsWith("--")) { projectValue = args[++index]; projectSet = true; }
    else throw new Error("Usage: agentpass integrate claude-code|cursor [--install | --remove [--execute]] [--project DIR]");
  }
  if (install && remove) throw new Error("Integration install and removal are mutually exclusive");
  if (execute && !remove) throw new Error("--execute is only valid with --remove");
  const projectDir = path.resolve(projectValue);
  if (!fs.statSync(projectDir).isDirectory()) throw new Error("Integration project must be a directory");
  const mcpServerPath = fileURLToPath(new URL("../adapters/mcp-server/bin/agentpass-mcp.mjs", import.meta.url));
  const plan = remove
    ? integrationRemovalPlan({ client, projectDir, nodePath: process.execPath, mcpServerPath })
    : integrationPlan({ client, projectDir, nodePath: process.execPath, mcpServerPath });
  const result = remove ? removeIntegration(plan, { dryRun: !execute }) : installIntegration(plan, { dryRun: !install });
  console.log(JSON.stringify({
    version: result.version,
    client: result.client,
    target: result.target,
    changed: result.changed,
    installed: result.installed ?? false,
    removed: result.removed ?? false,
    configuration: remove ? undefined : { mcpServers: { [result.server_name]: result.server } },
    protected_state_preserved: remove ? true : undefined,
    next_steps: remove && !execute ? ["Review the dry-run output, then rerun with `--remove --execute`."] : remove ? ["The AgentPass MCP entry was removed; protected native state and keys were not changed."] : [
      "Start an AgentPass session and export AGENTPASS_SESSION for the agent process.",
      "Configure this repository to use agentpass-git-sign as Git's SSH signing program.",
      "Ask the agent to run agentpass_check before committing."
    ]
  }, null, 2));
}

function parseAgentScope(values) {
  const flags = { "--operation": [], "--repository": [], "--branch": [], "--remote": [] };
  for (let index = 0; index < values.length; index += 2) {
    const flag = values[index];
    const value = values[index + 1];
    if (!Object.hasOwn(flags, flag) || !value) throw new Error("Scope requires repeated --operation, --repository, --branch, and --remote pairs");
    flags[flag].push(value);
  }
  if (Object.values(flags).some((items) => items.length === 0)) throw new Error("Scope requires at least one operation, repository, branch, and remote");
  if (flags["--repository"].some((repository) => !path.isAbsolute(repository))) throw new Error("Scoped repositories must be absolute paths");
  return { operations: flags["--operation"], repositories: flags["--repository"], branches: { allow: flags["--branch"] }, remotes: { allow: flags["--remote"] } };
}

function scopeFromPolicy(config) {
  return {
    operations: [...(config.operations ?? ["git.commit.sign"])],
    repositories: [...config.repositories],
    branches: structuredClone(Array.isArray(config.branches?.allow) ? config.branches : { allow: ["*"] }),
    remotes: structuredClone(Array.isArray(config.remotes?.allow) ? config.remotes : { allow: ["*"] })
  };
}

async function auditCommand() {
  const config = loadConfig();
  if (args[0] === "checkpoint") {
    const checkpoint = createAuditCheckpoint(config.audit_signing.public_key, defaultConfigDir);
    console.log(JSON.stringify(checkpoint, null, 2));
  } else if (args[0] === "public-key") {
    console.error(publicKeyFingerprint(config.audit_signing.public_key));
    console.log(config.audit_signing.public_key.trim());
  } else if (args[0] === "anchor") {
    await auditAnchorCommand(config);
  } else if (args.includes("--verify")) {
    const chain = verifyAudit(defaultConfigDir);
    const checkpoints = verifyAuditCheckpoints(config.audit_signing.public_key, defaultConfigDir);
    let anchor;
    try { anchor = verifyStoredAnchorReceipts(config, defaultConfigDir); }
    catch (error) { anchor = { valid: false, error: error.message }; }
    console.log(JSON.stringify({ valid: chain.valid && checkpoints.valid && anchor.valid, audit: chain, checkpoints, anchor }, null, 2));
    if (!chain.valid || !checkpoints.valid || !anchor.valid) process.exitCode = 1;
  } else if (args[0] === "--tail") {
    if (args.length !== 2 || !/^[1-9]\d*$/.test(args[1]) || Number(args[1]) > 50) throw new Error("audit --tail requires a count from 1 to 50");
    console.log(readAuditTail(auditPath(), Number(args[1])));
  } else {
    console.log(fs.existsSync(auditPath()) ? fs.readFileSync(auditPath(), "utf8") : "");
  }
}

function readAuditTail(file, count, maxBytes = 512 * 1024) {
  if (!fs.existsSync(file)) return "";
  const flags = fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW ?? 0);
  const descriptor = fs.openSync(file, flags);
  try {
    const stat = fs.fstatSync(descriptor);
    if (!stat.isFile() || stat.isSymbolicLink?.()) throw new Error("Audit log must be a regular file");
    const length = Math.min(stat.size, maxBytes);
    const buffer = Buffer.alloc(length);
    fs.readSync(descriptor, buffer, 0, length, stat.size - length);
    let text = buffer.toString("utf8");
    if (stat.size > length) {
      const newline = text.indexOf("\n");
      if (newline < 0) throw new Error("Recent audit event exceeds the tail limit");
      text = text.slice(newline + 1);
    }
    return text.split(/\r?\n/).filter(Boolean).slice(-count).join("\n");
  } finally { fs.closeSync(descriptor); }
}

async function auditAnchorCommand(config) {
  const action = args[1];
  if (action === "trust") {
    const url = requiredFlag("--url");
    const tenant = requiredFlag("--tenant");
    const publicKey = fs.readFileSync(path.resolve(requiredFlag("--key")), "utf8");
    const fingerprint = publicKeyFingerprint(publicKey);
    const previousFingerprint = config.audit_anchor?.public_key ? publicKeyFingerprint(config.audit_anchor.public_key) : null;
    const identityChanged = config.audit_anchor && (previousFingerprint !== fingerprint || config.audit_anchor.tenant !== tenant);
    if (identityChanged && !(args.includes("--confirm") && args.includes("ROTATE_ANCHOR_TRUST"))) {
      throw new Error("Replacing the audit anchor trust root requires --confirm ROTATE_ANCHOR_TRUST");
    }
    saveConfig({ ...config, audit_anchor: { url, tenant, public_key: publicKey } });
    const receiptFile = anchorReceiptPath();
    if (identityChanged && fs.existsSync(receiptFile)) fs.renameSync(receiptFile, `${receiptFile}.${Date.now()}.untrusted.bak`);
    audit({ operation: "audit.anchor.trust", decision: "allow", tenant, url, key_fingerprint: fingerprint, previous_key_fingerprint: previousFingerprint }, defaultConfigDir);
    console.log(JSON.stringify({ configured: true, tenant, url, fingerprint }, null, 2));
  } else if (action === "push") {
    if (!config.audit_anchor) throw new Error("No audit anchor is configured");
    audit({ operation: "audit.anchor.push", decision: "allow", tenant: config.audit_anchor.tenant, url: config.audit_anchor.url }, defaultConfigDir);
    createAuditCheckpoint(config.audit_signing.public_key, defaultConfigDir);
    console.log(JSON.stringify(await anchorPendingCheckpoints(config, defaultConfigDir), null, 2));
  } else if (action === "status") {
    if (!config.audit_anchor) {
      console.log(JSON.stringify({ configured: false }, null, 2));
      return;
    }
    const receipts = verifyStoredAnchorReceipts(config, defaultConfigDir);
    console.log(JSON.stringify({ configured: true, tenant: config.audit_anchor.tenant, url: config.audit_anchor.url, fingerprint: publicKeyFingerprint(config.audit_anchor.public_key), ...receipts }, null, 2));
  } else {
    throw new Error("Unknown audit anchor command");
  }
}

function brokerInstall() {
  if (process.platform !== "darwin") throw new Error("LaunchAgent installation is supported only on macOS");
  const launchAgents = path.join(os.homedir(), "Library", "LaunchAgents");
  const plist = path.join(launchAgents, "dev.agentpass.broker.plist");
  if (fs.existsSync(plist) && !args.includes("--force")) throw new Error(`${plist} exists; use --force to replace it`);
  fs.mkdirSync(launchAgents, { recursive: true, mode: 0o700 });
  const daemon = fileURLToPath(new URL("./agentpassd.mjs", import.meta.url));
  const xml = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>dev.agentpass.broker</string>
  <key>ProgramArguments</key><array><string>${xmlEscape(process.execPath)}</string><string>${xmlEscape(daemon)}</string></array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>ProcessType</key><string>Background</string>
  <key>Umask</key><integer>63</integer>
  <key>StandardOutPath</key><string>${xmlEscape(path.join(defaultConfigDir, "broker.out.log"))}</string>
  <key>StandardErrorPath</key><string>${xmlEscape(path.join(defaultConfigDir, "broker.err.log"))}</string>
</dict></plist>
`;
  const domain = `gui/${process.getuid()}`;
  if (args.includes("--force")) spawnSync("/bin/launchctl", ["bootout", `${domain}/dev.agentpass.broker`], { encoding: "utf8" });
  fs.writeFileSync(plist, xml, { mode: 0o600 });
  const result = spawnSync("/bin/launchctl", ["bootstrap", domain, plist], { encoding: "utf8" });
  if (result.status !== 0) throw new Error(result.stderr.trim() || "launchctl bootstrap failed");
  console.log(`Installed ${plist}`);
}

function brokerStop() {
  if (process.platform !== "darwin") throw new Error("LaunchAgent control is supported only on macOS");
  const result = spawnSync("/bin/launchctl", ["bootout", `gui/${process.getuid()}/dev.agentpass.broker`], { encoding: "utf8" });
  if (result.status !== 0) throw new Error(result.stderr.trim() || "launchctl bootout failed");
  console.log("AgentPass broker stopped.");
}

function xmlEscape(value) {
  return String(value).replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;").replaceAll('"', "&quot;").replaceAll("'", "&apos;");
}

try {
  if (command === "install") installProduction();
  else if (command === "setup") await setupNativeBridge();
  else if (command === "uninstall") await uninstallProduction();
  else if (command === "init") init();
  else if (command === "migrate") migrate();
  else if (command === "check") check();
  else if (command === "status") status();
  else if (command === "doctor") await doctor();
  else if (command === "broker" && args[0] === "ping") await brokerPing();
  else if (command === "broker" && args[0] === "install") brokerInstall();
  else if (command === "broker" && args[0] === "stop") brokerStop();
  else if (command === "native") await nativeManage();
  else if (command === "agent") agentManage();
  else if (command === "integrate") integrateAgent();
  else if (command === "control") await controlManage();
  else if (command === "recovery") recoveryManage();
  else if (command === "setup-macos") setupMacos();
  else if (command === "install-hook") installHook();
  else if (command === "push-check") await pushCheck();
  else if (command === "session" && args[0] === "start") await sessionStart();
  else if (command === "revoke") revoke();
  else if (command === "restore") restore();
  else if (command === "git-sign") await gitSign();
  else if (command === "-Y") await gitSign([command, ...args]);
  else if (command === "audit") await auditCommand();
  else usage();
} catch (error) {
  console.error(`agentpass: ${error.message}`);
  process.exitCode = 1;
}
