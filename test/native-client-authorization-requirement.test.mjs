import assert from 'node:assert/strict';
import fs from 'node:fs';
import test from 'node:test';

const service = fs.readFileSync(new URL('../native/macos/Sources/AgentPassNativeService/main.swift', import.meta.url), 'utf8');
const example = JSON.parse(fs.readFileSync(new URL('../native/macos/Resources/native-service.example.json', import.meta.url), 'utf8'));
const launchd = fs.readFileSync(new URL('../native/macos/Resources/dev.agentpass.native-service.plist', import.meta.url), 'utf8');
const postinstall = fs.readFileSync(new URL('../native/macos/scripts/installer-postinstall.sh', import.meta.url), 'utf8');

test('native service requires the exact Team ID, Developer ID leaf, and approval entitlement requirement', () => {
  assert.match(service, /NativeClientCodeRequirement\.requirement\(serviceAccessGroup: serviceAccessGroup\)/u);
  assert.match(service, /value\.clientCodeSigningRequirement\s*==/u);
  assert.match(example.client_code_signing_requirement, /certificate leaf\[field\.1\.2\.840\.113635\.100\.6\.1\.13\] exists/u);
  assert.ok(example.client_code_signing_requirement.includes('certificate leaf[subject.OU] = "TEAMID"'));
  assert.ok(example.client_code_signing_requirement.includes('entitlement["keychain-access-groups"] = "TEAMID.dev.agentpass.approval-keys"'));
});

test('native service example separates the Agent session endpoint and client requirement from management', () => {
  assert.equal(example.mach_service_name, 'dev.agentpass.native-service');
  assert.equal(example.agent_mach_service_name, 'dev.agentpass.agent-session');
  assert.notEqual(example.agent_mach_service_name, example.mach_service_name);
  assert.match(example.agent_client_code_signing_requirement, /anchor apple generic/u);
  assert.match(example.agent_client_code_signing_requirement, /identifier "dev\.agentpass\.agent-host"/u);
  assert.match(example.agent_client_code_signing_requirement, /certificate leaf\[field\.1\.2\.840\.113635\.100\.6\.1\.13\] exists/u);
  assert.match(example.agent_client_code_signing_requirement, /certificate leaf\[subject\.OU\] = "TEAMID"/u);
  assert.match(example.agent_client_code_signing_requirement, /entitlement\["dev\.agentpass\.agent-session-client"\] = true/u);
  assert.notEqual(example.agent_client_code_signing_requirement, example.client_code_signing_requirement);
  assert.match(launchd, /<key>dev\.agentpass\.native-service<\/key><true\/>/u);
  assert.match(launchd, /<key>dev\.agentpass\.agent-session<\/key><true\/>/u);
  assert.match(launchd, /<key>dev\.agentpass\.agent-host-control<\/key><true\/>/u);
});

test('Host control closes are admitted as Native Client operations, never as Host operations', () => {
  assert.match(service, /let hostControlRegistry = NativeAgentHostControlRegistry\(\s*authorizedControlBundleIdentifier: NativeClientCodeRequirement\.clientBundleID,\s*requireOwnerPrincipalMatch: false\s*\)/u);
  const controlSection = service.slice(service.indexOf('let hostControlDelegate'), service.indexOf('let childDelegate'));
  assert.match(controlSection, /codeSigningRequirement: configuration\.clientCodeSigningRequirement/u);
  assert.doesNotMatch(controlSection, /codeSigningRequirement: configuration\.agentClientCodeSigningRequirement/u);
});

test('Agent runtime authority configuration is complete, bounded, and device-enrollment dependent', () => {
  assert.equal(example.agent_signing_intent_directory, '/Library/Application Support/AgentPass/agent-signing-intents');
  assert.equal(example.agent_global_session_limit, 128);
  assert.equal(example.agent_per_agent_session_limit, 8);
  assert.equal(example.agent_per_worktree_session_limit, 4);
  assert.equal(example.agent_bootstrap_attempt_limit, 16);
  assert.equal(example.agent_worktree_observation_policy_version, 2);
  assert.match(service, /agentRuntimeCount\s*!=\s*0/u);
  assert.match(service, /agentRuntimeCount\s*==\s*agentRuntimeValues\.count/u);
  assert.match(service, /v2Count\s*==\s*v2Values\.count/u);
  assert.match(service, /NativeEnrollmentKeyMaterial\.fixedApplicationTag/u);
  assert.match(service, /NativeAgentSessionRegistry\.maximumActiveSessions/u);
  assert.match(service, /CodingKeys\.allCases\.map\(\\\.rawValue\)/u);
  assert.match(service, /private final class AgentRuntimeDependencies/u);
  assert.match(service, /NativeAgentGrantLeaseHTTPConsumer/u);
  assert.match(service, /NativeAgentSigningIntentStore/u);
  assert.match(service, /NativeAgentGitCommitSigner/u);
  assert.match(service, /switch try configuration\.agentRuntimeConfiguration\(\)/u);
  assert.match(postinstall, /AGENT_SIGNING_INTENT_STORE="\$STATE_ROOT\/agent-signing-intents"/u);
  assert.match(postinstall, /ensure_private_store "\$AGENT_SIGNING_INTENT_STORE"/u);
});

test('production listeners export separate management and connection-scoped Agent objects', () => {
  assert.match(service, /NSXPCListener\(machServiceName: configuration\.machServiceName\)/u);
  assert.match(service, /NSXPCListener\(machServiceName: configuration\.agentMachServiceName\)/u);
  assert.match(service, /connection\.exportedInterface = AgentPassAgentXPCInterface\.make\(\)/u);
  assert.match(service, /let endpoint = AgentConnectionEndpoint\(\s*connection: connection,\s*connectionGuard: guardValue,\s*observer: observer,\s*auditTokenSource: auditTokenSource,\s*runtime: runtime,\s*auditAppender: auditAppender,\s*qualificationFaultConsumer: qualificationFaultConsumer,\s*transportReplyFaultConsumer: transportReplyFaultConsumer,\s*sessionAssociationRegistry: sessionAssociationRegistry\s*\)/u);
  assert.match(service, /connection\.invalidationHandler[\s\S]*endpoint\?\.invalidateConnection\(\)/u);
  assert.match(service, /auditTokenSource\.completeAuditToken\(for: connection\)/u);
  assert.match(service, /observer\.observe\(pid: initialToken\.pid, expectedUserID: initialToken\.effectiveUserID\)/u);
  assert.match(service, /initialToken\.context\(matching: observation\)/u);
  const agentEndpoint = service.slice(service.indexOf('private final class AgentConnectionEndpoint'), service.indexOf('private final class AgentListenerDelegate'));
  assert.doesNotMatch(agentEndpoint, /ServiceEndpoint|AgentPassNativeServiceProtocol|rotateAudit|stageKey|applyControlBundle/u);
});

test('Agent bootstrap, sessions, and durable signing remain connection-bound and fail closed', () => {
  const agentEndpoint = service.slice(service.indexOf('private final class AgentConnectionEndpoint'), service.indexOf('private final class AgentListenerDelegate'));
  assert.match(agentEndpoint, /NativeAgentBootstrapChallengeStore/u);
  assert.match(agentEndpoint, /connectionGuard\.context\.tokenIdentity/u);
  assert.match(agentEndpoint, /connectionGuard\.processBindingHash/u);
  assert.match(agentEndpoint, /connectionGuard\.ancestryBindingHash/u);
  assert.match(agentEndpoint, /NativeAgentSystemClocks/u);
  assert.match(agentEndpoint, /clocks\.monotonicClock\.sample\(\)/u);
  assert.match(agentEndpoint, /clocks\.wallClock\.sample\(\)/u);
  assert.match(agentEndpoint, /NativeAgentSessionDenialReason\.peerDenied\.nsError/u);
  assert.match(agentEndpoint, /NativeAgentSessionDenialReason\.challengeDenied\.nsError/u);
  assert.match(agentEndpoint, /NativeAgentSessionDenialReason\.unavailable\.nsError/u);
  assert.match(agentEndpoint, /guard runtime != nil/u);
  assert.match(agentEndpoint, /NativeAgentSessionCoordinator/u);
  assert.match(agentEndpoint, /coordinator\.start\(bootstrapID: bootstrapID, proof: proof\)/u);
  assert.match(agentEndpoint, /coordinator\.status\(sessionID: sessionID\)/u);
  assert.match(agentEndpoint, /coordinator\.close\(sessionID: sessionID, reason: reason\)/u);
  assert.match(agentEndpoint, /coordinator\?\.invalidateConnection\(\)/u);
  assert.match(agentEndpoint, /func signGitCommit[\s\S]*authorizeConnection\(\)/u);
  assert.match(agentEndpoint, /func signGitCommit[\s\S]*coordinator\.makeSigningHandoff/u);
  assert.match(agentEndpoint, /func signGitCommit[\s\S]*bindingObserver\.observeSigningAuthority/u);
  assert.match(agentEndpoint, /func signGitCommit[\s\S]*NativeAgentSessionCoordinatorSigningAdapter/u);
  assert.match(agentEndpoint, /func signGitCommit[\s\S]*adapter\.execute/u);
  assert.match(agentEndpoint, /func signGitCommit[\s\S]*gitCommitSigner\.signGitCommitPayload/u);
  assert.match(agentEndpoint, /func signGitCommit[\s\S]*Self\.denial\(for: error\)\.nsError/u);
  const signMethod = agentEndpoint.slice(agentEndpoint.indexOf('func signGitCommit'), agentEndpoint.indexOf('func closeAgentSession'));
  const freshSigningPath = signMethod.slice(signMethod.indexOf('let handoff'));
  assert.doesNotMatch(freshSigningPath, /runtime\.signingTransactions\.(?:admit|markIntent|markProviderStarted|recordVerified|complete)/u);
  assert.match(agentEndpoint, /private let terminationState = NativeAgentConnectionTerminationState\(\)/u);
  assert.match(agentEndpoint, /terminationState\.install\(activation\.binding\)/u);
  assert.match(agentEndpoint, /private func cleanupConnectionState\(\)[\s\S]*terminationState\.beginCleanup\(\)/u);
  assert.match(agentEndpoint, /func invalidateConnection\(\)\s*\{\s*_ = cleanupConnectionState\(\)\s*\}/u);
  assert.match(agentEndpoint, /private func terminallyClose\(\)[\s\S]*guard cleanupConnectionState\(\) else \{ return \}[\s\S]*connection\.invalidate\(\)/u);
  assert.doesNotMatch(agentEndpoint, /AGENTPASS_SESSION|privateKey|private_key|authorizeV2|NativeSessionManager|error as NSError/u);
});

test('Agent runtime never invents a signing-key generation', () => {
  assert.match(service, /guard let deviceSigner = controlV2DeviceSigner,\s*let controlV2Manager,\s*let activeSigning else/u);
  assert.match(service, /keyGeneration: activeSigning\.generation/u);
  assert.doesNotMatch(service, /keyGeneration: activeSigning\?\.generation \?\?/u);
});
