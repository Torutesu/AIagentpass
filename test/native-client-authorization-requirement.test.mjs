import assert from 'node:assert/strict';
import fs from 'node:fs';
import test from 'node:test';

const service = fs.readFileSync(new URL('../native/macos/Sources/AgentPassNativeService/main.swift', import.meta.url), 'utf8');
const example = JSON.parse(fs.readFileSync(new URL('../native/macos/Resources/native-service.example.json', import.meta.url), 'utf8'));
const launchd = fs.readFileSync(new URL('../native/macos/Resources/dev.agentpass.native-service.plist', import.meta.url), 'utf8');

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
});

test('production listeners export separate management and connection-scoped Agent objects', () => {
  assert.match(service, /NSXPCListener\(machServiceName: configuration\.machServiceName\)/u);
  assert.match(service, /NSXPCListener\(machServiceName: configuration\.agentMachServiceName\)/u);
  assert.match(service, /connection\.exportedInterface = AgentPassAgentXPCInterface\.make\(\)/u);
  assert.match(service, /connection\.exportedObject = AgentConnectionEndpoint\(connectionGuard: guardValue, observer: observer\)/u);
  assert.match(service, /observer\.observe\(pid: peerPID, expectedUserID: peerUID\)/u);
  assert.match(service, /connection\.processIdentifier/u);
  assert.match(service, /connection\.auditSessionIdentifier/u);
  const agentEndpoint = service.slice(service.indexOf('private final class AgentConnectionEndpoint'), service.indexOf('private final class AgentListenerDelegate'));
  assert.doesNotMatch(agentEndpoint, /ServiceEndpoint|AgentPassNativeServiceProtocol|rotateAudit|stageKey|applyControlBundle/u);
});

test('Agent bootstrap is connection-bound while authority-bearing methods remain fail closed', () => {
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
  assert.doesNotMatch(agentEndpoint, /AGENTPASS_SESSION|privateKey|private_key|authorizeV2|NativeSessionManager|\.sign\(/u);
});
