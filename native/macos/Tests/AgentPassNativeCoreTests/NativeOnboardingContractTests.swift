import Foundation
import Testing
@testable import AgentPassNativeCore

private func onboardingFixture(_ name: String) throws -> Data {
    let directory = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
    return try Data(contentsOf: directory.appendingPathComponent("../../../../contracts/fixtures", isDirectory: true).appendingPathComponent(name).standardizedFileURL)
}

private func onboardingObject(_ data: Data) throws -> [String: Any] {
    try JSONSerialization.jsonObject(with: data, options: [.fragmentsAllowed]) as! [String: Any]
}

private func onboardingMutated(_ data: Data, _ mutate: (inout [String: Any]) -> Void) throws -> Data {
    var object = try onboardingObject(data)
    mutate(&object)
    return try JSONSerialization.data(withJSONObject: object, options: [])
}

@Test func nativeOnboardingPreflightIsCanonicalBoundedAndClosed() throws {
    let data = try onboardingFixture("device-onboarding-preflight.valid.json")
    let value = try NativeOnboardingPreflightCodec.decode(data)
    #expect(value.version == 1)
    #expect(value.platform == "macos")
    #expect(try NativeOnboardingPreflightCodec.canonicalJSON(data) == NativeStrictJSON.data(try onboardingObject(data)))
    #expect(throws: NativeDeviceSyncContractError.self) { try NativeOnboardingPreflightCodec.decode(try onboardingMutated(data) { $0["authority"] = "caller" }) }
    #expect(throws: NativeDeviceSyncContractError.self) { try NativeOnboardingPreflightCodec.decode(Data(#"{"version":1,"version":0,"platform":"macos","candidate_id":"release","device_key_fingerprint":"SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}"#.utf8)) }
    #expect(throws: NativeDeviceSyncContractError.self) { try NativeOnboardingPreflightCodec.decode(try onboardingMutated(data) { $0["version"] = 0 }) }
}

@Test func nativeTrustInstallationAcknowledgementIsSecretFreeAndFailClosed() throws {
    let data = try onboardingFixture("device-trust-installation-ack.valid.json")
    let value = try NativeTrustInstallationAcknowledgementCodec.decode(data)
    #expect(value.type == NativeTrustInstallationAcknowledgement.type)
    #expect(value.controlFormatEpoch == 2)
    #expect(value.result == "installed")
    #expect(try NativeTrustInstallationAcknowledgementCodec.canonicalJSON(data) == NativeStrictJSON.data(try onboardingObject(data)))
    #expect(throws: NativeDeviceSyncContractError.self) { try NativeTrustInstallationAcknowledgementCodec.decode(try onboardingMutated(data) { $0["authority_generation"] = 9 }) }
    #expect(throws: NativeDeviceSyncContractError.self) { try NativeTrustInstallationAcknowledgementCodec.decode(try onboardingMutated(data) { $0["version"] = 0 }) }
    #expect(throws: NativeDeviceSyncContractError.self) { try NativeTrustInstallationAcknowledgementCodec.decode(Data(#"{"version":1,"version":0,"type":"agentpass.browser-onboarding.trust-installation-ack"}"#.utf8)) }
}
