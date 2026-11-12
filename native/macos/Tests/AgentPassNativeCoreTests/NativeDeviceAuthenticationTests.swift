import CryptoKit
import Foundation
import Testing
@testable import AgentPassNativeCore

private struct DeviceTestSigner: P256MessageSigner {
    let key = P256.Signing.PrivateKey()
    var publicKeyX963: Data { key.publicKey.x963Representation }
    func sign(message: Data) throws -> Data { try key.signature(for: message).rawRepresentation }
}

@Test func nativeDeviceAuthenticationRejectsIncompleteOrAmbiguousInput() throws {
    let signer = DeviceTestSigner()
    let url = try #require(URL(string: "https://cloud.example/control#fragment"))
    #expect(throws: AgentPassNativeError.self) { _ = try nativeDeviceAuthenticationHeaders(method: "get", url: url, body: Data(), deviceID: "bad", timestampMilliseconds: -1, nonceBytes: Data(), signer: signer) }
    #expect(throws: AgentPassNativeError.self) { _ = try p256SubjectPublicKeyInfoPEM(x963: Data()) }
}
