import CryptoKit
import Foundation
import Testing
@testable import AgentPassNativeCore

private struct DeviceTestSigner: P256MessageSigner {
    let key = P256.Signing.PrivateKey()
    var publicKeyX963: Data { key.publicKey.x963Representation }
    func sign(message: Data) throws -> Data { try key.signature(for: message).rawRepresentation }
}

@Test func nativeDeviceAuthenticationMatchesCloudCanonicalProtocol() throws {
    let signer = DeviceTestSigner()
    let url = try #require(URL(string: "https://cloud.example/v1/organizations/11111111-1111-4111-8111-111111111111/bundles/22222222-2222-4222-8222-222222222222"))
    let headers = try nativeDeviceAuthenticationHeaders(method: "GET", url: url, body: Data(), deviceID: "22222222-2222-4222-8222-222222222222", timestampMilliseconds: 1_800_000_000_000, nonceBytes: Data(repeating: 7, count: 32), signer: signer)
    #expect(headers.contentSHA256 == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
    #expect(Data(base64Encoded: headers.signature)?.count == 64)
    let pem = try p256SubjectPublicKeyInfoPEM(x963: signer.publicKeyX963)
    #expect(pem.hasPrefix("-----BEGIN PUBLIC KEY-----\n"))
    #expect(pem.hasSuffix("-----END PUBLIC KEY-----\n"))
}

@Test func nativeDeviceAuthenticationRejectsIncompleteOrAmbiguousInput() throws {
    let signer = DeviceTestSigner()
    let url = try #require(URL(string: "https://cloud.example/control#fragment"))
    #expect(throws: AgentPassNativeError.self) { _ = try nativeDeviceAuthenticationHeaders(method: "get", url: url, body: Data(), deviceID: "bad", timestampMilliseconds: -1, nonceBytes: Data(), signer: signer) }
    #expect(throws: AgentPassNativeError.self) { _ = try p256SubjectPublicKeyInfoPEM(x963: Data()) }
}
