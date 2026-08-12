import CryptoKit
import Foundation

public struct NativeDeviceAuthenticationHeaders: Equatable, Sendable {
    public let deviceID: String
    public let timestamp: String
    public let nonce: String
    public let contentSHA256: String
    public let signature: String
}

/// Produces the exact Cloud API device-authentication preimage. The signer may
/// be backed by Secure Enclave; no private key bytes are accepted or returned.
public func nativeDeviceAuthenticationHeaders(
    method: String,
    url: URL,
    body: Data,
    deviceID: String,
    timestampMilliseconds: Int64,
    nonceBytes: Data,
    signer: P256MessageSigner
) throws -> NativeDeviceAuthenticationHeaders {
    guard method == method.uppercased(), !method.isEmpty,
          UUID(uuidString: deviceID) != nil,
          timestampMilliseconds >= 0,
          nonceBytes.count == 32,
          url.user == nil, url.password == nil, url.fragment == nil else {
        throw AgentPassNativeError.invalidConfiguration("Native device authentication input is invalid")
    }
    guard let components = URLComponents(url: url, resolvingAgainstBaseURL: false) else {
        throw AgentPassNativeError.invalidConfiguration("Native device authentication URL is invalid")
    }
    let path = components.percentEncodedPath.isEmpty ? "/" : components.percentEncodedPath
    let query = components.percentEncodedQuery ?? ""
    let digest = SHA256.hash(data: body).map { String(format: "%02x", $0) }.joined()
    let nonce = "A" + nonceBytes.base64EncodedString().replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "")
    let canonical = [method, path, query, digest, String(timestampMilliseconds), nonce].joined(separator: "\n")
    let signature = try signer.sign(message: Data(canonical.utf8))
    guard signature.count == 64 else { throw AgentPassNativeError.invalidSignature("Native device authentication signature must be 64-byte P1363") }
    return NativeDeviceAuthenticationHeaders(deviceID: deviceID.lowercased(), timestamp: String(timestampMilliseconds), nonce: nonce, contentSHA256: digest, signature: signature.base64EncodedString())
}

public func p256SubjectPublicKeyInfoPEM(x963: Data) throws -> String {
    guard x963.count == 65, x963.first == 0x04 else { throw AgentPassNativeError.invalidKey("P-256 public key must use uncompressed X9.63 encoding") }
    let prefix = Data([0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00])
    return "-----BEGIN PUBLIC KEY-----\n\((prefix + x963).base64EncodedString())\n-----END PUBLIC KEY-----\n"
}
