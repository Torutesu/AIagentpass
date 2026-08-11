import CryptoKit
import Foundation

public protocol P256MessageSigner {
    var publicKeyX963: Data { get }
    func sign(message: Data) throws -> Data
}

public enum SSHSIG {
    private static let algorithm = "ecdsa-sha2-nistp256"
    private static let curve = "nistp256"
    private static let hashAlgorithm = "sha256"

    public static func sign(payload: Data, namespace: String = "git", signer: P256MessageSigner) throws -> String {
        guard !namespace.isEmpty, !namespace.utf8.contains(0) else {
            throw AgentPassNativeError.invalidSignature("SSHSIG namespace is invalid")
        }
        guard signer.publicKeyX963.count == 65, signer.publicKeyX963.first == 0x04 else {
            throw AgentPassNativeError.invalidKey("P-256 public key must use uncompressed X9.63 encoding")
        }

        let digest = Data(SHA256.hash(data: payload))
        var signedData = Data("SSHSIG".utf8)
        signedData.appendSSHString(namespace)
        signedData.appendSSHString(Data())
        signedData.appendSSHString(hashAlgorithm)
        signedData.appendSSHString(digest)

        let rawSignature = try signer.sign(message: signedData)
        guard rawSignature.count == 64 else {
            throw AgentPassNativeError.invalidSignature("P-256 signature must contain 32-byte r and s values")
        }

        var publicKey = Data()
        publicKey.appendSSHString(algorithm)
        publicKey.appendSSHString(curve)
        publicKey.appendSSHString(signer.publicKeyX963)

        var ecdsaSignature = Data()
        ecdsaSignature.appendSSHString(mpint(rawSignature.prefix(32)))
        ecdsaSignature.appendSSHString(mpint(rawSignature.suffix(32)))

        var signatureBlob = Data()
        signatureBlob.appendSSHString(algorithm)
        signatureBlob.appendSSHString(ecdsaSignature)

        var envelope = Data("SSHSIG".utf8)
        envelope.appendUInt32(1)
        envelope.appendSSHString(publicKey)
        envelope.appendSSHString(namespace)
        envelope.appendSSHString(Data())
        envelope.appendSSHString(hashAlgorithm)
        envelope.appendSSHString(signatureBlob)
        return armor(envelope)
    }

    public static func authorizedKey(publicKeyX963: Data) throws -> String {
        guard publicKeyX963.count == 65, publicKeyX963.first == 0x04 else {
            throw AgentPassNativeError.invalidKey("P-256 public key must use uncompressed X9.63 encoding")
        }
        var blob = Data()
        blob.appendSSHString(algorithm)
        blob.appendSSHString(curve)
        blob.appendSSHString(publicKeyX963)
        return "\(algorithm) \(blob.base64EncodedString())"
    }

    public static func p256PublicKey(fromAuthorizedKey value: String) throws -> Data {
        let fields = value.split(whereSeparator: \.isWhitespace)
        guard fields.count >= 2, fields[0] == Substring(algorithm), let blob = Data(base64Encoded: String(fields[1])) else {
            throw AgentPassNativeError.invalidKey("P-256 authorized key is invalid")
        }
        var cursor = SSHWireCursor(data: blob)
        guard try cursor.readString() == Data(algorithm.utf8),
              try cursor.readString() == Data(curve.utf8) else {
            throw AgentPassNativeError.invalidKey("P-256 authorized key algorithm is invalid")
        }
        let publicKey = try cursor.readString()
        guard cursor.isAtEnd, publicKey.count == 65, publicKey.first == 0x04 else {
            throw AgentPassNativeError.invalidKey("P-256 authorized key encoding is invalid")
        }
        return publicKey
    }

    private static func mpint<T: DataProtocol>(_ input: T) -> Data {
        var bytes = Array(input)
        while bytes.first == 0 && bytes.count > 1 { bytes.removeFirst() }
        if bytes.allSatisfy({ $0 == 0 }) { return Data() }
        if let first = bytes.first, first & 0x80 != 0 { bytes.insert(0, at: 0) }
        return Data(bytes)
    }

    private static func armor(_ data: Data) -> String {
        let encoded = data.base64EncodedString()
        let lines = stride(from: 0, to: encoded.count, by: 70).map { offset -> String in
            let start = encoded.index(encoded.startIndex, offsetBy: offset)
            let end = encoded.index(start, offsetBy: min(70, encoded.count - offset))
            return String(encoded[start..<end])
        }
        return (["-----BEGIN SSH SIGNATURE-----"] + lines + ["-----END SSH SIGNATURE-----", ""]).joined(separator: "\n")
    }
}

private struct SSHWireCursor {
    let data: Data
    var offset = 0
    var isAtEnd: Bool { offset == data.count }

    mutating func readString() throws -> Data {
        guard offset + 4 <= data.count else { throw AgentPassNativeError.invalidKey("SSH key field is truncated") }
        let length = data[offset..<(offset + 4)].reduce(0) { ($0 << 8) | Int($1) }
        offset += 4
        guard length >= 0, offset + length <= data.count else { throw AgentPassNativeError.invalidKey("SSH key field length is invalid") }
        defer { offset += length }
        return data.subdata(in: offset..<(offset + length))
    }
}

extension Data {
    mutating func appendUInt32(_ value: UInt32) {
        append(UInt8((value >> 24) & 0xff))
        append(UInt8((value >> 16) & 0xff))
        append(UInt8((value >> 8) & 0xff))
        append(UInt8(value & 0xff))
    }

    mutating func appendSSHString(_ value: String) {
        appendSSHString(Data(value.utf8))
    }

    mutating func appendSSHString(_ value: Data) {
        precondition(value.count <= Int(UInt32.max))
        appendUInt32(UInt32(value.count))
        append(value)
    }
}
