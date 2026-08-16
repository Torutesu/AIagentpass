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

    public static func verify(
        payload: Data,
        signature: String,
        namespace: String = "git",
        publicKeyX963: Data
    ) throws -> Bool {
        guard !namespace.isEmpty, !namespace.utf8.contains(0),
              publicKeyX963.count == 65, publicKeyX963.first == 0x04 else {
            throw AgentPassNativeError.invalidSignature("SSHSIG verification input is invalid")
        }
        let prefix = "-----BEGIN SSH SIGNATURE-----\n"
        let suffix = "\n-----END SSH SIGNATURE-----\n"
        guard signature.hasPrefix(prefix), signature.hasSuffix(suffix) else {
            return false
        }
        let encoded = String(signature.dropFirst(prefix.utf8.count).dropLast(suffix.utf8.count))
        guard let envelope = Data(base64Encoded: encoded) else { return false }
        var cursor = SSHWireCursor(data: envelope)
        guard try cursor.readBytes(count: 6) == Data("SSHSIG".utf8),
              try cursor.readUInt32() == 1 else { return false }

        var publicKeyCursor = SSHWireCursor(data: try cursor.readString())
        guard try publicKeyCursor.readString() == Data(algorithm.utf8),
              try publicKeyCursor.readString() == Data(curve.utf8),
              try publicKeyCursor.readString() == publicKeyX963,
              publicKeyCursor.isAtEnd else { return false }
        guard try cursor.readString() == Data(namespace.utf8),
              try cursor.readString().isEmpty,
              try cursor.readString() == Data(hashAlgorithm.utf8) else { return false }

        var signatureCursor = SSHWireCursor(data: try cursor.readString())
        guard try signatureCursor.readString() == Data(algorithm.utf8) else { return false }
        var ecdsaCursor = SSHWireCursor(data: try signatureCursor.readString())
        let r = try normalizedMPInt(ecdsaCursor.readString())
        let s = try normalizedMPInt(ecdsaCursor.readString())
        guard ecdsaCursor.isAtEnd, signatureCursor.isAtEnd, cursor.isAtEnd else { return false }
        let raw = r + s
        let publicKey = try P256.Signing.PublicKey(x963Representation: publicKeyX963)
        let ecdsaSignature = try P256.Signing.ECDSASignature(rawRepresentation: raw)
        var signedData = Data("SSHSIG".utf8)
        signedData.appendSSHString(namespace)
        signedData.appendSSHString(Data())
        signedData.appendSSHString(hashAlgorithm)
        signedData.appendSSHString(Data(SHA256.hash(data: payload)))
        return publicKey.isValidSignature(ecdsaSignature, for: signedData)
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

    mutating func readUInt32() throws -> UInt32 {
        guard offset + 4 <= data.count else { throw AgentPassNativeError.invalidSignature("SSHSIG integer is truncated") }
        let value = data[offset..<(offset + 4)].reduce(UInt32(0)) { ($0 << 8) | UInt32($1) }
        offset += 4
        return value
    }

    mutating func readBytes(count: Int) throws -> Data {
        guard count >= 0, offset + count <= data.count else { throw AgentPassNativeError.invalidSignature("SSHSIG bytes are truncated") }
        defer { offset += count }
        return data.subdata(in: offset..<(offset + count))
    }
}

private func normalizedMPInt(_ value: Data) throws -> Data {
    var bytes = Array(value)
    while bytes.count > 32, bytes.first == 0 { bytes.removeFirst() }
    guard !bytes.isEmpty, bytes.count <= 32 else {
        throw AgentPassNativeError.invalidSignature("SSHSIG ECDSA integer is invalid")
    }
    return Data(repeating: 0, count: 32 - bytes.count) + Data(bytes)
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
