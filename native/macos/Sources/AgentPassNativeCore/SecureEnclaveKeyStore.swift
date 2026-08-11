import Foundation
import LocalAuthentication
import Security

public final class SecureEnclaveKeyStore: P256MessageSigner, @unchecked Sendable {
    private let privateKey: SecKey
    public let publicKeyX963: Data

    public init(applicationTag: String, accessGroup: String? = nil, createIfMissing: Bool = true, requiresUserPresence: Bool = false, operationPrompt: String? = nil) throws {
        guard !applicationTag.isEmpty else {
            throw AgentPassNativeError.invalidConfiguration("Secure Enclave key tag must not be empty")
        }
        let tag = Data(applicationTag.utf8)
        if let existing = try Self.load(tag: tag, accessGroup: accessGroup, operationPrompt: operationPrompt) {
            privateKey = existing
        } else {
            guard createIfMissing else { throw AgentPassNativeError.invalidKey("Secure Enclave key does not exist") }
            privateKey = try Self.create(tag: tag, accessGroup: accessGroup, requiresUserPresence: requiresUserPresence)
        }
        guard let publicKey = SecKeyCopyPublicKey(privateKey),
              let representation = SecKeyCopyExternalRepresentation(publicKey, nil) as Data? else {
            throw AgentPassNativeError.invalidKey("Unable to export the Secure Enclave public key")
        }
        guard representation.count == 65, representation.first == 0x04 else {
            throw AgentPassNativeError.invalidKey("Secure Enclave returned an unexpected public key encoding")
        }
        publicKeyX963 = representation
    }

    public func sign(message: Data) throws -> Data {
        var error: Unmanaged<CFError>?
        guard let der = SecKeyCreateSignature(privateKey, .ecdsaSignatureMessageX962SHA256, message as CFData, &error) as Data? else {
            throw error?.takeRetainedValue() as Error? ?? AgentPassNativeError.invalidSignature("Secure Enclave signing failed")
        }
        return try Self.rawSignature(fromDER: der)
    }

    private static func load(tag: Data, accessGroup: String?, operationPrompt: String?) throws -> SecKey? {
        var query: [CFString: Any] = [
            kSecClass: kSecClassKey,
            kSecAttrApplicationTag: tag,
            kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom,
            kSecReturnRef: true,
            kSecMatchLimit: kSecMatchLimitOne
        ]
        if let accessGroup { query[kSecAttrAccessGroup] = accessGroup }
        if let operationPrompt {
            let context = LAContext()
            context.localizedReason = operationPrompt
            query[kSecUseAuthenticationContext] = context
        }
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess, let key = item as! SecKey? else {
            throw AgentPassNativeError.keychain("Secure Enclave key lookup", status)
        }
        return key
    }

    private static func create(tag: Data, accessGroup: String?, requiresUserPresence: Bool) throws -> SecKey {
        var accessError: Unmanaged<CFError>?
        guard let access = SecAccessControlCreateWithFlags(
            nil,
            requiresUserPresence ? kSecAttrAccessibleWhenUnlockedThisDeviceOnly : kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
            requiresUserPresence ? [.privateKeyUsage, .userPresence] : .privateKeyUsage,
            &accessError
        ) else {
            throw accessError?.takeRetainedValue() as Error? ?? AgentPassNativeError.invalidKey("Unable to create key access control")
        }
        var privateAttributes: [CFString: Any] = [
            kSecAttrIsPermanent: true,
            kSecAttrApplicationTag: tag,
            kSecAttrAccessControl: access
        ]
        if let accessGroup { privateAttributes[kSecAttrAccessGroup] = accessGroup }
        let attributes: [CFString: Any] = [
            kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits: 256,
            kSecAttrTokenID: kSecAttrTokenIDSecureEnclave,
            kSecPrivateKeyAttrs: privateAttributes
        ]
        var error: Unmanaged<CFError>?
        guard let key = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
            let underlying = error?.takeRetainedValue()
            if let underlying {
                let nsError = underlying as Error as NSError
                if nsError.code == Int(errSecUnimplemented) || nsError.code == Int(errSecNotAvailable) {
                    throw AgentPassNativeError.secureEnclaveUnavailable
                }
            }
            throw underlying as Error? ?? AgentPassNativeError.invalidKey("Secure Enclave key creation failed")
        }
        return key
    }

    static func rawSignature(fromDER der: Data) throws -> Data {
        var cursor = DERCursor(data: der)
        let sequence = try cursor.read(tag: 0x30)
        guard cursor.isAtEnd else { throw AgentPassNativeError.invalidSignature("ECDSA DER signature has trailing data") }
        var values = DERCursor(data: sequence)
        let r = try values.read(tag: 0x02)
        let s = try values.read(tag: 0x02)
        guard values.isAtEnd else { throw AgentPassNativeError.invalidSignature("ECDSA DER signature contains extra values") }
        return try fixedInteger(r) + fixedInteger(s)
    }

    private static func fixedInteger(_ value: Data) throws -> Data {
        var bytes = Array(value)
        guard !bytes.isEmpty, bytes.first! & 0x80 == 0 else {
            throw AgentPassNativeError.invalidSignature("ECDSA DER integer is invalid")
        }
        while bytes.first == 0 && bytes.count > 32 { bytes.removeFirst() }
        guard bytes.count <= 32 else {
            throw AgentPassNativeError.invalidSignature("ECDSA DER integer is invalid")
        }
        return Data(repeating: 0, count: 32 - bytes.count) + Data(bytes)
    }
}

private struct DERCursor {
    let data: Data
    var offset = 0
    var isAtEnd: Bool { offset == data.count }

    mutating func read(tag expectedTag: UInt8) throws -> Data {
        guard offset < data.count, data[offset] == expectedTag else {
            throw AgentPassNativeError.invalidSignature("ECDSA DER tag is invalid")
        }
        offset += 1
        let length = try readLength()
        guard length >= 0, offset + length <= data.count else {
            throw AgentPassNativeError.invalidSignature("ECDSA DER length is invalid")
        }
        defer { offset += length }
        return data.subdata(in: offset..<(offset + length))
    }

    private mutating func readLength() throws -> Int {
        guard offset < data.count else { throw AgentPassNativeError.invalidSignature("ECDSA DER length is missing") }
        let first = data[offset]
        offset += 1
        if first & 0x80 == 0 { return Int(first) }
        let count = Int(first & 0x7f)
        guard count > 0, count <= 4, offset + count <= data.count else {
            throw AgentPassNativeError.invalidSignature("ECDSA DER long-form length is invalid")
        }
        var length = 0
        for _ in 0..<count {
            length = (length << 8) | Int(data[offset])
            offset += 1
        }
        return length
    }
}
