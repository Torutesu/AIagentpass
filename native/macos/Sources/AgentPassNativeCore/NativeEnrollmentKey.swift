import CryptoKit
import Foundation
import Security

public enum NativeEnrollmentProof {
    public static let protocolIdentifier = "AgentPass-Enrollment-Proof-v1"
    public static let maximumPreimageBytes = 16 * 1024

    /// Validates the exact five-line v1 proof preimage emitted by the
    /// enrollment client. No normalization is performed: the bytes signed are
    /// exactly the bytes received from stdin.
    public static func validatedPreimage(_ preimage: Data) throws -> Data {
        guard !preimage.isEmpty, preimage.count <= maximumPreimageBytes,
              let text = String(data: preimage, encoding: .utf8),
              Data(text.utf8) == preimage else {
            throw AgentPassNativeError.invalidSignature("Enrollment proof preimage is not bounded UTF-8")
        }

        let fields = text.split(separator: "\n", omittingEmptySubsequences: false).map(String.init)
        guard fields.count == 5,
              fields[0] == protocolIdentifier,
              fields[1] == "POST",
              fields[2].range(of: "^/v1/enrollments/[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-8][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$", options: .regularExpression) != nil,
              fields[3].range(of: "^[0-9a-f]{64}$", options: .regularExpression) != nil,
              fields[4].range(of: "^[0-9a-f]{64}$", options: .regularExpression) != nil else {
            throw AgentPassNativeError.invalidSignature("Enrollment proof preimage is not the exact AgentPass-Enrollment-Proof-v1 schema")
        }
        return preimage
    }
}

/// The only key material crossing the enrollment boundary is the public X9.63
/// representation. Implementations must keep the private key inside their
/// hardware-backed boundary.
public protocol NativeEnrollmentKeyStore: Sendable {
    func loadExistingPublicKeyX963() throws -> Data?
    func createPublicKeyX963() throws -> Data
    func signEnrollmentProof(preimage: Data) throws -> Data
}

public struct NativeEnrollmentKeyMaterial: Equatable, Sendable {
    public static let version = 1
    public static let fixedApplicationTag = "dev.agentpass.device-auth.v1"

    public let publicKeyPEM: String
    public let fingerprint: String

    public init(publicKeyX963: Data) throws {
        guard publicKeyX963.count == 65, publicKeyX963.first == 0x04,
              (try? P256.Signing.PublicKey(x963Representation: publicKeyX963)) != nil else {
            throw AgentPassNativeError.invalidKey("Enrollment key must be a valid P-256 public key")
        }

        let pem = try p256SubjectPublicKeyInfoPEM(x963: publicKeyX963)
        let der = try Self.subjectPublicKeyInfoDER(fromCanonicalPEM: pem)
        publicKeyPEM = pem
        fingerprint = Self.fingerprint(der)
    }

    /// Fingerprints the canonical DER SubjectPublicKeyInfo, not the private
    /// key or the provider-specific X9.63 representation.
    public static func fingerprint(_ subjectPublicKeyInfoDER: Data) -> String {
        let digest = Data(SHA256.hash(data: subjectPublicKeyInfoDER))
            .base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
        return "SHA256:\(digest)"
    }

    private static func subjectPublicKeyInfoDER(fromCanonicalPEM pem: String) throws -> Data {
        let lines = pem.split(whereSeparator: \.isNewline).map(String.init)
        guard lines.count == 3,
              lines[0] == "-----BEGIN PUBLIC KEY-----",
              lines[2] == "-----END PUBLIC KEY-----",
              let der = Data(base64Encoded: lines[1]),
              der.count == 91,
              der.prefix(2) == Data([0x30, 0x59]),
              der[der.index(der.startIndex, offsetBy: 2)] == 0x30 else {
            throw AgentPassNativeError.invalidKey("Enrollment public key PEM is not canonical P-256 SPKI")
        }
        return der
    }
}

/// Idempotent orchestration is deliberately separate from Keychain/Secure
/// Enclave access so CI can exercise all output and retry invariants with a
/// fake provider.
public struct NativeEnrollmentKeyPrimitive: Sendable {
    private let store: any NativeEnrollmentKeyStore

    public init(store: any NativeEnrollmentKeyStore) {
        self.store = store
    }

    public func loadOrCreate() throws -> NativeEnrollmentKeyMaterial {
        if let existing = try store.loadExistingPublicKeyX963() {
            return try NativeEnrollmentKeyMaterial(publicKeyX963: existing)
        }

        do {
            return try NativeEnrollmentKeyMaterial(publicKeyX963: store.createPublicKeyX963())
        } catch let creationError {
            // A second process may have won the create race. Reconcile only by
            // loading the same provider-owned fixed binding; never replace it.
            if let existing = try store.loadExistingPublicKeyX963() {
                return try NativeEnrollmentKeyMaterial(publicKeyX963: existing)
            }
            throw creationError
        }
    }

    public func signEnrollmentProof(preimage: Data) throws -> Data {
        let exactPreimage = try NativeEnrollmentProof.validatedPreimage(preimage)
        let signature = try store.signEnrollmentProof(preimage: exactPreimage)
        guard signature.count == 64 else {
            throw AgentPassNativeError.invalidSignature("Enrollment proof signature must be raw 64-byte IEEE-P1363")
        }
        return signature
    }
}

/// Production provider for the signed native client. The tag is intentionally
/// not an initializer argument: callers cannot redirect this command to an
/// arbitrary Keychain namespace.
public struct SecureEnclaveNativeEnrollmentKeyStore: NativeEnrollmentKeyStore, Sendable {
    public let accessGroup: String?

    public init(accessGroup: String? = nil) {
        self.accessGroup = accessGroup
    }

    public func loadExistingPublicKeyX963() throws -> Data? {
        guard let key = try loadKey() else { return nil }
        try Self.validateSecureEnclavePrivateKey(key)
        return try Self.exportPublicKey(from: key)
    }

    public func createPublicKeyX963() throws -> Data {
        var accessError: Unmanaged<CFError>?
        guard let access = SecAccessControlCreateWithFlags(
            nil,
            kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
            [.privateKeyUsage],
            &accessError
        ) else {
            throw accessError?.takeRetainedValue() as Error?
                ?? AgentPassNativeError.invalidKey("Unable to create enrollment key access control")
        }

        var privateAttributes: [CFString: Any] = [
            kSecAttrIsPermanent: true,
            kSecAttrApplicationTag: Data(NativeEnrollmentKeyMaterial.fixedApplicationTag.utf8),
            kSecAttrAccessControl: access
        ]
        if let accessGroup {
            privateAttributes[kSecAttrAccessGroup] = accessGroup
        }

        let attributes: [CFString: Any] = [
            kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits: 256,
            kSecAttrTokenID: kSecAttrTokenIDSecureEnclave,
            kSecPrivateKeyAttrs: privateAttributes
        ]
        var keyError: Unmanaged<CFError>?
        guard let key = SecKeyCreateRandomKey(attributes as CFDictionary, &keyError) else {
            if let underlying = keyError?.takeRetainedValue() {
                let nsError = underlying as Error as NSError
                if nsError.code == Int(errSecUnimplemented) || nsError.code == Int(errSecNotAvailable) {
                    throw AgentPassNativeError.secureEnclaveUnavailable
                }
                throw underlying
            }
            throw AgentPassNativeError.invalidKey("Secure Enclave enrollment key creation failed")
        }
        try Self.validateSecureEnclavePrivateKey(key)
        return try Self.exportPublicKey(from: key)
    }

    public func signEnrollmentProof(preimage: Data) throws -> Data {
        let exactPreimage = try NativeEnrollmentProof.validatedPreimage(preimage)
        guard let key = try loadKey() else {
            throw AgentPassNativeError.invalidKey("Secure Enclave enrollment key does not exist for the fixed tag")
        }
        try Self.validateSecureEnclavePrivateKey(key)
        var error: Unmanaged<CFError>?
        guard let der = SecKeyCreateSignature(
            key,
            .ecdsaSignatureMessageX962SHA256,
            exactPreimage as CFData,
            &error
        ) as Data? else {
            throw error?.takeRetainedValue() as Error?
                ?? AgentPassNativeError.invalidSignature("Secure Enclave enrollment proof signing failed")
        }
        let raw = try SecureEnclaveKeyStore.rawSignature(fromDER: der)
        guard raw.count == 64 else {
            throw AgentPassNativeError.invalidSignature("Secure Enclave enrollment proof signature is not raw IEEE-P1363")
        }
        return raw
    }

    private func loadKey() throws -> SecKey? {
        var query: [CFString: Any] = [
            kSecClass: kSecClassKey,
            kSecAttrApplicationTag: Data(NativeEnrollmentKeyMaterial.fixedApplicationTag.utf8),
            kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom,
            kSecReturnRef: true,
            kSecMatchLimit: kSecMatchLimitAll
        ]
        if let accessGroup {
            query[kSecAttrAccessGroup] = accessGroup
        }

        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess else {
            throw AgentPassNativeError.keychain("Secure Enclave enrollment key lookup", status)
        }
        if let keys = item as? [SecKey] {
            guard keys.count == 1, let key = keys.first else {
                throw AgentPassNativeError.invalidKey("Enrollment key lookup is ambiguous for the fixed tag")
            }
            return key
        }
        guard let item, CFGetTypeID(item) == SecKeyGetTypeID() else {
            throw AgentPassNativeError.invalidKey("Enrollment key lookup returned an unexpected item")
        }
        return unsafeDowncast(item, to: SecKey.self)
    }

    private static func validateSecureEnclavePrivateKey(_ key: SecKey) throws {
        guard let attributes = SecKeyCopyAttributes(key) as? [CFString: Any],
              (attributes[kSecAttrKeyType] as? String) == (kSecAttrKeyTypeECSECPrimeRandom as String),
              (attributes[kSecAttrKeyClass] as? String) == (kSecAttrKeyClassPrivate as String),
              (attributes[kSecAttrTokenID] as? String) == (kSecAttrTokenIDSecureEnclave as String),
              (attributes[kSecAttrKeySizeInBits] as? NSNumber)?.intValue == 256,
              SecKeyIsAlgorithmSupported(key, .sign, .ecdsaSignatureMessageX962SHA256) else {
            throw AgentPassNativeError.invalidKey("Fixed enrollment binding is not a Secure Enclave P-256 private key")
        }

        // A Secure Enclave private key must not have an exportable private
        // representation. This check does not retain or return any bytes.
        guard SecKeyCopyExternalRepresentation(key, nil) == nil else {
            throw AgentPassNativeError.invalidKey("Enrollment private key is exportable")
        }
    }

    private static func exportPublicKey(from privateKey: SecKey) throws -> Data {
        guard let publicKey = SecKeyCopyPublicKey(privateKey),
              let representation = SecKeyCopyExternalRepresentation(publicKey, nil) as Data?,
              representation.count == 65, representation.first == 0x04,
              (try? P256.Signing.PublicKey(x963Representation: representation)) != nil else {
            throw AgentPassNativeError.invalidKey("Unable to export the Secure Enclave enrollment public key")
        }
        return representation
    }
}
