import CryptoKit
import Foundation

public enum NativeAgentGitCommitSignerError: String, Error, Equatable, Sendable {
    case invalidPayload = "invalid_payload"
    case invalidSigner = "invalid_signer"
    case signingFailed = "signing_failed"
    case invalidSignature = "invalid_signature"
}

/// M2's only key-use adapter. Callers cannot choose an operation, key,
/// namespace, hash algorithm, SSHSIG options, or output format.
public final class NativeAgentGitCommitSigner: NativeAgentGitCommitSigning, @unchecked Sendable {
    public static let maximumPayloadBytes = AgentPassAgentSignRequest.maximumCommitPayloadBytes

    private let signer: any P256MessageSigner
    private let lock = NSLock()

    public init(signer: any P256MessageSigner) throws {
        guard signer.publicKeyX963.count == 65, signer.publicKeyX963.first == 0x04 else {
            throw NativeAgentGitCommitSignerError.invalidSigner
        }
        self.signer = signer
    }

    public var keyLifecycleIdentity: String {
        NativeSigningTransactionRequest.hex(SHA256.hash(data: signer.publicKeyX963))
    }

    public func signGitCommitPayload(_ payload: Data) throws -> Data {
        guard !payload.isEmpty, payload.count <= Self.maximumPayloadBytes else {
            throw NativeAgentGitCommitSignerError.invalidPayload
        }
        // SecKey use and signer implementations are serialized so one registry
        // reservation corresponds to at most one hardware-key invocation.
        return try lock.withLock {
            let armored: String
            do {
                armored = try SSHSIG.sign(payload: payload, namespace: "git", signer: signer)
            } catch {
                throw NativeAgentGitCommitSignerError.signingFailed
            }
            let output = Data(armored.utf8)
            guard output.count <= AgentPassAgentSignResponse.maximumSignatureBytes,
                  armored.hasPrefix("-----BEGIN SSH SIGNATURE-----\n"),
                  armored.hasSuffix("-----END SSH SIGNATURE-----\n") else {
                throw NativeAgentGitCommitSignerError.invalidSignature
            }
            return output
        }
    }

    public func verifyGitCommitSignature(payload: Data, signature: Data) throws -> Bool {
        guard !payload.isEmpty, payload.count <= Self.maximumPayloadBytes,
              signature.count <= AgentPassAgentSignResponse.maximumSignatureBytes,
              let armored = String(data: signature, encoding: .utf8) else {
            throw NativeAgentGitCommitSignerError.invalidSignature
        }
        do {
            return try SSHSIG.verify(
                payload: payload,
                signature: armored,
                namespace: "git",
                publicKeyX963: signer.publicKeyX963)
        } catch {
            throw NativeAgentGitCommitSignerError.invalidSignature
        }
    }
}
