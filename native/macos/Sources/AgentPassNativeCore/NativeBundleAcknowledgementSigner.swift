import CryptoKit
import Foundation

/// Creates the exact device-signed acknowledgement envelope after a verified
/// ControlBundle has either been durably installed or deterministically
/// blocked. The signer can be backed by Secure Enclave; private key material
/// is never accepted by this API.
public enum NativeBundleAcknowledgementSigner {
    public static func create(
        organizationID: String,
        deviceID: String,
        deviceKeyEpoch: Int64,
        sequence: Int64,
        statementHash: String,
        result: NativeBundleAcknowledgementResult,
        reasonCode: NativeBundleAcknowledgementReasonCode? = nil,
        observedAtMilliseconds: Int64 = Int64(Date().timeIntervalSince1970 * 1_000),
        nonce: String,
        signer: any P256MessageSigner
    ) throws -> NativeBundleAcknowledgement {
        guard observedAtMilliseconds >= 0, observedAtMilliseconds <= 9_007_199_254_740_991 else {
            throw NativeDeviceSyncContractError(.invalidTimestamp, "ACK observation time is invalid")
        }
        let placeholder = NativeBundleAcknowledgement(
            organizationID: organizationID,
            deviceID: deviceID,
            deviceKeyEpoch: deviceKeyEpoch,
            sequence: sequence,
            statementHash: statementHash,
            result: result,
            reasonCode: reasonCode,
            observedAt: timestamp(observedAtMilliseconds),
            nonce: nonce,
            signature: Data(repeating: 1, count: 64).base64URL
        )
        // Parsing the placeholder applies the complete closed schema before
        // the Secure Enclave is asked to sign anything.
        let normalized = try NativeBundleAcknowledgementCodec.decode(NativeBundleAcknowledgementCodec.canonicalJSON(placeholder))
        let signingData = try NativeBundleAcknowledgementCodec.signingData(normalized)
        let signature = try NativeP256CanonicalSignature.canonicalized(signer.sign(message: signingData))
        guard signer.publicKeyX963.count == 65, signer.publicKeyX963.first == 0x04,
              let publicKey = try? P256.Signing.PublicKey(x963Representation: signer.publicKeyX963),
              let parsedSignature = try? P256.Signing.ECDSASignature(rawRepresentation: signature),
              publicKey.isValidSignature(parsedSignature, for: signingData) else {
            throw NativeDeviceSyncContractError(.invalidSignature, "ACK signer did not produce a signature for its enrolled public key")
        }
        let acknowledgement = NativeBundleAcknowledgement(
            organizationID: normalized.organizationID,
            deviceID: normalized.deviceID,
            deviceKeyEpoch: normalized.deviceKeyEpoch,
            sequence: normalized.sequence,
            statementHash: normalized.statementHash,
            result: normalized.result,
            reasonCode: normalized.reasonCode,
            observedAt: normalized.observedAt,
            nonce: normalized.nonce,
            signature: signature.base64URL
        )
        return try NativeBundleAcknowledgementCodec.decode(NativeBundleAcknowledgementCodec.canonicalJSON(acknowledgement))
    }

    private static func timestamp(_ milliseconds: Int64) -> String {
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.timeZone = TimeZone(secondsFromGMT: 0)
        formatter.dateFormat = "yyyy-MM-dd'T'HH:mm:ss.SSS'Z'"
        return formatter.string(from: Date(timeIntervalSince1970: Double(milliseconds) / 1_000))
    }
}

private extension Data {
    var base64URL: String {
        base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }
}
