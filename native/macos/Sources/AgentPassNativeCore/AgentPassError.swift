import Foundation
import Security

public enum AgentPassNativeError: LocalizedError {
    case invalidKey(String)
    case invalidSignature(String)
    case keychain(String, OSStatus)
    case secureEnclaveUnavailable
    case invalidConfiguration(String)
    case unauthorizedClient(String)

    public var errorDescription: String? {
        switch self {
        case .invalidKey(let message), .invalidSignature(let message), .invalidConfiguration(let message), .unauthorizedClient(let message):
            return message
        case .keychain(let operation, let status):
            let detail = SecCopyErrorMessageString(status, nil) as String? ?? "OSStatus \(status)"
            return "\(operation) failed: \(detail)"
        case .secureEnclaveUnavailable:
            return "Secure Enclave is unavailable on this Mac"
        }
    }
}
