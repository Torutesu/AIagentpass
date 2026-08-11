import AgentPassNativeCore
import Foundation

private func loadProtectedFile(path: String, label: String) throws -> Data {
    let original = URL(fileURLWithPath: path).standardizedFileURL
    guard original.path.hasPrefix("/"), original.resolvingSymlinksInPath().path == original.path else {
        throw AgentPassNativeError.invalidConfiguration("\(label) path must be absolute and contain no symbolic links")
    }
    var current = original
    while true {
        let attributes = try FileManager.default.attributesOfItem(atPath: current.path)
        let owner = (attributes[.ownerAccountID] as? NSNumber)?.uint32Value
        let permissions = (attributes[.posixPermissions] as? NSNumber)?.uint16Value ?? 0xffff
        guard owner == 0, permissions & 0o022 == 0 else {
            throw AgentPassNativeError.invalidConfiguration("\(label) and every parent must be root-owned and not group/world writable")
        }
        if current.path == "/" { break }
        current.deleteLastPathComponent()
    }
    let attributes = try FileManager.default.attributesOfItem(atPath: original.path)
    guard (attributes[.type] as? FileAttributeType) == .typeRegular else {
        throw AgentPassNativeError.invalidConfiguration("\(label) must be a regular file")
    }
    return try Data(contentsOf: original, options: .mappedIfSafe)
}

private struct ServiceConfiguration: Decodable {
    let machServiceName: String
    let keyTag: String
    let keychainAccessGroup: String?
    let policyPath: String
    let clientCodeSigningRequirement: String
    let allowedClientUID: UInt32

    enum CodingKeys: String, CodingKey {
        case machServiceName = "mach_service_name"
        case keyTag = "key_tag"
        case keychainAccessGroup = "keychain_access_group"
        case policyPath = "policy_path"
        case clientCodeSigningRequirement = "client_code_signing_requirement"
        case allowedClientUID = "allowed_client_uid"
    }

    static func load(path: String) throws -> Self {
        let value = try JSONDecoder().decode(Self.self, from: loadProtectedFile(path: path, label: "Native service configuration"))
        guard !value.machServiceName.isEmpty, !value.keyTag.isEmpty, value.policyPath.hasPrefix("/"),
              !value.clientCodeSigningRequirement.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
            throw AgentPassNativeError.invalidConfiguration("Native service configuration contains empty trust parameters")
        }
        return value
    }
}

private final class ServiceEndpoint: NSObject, AgentPassNativeServiceProtocol {
    private let keyStore: SecureEnclaveKeyStore
    private let authorizer: NativeRequestAuthorizer

    init(keyStore: SecureEnclaveKeyStore, authorizer: NativeRequestAuthorizer) {
        self.keyStore = keyStore
        self.authorizer = authorizer
    }

    func health(withReply reply: @escaping (NSDictionary) -> Void) {
        reply(["ok": true, "protocol_version": 1, "key_backend": "secure-enclave"])
    }

    func publicKey(withReply reply: @escaping (NSString?, NSError?) -> Void) {
        do { reply(try SSHSIG.authorizedKey(publicKeyX963: keyStore.publicKeyX963) as NSString, nil) }
        catch { reply(nil, error as NSError) }
    }

    func sign(request: NSData, withReply reply: @escaping (NSString?, NSError?) -> Void) {
        do {
            let authorized = try authorizer.authorize(requestData: request as Data)
            reply(try SSHSIG.sign(payload: authorized.payload, signer: keyStore) as NSString, nil)
        } catch {
            reply(nil, error as NSError)
        }
    }
}

private final class ListenerDelegate: NSObject, NSXPCListenerDelegate {
    private let configuration: ServiceConfiguration
    private let endpoint: ServiceEndpoint

    init(configuration: ServiceConfiguration, endpoint: ServiceEndpoint) {
        self.configuration = configuration
        self.endpoint = endpoint
    }

    func listener(_ listener: NSXPCListener, shouldAcceptNewConnection connection: NSXPCConnection) -> Bool {
        guard connection.effectiveUserIdentifier == configuration.allowedClientUID else { return false }
        connection.setCodeSigningRequirement(configuration.clientCodeSigningRequirement)
        connection.exportedInterface = NSXPCInterface(with: AgentPassNativeServiceProtocol.self)
        connection.exportedObject = endpoint
        connection.resume()
        return true
    }
}

do {
    guard CommandLine.arguments.count == 3, CommandLine.arguments[1] == "--config" else {
        throw AgentPassNativeError.invalidConfiguration("Usage: agentpass-native-service --config /Library/Application Support/AgentPass/native-service.json")
    }
    let configuration = try ServiceConfiguration.load(path: CommandLine.arguments[2])
    let keyStore = try SecureEnclaveKeyStore(
        applicationTag: configuration.keyTag,
        accessGroup: configuration.keychainAccessGroup
    )
    let authorizer = try NativeRequestAuthorizer(policyData: loadProtectedFile(path: configuration.policyPath, label: "Native policy"))
    let listener = NSXPCListener(machServiceName: configuration.machServiceName)
    let delegate = ListenerDelegate(configuration: configuration, endpoint: ServiceEndpoint(keyStore: keyStore, authorizer: authorizer))
    listener.delegate = delegate
    listener.resume()
    RunLoop.current.run()
} catch {
    FileHandle.standardError.write(Data("agentpass-native-service: \(error.localizedDescription)\n".utf8))
    exit(1)
}
