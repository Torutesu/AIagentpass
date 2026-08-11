import Foundation
import ServiceManagement

private struct ManagerOutput: Encodable {
    let ok: Bool
    let action: String
    let status: String
    let requiresApproval: Bool
    let openedSettings: Bool
    let bundlePath: String
    let plistPath: String
    let plistPresent: Bool
    let error: String?

    enum CodingKeys: String, CodingKey {
        case ok, action, status, error
        case requiresApproval = "requires_approval"
        case openedSettings = "opened_settings"
        case bundlePath = "bundle_path"
        case plistPath = "plist_path"
        case plistPresent = "plist_present"
    }
}

private func serviceStatus(_ status: SMAppService.Status) -> (String, Bool) {
    switch status {
    case .notRegistered: return ("not_registered", false)
    case .enabled: return ("enabled", false)
    case .requiresApproval: return ("requires_approval", true)
    case .notFound: return ("not_found", false)
    @unknown default: return ("unknown", false)
    }
}

private let daemonPlistName = "dev.agentpass.native-service.plist"
private let bundleURL = Bundle.main.bundleURL.standardizedFileURL
private let plistURL = bundleURL
    .appendingPathComponent("Contents", isDirectory: true)
    .appendingPathComponent("Library", isDirectory: true)
    .appendingPathComponent("LaunchDaemons", isDirectory: true)
    .appendingPathComponent(daemonPlistName, isDirectory: false)

private func emit(action: String, openedSettings: Bool = false, error: (any Error)? = nil) -> Never {
    let service = SMAppService.daemon(plistName: daemonPlistName)
    let state = serviceStatus(service.status)
    let output = ManagerOutput(
        ok: error == nil,
        action: action,
        status: state.0,
        requiresApproval: state.1,
        openedSettings: openedSettings,
        bundlePath: bundleURL.path,
        plistPath: plistURL.path,
        plistPresent: FileManager.default.fileExists(atPath: plistURL.path),
        error: error?.localizedDescription
    )
    let encoder = JSONEncoder()
    encoder.outputFormatting = [.sortedKeys]
    let data = (try? encoder.encode(output)) ?? Data("{\"ok\":false,\"error\":\"encoding failure\"}".utf8)
    FileHandle.standardOutput.write(data + Data("\n".utf8))
    exit(error == nil ? 0 : 1)
}

guard CommandLine.arguments.count == 2 else {
    FileHandle.standardError.write(Data("Usage: agentpass-native-manager register|unregister|status|open-settings\n".utf8))
    exit(2)
}

let action = CommandLine.arguments[1]
guard FileManager.default.fileExists(atPath: plistURL.path) else {
    let error = NSError(
        domain: "dev.agentpass.native-manager",
        code: 1,
        userInfo: [NSLocalizedDescriptionKey: "The daemon property list is missing from the AgentPass app bundle"]
    )
    emit(action: action, error: error)
}

let service = SMAppService.daemon(plistName: daemonPlistName)
do {
    switch action {
    case "register":
        try service.register()
        switch service.status {
        case .enabled:
            emit(action: action)
        case .requiresApproval:
            SMAppService.openSystemSettingsLoginItems()
            emit(action: action, openedSettings: true)
        default:
            let error = NSError(
                domain: "dev.agentpass.native-manager",
                code: 2,
                userInfo: [NSLocalizedDescriptionKey: "Service Management did not accept the daemon registration"]
            )
            emit(action: action, error: error)
        }
    case "unregister": try service.unregister()
    case "status": break
    case "open-settings":
        SMAppService.openSystemSettingsLoginItems()
        emit(action: action, openedSettings: true)
    default:
        FileHandle.standardError.write(Data("Unknown native manager action\n".utf8))
        exit(2)
    }
    emit(action: action)
} catch {
    emit(action: action, error: error)
}
