import Foundation

/// Exact designated requirement for the narrow Agent XPC host.  The host is
/// intentionally a different signed executable and entitlement principal from
/// the management client, so passing one listener's admission check cannot
/// confer access to the other listener.
public enum NativeAgentCodeRequirement {
    public static let hostBundleID = "dev.agentpass.agent-host"
    public static let clientEntitlement = "dev.agentpass.agent-session-client"

    public static func requirement(teamID: String) throws -> String {
        _ = try NativeClientCodeRequirement.teamID(
            serviceAccessGroup: teamID + NativeClientCodeRequirement.serviceAccessGroupSuffix
        )
        return "anchor apple generic and identifier \"\(hostBundleID)\" and certificate leaf[field.1.2.840.113635.100.6.1.13] exists and certificate leaf[subject.OU] = \"\(teamID)\" and entitlement[\"\(clientEntitlement)\"] = true"
    }

    public static func requirement(serviceAccessGroup: String) throws -> String {
        try requirement(teamID: NativeClientCodeRequirement.teamID(serviceAccessGroup: serviceAccessGroup))
    }
}
