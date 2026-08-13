import Foundation

public enum NativeClientCodeRequirement {
    public static let clientBundleID = "dev.agentpass.native-client"
    public static let serviceAccessGroupSuffix = ".dev.agentpass.service-keys"
    public static let approvalAccessGroupSuffix = ".dev.agentpass.approval-keys"

    public static func teamID(serviceAccessGroup: String) throws -> String {
        guard serviceAccessGroup.hasSuffix(serviceAccessGroupSuffix) else {
            throw AgentPassNativeError.invalidConfiguration("Native service access group is not the fixed service group")
        }
        let teamID = String(serviceAccessGroup.dropLast(serviceAccessGroupSuffix.count))
        guard teamID.count == 10,
              teamID.unicodeScalars.allSatisfy({ scalar in
                  (scalar.value >= 48 && scalar.value <= 57) || (scalar.value >= 65 && scalar.value <= 90)
              }) else {
            throw AgentPassNativeError.invalidConfiguration("Native service access group has an invalid Team ID")
        }
        return teamID
    }

    public static func requirement(teamID: String) throws -> String {
        _ = try self.teamID(serviceAccessGroup: teamID + serviceAccessGroupSuffix)
        return "anchor apple generic and identifier \"\(clientBundleID)\" and certificate leaf[field.1.2.840.113635.100.6.1.13] exists and certificate leaf[subject.OU] = \"\(teamID)\" and entitlement[\"keychain-access-groups\"] = \"\(teamID)\(approvalAccessGroupSuffix)\""
    }

    public static func requirement(serviceAccessGroup: String) throws -> String {
        try requirement(teamID: teamID(serviceAccessGroup: serviceAccessGroup))
    }
}
