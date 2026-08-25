import Foundation

/// Exact designated requirement for the external physical-qualification
/// controller. The controller is deliberately not bundled with AgentPass and
/// is a different principal from both the management client and Agent host.
/// A listener using this requirement must still be disabled unless a complete
/// root-owned qualification configuration is present.
public enum NativeAgentQualificationCodeRequirement {
  public static let controllerBundleID = "dev.agentpass.qualification-controller"
  public static let controllerEntitlement = "dev.agentpass.qualification-control"
  public static let codeDirectoryHashHexLength = 40

  public static func requirement(teamID: String, controllerCodeDirectoryHash: String) throws -> String {
    _ = try NativeClientCodeRequirement.teamID(
      serviceAccessGroup: teamID + NativeClientCodeRequirement.serviceAccessGroupSuffix)
    guard controllerCodeDirectoryHash.utf8.count == codeDirectoryHashHexLength,
      controllerCodeDirectoryHash.utf8.allSatisfy({ byte in
        (byte >= 48 && byte <= 57) || (byte >= 97 && byte <= 102)
      }),
      controllerCodeDirectoryHash.utf8.contains(where: { $0 != 48 })
    else {
      throw AgentPassNativeError.invalidConfiguration(
        "Qualification controller CodeDirectory hash is invalid")
    }
    return
      "anchor apple generic and identifier \"\(controllerBundleID)\" and certificate leaf[field.1.2.840.113635.100.6.1.13] exists and certificate leaf[subject.OU] = \"\(teamID)\" and entitlement[\"\(controllerEntitlement)\"] exists and cdhash H\"\(controllerCodeDirectoryHash)\""
  }

  public static func requirement(
    serviceAccessGroup: String,
    controllerCodeDirectoryHash: String
  ) throws -> String {
    try requirement(
      teamID: NativeClientCodeRequirement.teamID(serviceAccessGroup: serviceAccessGroup),
      controllerCodeDirectoryHash: controllerCodeDirectoryHash)
  }
}
