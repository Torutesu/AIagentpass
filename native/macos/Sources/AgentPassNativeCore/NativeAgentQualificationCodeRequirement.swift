import Foundation

/// Exact designated requirement for the external physical-qualification
/// controller. The controller is deliberately not bundled with AgentPass and
/// is a different principal from both the management client and Agent host.
/// A listener using this requirement must still be disabled unless a complete
/// root-owned qualification configuration is present.
public enum NativeAgentQualificationCodeRequirement {
  public static let controllerBundleID = "dev.agentpass.qualification-controller"
  public static let controllerEntitlement = "dev.agentpass.qualification-control"

  public static func requirement(teamID: String) throws -> String {
    _ = try NativeClientCodeRequirement.teamID(
      serviceAccessGroup: teamID + NativeClientCodeRequirement.serviceAccessGroupSuffix)
    return
      "anchor apple generic and identifier \"\(controllerBundleID)\" and certificate leaf[field.1.2.840.113635.100.6.1.13] exists and certificate leaf[subject.OU] = \"\(teamID)\" and entitlement[\"\(controllerEntitlement)\"] = true"
  }

  public static func requirement(serviceAccessGroup: String) throws -> String {
    try requirement(
      teamID: NativeClientCodeRequirement.teamID(serviceAccessGroup: serviceAccessGroup))
  }
}
