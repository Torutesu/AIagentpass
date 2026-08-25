import CryptoKit
import Foundation

public enum NativeAgentWorktreeBindingError: String, Error, Equatable, Sendable {
  case invalidPath = "invalid_path"
  case invalidIdentity = "invalid_identity"
  case invalidLayout = "invalid_layout"
  case invalidHead = "invalid_head"
  case invalidObjectAuthority = "invalid_object_authority"
  case invalidRemote = "invalid_remote"
  case invalidCanonicalEncoding = "invalid_canonical_encoding"
}

public enum NativeAgentGitDirectoryLayout: String, CaseIterable, Sendable {
  case embedded
  case linked
}

public enum NativeAgentGitObjectFormat: String, CaseIterable, Sendable {
  case sha1
  case sha256

  public var objectIDHexLength: Int {
    switch self {
    case .sha1: return 40
    case .sha256: return 64
    }
  }
}

/// Stable directory identity captured from an already-open descriptor. Paths
/// alone are not worktree authority and must never be used to construct this
/// value without an immediate descriptor/path identity comparison.
public struct NativeAgentWorktreeDirectoryIdentity: Equatable, Sendable {
  public let device: UInt64
  public let inode: UInt64
  public let generation: UInt32
  public let ownerUserID: UInt32
  public let permissions: UInt16

  public init(
    device: UInt64,
    inode: UInt64,
    generation: UInt32,
    ownerUserID: UInt32,
    permissions: UInt16
  ) throws {
    guard device > 0, inode > 0, permissions <= 0o777,
      permissions & 0o022 == 0
    else {
      throw NativeAgentWorktreeBindingError.invalidIdentity
    }
    self.device = device
    self.inode = inode
    self.generation = generation
    self.ownerUserID = ownerUserID
    self.permissions = permissions
  }
}

public enum NativeAgentGitHead: Equatable, Sendable {
  case branch(String)
  case detached(String)

  fileprivate var kind: String {
    switch self {
    case .branch: return "branch"
    case .detached: return "detached"
    }
  }

  fileprivate var value: String {
    switch self {
    case .branch(let value), .detached(let value): return value
    }
  }
}

public struct NativeAgentGitRemote: Equatable, Sendable {
  public let name: String
  public let url: String

  public init(name: String, url: String) throws {
    guard Self.validName(name), Self.validURL(url) else {
      throw NativeAgentWorktreeBindingError.invalidRemote
    }
    self.name = name
    self.url = url
  }

  private static func validName(_ value: String) -> Bool {
    value.utf8.count <= 128
      && value.range(
        of: "^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$",
        options: .regularExpression
      ) != nil
  }

  private static func validURL(_ value: String) -> Bool {
    guard !value.isEmpty, value.utf8.count <= 2_048,
      !value.unicodeScalars.contains(where: {
        $0.value < 0x21 || $0.value == 0x7f
      }),
      value.range(of: "%(?![0-9A-Fa-f]{2})", options: .regularExpression) == nil
    else {
      return false
    }
    if value.contains("://") {
      guard let components = URLComponents(string: value),
        let scheme = components.scheme?.lowercased(),
        ["git", "http", "https", "ssh"].contains(scheme),
        let host = components.host, !host.isEmpty,
        components.password == nil, components.fragment == nil
      else { return false }
      if scheme != "ssh", components.user != nil { return false }
      return true
    }
    if value.range(of: "^[A-Za-z][A-Za-z0-9+.-]*:", options: .regularExpression) != nil {
      return value.range(
        of: "^[A-Za-z0-9._-]+@[A-Za-z0-9.-]+:.+$", options: .regularExpression) != nil
    }
    return true
  }
}

/// Pure, non-Codable binding produced from OS-observed Git state. Raw paths
/// stay process-local; only `digest` is permitted in Lease, XPC, or audit
/// projections. This codec does not perform filesystem observation itself.
public struct NativeAgentWorktreeBinding: Equatable, Sendable {
  public static let version = 2
  private static let domain = Data("AgentPass-Worktree-Binding-v2\0".utf8)
  private static let maximumPathBytes = 4_096
  private static let maximumRemotes = 32

  public let layout: NativeAgentGitDirectoryLayout
  public let repositoryPath: String
  public let gitDirectoryPath: String
  public let commonDirectoryPath: String
  public let repositoryIdentity: NativeAgentWorktreeDirectoryIdentity
  public let gitDirectoryIdentity: NativeAgentWorktreeDirectoryIdentity
  public let commonDirectoryIdentity: NativeAgentWorktreeDirectoryIdentity
  public let objectFormat: NativeAgentGitObjectFormat
  public let head: NativeAgentGitHead
  public let headObjectID: String?
  public let headTreeID: String?
  public let remotes: [NativeAgentGitRemote]
  public let digest: Data

  public var headKind: String {
    switch head {
    case .branch: return "branch"
    case .detached: return "detached"
    }
  }

  public var headValue: String {
    switch head {
    case .branch(let value), .detached(let value): return value
    }
  }

  public init(
    layout: NativeAgentGitDirectoryLayout,
    repositoryPath: String,
    gitDirectoryPath: String,
    commonDirectoryPath: String,
    repositoryIdentity: NativeAgentWorktreeDirectoryIdentity,
    gitDirectoryIdentity: NativeAgentWorktreeDirectoryIdentity,
    commonDirectoryIdentity: NativeAgentWorktreeDirectoryIdentity,
    objectFormat: NativeAgentGitObjectFormat,
    head: NativeAgentGitHead,
    headObjectID: String?,
    headTreeID: String?,
    remotes: [NativeAgentGitRemote]
  ) throws {
    let repositoryPath = try Self.path(repositoryPath)
    let gitDirectoryPath = try Self.path(gitDirectoryPath)
    let commonDirectoryPath = try Self.path(commonDirectoryPath)
    try Self.validateLayout(
      layout,
      repositoryPath: repositoryPath,
      gitDirectoryPath: gitDirectoryPath,
      commonDirectoryPath: commonDirectoryPath,
      repositoryIdentity: repositoryIdentity,
      gitIdentity: gitDirectoryIdentity,
      commonIdentity: commonDirectoryIdentity
    )
    try Self.validateHead(head)
    try Self.validateObjectAuthority(
      format: objectFormat, head: head, objectID: headObjectID, treeID: headTreeID)
    guard remotes.count <= Self.maximumRemotes,
      remotes.map(\.name) == remotes.map(\.name).sorted(),
      Set(remotes.map(\.name)).count == remotes.count
    else {
      throw NativeAgentWorktreeBindingError.invalidRemote
    }

    self.layout = layout
    self.repositoryPath = repositoryPath
    self.gitDirectoryPath = gitDirectoryPath
    self.commonDirectoryPath = commonDirectoryPath
    self.repositoryIdentity = repositoryIdentity
    self.gitDirectoryIdentity = gitDirectoryIdentity
    self.commonDirectoryIdentity = commonDirectoryIdentity
    self.objectFormat = objectFormat
    self.head = head
    self.headObjectID = headObjectID
    self.headTreeID = headTreeID
    self.remotes = remotes
    let canonical = Self.canonicalObject(
      layout: layout,
      repositoryPath: repositoryPath,
      gitDirectoryPath: gitDirectoryPath,
      commonDirectoryPath: commonDirectoryPath,
      repositoryIdentity: repositoryIdentity,
      gitDirectoryIdentity: gitDirectoryIdentity,
      commonDirectoryIdentity: commonDirectoryIdentity,
      objectFormat: objectFormat,
      head: head,
      headObjectID: headObjectID,
      headTreeID: headTreeID,
      remotes: remotes
    )
    do {
      digest = Data(SHA256.hash(data: Self.domain + (try NativeStrictJSON.data(canonical))))
    } catch {
      throw NativeAgentWorktreeBindingError.invalidCanonicalEncoding
    }
  }

  internal func canonicalDataForVerification() throws -> Data {
    try NativeStrictJSON.data(
      Self.canonicalObject(
        layout: layout,
        repositoryPath: repositoryPath,
        gitDirectoryPath: gitDirectoryPath,
        commonDirectoryPath: commonDirectoryPath,
        repositoryIdentity: repositoryIdentity,
        gitDirectoryIdentity: gitDirectoryIdentity,
        commonDirectoryIdentity: commonDirectoryIdentity,
        objectFormat: objectFormat,
        head: head,
        headObjectID: headObjectID,
        headTreeID: headTreeID,
        remotes: remotes
      )
    )
  }

  internal var authoritySnapshot: NativeAgentWorktreeAuthoritySnapshot {
    NativeAgentWorktreeAuthoritySnapshot(
      objectFormat: objectFormat,
      head: head,
      objectID: headObjectID,
      treeID: headTreeID,
      remotes: remotes)
  }

  private static func path(_ value: String) throws -> String {
    guard value.hasPrefix("/"), value != "/", !value.hasSuffix("/"),
      value.utf8.count <= maximumPathBytes,
      !value.split(separator: "/", omittingEmptySubsequences: false).contains(where: {
        $0 == "." || $0 == ".." || ($0.isEmpty && $0.startIndex != value.startIndex)
      })
    else {
      throw NativeAgentWorktreeBindingError.invalidPath
    }
    return value
  }

  private static func validateLayout(
    _ layout: NativeAgentGitDirectoryLayout,
    repositoryPath: String,
    gitDirectoryPath: String,
    commonDirectoryPath: String,
    repositoryIdentity: NativeAgentWorktreeDirectoryIdentity,
    gitIdentity: NativeAgentWorktreeDirectoryIdentity,
    commonIdentity: NativeAgentWorktreeDirectoryIdentity
  ) throws {
    switch layout {
    case .embedded:
      guard gitDirectoryPath == repositoryPath + "/.git",
        commonDirectoryPath == gitDirectoryPath,
        gitIdentity == commonIdentity, repositoryIdentity != gitIdentity
      else {
        throw NativeAgentWorktreeBindingError.invalidLayout
      }
    case .linked:
      guard gitDirectoryPath != commonDirectoryPath,
        gitDirectoryPath.hasPrefix(commonDirectoryPath + "/worktrees/"),
        !commonDirectoryPath.hasPrefix(repositoryPath + "/"),
        !gitDirectoryPath.hasPrefix(repositoryPath + "/"),
        repositoryIdentity != gitIdentity, repositoryIdentity != commonIdentity,
        gitIdentity != commonIdentity
      else {
        throw NativeAgentWorktreeBindingError.invalidLayout
      }
    }
  }

  private static func validateHead(_ head: NativeAgentGitHead) throws {
    switch head {
    case .branch(let value):
      let components = value.split(separator: "/", omittingEmptySubsequences: false)
      guard !value.isEmpty, !value.hasPrefix("refs/"), value != "@", value.utf8.count <= 1_024,
        !value.contains(".."), !value.contains("@{"),
        !value.unicodeScalars.contains(where: {
          $0.value < 0x20 || $0.value == 0x7f || " ~^:?*[\\".unicodeScalars.contains($0)
        }),
        components.allSatisfy({ component in
          !component.isEmpty && !component.hasPrefix(".") && !component.hasSuffix(".")
            && !component.hasSuffix(".lock")
        })
      else {
        throw NativeAgentWorktreeBindingError.invalidHead
      }
    case .detached(let value):
      guard value.utf8.count == 40 || value.utf8.count == 64,
        value.range(of: "^[0-9a-f]+$", options: .regularExpression) != nil
      else {
        throw NativeAgentWorktreeBindingError.invalidHead
      }
    }
  }

  private static func validateObjectAuthority(
    format: NativeAgentGitObjectFormat,
    head: NativeAgentGitHead,
    objectID: String?,
    treeID: String?
  ) throws {
    switch head {
    case .branch:
      guard (objectID == nil) == (treeID == nil) else {
        throw NativeAgentWorktreeBindingError.invalidObjectAuthority
      }
    case .detached(let detachedObjectID):
      guard objectID == detachedObjectID, treeID != nil else {
        throw NativeAgentWorktreeBindingError.invalidObjectAuthority
      }
    }
    for value in [objectID, treeID].compactMap({ $0 }) {
      guard value.utf8.count == format.objectIDHexLength,
        value.range(of: "^[0-9a-f]+$", options: .regularExpression) != nil
      else { throw NativeAgentWorktreeBindingError.invalidObjectAuthority }
    }
  }

  private static func canonicalObject(
    layout: NativeAgentGitDirectoryLayout,
    repositoryPath: String,
    gitDirectoryPath: String,
    commonDirectoryPath: String,
    repositoryIdentity: NativeAgentWorktreeDirectoryIdentity,
    gitDirectoryIdentity: NativeAgentWorktreeDirectoryIdentity,
    commonDirectoryIdentity: NativeAgentWorktreeDirectoryIdentity,
    objectFormat: NativeAgentGitObjectFormat,
    head: NativeAgentGitHead,
    headObjectID: String?,
    headTreeID: String?,
    remotes: [NativeAgentGitRemote]
  ) -> [String: Any] {
    [
      "version": version,
      "layout": layout.rawValue,
      "repository_path": repositoryPath,
      "git_directory_path": gitDirectoryPath,
      "common_directory_path": commonDirectoryPath,
      "repository_identity": identityObject(repositoryIdentity),
      "git_directory_identity": identityObject(gitDirectoryIdentity),
      "common_directory_identity": identityObject(commonDirectoryIdentity),
      "object_format": objectFormat.rawValue,
      "head": [
        "kind": head.kind,
        "state": headObjectID == nil ? "unborn" : "resolved",
        "value": head.value,
        "object_id": headObjectID.map { $0 as Any } ?? NSNull(),
        "tree_id": headTreeID.map { $0 as Any } ?? NSNull(),
      ],
      "remotes": remotes.map { ["name": $0.name, "url": $0.url] },
    ]
  }

  private static func identityObject(_ value: NativeAgentWorktreeDirectoryIdentity) -> [String: Any]
  {
    [
      // Decimal strings avoid JSON number precision differences between Swift
      // and JavaScript implementations of the shared canonical codec.
      "device": String(value.device),
      "inode": String(value.inode),
      "generation": value.generation,
      "owner_user_id": value.ownerUserID,
      "permissions": value.permissions,
    ]
  }
}

internal struct NativeAgentWorktreeAuthoritySnapshot: Equatable, Sendable {
  let objectFormat: NativeAgentGitObjectFormat
  let head: NativeAgentGitHead
  let objectID: String?
  let treeID: String?
  let remotes: [NativeAgentGitRemote]
}
