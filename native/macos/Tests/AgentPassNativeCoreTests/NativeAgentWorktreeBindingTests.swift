import Foundation
import Testing

@testable import AgentPassNativeCore

private func worktreeIdentity(
  inode: UInt64,
  generation: UInt32 = 1,
  owner: UInt32 = 501,
  permissions: UInt16 = 0o755
) throws -> NativeAgentWorktreeDirectoryIdentity {
  try .init(
    device: 7,
    inode: inode,
    generation: generation,
    ownerUserID: owner,
    permissions: permissions
  )
}

private func embeddedWorktree(
  repositoryPath: String = "/Users/build/project",
  repositoryIdentity: NativeAgentWorktreeDirectoryIdentity? = nil,
  head: NativeAgentGitHead = .branch("feature/agent-pass"),
  objectFormat: NativeAgentGitObjectFormat = .sha1,
  headObjectID: String? = String(repeating: "a", count: 40),
  headTreeID: String? = String(repeating: "b", count: 40),
  remotes: [NativeAgentGitRemote]? = nil
) throws -> NativeAgentWorktreeBinding {
  let git = try worktreeIdentity(inode: 12)
  return try .init(
    layout: .embedded,
    repositoryPath: repositoryPath,
    gitDirectoryPath: repositoryPath + "/.git",
    commonDirectoryPath: repositoryPath + "/.git",
    repositoryIdentity: repositoryIdentity ?? worktreeIdentity(inode: 11),
    gitDirectoryIdentity: git,
    commonDirectoryIdentity: git,
    objectFormat: objectFormat,
    head: head,
    headObjectID: headObjectID,
    headTreeID: headTreeID,
    remotes: remotes ?? [
      try NativeAgentGitRemote(name: "origin", url: "git@github.com:org/project.git")
    ]
  )
}

@Test func worktreeBindingIsCanonicalDeterministicAndDomainSeparated() throws {
  let first = try embeddedWorktree()
  let second = try embeddedWorktree()
  #expect(first == second)
  #expect(first.digest.count == 32)
  #expect(first.digest == second.digest)
  let digestHex = first.digest.map { String(format: "%02x", $0) }.joined()
  #expect(digestHex == "85402470107f2c6ff4ac615a4f16f11c00aae865b85debd702d252626f8ff15b")
  let object = try NativeStrictJSON.object(
    from: first.canonicalDataForVerification(), maxBytes: 64 * 1024, maxDepth: 12)
  #expect(
    Set(object.keys) == [
      "version", "layout", "repository_path", "git_directory_path",
      "common_directory_path", "repository_identity", "git_directory_identity",
      "common_directory_identity", "object_format", "head", "remotes",
    ])
}

@Test func worktreeBindingMatchesSharedNodeCanonicalVector() throws {
  let fixtureURL = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
    .appendingPathComponent("../../../../contracts/vectors/worktree-binding-v2.json")
    .standardizedFileURL
  let fixture = try #require(
    JSONSerialization.jsonObject(with: Data(contentsOf: fixtureURL)) as? [String: Any])
  let expectedObject = try #require(fixture["binding"] as? [String: Any])
  let expectedDigest = try #require(fixture["sha256"] as? String)
  let binding = try embeddedWorktree()
  #expect(try NativeStrictJSON.data(expectedObject) == binding.canonicalDataForVerification())
  #expect(binding.digest.map { String(format: "%02x", $0) }.joined() == expectedDigest)
}

@Test func everyWorktreeAuthoritySubstitutionChangesTheDigest() throws {
  let base = try embeddedWorktree()
  let path = try embeddedWorktree(repositoryPath: "/Users/build/project-copy")
  let identity = try embeddedWorktree(repositoryIdentity: worktreeIdentity(inode: 99))
  let head = try embeddedWorktree(
    head: .detached(String(repeating: "c", count: 40)),
    headObjectID: String(repeating: "c", count: 40))
  let tree = try embeddedWorktree(headTreeID: String(repeating: "d", count: 40))
  let objectFormat = try embeddedWorktree(
    objectFormat: .sha256,
    headObjectID: String(repeating: "a", count: 64),
    headTreeID: String(repeating: "b", count: 64))
  let remote = try embeddedWorktree(remotes: [
    NativeAgentGitRemote(name: "origin", url: "git@github.com:org/other.git")
  ])
  for changed in [path, identity, head, tree, objectFormat, remote] {
    #expect(changed.digest != base.digest)
  }
}

@Test func linkedWorktreeBindsPerWorktreeAndCommonGitDirectories() throws {
  let binding = try NativeAgentWorktreeBinding(
    layout: .linked,
    repositoryPath: "/Users/build/feature-checkout",
    gitDirectoryPath: "/Users/build/main/.git/worktrees/feature-checkout",
    commonDirectoryPath: "/Users/build/main/.git",
    repositoryIdentity: worktreeIdentity(inode: 20),
    gitDirectoryIdentity: worktreeIdentity(inode: 21),
    commonDirectoryIdentity: worktreeIdentity(inode: 22),
    objectFormat: .sha1,
    head: .branch("feature/linked"),
    headObjectID: String(repeating: "a", count: 40),
    headTreeID: String(repeating: "b", count: 40),
    remotes: [NativeAgentGitRemote(name: "origin", url: "ssh://git@github.com/org/project.git")]
  )
  #expect(binding.layout == .linked)
  #expect(binding.digest.count == 32)
}

@Test func worktreeBindingRejectsPathLayoutAndIdentityAmbiguity() throws {
  #expect(throws: NativeAgentWorktreeBindingError.invalidPath) {
    _ = try embeddedWorktree(repositoryPath: "/Users/build/../other")
  }
  #expect(throws: NativeAgentWorktreeBindingError.invalidIdentity) {
    _ = try worktreeIdentity(inode: 0)
  }
  #expect(throws: NativeAgentWorktreeBindingError.invalidIdentity) {
    _ = try worktreeIdentity(inode: 1, permissions: 0o777)
  }
  #expect(throws: NativeAgentWorktreeBindingError.invalidLayout) {
    _ = try NativeAgentWorktreeBinding(
      layout: .embedded,
      repositoryPath: "/Users/build/project",
      gitDirectoryPath: "/Users/build/other/.git",
      commonDirectoryPath: "/Users/build/other/.git",
      repositoryIdentity: worktreeIdentity(inode: 1),
      gitDirectoryIdentity: worktreeIdentity(inode: 2),
      commonDirectoryIdentity: worktreeIdentity(inode: 2),
      objectFormat: .sha1,
      head: .branch("main"),
      headObjectID: nil,
      headTreeID: nil,
      remotes: []
    )
  }
}

@Test func worktreeBindingRejectsInvalidHeadAndRemoteRepresentations() throws {
  for value in ["main..other", "refs/heads/main", "main lock", "main.lock", "topic@{1}"] {
    #expect(throws: NativeAgentWorktreeBindingError.invalidHead) {
      _ = try embeddedWorktree(head: .branch(value))
    }
  }
  #expect(throws: NativeAgentWorktreeBindingError.invalidHead) {
    _ = try embeddedWorktree(
      head: .detached(String(repeating: "A", count: 40)),
      headObjectID: String(repeating: "A", count: 40))
  }
  #expect(try embeddedWorktree(head: .branch("x")).head == .branch("x"))
  for value in ["release/v1.2", "topic.with.dot", "_topic", "feature/foo@"] {
    #expect(try embeddedWorktree(head: .branch(value)).head == .branch(value))
  }
  #expect(throws: NativeAgentWorktreeBindingError.invalidRemote) {
    _ = try NativeAgentGitRemote(name: "bad remote", url: "https://github.com/org/project")
  }
  #expect(throws: NativeAgentWorktreeBindingError.invalidRemote) {
    _ = try NativeAgentGitRemote(name: "origin", url: "https://user:secret@example.com/project")
  }
  #expect(throws: NativeAgentWorktreeBindingError.invalidRemote) {
    _ = try embeddedWorktree(remotes: [
      NativeAgentGitRemote(name: "upstream", url: "ssh://git@example.com/upstream"),
      NativeAgentGitRemote(name: "origin", url: "ssh://git@example.com/origin"),
    ])
  }
  for value in [
    "https://[::1", "https://", "https:example", "https://host/path with space", "https://host/%zz",
    "https://token@host/project",
  ] {
    #expect(throws: NativeAgentWorktreeBindingError.invalidRemote) {
      _ = try NativeAgentGitRemote(name: "origin", url: value)
    }
  }
}

@Test func worktreeBindingRejectsIncompleteOrCrossFormatObjectAuthority() throws {
  #expect(throws: NativeAgentWorktreeBindingError.invalidObjectAuthority) {
    _ = try embeddedWorktree(headObjectID: String(repeating: "a", count: 40), headTreeID: nil)
  }
  #expect(throws: NativeAgentWorktreeBindingError.invalidObjectAuthority) {
    _ = try embeddedWorktree(
      objectFormat: .sha256,
      headObjectID: String(repeating: "a", count: 40),
      headTreeID: String(repeating: "b", count: 40))
  }
  #expect(throws: NativeAgentWorktreeBindingError.invalidObjectAuthority) {
    _ = try embeddedWorktree(
      head: .detached(String(repeating: "c", count: 40)),
      headObjectID: String(repeating: "a", count: 40),
      headTreeID: String(repeating: "b", count: 40))
  }
  let unborn = try embeddedWorktree(headObjectID: nil, headTreeID: nil)
  #expect(unborn.headObjectID == nil)
  #expect(unborn.headTreeID == nil)
}

@Test func worktreeBindingPreservesFullWidthFilesystemIdentityCanonically() throws {
  let identity = try NativeAgentWorktreeDirectoryIdentity(
    device: UInt64.max,
    inode: UInt64.max,
    generation: UInt32.max,
    ownerUserID: UInt32.max,
    permissions: 0o700
  )
  let binding = try embeddedWorktree(repositoryIdentity: identity)
  let object = try NativeStrictJSON.object(
    from: binding.canonicalDataForVerification(), maxBytes: 64 * 1024, maxDepth: 12)
  let encoded = try #require(object["repository_identity"] as? [String: Any])
  #expect(encoded["device"] as? String == String(UInt64.max))
  #expect(encoded["inode"] as? String == String(UInt64.max))
}
