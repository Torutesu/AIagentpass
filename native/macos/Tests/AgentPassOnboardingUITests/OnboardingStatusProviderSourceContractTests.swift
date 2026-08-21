import Foundation
import Testing

// SwiftPM constraint: this package targets macOS 14+, so the production
// boundary may use Darwin file-descriptor APIs and Security.framework. Keep
// the test target free of XCTest/process-launch helpers; these assertions are
// source contracts and the runtime launch test uses the provider's @testable
// runner seam only.
@Test func onboardingStatusProviderPinsTheNativeTrustContract() throws {
    let source = try providerSource()

    #expect(source.contains("SecStaticCodeCreateWithPath"))
    #expect(source.contains("SecStaticCodeCheckValidity"))
    #expect(source.contains("SecCodeCopySigningInformation"))
    #expect(source.contains("trustedExecutableIdentifiers: Set<String> = [\"dev.agentpass\"]"))
    #expect(source.contains("(opened.st_mode & S_IFMT) == S_IFREG"))
    #expect(source.contains("(opened.st_mode & 0o222) == 0"))
    #expect(source.contains("opened.st_nlink == 1"))
    #expect(source.contains("opened.st_uid == 0 || opened.st_uid == getuid()"))
    #expect(source.contains("Darwin.openat("))
    #expect(source.contains("O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC"))
    #expect(source.contains("if !requireTrustedCode"))
    #expect(source.contains("URL(fileURLWithPath: \"/dev/fd/\\(descriptor)\")"))
    #expect(source.contains("fcntl(descriptor, F_SETFD, descriptorFlags & ~FD_CLOEXEC) == 0"))
    #expect(source.contains("Self.pathStillNames(url, opened)"))
    #expect(source.contains("process.executableURL = executable.launchURL"))
    #expect(source.contains("return try await commandRunner(executableURL, arguments, maximumOutputBytes, timeout)"))
    #expect(source.contains("process.executableURL = executableURL") == false)
    #expect(source.contains("Process().run") == false)
    #expect(source.contains("public typealias CommandRunner") == false)
    #expect(source.contains("if error == .untrustedExecutable { throw error }"))
    #expect(source.contains("Unmanaged<CFDictionary>") == false)
}

private func providerSource() throws -> String {
    let testDirectory = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
    let sourceURL = testDirectory
        .deletingLastPathComponent()
        .deletingLastPathComponent()
        .appendingPathComponent("Sources/AgentPassOnboardingUI/OnboardingStatusProvider.swift")
    return try String(contentsOf: sourceURL, encoding: .utf8)
}
