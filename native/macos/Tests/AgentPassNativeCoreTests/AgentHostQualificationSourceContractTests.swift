import Foundation
import Testing

private func agentHostSource() throws -> String {
    let testDirectory = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
    let sourceURL = testDirectory
        .deletingLastPathComponent()
        .deletingLastPathComponent()
        .appendingPathComponent("Sources/AgentPassNativeAgentHost/main.swift")
    return try String(contentsOf: sourceURL, encoding: .utf8)
}

@Test func qualificationActivationUsesTheClosedFD3DocumentContract() throws {
    let source = try agentHostSource()

    #expect(source.contains("static let activationDocumentFD: Int32 = 3"))
    #expect(source.contains("NativeAgentLaunchAuthorityHandoff.maximumDocumentBytes"))
    #expect(source.contains("NativeAgentLaunchAuthorityHandoff.decode(data)"))
    #expect(source.contains("data.resetBytes"))
    #expect(source.contains("buffer.withUnsafeMutableBytes"))
    #expect(source.contains("proof: document.proof"))
    #expect(source.contains("AgentPassAgentSessionRequest("))
    #expect(source.contains("arguments == [\"qualification-activate\"]"))
}

@Test func qualificationActivationUsesTheExistingXPCLifecycleOnOneConnection() throws {
    let source = try agentHostSource()

    #expect(source.contains("let connection = NSXPCConnection(machServiceName: AgentHostContract.machServiceName"))
    #expect(source.contains("proxy.bootstrapAgent(bootstrapRequest, withReply: reply)"))
    #expect(source.contains("proxy.startAgentSession(sessionRequest, withReply: reply)"))
    #expect(source.contains("proxy.closeAgentSession(request, withReply: reply)"))
    #expect(source.contains("signal(SIGTERM, SIG_IGN)"))
    #expect(source.contains("signal(SIGINT, SIG_IGN)"))
    #expect(source.contains("DispatchSource.makeSignalSource(signal: SIGTERM"))
    #expect(source.contains("DispatchSource.makeSignalSource(signal: SIGINT"))
    #expect(source.contains("SecRandomCopyBytes"))
    #expect(source.contains("let signalController = ActivationSignalController()"))
    #expect(source.range(of: "let signalController = ActivationSignalController()")!.lowerBound < source.range(of: "let bootstrapResult = waitForReply")!.lowerBound)
    #expect(source.contains("case .timedOut:"))
    let qualificationSource = String(source[source.range(of: "private func runQualificationActivation()")!.lowerBound...])
    #expect(qualificationSource.components(separatedBy: "proxy.startAgentSession(sessionRequest, withReply: reply)").count - 1 == 2)
    #expect(source.contains("same XPC\n        // connection"))
}

@Test func qualificationActivationPublicOutputDoesNotExposeAuthorityOrPaths() throws {
    let source = try agentHostSource()

    #expect(source.contains("let status: String"))
    #expect(source.contains("let error: String?"))
    #expect(source.contains("bootstrap.challenge") == false)
    #expect(source.contains("bootstrap.bootstrapID") == true)
    #expect(source.contains("document.proof") == true)
    #expect(source.contains("CommandLine.arguments"))
    #expect(source.contains("activationDocumentFD"))
    #expect(source.contains("path:" ) == false)
}

@Test func launchHostInstallsTerminalCleanupForSignalsAndXPCDisconnect() throws {
    let source = try agentHostSource()

    #expect(source.contains("terminalController.install()"))
    #expect(source.contains("serviceClient.connection.invalidationHandler"))
    #expect(source.contains("terminalController.setConnection(serviceClient.connection)"))
    #expect(source.contains("terminalController.markBootstrapKnown()"))
    #expect(source.contains("coordinator.requestTermination()"))
    #expect(source.contains("agent_session_close_failed"))
}
