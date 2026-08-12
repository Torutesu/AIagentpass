import CryptoKit
import Darwin
import Foundation
import Testing
@testable import AgentPassNativeCore

@Suite(.serialized)
struct NativeAuditPruneCoordinatorTests {
    private struct Signer: P256MessageSigner {
        let key = try! P256.Signing.PrivateKey(rawRepresentation: Data(repeating: 0x61, count: 32))
        var publicKeyX963: Data { key.publicKey.x963Representation }
        func sign(message: Data) throws -> Data { try key.signature(for: message).rawRepresentation }
    }

    private final class Trust: NativeAuditPruneTrustSource, @unchecked Sendable {
        private let lock = NSLock()
        private var boundaryValue: NativeAuditRetentionBoundary
        private var stateValue: NativeAuditPruneChainState
        private var revision = 1
        private var reservation: NativeAuditPruneMutationReservation?
        private var pinnedReceiptPosition: NativeAuditPruneExternalReceiptPosition?
        private var destructiveLeaseValidationLimit: Int?
        private var destructiveLeaseValidations = 0
        init(boundary: NativeAuditRetentionBoundary, state: NativeAuditPruneChainState = .init()) {
            boundaryValue = boundary; stateValue = state
        }
        func currentAuditPruneTrustSnapshot() throws -> NativeAuditPruneTrustSnapshot {
            lock.withLock { NativeAuditPruneTrustSnapshot(revision: revision, boundary: boundaryValue, chainState: stateValue, activeReservationID: reservation?.reservationID) }
        }
        func acquireAuditPruneMutationReservation(operationID: String, expected: NativeAuditPruneMutationReservation?) throws -> NativeAuditPruneMutationReservation {
            try lock.withLock {
                if let expected {
                    guard reservation == expected else { throw AgentPassNativeError.invalidSignature("test reservation changed") }
                    return expected
                }
                guard reservation == nil else { throw AgentPassNativeError.invalidSignature("test mutation already reserved") }
                let value = NativeAuditPruneMutationReservation(reservationID: "reservation-\(operationID)", operationID: operationID, snapshotRevision: revision, boundary: boundaryValue, chainState: stateValue)
                reservation = value
                return value
            }
        }
        func validateAuditPruneMutationReservation(_ value: NativeAuditPruneMutationReservation) throws {
            try lock.withLock {
                guard reservation == value, value.snapshotRevision == revision,
                      value.boundary == boundaryValue, value.chainState == stateValue else {
                    throw AgentPassNativeError.invalidSignature("test reservation is stale")
                }
            }
        }
        func completeAuditPruneMutationReservation(_ value: NativeAuditPruneMutationReservation, nextState: NativeAuditPruneChainState) throws {
            try lock.withLock {
                guard reservation == value else { throw AgentPassNativeError.invalidSignature("test completion reservation changed") }
                stateValue = nextState; revision += 1; reservation = nil
            }
        }
        func cancelAuditPruneMutationReservation(_ value: NativeAuditPruneMutationReservation) throws {
            try lock.withLock {
                guard reservation == value else { throw AgentPassNativeError.invalidSignature("test cancellation reservation changed") }
                reservation = nil
            }
        }
        func consumeAuditPruneExternalReceiptObservation(_ observation: NativeAuditPruneExternalReceiptObservation?, purpose: NativeAuditPruneExternalObservationPurpose, operationID: String?) throws -> NativeAuditPruneExternalReceiptPosition? { lock.withLock { pinnedReceiptPosition } }
        func validateConsumedAuditPruneExternalLease(_ observation: NativeAuditPruneExternalReceiptObservation, purpose: NativeAuditPruneExternalObservationPurpose, operationID: String?) throws {
            try lock.withLock {
                destructiveLeaseValidations += 1
                if let limit = destructiveLeaseValidationLimit, destructiveLeaseValidations > limit {
                    throw AgentPassNativeError.invalidSignature("test destructive lease expired")
                }
            }
        }
        func setDestructiveLeaseValidationLimit(_ value: Int?) { lock.withLock { destructiveLeaseValidationLimit = value; destructiveLeaseValidations = 0 } }
        func setPinnedReceiptPosition(_ value: NativeAuditPruneExternalReceiptPosition?) { lock.withLock { pinnedReceiptPosition = value } }
        func setBoundary(_ value: NativeAuditRetentionBoundary) { lock.withLock { boundaryValue = value; revision += 1 } }
        func setState(_ value: NativeAuditPruneChainState) { lock.withLock { stateValue = value; revision += 1 } }
    }

    private enum Injected: Error { case crash, lostResponse }

    private static func executeObservation(operationID: String) -> NativeAuditPruneExternalReceiptObservation {
        let lease = NativeAuditPruneExternalReceiptLease(canonicalData: Data("{}".utf8), leaseID: String(repeating: "L", count: 43), purpose: .execute, operationID: operationID, position: nil, destructiveDeadlineUptimeNanoseconds: .max)
        return .init(observationID: UUID().uuidString, generation: 1, purpose: .execute, operationID: operationID, trustRevision: 0, reservationID: nil, chainSequence: 0, chainReceiptHash: hash("0"), position: nil, externalLease: lease, expiresAtUptimeNanoseconds: .max)
    }

    private final class Transport: NativeAuditPruneTransport, @unchecked Sendable {
        private let lock = NSLock()
        private let anchor: Curve25519.Signing.PrivateKey
        private var loseFirstResponse: Bool
        private var forged: Bool
        private var future: Bool
        private let networkStarted: DispatchSemaphore?
        private let releaseNetwork: DispatchSemaphore?
        private(set) var submissions: [Data] = []
        init(anchor: Curve25519.Signing.PrivateKey, loseFirstResponse: Bool = false, forged: Bool = false, future: Bool = false, networkStarted: DispatchSemaphore? = nil, releaseNetwork: DispatchSemaphore? = nil) {
            self.anchor = anchor; self.loseFirstResponse = loseFirstResponse; self.forged = forged; self.future = future
            self.networkStarted = networkStarted; self.releaseNetwork = releaseNetwork
        }
        func submitAuditPrune(tenant: String, authorizationData: Data) throws -> Data {
            try lock.withLock {
                submissions.append(authorizationData)
                networkStarted?.signal()
                if let releaseNetwork, releaseNetwork.wait(timeout: .now() + 10) != .success { throw Injected.crash }
                let authorization = try NativeAuditPruneAuthorization.decodeCanonical(authorizationData)
                var data = try Self.receipt(authorization, anchor: anchor, receivedAt: future ? "2030-01-01T00:00:00.000Z" : "2027-01-20T00:00:00.000Z")
                if forged {
                    var object = try JSONSerialization.jsonObject(with: data) as! [String: Any]
                    object["previous_anchor_event_hash"] = hash("f")
                    data = try NativeAuditLog.canonical(object)
                }
                if loseFirstResponse { loseFirstResponse = false; throw Injected.lostResponse }
                return data
            }
        }
        func count() -> Int { lock.withLock { submissions.count } }
        func submitted() -> [Data] { lock.withLock { submissions } }

        static func receipt(_ authorization: NativeAuditPruneAuthorization, anchor: Curve25519.Signing.PrivateKey, receivedAt: String) throws -> Data {
            let statement: [String: Any] = [
                "version": 1, "tenant": authorization.tenant, "sequence": authorization.sequence,
                "authorization_hash": authorization.authorizationHash,
                "previous_receipt_hash": authorization.previousPruneReceiptHash,
                "anchor_event_index": authorization.boundary.anchorEventIndex + 1,
                "previous_anchor_event_hash": authorization.boundary.anchorEventHash,
                "received_at": receivedAt
            ]
            let signature = try anchor.signature(for: NativeAuditLog.canonical(statement)).base64EncodedString()
            var signed = statement
            signed["anchor_key_fingerprint"] = anchorFingerprint(anchor)
            signed["signature"] = signature
            signed["receipt_hash"] = NativeAuditLog.hash(try NativeAuditLog.canonical(signed))
            return try NativeAuditLog.canonical(signed)
        }
    }

    private final class CoordinatorFault: @unchecked Sendable {
        private let lock = NSLock()
        private var target: NativeAuditPruneCoordinatorCrashPoint?
        private let onHit: @Sendable () -> Void
        private let shouldThrow: Bool
        init(_ target: NativeAuditPruneCoordinatorCrashPoint?, shouldThrow: Bool = true, onHit: @escaping @Sendable () -> Void = {}) { self.target = target; self.shouldThrow = shouldThrow; self.onHit = onHit }
        func inject(_ point: NativeAuditPruneCoordinatorCrashPoint) throws {
            try lock.withLock {
                if point == target { target = nil; onHit(); if shouldThrow { throw Injected.crash } }
            }
        }
    }

    private final class Clock: @unchecked Sendable {
        private let lock = NSLock(); private var value: Date
        init(_ value: Date) { self.value = value }
        func now() -> Date { lock.withLock { value } }
        func set(_ value: Date) { lock.withLock { self.value = value } }
    }

    private final class ExecutorFault: @unchecked Sendable {
        private let lock = NSLock()
        private var target: NativeAuditPruneExecutionCrashPoint?
        private let shouldThrow: Bool
        private let onHit: @Sendable () -> Void
        init(_ target: NativeAuditPruneExecutionCrashPoint?, shouldThrow: Bool = true, onHit: @escaping @Sendable () -> Void = {}) { self.target = target; self.shouldThrow = shouldThrow; self.onHit = onHit }
        func inject(_ point: NativeAuditPruneExecutionCrashPoint) throws {
            try lock.withLock {
                if point == target { target = nil; onHit(); if shouldThrow { throw Injected.crash } }
            }
        }
    }

    private struct Fixture {
        let root: URL
        let archive: URL
        let journal: URL
        let segment: NativeAuditRetentionSegment
        let retained: NativeAuditRetentionSegment
        let trust: Trust
        let transport: Transport
        let signer: Signer
        let anchor: Curve25519.Signing.PrivateKey

        func coordinator(
            coordinatorFault: CoordinatorFault = CoordinatorFault(nil),
            executorFault: ExecutorFault = ExecutorFault(nil),
            clock: Clock? = nil
        ) throws -> NativeAuditPruneCoordinator {
            try NativeAuditPruneCoordinator(
                tenant: "native-host", archiveDirectory: archive.path,
                journal: NativeAuditPruneJournal(directory: journal.path, tenant: "native-host"),
                verifier: verifier(signer: signer, anchor: anchor), signer: signer,
                transport: transport, trustSource: trust,
                now: { clock?.now() ?? fixedDate }, executorFaultInjector: executorFault.inject,
                faultInjector: coordinatorFault.inject
            )
        }
    }

    private static let fixedDate = date("2027-01-20T00:00:00.000Z")

    private static func fixture(transport: Transport? = nil) throws -> Fixture {
        let root = try temporaryDirectory("agentpass-prune-coordinator")
        let archive = root.appendingPathComponent("archive", isDirectory: true)
        let journal = root.appendingPathComponent("journal", isDirectory: true)
        try protectedDirectory(archive); try protectedDirectory(journal)
        let segment = makeSegment()
        let retained = makeRetained(after: segment)
        try writeArchives(segment, directory: archive)
        try writeArchives(retained, directory: archive)
        let signer = Signer()
        let anchor = try Curve25519.Signing.PrivateKey(rawRepresentation: Data(repeating: 0x72, count: 32))
        return Fixture(root: root, archive: archive, journal: journal, segment: segment, retained: retained, trust: Trust(boundary: boundary), transport: transport ?? Transport(anchor: anchor), signer: signer, anchor: anchor)
    }

    @Test static func happyPathPersistsExactReceiptManifestAndServiceBundle() throws {
        let value = try Self.fixture(); defer { try? FileManager.default.removeItem(at: value.root) }
        let coordinator = try value.coordinator()
        let prepared = try coordinator.prepare(operationID: "prune-1", retentionSeconds: retentionSeconds, segments: [value.segment], expectedNextRetained: value.retained)
        #expect(value.transport.count() == 0)
        #expect(try NativeAuditPruneAuthorization.decodeCanonical(prepared.authorizationData) == prepared.authorization)
        let accepted = try coordinator.submitPending()
        #expect(value.transport.count() == 1)
        let result = try coordinator.executePending()
        #expect(result.accepted.receiptData == accepted.receiptData)
        let canonicalManifest = try result.manifest.canonicalData()
        let canonicalCompletionProof = try result.completionProof.canonicalData()
        #expect(result.manifestData == canonicalManifest)
        #expect(result.completionProofData == canonicalCompletionProof)
        #expect(NativeP256CanonicalSignature.isCanonicalLowS(Data(base64Encoded: prepared.authorization.signature)!))
        #expect(NativeP256CanonicalSignature.isCanonicalLowS(Data(base64Encoded: result.manifest.signature)!))
        #expect(NativeP256CanonicalSignature.isCanonicalLowS(Data(base64Encoded: result.completionProof.signature)!))
        #expect(result.completionProof.executorCompletionHash.wholeMatch(of: /^[0-9a-f]{64}$/) != nil)
        #expect(result.nextState.manifestHash == result.manifest.manifestHash)
        #expect(!result.recovered)
        try expectTargets(value.segment, directory: value.archive, exist: false)
        try expectTargets(value.retained, directory: value.archive, exist: true)
        let object = try #require(JSONSerialization.jsonObject(with: result.deletionEvidenceBundleData) as? [String: Any])
        #expect(Set(object.keys) == Set(["version", "authorization_base64", "anchor_prune_receipt_base64", "post_prune_manifest_base64", "completion_proof_base64", "executor_completion_statement_base64", "executor_quarantined_marker_base64", "executor_manifest_commit_marker_base64", "prior_chain_state", "expected_next_retained", "expected_next_retained_file_identities"]))
        #expect(object["version"] as? Int == 4)
        #expect(Data(base64Encoded: object["authorization_base64"] as! String) == prepared.authorizationData)
        #expect(Data(base64Encoded: object["anchor_prune_receipt_base64"] as! String) == accepted.receiptData)
        #expect(Data(base64Encoded: object["post_prune_manifest_base64"] as! String) == result.manifestData)
        #expect(Data(base64Encoded: object["completion_proof_base64"] as! String) == result.completionProofData)
        #expect(try NativeAuditLog.canonical(object) == result.deletionEvidenceBundleData)
        let status = try coordinator.status()
        #expect(status.completed.count == 1)
        #expect(status.pendingPreparation == nil)
    }

    @Test static func neverEntersDeletionWithoutDurableReceipt() throws {
        let value = try Self.fixture(); defer { try? FileManager.default.removeItem(at: value.root) }
        let coordinator = try value.coordinator()
        _ = try coordinator.prepare(operationID: "prune-no-receipt", retentionSeconds: retentionSeconds, segments: [value.segment], expectedNextRetained: value.retained)
        #expect(throws: AgentPassNativeError.self) { try coordinator.executePending() }
        try expectTargets(value.segment, directory: value.archive, exist: true)
        let executorState = value.archive.appendingPathComponent(".agentpass-prune-transactions", isDirectory: true)
        let entries = try FileManager.default.contentsOfDirectory(atPath: executorState.path)
        #expect(entries.isEmpty)
    }

    @Test static func nullRetainedCapabilityIsRejectedBeforeJournalAndAnchor() throws {
        let value = try Self.fixture(); defer { try? FileManager.default.removeItem(at: value.root) }
        let coordinator = try value.coordinator()
        #expect(throws: AgentPassNativeError.self) {
            try coordinator.prepare(operationID: "prune-null-retained", retentionSeconds: retentionSeconds, segments: [value.segment], expectedNextRetained: nil)
        }
        #expect(value.transport.count() == 0)
        #expect(try coordinator.status().pendingPreparation == nil)
        try expectTargets(value.segment, directory: value.archive, exist: true)
    }

    @Test static func externalModuleCannotCallArbitraryCompletionProofFactory() throws {
        let root = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
        let modules = root.appendingPathComponent(".build/arm64-apple-macosx/debug/Modules", isDirectory: true)
        let temporary = try temporaryDirectory("agentpass-public-api-negative")
        defer { try? FileManager.default.removeItem(at: temporary) }
        let source = temporary.appendingPathComponent("Misuse.swift")
        try Data("""
        import AgentPassNativeCore
        func misuse<S: P256MessageSigner>(_ plan: NativeAuditPrunePlan, _ execution: NativeAuditPruneExecutionResult, _ signer: S) throws {
            _ = try NativeAuditPruneCompletionProof.create(plan: plan, execution: execution, signer: signer)
        }
        """.utf8).write(to: source)
        let process = Process(); let stderr = Pipe()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/xcrun")
        process.arguments = ["swiftc", "-typecheck", "-I", modules.path, source.path]
        process.standardError = stderr
        try process.run(); process.waitUntilExit()
        let diagnostic = String(decoding: stderr.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
        #expect(process.terminationStatus != 0)
        #expect(diagnostic.contains("inaccessible") || diagnostic.contains("internal protection level"))
    }

    @Test static func externalModuleCannotCallPhaseChainOmittingVerifier() throws {
        let root = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
        let modules = root.appendingPathComponent(".build/arm64-apple-macosx/debug/Modules", isDirectory: true)
        let temporary = try temporaryDirectory("agentpass-phase-chain-public-api-negative")
        defer { try? FileManager.default.removeItem(at: temporary) }
        let source = temporary.appendingPathComponent("Misuse.swift")
        try Data("""
        import Foundation
        import AgentPassNativeCore
        func misuse(
            _ verifier: NativeAuditRetentionVerifier,
            _ authorization: Data, _ receipt: Data, _ manifest: Data, _ proof: Data,
            _ completion: Data, _ prior: NativeAuditPruneChainState,
            _ boundary: NativeAuditRetentionBoundary, _ retained: NativeAuditRetentionSegment,
            _ identities: [NativeAuditRetentionFileIdentity]
        ) throws {
            _ = try verifier.verifyCompletedPruneEvidence(
                authorizationData: authorization, receiptData: receipt, manifestData: manifest,
                completionProofData: proof, completionStatementData: completion, prior: prior,
                currentBoundary: boundary, expectedNextRetained: retained,
                expectedNextRetainedFileIdentities: identities
            )
        }
        """.utf8).write(to: source)
        let process = Process(); let stderr = Pipe()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/xcrun")
        process.arguments = ["swiftc", "-typecheck", "-I", modules.path, source.path]
        process.standardError = stderr
        try process.run(); process.waitUntilExit()
        let diagnostic = String(decoding: stderr.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
        #expect(process.terminationStatus != 0)
        #expect(diagnostic.contains("verifyCompletedPruneEvidence"))
        #expect(
            diagnostic.contains("inaccessible") || diagnostic.contains("internal protection level")
                || diagnostic.contains("extra argument") || diagnostic.contains("missing argument")
                || diagnostic.contains("no exact matches")
        )
    }

    @Test static func lostResponseRetriesByteExactAuthorizationAfterRestart() throws {
        let anchor = try Curve25519.Signing.PrivateKey(rawRepresentation: Data(repeating: 0x72, count: 32))
        let transport = Transport(anchor: anchor, loseFirstResponse: true)
        let value = try Self.fixture(transport: transport); defer { try? FileManager.default.removeItem(at: value.root) }
        let first = try value.coordinator()
        let prepared = try first.prepare(operationID: "prune-lost", retentionSeconds: retentionSeconds, segments: [value.segment], expectedNextRetained: value.retained)
        #expect(throws: Injected.self) { try first.submitPending() }
        #expect(try first.status().pendingReceiptData == nil)
        let second = try value.coordinator()
        let accepted = try second.submitPending()
        #expect(transport.count() == 2)
        #expect(transport.submitted() == [prepared.authorizationData, prepared.authorizationData])
        #expect(try second.status().pendingReceiptData == accepted.receiptData)
        try expectTargets(value.segment, directory: value.archive, exist: true)
    }

    @Test static func submitNetworkWaitDoesNotHoldCoordinatorLock() throws {
        let anchor = try Curve25519.Signing.PrivateKey(rawRepresentation: Data(repeating: 0x72, count: 32))
        let started = DispatchSemaphore(value: 0), release = DispatchSemaphore(value: 0)
        let transport = Transport(anchor: anchor, networkStarted: started, releaseNetwork: release)
        let value = try Self.fixture(transport: transport); defer { try? FileManager.default.removeItem(at: value.root) }
        let coordinator = try value.coordinator()
        _ = try coordinator.prepare(operationID: "prune-network-unlock", retentionSeconds: retentionSeconds, segments: [value.segment], expectedNextRetained: value.retained)
        let submitFinished = DispatchSemaphore(value: 0)
        nonisolated(unsafe) var submitError: Error?
        let submitter = Thread {
            do { _ = try coordinator.submitPending() } catch { submitError = error }
            submitFinished.signal()
        }
        submitter.start()
        #expect(started.wait(timeout: .now() + 10) == .success)
        let statusFinished = DispatchSemaphore(value: 0)
        nonisolated(unsafe) var observedPending = false
        let observer = Thread {
            observedPending = (try? coordinator.status().pendingPreparation != nil) == true
            statusFinished.signal()
        }
        observer.start()
        #expect(statusFinished.wait(timeout: .now() + 2) == .success)
        #expect(observedPending)
        release.signal()
        #expect(submitFinished.wait(timeout: .now() + 10) == .success)
        #expect(submitError == nil)
    }

    @Test static func restartWithDurableReceiptNeverContactsAnchorAgain() throws {
        let value = try Self.fixture(); defer { try? FileManager.default.removeItem(at: value.root) }
        let first = try value.coordinator()
        _ = try first.prepare(operationID: "prune-receipt-restart", retentionSeconds: retentionSeconds, segments: [value.segment], expectedNextRetained: value.retained)
        let accepted = try first.submitPending()
        let second = try value.coordinator()
        let restored = try second.submitPending()
        #expect(restored.receiptData == accepted.receiptData)
        #expect(value.transport.count() == 1)
    }

    @Test static func crashAfterExecutorRecoversExactManifestAndBundle() throws {
        let value = try Self.fixture(); defer { try? FileManager.default.removeItem(at: value.root) }
        let fault = CoordinatorFault(.afterExecutorBeforeCompletion)
        let first = try value.coordinator(coordinatorFault: fault)
        _ = try first.prepare(operationID: "prune-post-executor-crash", retentionSeconds: retentionSeconds, segments: [value.segment], expectedNextRetained: value.retained)
        _ = try first.submitPending()
        #expect(throws: Injected.self) { try first.executePending() }
        try expectTargets(value.segment, directory: value.archive, exist: false)
        let crashedStatus = try first.status()
        #expect(crashedStatus.pendingReceiptData != nil)
        #expect(crashedStatus.completed.isEmpty)
        let recovered = try value.coordinator().executePending()
        #expect(recovered.recovered)
        #expect(try NativeAuditPostPruneManifest.decodeCanonical(recovered.manifestData) == recovered.manifest)
        #expect(try NativeAuditPruneCompletionProof.decodeCanonical(recovered.completionProofData) == recovered.completionProof)
        #expect(try value.coordinator().status().completed.first?.deletionEvidenceBundleData == recovered.deletionEvidenceBundleData)
        try expectTargets(value.retained, directory: value.archive, exist: true)
    }

    @Test static func completedBundleVerifiesOfflineAfterTargetsAreGone() throws {
        let value = try Self.fixture(); defer { try? FileManager.default.removeItem(at: value.root) }
        let coordinator = try value.coordinator()
        let prepared = try coordinator.prepare(operationID: "prune-offline", retentionSeconds: retentionSeconds, segments: [value.segment], expectedNextRetained: value.retained)
        _ = try coordinator.submitPending()
        let result = try coordinator.executePending()
        try expectTargets(value.segment, directory: value.archive, exist: false)
        let verified = try verifier(signer: value.signer, anchor: value.anchor).verifyCompletedPruneEvidence(
            authorizationData: prepared.authorizationData,
            receiptData: result.accepted.receiptData,
            manifestData: result.manifestData,
            completionProofData: result.completionProofData,
            completionStatementData: Data(base64Encoded: (try #require(JSONSerialization.jsonObject(with: result.deletionEvidenceBundleData) as? [String: Any]))["executor_completion_statement_base64"] as! String)!,
            quarantinedMarkerData: result.quarantinedMarkerData,
            manifestCommitMarkerData: result.manifestCommitMarkerData,
            prior: prepared.priorState,
            currentBoundary: prepared.boundary,
            expectedNextRetained: prepared.expectedNextRetained,
            expectedNextRetainedFileIdentities: prepared.expectedNextRetainedFileIdentities
        )
        #expect(verified == result.nextState)
        #expect(throws: AgentPassNativeError.self) {
            try verifier(signer: value.signer, anchor: value.anchor).verifyCompletedPruneEvidence(
                authorizationData: prepared.authorizationData, receiptData: result.accepted.receiptData,
                manifestData: result.manifestData, completionProofData: result.completionProofData,
                prior: prepared.priorState, currentBoundary: prepared.boundary,
                expectedNextRetained: prepared.expectedNextRetained
            )
        }
        let retainedIdentities = try #require(prepared.expectedNextRetainedFileIdentities)
        #expect(throws: AgentPassNativeError.self) {
            try verifier(signer: value.signer, anchor: value.anchor).verifyCompletedPruneEvidence(
                authorizationData: prepared.authorizationData, receiptData: result.accepted.receiptData,
                manifestData: result.manifestData, completionProofData: result.completionProofData,
                completionStatementData: result.completionStatementData,
                prior: prepared.priorState, currentBoundary: prepared.boundary,
                expectedNextRetained: prepared.expectedNextRetained,
                expectedNextRetainedFileIdentities: retainedIdentities
            )
        }
    }

    @Test static func productionIsLowSAndEquivalentHighSSignaturesAreRejected() throws {
        let value = try Self.fixture(); defer { try? FileManager.default.removeItem(at: value.root) }
        let coordinator = try value.coordinator()
        let prepared = try coordinator.prepare(operationID: "prune-high-s", retentionSeconds: retentionSeconds, segments: [value.segment], expectedNextRetained: value.retained)
        let highAuthorizationData = try highSDocument(prepared.authorizationData, hashKey: "authorization_hash")
        let highAuthorization = try NativeAuditPruneAuthorization.decodeCanonical(highAuthorizationData)
        let matchingReceipt = try Transport.receipt(highAuthorization, anchor: value.anchor, receivedAt: "2027-01-20T00:00:00.000Z")
        let observations = [try NativeAuditRetentionArchiveObservation.observe(archiveDirectory: value.archive.path, segment: value.segment)]
        #expect(throws: AgentPassNativeError.self) {
            try verifier(signer: value.signer, anchor: value.anchor).persistedExecutablePlan(
                authorizationData: highAuthorizationData, receiptData: matchingReceipt,
                observedArchives: observations, prior: prepared.priorState,
                currentBoundary: prepared.boundary
            )
        }

        _ = try coordinator.submitPending()
        let result = try coordinator.executePending()
        let highManifest = try highSDocument(result.manifestData, hashKey: "manifest_hash")
        #expect(throws: AgentPassNativeError.self) {
            try verifier(signer: value.signer, anchor: value.anchor).verifyCompletedPruneEvidence(
                authorizationData: prepared.authorizationData, receiptData: result.accepted.receiptData,
                manifestData: highManifest, completionProofData: result.completionProofData,
                completionStatementData: result.completionStatementData,
                quarantinedMarkerData: result.quarantinedMarkerData,
                manifestCommitMarkerData: result.manifestCommitMarkerData,
                prior: prepared.priorState, currentBoundary: prepared.boundary,
                expectedNextRetained: prepared.expectedNextRetained,
                expectedNextRetainedFileIdentities: prepared.expectedNextRetainedFileIdentities
            )
        }
        let highProof = try highSDocument(result.completionProofData, hashKey: "proof_hash")
        #expect(throws: AgentPassNativeError.self) {
            try verifier(signer: value.signer, anchor: value.anchor).verifyCompletedPruneEvidence(
                authorizationData: prepared.authorizationData, receiptData: result.accepted.receiptData,
                manifestData: result.manifestData, completionProofData: highProof,
                completionStatementData: result.completionStatementData,
                quarantinedMarkerData: result.quarantinedMarkerData,
                manifestCommitMarkerData: result.manifestCommitMarkerData,
                prior: prepared.priorState, currentBoundary: prepared.boundary,
                expectedNextRetained: prepared.expectedNextRetained,
                expectedNextRetainedFileIdentities: prepared.expectedNextRetainedFileIdentities
            )
        }
    }

    @Test static func durableReceiptPrecedesExecutorAndSurvivesPreExecutorCrash() throws {
        let value = try Self.fixture(); defer { try? FileManager.default.removeItem(at: value.root) }
        let fault = CoordinatorFault(.beforeExecutor)
        let coordinator = try value.coordinator(coordinatorFault: fault)
        _ = try coordinator.prepare(operationID: "prune-before-executor", retentionSeconds: retentionSeconds, segments: [value.segment], expectedNextRetained: value.retained)
        let accepted = try coordinator.submitPending()
        #expect(throws: Injected.self) { try coordinator.executePending() }
        #expect(try coordinator.status().pendingReceiptData == accepted.receiptData)
        try expectTargets(value.segment, directory: value.archive, exist: true)
    }

    @Test(arguments: [
        NativeAuditPruneExecutionCrashPoint.afterIntentSynced,
        .afterFileQuarantined(0), .afterFileQuarantined(1), .afterFileQuarantined(2),
        .afterQuarantineSynced, .afterManifestCommitted,
        .afterFileUnlinked(0), .afterFileUnlinked(1), .afterFileUnlinked(2),
        .afterCompletionSynced
    ]) static func recoversEveryExecutorCrashBoundary(point: NativeAuditPruneExecutionCrashPoint) throws {
        let value = try Self.fixture(); defer { try? FileManager.default.removeItem(at: value.root) }
        let first = try value.coordinator(executorFault: ExecutorFault(point))
        _ = try first.prepare(operationID: "prune-executor-crash", retentionSeconds: retentionSeconds, segments: [value.segment], expectedNextRetained: value.retained)
        _ = try first.submitPending()
        #expect(throws: Injected.self) { try first.executePending() }
        let recovered = try value.coordinator().executePending()
        #expect(recovered.recovered)
        try expectTargets(value.segment, directory: value.archive, exist: false)
        try expectTargets(value.retained, directory: value.archive, exist: true)
    }

    @Test(arguments: [
        NativeAuditPruneExecutionCrashPoint.afterIntentSynced,
        .afterFileQuarantined(0), .afterQuarantineSynced, .afterManifestCommitted,
        .afterFileUnlinked(0), .afterCompletionSynced
    ]) static func durableIntentRecoveryIgnoresWallClockRollback(point: NativeAuditPruneExecutionCrashPoint) throws {
        let value = try Self.fixture(); defer { try? FileManager.default.removeItem(at: value.root) }
        let clock = Clock(fixedDate)
        let first = try value.coordinator(executorFault: ExecutorFault(point), clock: clock)
        _ = try first.prepare(operationID: "prune-clock-recovery", retentionSeconds: retentionSeconds, segments: [value.segment], expectedNextRetained: value.retained)
        _ = try first.submitPending()
        #expect(throws: Injected.self) { try first.executePending() }
        clock.set(date("2020-01-01T00:00:00.000Z"))
        let recovered = try value.coordinator(clock: clock).executePending()
        #expect(recovered.recovered)
        try expectTargets(value.segment, directory: value.archive, exist: false)
        try expectTargets(value.retained, directory: value.archive, exist: true)
    }

    @Test static func reservationMutationBetweenValidationAndIntentFailsBeforeDeletion() throws {
        let value = try Self.fixture(); defer { try? FileManager.default.removeItem(at: value.root) }
        let fault = CoordinatorFault(.beforeExecutor, shouldThrow: false) {
            value.trust.setBoundary(NativeAuditRetentionBoundary(
                lifecycleHeadHash: hash("9"), auditKeyTransitionReceiptHash: boundary.auditKeyTransitionReceiptHash,
                anchorEventIndex: boundary.anchorEventIndex, anchorEventHash: boundary.anchorEventHash,
                checkpointIndex: boundary.checkpointIndex, checkpointHash: boundary.checkpointHash,
                checkpointReceiptHash: boundary.checkpointReceiptHash
            ))
        }
        let coordinator = try value.coordinator(coordinatorFault: fault)
        _ = try coordinator.prepare(operationID: "prune-reservation-race", retentionSeconds: retentionSeconds, segments: [value.segment], expectedNextRetained: value.retained)
        _ = try coordinator.submitPending()
        #expect(throws: AgentPassNativeError.self) { try coordinator.executePending() }
        try expectTargets(value.segment, directory: value.archive, exist: true)
        try expectTargets(value.retained, directory: value.archive, exist: true)
        let executorState = value.archive.appendingPathComponent(".agentpass-prune-transactions", isDirectory: true)
        #expect(try FileManager.default.contentsOfDirectory(atPath: executorState.path).isEmpty)
    }

    @Test static func boundaryDriftFailsBeforeAnchorAndBeforeDeletion() throws {
        let value = try Self.fixture(); defer { try? FileManager.default.removeItem(at: value.root) }
        let coordinator = try value.coordinator()
        _ = try coordinator.prepare(operationID: "prune-boundary-drift", retentionSeconds: retentionSeconds, segments: [value.segment], expectedNextRetained: value.retained)
        value.trust.setBoundary(NativeAuditRetentionBoundary(lifecycleHeadHash: hash("9"), auditKeyTransitionReceiptHash: boundary.auditKeyTransitionReceiptHash, anchorEventIndex: boundary.anchorEventIndex, anchorEventHash: boundary.anchorEventHash, checkpointIndex: boundary.checkpointIndex, checkpointHash: boundary.checkpointHash, checkpointReceiptHash: boundary.checkpointReceiptHash))
        #expect(throws: AgentPassNativeError.self) { try coordinator.submitPending() }
        #expect(value.transport.count() == 0)
        try expectTargets(value.segment, directory: value.archive, exist: true)
    }

    @Test static func priorStateDriftAfterReceiptFailsBeforeDeletion() throws {
        let value = try Self.fixture(); defer { try? FileManager.default.removeItem(at: value.root) }
        let coordinator = try value.coordinator()
        _ = try coordinator.prepare(operationID: "prune-state-drift", retentionSeconds: retentionSeconds, segments: [value.segment], expectedNextRetained: value.retained)
        _ = try coordinator.submitPending()
        value.trust.setState(NativeAuditPruneChainState(sequence: 1, authorizationHash: hash("1"), receiptHash: hash("2"), manifestHash: hash("3"), lastEventIndex: 1, lastCheckpointIndex: 1, lastReceiptIndex: 1, lastEventHash: hash("4"), lastCheckpointHash: hash("5"), lastArchiveReceiptHash: hash("6")))
        #expect(throws: AgentPassNativeError.self) { try coordinator.executePending() }
        try expectTargets(value.segment, directory: value.archive, exist: true)
    }

    @Test static func destructiveLeaseExpiryStopsBeforeNextUnlinkAndRecoversWithFreshLease() throws {
        let value = try Self.fixture(); defer { try? FileManager.default.removeItem(at: value.root) }
        let coordinator = try value.coordinator()
        let operationID = "prune-lease-expiry"
        _ = try coordinator.prepare(operationID: operationID, retentionSeconds: retentionSeconds, segments: [value.segment], expectedNextRetained: value.retained)
        _ = try coordinator.submitPending()
        value.trust.setDestructiveLeaseValidationLimit(1)
        #expect(throws: AgentPassNativeError.self) { try coordinator.executePending(observation: executeObservation(operationID: operationID)) }
        let quarantine = value.archive.appendingPathComponent(".agentpass-prune-transactions/op-\(NativeAuditLog.hash(Data(operationID.utf8)))/quarantine")
        #expect(try FileManager.default.contentsOfDirectory(atPath: quarantine.path).count == 2)
        value.trust.setDestructiveLeaseValidationLimit(nil)
        let recovered = try coordinator.executePending(observation: executeObservation(operationID: operationID))
        #expect(recovered.recovered)
        try expectTargets(value.segment, directory: value.archive, exist: false)
        try expectTargets(value.retained, directory: value.archive, exist: true)
    }

    @Test static func fileSwapAfterReceiptIsRejectedWithoutDeletion() throws {
        let value = try Self.fixture(); defer { try? FileManager.default.removeItem(at: value.root) }
        let coordinator = try value.coordinator()
        _ = try coordinator.prepare(operationID: "prune-swap", retentionSeconds: retentionSeconds, segments: [value.segment], expectedNextRetained: value.retained)
        _ = try coordinator.submitPending()
        let path = value.archive.appendingPathComponent(value.segment.auditArchiveFile)
        try FileManager.default.removeItem(at: path)
        try archiveData("audit", value.segment.segmentID).write(to: path)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: path.path)
        #expect(throws: AgentPassNativeError.self) { try coordinator.executePending() }
        #expect(FileManager.default.fileExists(atPath: path.path))
        #expect(FileManager.default.fileExists(atPath: value.archive.appendingPathComponent(value.segment.checkpointArchiveFile).path))
        try expectTargets(value.retained, directory: value.archive, exist: true)
    }

    @Test static func retainedIdentitySwapAfterReceiptIsRejectedWithoutDeletion() throws {
        let value = try Self.fixture(); defer { try? FileManager.default.removeItem(at: value.root) }
        let coordinator = try value.coordinator()
        _ = try coordinator.prepare(operationID: "prune-retained-swap", retentionSeconds: retentionSeconds, segments: [value.segment], expectedNextRetained: value.retained)
        _ = try coordinator.submitPending()
        let path = value.archive.appendingPathComponent(value.retained.auditArchiveFile)
        try FileManager.default.removeItem(at: path)
        try archiveData("audit", value.retained.segmentID).write(to: path)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: path.path)
        #expect(throws: AgentPassNativeError.self) { try coordinator.executePending() }
        try expectTargets(value.segment, directory: value.archive, exist: true)
        try expectTargets(value.retained, directory: value.archive, exist: true)
    }

    @Test(arguments: [false, true]) static func retainedDeletionOrSameContentReplacementAfterIntentIsRejected(replace: Bool) throws {
        let value = try Self.fixture(); defer { try? FileManager.default.removeItem(at: value.root) }
        let first = try value.coordinator(executorFault: ExecutorFault(.afterIntentSynced))
        _ = try first.prepare(operationID: "prune-retained-after-intent", retentionSeconds: retentionSeconds, segments: [value.segment], expectedNextRetained: value.retained)
        _ = try first.submitPending()
        #expect(throws: Injected.self) { try first.executePending() }
        let retainedPath = value.archive.appendingPathComponent(value.retained.auditArchiveFile)
        try FileManager.default.removeItem(at: retainedPath)
        if replace {
            try archiveData("audit", value.retained.segmentID).write(to: retainedPath)
            try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: retainedPath.path)
        }
        #expect(throws: AgentPassNativeError.self) { try value.coordinator().executePending() }
        try expectTargets(value.segment, directory: value.archive, exist: true)
        #expect(FileManager.default.fileExists(atPath: retainedPath.path) == replace)
        #expect(FileManager.default.fileExists(atPath: value.archive.appendingPathComponent(value.retained.checkpointArchiveFile).path))
        #expect(FileManager.default.fileExists(atPath: value.archive.appendingPathComponent(value.retained.receiptArchiveFile).path))
    }

    @Test static func validatedPreRenameTemporaryIntentIsRemovedAndRetriedAfterRestart() throws {
        let value = try Self.fixture(); defer { try? FileManager.default.removeItem(at: value.root) }
        let first = try value.coordinator(executorFault: ExecutorFault(.beforeIntentRename))
        _ = try first.prepare(operationID: "prune-pre-rename-crash", retentionSeconds: retentionSeconds, segments: [value.segment], expectedNextRetained: value.retained)
        _ = try first.submitPending()
        #expect(throws: Injected.self) { try first.executePending() }
        let state = value.archive.appendingPathComponent(".agentpass-prune-transactions", isDirectory: true)
        let remnants = try FileManager.default.contentsOfDirectory(atPath: state.path)
        #expect(remnants.count == 1)
        #expect(remnants.first?.wholeMatch(of: /^\.tmp-op-[0-9a-f]{64}-[0-9a-f-]{36}$/) != nil)
        try expectTargets(value.segment, directory: value.archive, exist: true)
        let recovered = try value.coordinator().executePending()
        #expect(recovered.recovered == false)
        #expect(!(try FileManager.default.contentsOfDirectory(atPath: state.path)).contains(where: { $0.hasPrefix(".tmp-") }))
        try expectTargets(value.segment, directory: value.archive, exist: false)
        try expectTargets(value.retained, directory: value.archive, exist: true)
    }

    @Test static func completedAtIsCapturedAfterDeleteAndRemainsMonotonicOnRecovery() throws {
        let value = try Self.fixture(); defer { try? FileManager.default.removeItem(at: value.root) }
        let clock = Clock(fixedDate)
        let later = date("2027-01-20T00:02:00.000Z")
        let fault = ExecutorFault(.afterFileUnlinked(0), onHit: { clock.set(later) })
        let first = try value.coordinator(executorFault: fault, clock: clock)
        _ = try first.prepare(operationID: "prune-real-completed-at", retentionSeconds: retentionSeconds, segments: [value.segment], expectedNextRetained: value.retained)
        _ = try first.submitPending()
        #expect(throws: Injected.self) { try first.executePending() }
        let result = try value.coordinator(clock: clock).executePending()
        let statement = try NativeAuditPruneExecutorCompletionStatement.decodeCanonical(result.completionStatementData)
        #expect(statement.intentCreatedAt == result.manifest.intentCreatedAt)
        #expect(statement.completedAt == "2027-01-20T00:02:00.000Z")
        #expect(result.completionProof.completedAt == statement.completedAt)
        #expect(date(statement.completedAt) >= date(statement.intentCreatedAt))
        try expectTargets(value.segment, directory: value.archive, exist: false)
    }

    @Test static func bundleParserRejectsNullRetainedIdentityAndCompletionSubstitution() throws {
        let value = try Self.fixture(); defer { try? FileManager.default.removeItem(at: value.root) }
        let coordinator = try value.coordinator()
        let prepared = try coordinator.prepare(operationID: "prune-bundle-substitution", retentionSeconds: retentionSeconds, segments: [value.segment], expectedNextRetained: value.retained)
        _ = try coordinator.submitPending()
        let result = try coordinator.executePending()
        func verify(_ data: Data) throws {
            try NativeAuditPruneJournal.verifyDeletionBundle(data, preparation: prepared, receiptData: result.accepted.receiptData, manifestData: result.manifestData, completionProofData: result.completionProofData, completionStatementData: result.completionStatementData, quarantinedMarkerData: result.quarantinedMarkerData, manifestCommitMarkerData: result.manifestCommitMarkerData)
        }
        try verify(result.deletionEvidenceBundleData)
        for mutate in [
            { (object: inout [String: Any]) in object["expected_next_retained"] = NSNull() },
            { (object: inout [String: Any]) in var retained = object["expected_next_retained"] as! [String: Any]; retained["segment_id"] = "substituted"; object["expected_next_retained"] = retained },
            { (object: inout [String: Any]) in object["expected_next_retained_file_identities"] = NSNull() },
            { (object: inout [String: Any]) in var identities = object["expected_next_retained_file_identities"] as! [[String: Any]]; identities[0]["inode"] = (identities[0]["inode"] as! Int) + 1; object["expected_next_retained_file_identities"] = identities },
            { (object: inout [String: Any]) in object["executor_completion_statement_base64"] = Data("substituted".utf8).base64EncodedString() },
            { (object: inout [String: Any]) in object["executor_quarantined_marker_base64"] = Data("substituted".utf8).base64EncodedString() },
            { (object: inout [String: Any]) in object["executor_manifest_commit_marker_base64"] = Data("substituted".utf8).base64EncodedString() }
        ] {
            var object = try #require(JSONSerialization.jsonObject(with: result.deletionEvidenceBundleData) as? [String: Any])
            mutate(&object)
            let changed = try NativeAuditLog.canonical(object)
            #expect(throws: AgentPassNativeError.self) { try verify(changed) }
        }
    }

    @Test static func emptyJournalRejectsTrustedChainAheadAndUnknownExecutorOperation() throws {
        do {
            let value = try Self.fixture(); defer { try? FileManager.default.removeItem(at: value.root) }
            value.trust.setState(NativeAuditPruneChainState(sequence: 1, authorizationHash: hash("1"), receiptHash: hash("2"), manifestHash: hash("3"), lastEventIndex: 1, lastCheckpointIndex: 1, lastReceiptIndex: 1, lastEventHash: hash("4"), lastCheckpointHash: hash("5"), lastArchiveReceiptHash: hash("6")))
            #expect(throws: AgentPassNativeError.self) { try value.coordinator().status() }
        }
        do {
            let value = try Self.fixture(); defer { try? FileManager.default.removeItem(at: value.root) }
            _ = try value.coordinator().status()
            let unknown = value.archive.appendingPathComponent(".agentpass-prune-transactions/op-" + hash("a"), isDirectory: true)
            try FileManager.default.createDirectory(at: unknown, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
            try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: unknown.path)
            #expect(throws: AgentPassNativeError.self) { try value.coordinator().status() }
        }
    }

    @Test static func externalNodeReceiptPositionDetectsCoherentLocalRollbackMismatch() throws {
        let value = try Self.fixture(); defer { try? FileManager.default.removeItem(at: value.root) }
        let coordinator = try value.coordinator()
        _ = try coordinator.prepare(operationID: "prune-external-receipt-position", retentionSeconds: retentionSeconds, segments: [value.segment], expectedNextRetained: value.retained)
        let accepted = try coordinator.submitPending()
        value.trust.setPinnedReceiptPosition(.init(sequence: accepted.receipt.sequence, receiptHash: accepted.receipt.receiptHash))
        #expect(try coordinator.status().pendingReceiptData == accepted.receiptData)
        value.trust.setPinnedReceiptPosition(.init(sequence: accepted.receipt.sequence, receiptHash: hash("9")))
        #expect(throws: AgentPassNativeError.self) { try coordinator.status() }
        try expectTargets(value.segment, directory: value.archive, exist: true)
    }

    @Test static func hardlinkedArchiveIsRejectedAtPreparation() throws {
        let value = try Self.fixture(); defer { try? FileManager.default.removeItem(at: value.root) }
        let source = value.archive.appendingPathComponent(value.segment.auditArchiveFile).path
        let alias = value.archive.appendingPathComponent("hardlink-alias.jsonl").path
        #expect(link(source, alias) == 0)
        #expect(throws: AgentPassNativeError.self) {
            try value.coordinator().prepare(operationID: "prune-hardlink", retentionSeconds: retentionSeconds, segments: [value.segment], expectedNextRetained: value.retained)
        }
    }

    @Test static func onePendingOperationAndOperationEquivocationFailClosed() throws {
        let value = try Self.fixture(); defer { try? FileManager.default.removeItem(at: value.root) }
        let coordinator = try value.coordinator()
        let first = try coordinator.prepare(operationID: "prune-pending", retentionSeconds: retentionSeconds, segments: [value.segment], expectedNextRetained: value.retained)
        #expect(throws: AgentPassNativeError.self) {
            try coordinator.prepare(operationID: "prune-other", retentionSeconds: retentionSeconds, segments: [value.segment], expectedNextRetained: value.retained)
        }
        #expect(throws: AgentPassNativeError.self) {
            try coordinator.prepare(operationID: "prune-pending", retentionSeconds: retentionSeconds + 1, segments: [value.segment], expectedNextRetained: value.retained)
        }
        let same = try coordinator.prepare(operationID: "prune-pending", retentionSeconds: retentionSeconds, segments: [value.segment], expectedNextRetained: value.retained)
        #expect(same.authorizationData == first.authorizationData)
    }

    @Test static func completedOperationReplayIsRejected() throws {
        let value = try Self.fixture(); defer { try? FileManager.default.removeItem(at: value.root) }
        let coordinator = try value.coordinator()
        _ = try coordinator.prepare(operationID: "prune-replay", retentionSeconds: retentionSeconds, segments: [value.segment], expectedNextRetained: value.retained)
        _ = try coordinator.submitPending(); _ = try coordinator.executePending()
        #expect(throws: AgentPassNativeError.self) {
            try coordinator.prepare(operationID: "prune-replay", retentionSeconds: retentionSeconds, segments: [value.retained])
        }
    }

    @Test static func forgedAnchorReceiptIsNeverPersisted() throws {
        let anchor = try Curve25519.Signing.PrivateKey(rawRepresentation: Data(repeating: 0x72, count: 32))
        let transport = Transport(anchor: anchor, forged: true)
        let value = try Self.fixture(transport: transport); defer { try? FileManager.default.removeItem(at: value.root) }
        let coordinator = try value.coordinator()
        _ = try coordinator.prepare(operationID: "prune-forged", retentionSeconds: retentionSeconds, segments: [value.segment], expectedNextRetained: value.retained)
        #expect(throws: AgentPassNativeError.self) { try coordinator.submitPending() }
        #expect(try coordinator.status().pendingReceiptData == nil)
        try expectTargets(value.segment, directory: value.archive, exist: true)
    }

    @Test static func futureDatedAnchorReceiptIsNeverPersisted() throws {
        let anchor = try Curve25519.Signing.PrivateKey(rawRepresentation: Data(repeating: 0x72, count: 32))
        let transport = Transport(anchor: anchor, future: true)
        let value = try Self.fixture(transport: transport); defer { try? FileManager.default.removeItem(at: value.root) }
        let coordinator = try value.coordinator()
        _ = try coordinator.prepare(operationID: "prune-future", retentionSeconds: retentionSeconds, segments: [value.segment], expectedNextRetained: value.retained)
        #expect(throws: AgentPassNativeError.self) { try coordinator.submitPending() }
        #expect(try coordinator.status().pendingReceiptData == nil)
    }

    @Test static func journalRepairsOneDurableTailButRejectsTwoRecordRollback() throws {
        let value = try Self.fixture(); defer { try? FileManager.default.removeItem(at: value.root) }
        let coordinator = try value.coordinator()
        let tip = value.journal.appendingPathComponent("tip.json")
        let initialTip = try Data(contentsOf: tip)
        _ = try coordinator.prepare(operationID: "prune-tail", retentionSeconds: retentionSeconds, segments: [value.segment], expectedNextRetained: value.retained)
        try initialTip.write(to: tip)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: tip.path)
        let repaired = try NativeAuditPruneJournal(directory: value.journal.path, tenant: "native-host")
        #expect(try repaired.status().pendingPreparation?.authorization.operationID == "prune-tail")

        _ = try value.coordinator().submitPending()
        try initialTip.write(to: tip)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: tip.path)
        #expect(throws: AgentPassNativeError.self) {
            try NativeAuditPruneJournal(directory: value.journal.path, tenant: "native-host")
        }
    }

    @Test static func journalRejectsTruncationUnknownEntryHardlinkAndModeWidening() throws {
        try assertJournalTamperRejected { fixture in
            let record = try firstRecord(fixture.journal)
            try FileManager.default.removeItem(at: record)
        }
        try assertJournalTamperRejected { fixture in
            try Data("unknown".utf8).write(to: fixture.journal.appendingPathComponent("unknown"))
        }
        try assertJournalTamperRejected { fixture in
            let record = try firstRecord(fixture.journal)
            #expect(link(record.path, fixture.journal.appendingPathComponent("linked-record").path) == 0)
        }
        try assertJournalTamperRejected { fixture in
            let record = try firstRecord(fixture.journal)
            try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: record.path)
        }
    }

    @Test static func journalRejectsSymlinkRootAndUnsafeTemporaryLink() throws {
        let value = try Self.fixture(); defer { try? FileManager.default.removeItem(at: value.root) }
        let linkPath = value.root.appendingPathComponent("journal-link")
        #expect(symlink(value.journal.path, linkPath.path) == 0)
        #expect(throws: AgentPassNativeError.self) { try NativeAuditPruneJournal(directory: linkPath.path, tenant: "native-host") }

        let unsafe = value.journal.appendingPathComponent(".tmp-11111111-1111-1111-1111-111111111111")
        #expect(symlink("tip.json", unsafe.path) == 0)
        #expect(throws: AgentPassNativeError.self) { try NativeAuditPruneJournal(directory: value.journal.path, tenant: "native-host") }
    }

    @Test static func retainedGapAndArchiveSequenceGapAreRejectedBeforeJournal() throws {
        let value = try Self.fixture(); defer { try? FileManager.default.removeItem(at: value.root) }
        let badRetained = makeSegment(id: "bad-retained", event: 102...201, checkpoint: 3...4, previousEvent: value.segment.terminalEventHash, previousCheckpoint: value.segment.terminalCheckpointHash, previousReceipt: value.segment.terminalReceiptHash, terminalEvent: hash("d"), terminalCheckpoint: hash("e"), terminalReceipt: hash("f"))
        #expect(throws: AgentPassNativeError.self) {
            try value.coordinator().prepare(operationID: "prune-retained-gap", retentionSeconds: retentionSeconds, segments: [value.segment], expectedNextRetained: badRetained)
        }
        let gap = makeSegment(id: "gap", event: 102...200, checkpoint: 3...4, previousEvent: value.segment.terminalEventHash, previousCheckpoint: value.segment.terminalCheckpointHash, previousReceipt: value.segment.terminalReceiptHash, terminalEvent: hash("6"), terminalCheckpoint: hash("7"), terminalReceipt: hash("8"))
        try writeArchives(gap, directory: value.archive)
        #expect(throws: AgentPassNativeError.self) {
            try value.coordinator().prepare(operationID: "prune-segment-gap", retentionSeconds: retentionSeconds, segments: [value.segment, gap])
        }
        #expect(try value.coordinator().status().pendingPreparation == nil)
    }

    // MARK: helpers

    private static let retentionSeconds = 7 * 24 * 60 * 60
    private static let signer = Signer()
    private static let boundary = NativeAuditRetentionBoundary(
        lifecycleHeadHash: hash("1"), auditKeyTransitionReceiptHash: hash("2"),
        anchorEventIndex: 20, anchorEventHash: hash("3"), checkpointIndex: 10,
        checkpointHash: hash("4"), checkpointReceiptHash: hash("5")
    )

    private static func hash(_ value: Character) -> String { String(repeating: value, count: 64) }
    private static func archiveData(_ kind: String, _ id: String) -> Data { Data("\(kind):\(id)\n".utf8) }
    /// Produces the mathematically equivalent `(r, n-s)` IEEE-P1363 signature used by
    /// Node interoperability tests, then recomputes the document's signature-inclusive hash.
    private static func highSDocument(_ data: Data, hashKey: String) throws -> Data {
        var object = try #require(JSONSerialization.jsonObject(with: data) as? [String: Any])
        let encoded = try #require(object["signature"] as? String)
        let low = try #require(Data(base64Encoded: encoded))
        #expect(NativeP256CanonicalSignature.isCanonicalLowS(low))
        let order: [UInt8] = [
            0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84,
            0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x51
        ]
        let scalar = [UInt8](low.suffix(32))
        var highScalar = [UInt8](repeating: 0, count: 32)
        var borrow = 0
        for index in stride(from: 31, through: 0, by: -1) {
            var difference = Int(order[index]) - Int(scalar[index]) - borrow
            if difference < 0 { difference += 256; borrow = 1 } else { borrow = 0 }
            highScalar[index] = UInt8(difference)
        }
        let high = Data(low.prefix(32)) + Data(highScalar)
        #expect(!NativeP256CanonicalSignature.isCanonicalLowS(high))
        object["signature"] = high.base64EncodedString()
        object.removeValue(forKey: hashKey)
        object[hashKey] = NativeAuditLog.hash(try NativeAuditLog.canonical(object))
        return try NativeAuditLog.canonical(object)
    }
    private static func date(_ value: String) -> Date {
        let formatter = ISO8601DateFormatter(); formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        return formatter.date(from: value)!
    }
    private static func anchorFingerprint(_ anchor: Curve25519.Signing.PrivateKey) -> String {
        let der = Data([0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00]) + anchor.publicKey.rawRepresentation
        return "SHA256:" + Data(SHA256.hash(data: der)).base64EncodedString().replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "")
    }
    private static func anchorPEM(_ anchor: Curve25519.Signing.PrivateKey) -> String {
        let der = Data([0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00]) + anchor.publicKey.rawRepresentation
        return "-----BEGIN PUBLIC KEY-----\n\(der.base64EncodedString())\n-----END PUBLIC KEY-----\n"
    }
    private static func verifier(signer: Signer, anchor: Curve25519.Signing.PrivateKey) throws -> NativeAuditRetentionVerifier {
        try NativeAuditRetentionVerifier(tenant: "native-host", authorizerPublicKeyX963: signer.publicKeyX963, anchorPublicKeyPEM: anchorPEM(anchor), minimumRetentionSeconds: retentionSeconds)
    }
    private static func makeSegment(
        id: String = "segment-1", event: ClosedRange<Int> = 1...100, checkpoint: ClosedRange<Int> = 1...2,
        previousEvent: String = NativeAuditLog.zeroHash, previousCheckpoint: String = NativeAuditLog.zeroHash,
        previousReceipt: String = NativeAuditLog.zeroHash, terminalEvent: String = hash("a"),
        terminalCheckpoint: String = hash("b"), terminalReceipt: String = hash("c")
    ) -> NativeAuditRetentionSegment {
        NativeAuditRetentionSegment(
            segmentID: id, auditArchiveFile: "audit-\(id).jsonl", auditArchiveSHA256: NativeAuditLog.hash(archiveData("audit", id)),
            firstEventIndex: event.lowerBound, lastEventIndex: event.upperBound, previousEventHash: previousEvent, terminalEventHash: terminalEvent,
            checkpointArchiveFile: "checkpoints-\(id).jsonl", checkpointArchiveSHA256: NativeAuditLog.hash(archiveData("checkpoint", id)),
            firstCheckpointIndex: checkpoint.lowerBound, lastCheckpointIndex: checkpoint.upperBound, previousCheckpointHash: previousCheckpoint, terminalCheckpointHash: terminalCheckpoint,
            receiptArchiveFile: "receipts-\(id).jsonl", receiptArchiveSHA256: NativeAuditLog.hash(archiveData("receipt", id)),
            firstReceiptIndex: checkpoint.lowerBound, lastReceiptIndex: checkpoint.upperBound, previousReceiptHash: previousReceipt, terminalReceiptHash: terminalReceipt,
            anchoredEventIndex: event.upperBound, anchoredEventHash: terminalEvent,
            sealedAt: "2026-12-31T23:00:00.000Z", latestAnchorReceivedAt: "2027-01-01T00:00:00.000Z"
        )
    }
    private static func makeRetained(after segment: NativeAuditRetentionSegment) -> NativeAuditRetentionSegment {
        makeSegment(id: "retained", event: (segment.lastEventIndex + 1)...(segment.lastEventIndex + 100), checkpoint: (segment.lastCheckpointIndex + 1)...(segment.lastCheckpointIndex + 2), previousEvent: segment.terminalEventHash, previousCheckpoint: segment.terminalCheckpointHash, previousReceipt: segment.terminalReceiptHash, terminalEvent: hash("d"), terminalCheckpoint: hash("e"), terminalReceipt: hash("f"))
    }
    private static func temporaryDirectory(_ prefix: String) throws -> URL {
        let candidate = FileManager.default.temporaryDirectory.appendingPathComponent("\(prefix)-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: candidate, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: candidate.path)
        guard let pointer = realpath(candidate.path, nil) else { throw POSIXError(.EIO) }
        defer { free(pointer) }
        return URL(fileURLWithPath: String(cString: pointer), isDirectory: true)
    }
    private static func protectedDirectory(_ url: URL) throws {
        try FileManager.default.createDirectory(at: url, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: url.path)
    }
    private static func writeArchives(_ segment: NativeAuditRetentionSegment, directory: URL) throws {
        for (name, data) in [(segment.auditArchiveFile, archiveData("audit", segment.segmentID)), (segment.checkpointArchiveFile, archiveData("checkpoint", segment.segmentID)), (segment.receiptArchiveFile, archiveData("receipt", segment.segmentID))] {
            let url = directory.appendingPathComponent(name)
            try data.write(to: url, options: .withoutOverwriting)
            try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
        }
    }
    private static func expectTargets(_ segment: NativeAuditRetentionSegment, directory: URL, exist: Bool) throws {
        for name in [segment.auditArchiveFile, segment.checkpointArchiveFile, segment.receiptArchiveFile] {
            #expect(FileManager.default.fileExists(atPath: directory.appendingPathComponent(name).path) == exist)
        }
    }
    private static func firstRecord(_ journal: URL) throws -> URL {
        try #require(FileManager.default.contentsOfDirectory(at: journal, includingPropertiesForKeys: nil).first(where: { $0.lastPathComponent.hasSuffix("-prepared.json") }))
    }
    private static func assertJournalTamperRejected(_ mutation: (Fixture) throws -> Void) throws {
        let value = try fixture(); defer { try? FileManager.default.removeItem(at: value.root) }
        _ = try value.coordinator().prepare(operationID: "prune-tamper", retentionSeconds: retentionSeconds, segments: [value.segment], expectedNextRetained: value.retained)
        try mutation(value)
        #expect(throws: AgentPassNativeError.self) {
            try NativeAuditPruneJournal(directory: value.journal.path, tenant: "native-host")
        }
    }
}
