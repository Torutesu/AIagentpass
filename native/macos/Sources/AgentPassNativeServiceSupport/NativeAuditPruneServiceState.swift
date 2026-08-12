import AgentPassNativeCore
import CryptoKit
import Darwin
import Foundation

/// An external monotonic pin must reject rollback and provide compare-and-swap semantics.
/// It is intentionally abstract so production can bind the WAL head to hardware, a remote
/// append-only service, or another independently administered monotonic store.
public protocol NativeAuditPruneWALHeadPin: Sendable {
    func currentAuditPruneTrustHead() throws -> String?
    func advanceAuditPruneTrustHead(expected: String?, newHead: String) throws
}

/// Independently administered view of the Node prune-receipt chain head. Providers must
/// authenticate the returned receipt before exposing its sequence/hash position.
public protocol NativeAuditPruneExternalReceiptPositionProvider: Sendable {
    func readAuditPruneReceiptHead() throws -> NativeAuditPruneExternalReceiptHead
    func acquireAuditPruneReceiptLease(purpose: NativeAuditPruneExternalObservationPurpose, operationID: String, expected: NativeAuditPruneExternalReceiptPosition?) throws -> NativeAuditPruneExternalReceiptLease
    func releaseAuditPruneReceiptLease(_ lease: NativeAuditPruneExternalReceiptLease) throws
}

/// Root-private append-only state for the audit-prune mutation domain. The immutable
/// record chain and separately fsync'd tip detect local truncation while newer records
/// survive. `walHeadPin` protects this WAL only; it is never reported to Core as a
/// Node receipt-chain position.
public final class NativeAuditPruneServiceTrustSource: NativeAuditPruneTrustSource, @unchecked Sendable {
    private let rootPath: String
    private let rootFD: Int32
    private let rootDevice: dev_t
    private let rootInode: ino_t
    private let tenant: String
    private let walHeadPin: (any NativeAuditPruneWALHeadPin)?
    private let externalReceiptObservationRequired: Bool
    private let observationClock: @Sendable () -> UInt64
    private var observationGeneration = 0
    private var pendingObservations: [String: NativeAuditPruneExternalReceiptObservation] = [:]
    private var consumedObservations: [String: NativeAuditPruneExternalReceiptObservation] = [:]
    private let lock = NSLock()

    public init(rootPath: String, tenant: String, initialBoundary: NativeAuditRetentionBoundary, walHeadPin: (any NativeAuditPruneWALHeadPin)? = nil, externalReceiptObservationRequired: Bool = false, observationClock: @escaping @Sendable () -> UInt64 = { DispatchTime.now().uptimeNanoseconds }) throws {
        guard rootPath.hasPrefix("/"), Self.slug(tenant),
              URL(fileURLWithPath: rootPath).standardizedFileURL.resolvingSymlinksInPath().path == rootPath else {
            throw AgentPassNativeError.invalidConfiguration("Audit prune trust path or tenant is invalid")
        }
        let fd = open(rootPath, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard fd >= 0 else { throw Self.posixError() }
        var info = stat()
        guard fstat(fd, &info) == 0, (info.st_mode & S_IFMT) == S_IFDIR,
              info.st_uid == geteuid(), info.st_mode & 0o777 == 0o700 else {
            close(fd)
            throw AgentPassNativeError.invalidConfiguration("Audit prune trust directory must be service-owned mode 0700")
        }
        self.rootPath = rootPath; rootFD = fd; rootDevice = info.st_dev; rootInode = info.st_ino
        self.tenant = tenant; self.walHeadPin = walHeadPin
        self.externalReceiptObservationRequired = externalReceiptObservationRequired
        self.observationClock = observationClock
        do {
            try cleanSafeTemporaryEntries()
            let records = try readRecords()
            if records.isEmpty {
                _ = try append(boundary: initialBoundary, chain: NativeAuditPruneChainState(), reservation: nil, previous: nil)
            } else {
                let latest = try verifiedLatest(records: records)
                guard !Self.boundaryRegresses(initialBoundary, from: latest.boundary) else {
                    throw AgentPassNativeError.invalidSignature("Observed audit boundary regressed behind durable prune trust")
                }
                if latest.reservationID != nil {
                    guard latest.boundary == initialBoundary else {
                        throw AgentPassNativeError.invalidSignature("Audit prune reservation boundary changed while the service was offline")
                    }
                } else if latest.boundary != initialBoundary {
                    _ = try append(boundary: initialBoundary, chain: latest.chain, reservation: nil, previous: latest)
                }
            }
        } catch { close(fd); throw error }
    }

    deinit { close(rootFD) }

    public var externalReceiptPositionProviderConfigured: Bool { externalReceiptObservationRequired }

    /// Compatibility helper for deterministic unit fixtures. Read-only observations deliberately
    /// discard the supplied fixture lease so production status paths can never hold a Node lease.
    public func issueAuditPruneExternalReceiptObservation(
        lease: NativeAuditPruneExternalReceiptLease,
        purpose: NativeAuditPruneExternalObservationPurpose,
        operationID: String? = nil
    ) throws -> NativeAuditPruneExternalReceiptObservation {
        try issueAuditPruneExternalReceiptObservation(
            position: lease.position, lease: purpose == .status ? nil : lease,
            purpose: purpose, operationID: operationID
        )
    }

    public func issueAuditPruneExternalReceiptObservation(
        position: NativeAuditPruneExternalReceiptPosition?,
        lease: NativeAuditPruneExternalReceiptLease? = nil,
        purpose: NativeAuditPruneExternalObservationPurpose,
        operationID: String? = nil
    ) throws -> NativeAuditPruneExternalReceiptObservation {
        try withLock {
            guard externalReceiptObservationRequired else {
                throw AgentPassNativeError.invalidConfiguration("External audit prune receipt observations are not configured")
            }
            let now = observationClock()
            pendingObservations = pendingObservations.filter { $0.value.expiresAtUptimeNanoseconds >= now }
            guard pendingObservations.count < 32 else {
                throw AgentPassNativeError.invalidConfiguration("Too many pending audit prune receipt observations")
            }
            let latest = try verifiedLatest(records: readRecords())
            let leaseRequired = purpose != .status
            guard leaseRequired == (lease != nil) else {
                throw AgentPassNativeError.invalidSignature("External audit prune lease presence does not match operation mutability")
            }
            if let lease {
                guard lease.purpose == purpose, lease.operationID == (operationID ?? latest.operationID),
                      lease.position == position, now < lease.destructiveDeadlineUptimeNanoseconds else {
                    throw AgentPassNativeError.invalidSignature("External audit prune lease binding or expiry is invalid")
                }
            }
            try validateExternalPosition(position, against: latest)
            let boundOperationID = operationID ?? latest.operationID
            if let operationID, let durableOperationID = latest.operationID, operationID != durableOperationID {
                throw AgentPassNativeError.invalidSignature("External audit prune observation operation changed")
            }
            let (localExpires, overflow) = now.addingReportingOverflow(5_000_000_000)
            guard !overflow else { throw AgentPassNativeError.invalidConfiguration("Audit prune observation clock overflow") }
            let expires = min(localExpires, lease?.destructiveDeadlineUptimeNanoseconds ?? localExpires)
            observationGeneration += 1
            let observation = NativeAuditPruneExternalReceiptObservation(
                observationID: UUID().uuidString.lowercased(), generation: observationGeneration,
                purpose: purpose, operationID: boundOperationID, trustRevision: latest.revision,
                reservationID: latest.reservationID, chainSequence: latest.chain.sequence,
                chainReceiptHash: latest.chain.receiptHash, position: position, externalLease: lease,
                expiresAtUptimeNanoseconds: expires
            )
            pendingObservations[observation.observationID] = observation
            return observation
        }
    }

    public func consumeAuditPruneExternalReceiptObservation(_ observation: NativeAuditPruneExternalReceiptObservation?, purpose: NativeAuditPruneExternalObservationPurpose, operationID: String?) throws -> NativeAuditPruneExternalReceiptPosition? {
        try withLock {
            guard externalReceiptObservationRequired else {
                guard observation == nil else { throw AgentPassNativeError.invalidSignature("Unexpected external audit prune observation") }
                return nil
            }
            guard let observation, let issued = pendingObservations.removeValue(forKey: observation.observationID), issued == observation else {
                throw AgentPassNativeError.invalidSignature("Audit prune receipt observation is missing, replayed, or substituted")
            }
            let now = observationClock()
            guard now <= observation.expiresAtUptimeNanoseconds,
                  observation.purpose == purpose, observation.operationID == operationID else {
                throw AgentPassNativeError.invalidSignature("Audit prune receipt observation is expired or incorrectly bound")
            }
            let latest = try verifiedLatest(records: readRecords())
            guard observation.trustRevision == latest.revision,
                  observation.reservationID == latest.reservationID,
                  observation.chainSequence == latest.chain.sequence,
                  observation.chainReceiptHash == latest.chain.receiptHash,
                  observation.operationID == (operationID ?? latest.operationID) else {
                throw AgentPassNativeError.invalidSignature("Audit prune receipt observation local generation is stale")
            }
            try validateExternalPosition(observation.position, against: latest)
            if purpose == .status {
                guard observation.externalLease == nil else { throw AgentPassNativeError.invalidSignature("Read-only audit prune observation unexpectedly contains a lease") }
            } else {
                guard let lease = observation.externalLease, lease.purpose == purpose,
                      lease.operationID == operationID, now < lease.destructiveDeadlineUptimeNanoseconds else {
                    throw AgentPassNativeError.invalidSignature("Audit prune external lease is missing, expired, or substituted")
                }
            }
            consumedObservations[observation.observationID] = observation
            return observation.position
        }
    }

    public func validateConsumedAuditPruneExternalLease(_ observation: NativeAuditPruneExternalReceiptObservation, purpose: NativeAuditPruneExternalObservationPurpose, operationID: String?) throws {
        try withLock {
            guard let consumed = consumedObservations[observation.observationID], consumed == observation,
                  observation.purpose == purpose, observation.operationID == operationID,
                  let lease = observation.externalLease, lease.purpose == purpose,
                  lease.operationID == operationID, observationClock() < lease.destructiveDeadlineUptimeNanoseconds else {
                throw AgentPassNativeError.invalidSignature("Audit prune destructive lease is expired, replayed, or incorrectly bound")
            }
            let latest = try verifiedLatest(records: readRecords())
            guard observation.trustRevision == latest.revision,
                  observation.reservationID == latest.reservationID,
                  observation.chainSequence == latest.chain.sequence,
                  observation.chainReceiptHash == latest.chain.receiptHash else {
                throw AgentPassNativeError.invalidSignature("Audit prune destructive lease local generation changed")
            }
        }
    }

    public func finishAuditPruneExternalReceiptObservation(_ observation: NativeAuditPruneExternalReceiptObservation) throws {
        try withLock {
            guard consumedObservations.removeValue(forKey: observation.observationID) == observation else {
                throw AgentPassNativeError.invalidSignature("Audit prune external observation was not consumed exactly once")
            }
        }
    }

    public func discardAuditPruneExternalReceiptObservation(_ observation: NativeAuditPruneExternalReceiptObservation) {
        try? withLock {
            pendingObservations.removeValue(forKey: observation.observationID)
            consumedObservations.removeValue(forKey: observation.observationID)
        }
    }

    public func currentAuditPruneOperationID() throws -> String? {
        try withLock { try verifiedLatest(records: readRecords()).operationID }
    }

    private func validateExternalPosition(_ value: NativeAuditPruneExternalReceiptPosition?, against latest: Record) throws {
        guard let value else {
            guard latest.chain.sequence == 0 else {
                throw AgentPassNativeError.invalidSignature("External audit prune receipt chain is empty behind durable local state")
            }
            return
        }
        guard value.sequence > 0, value.sequence <= 9_007_199_254_740_991,
              value.receiptHash.wholeMatch(of: /^[0-9a-f]{64}$/) != nil else {
            throw AgentPassNativeError.invalidSignature("External audit prune receipt position is malformed")
        }
        let matchesCompleted = value.sequence == latest.chain.sequence && value.receiptHash == latest.chain.receiptHash
        let matchesSubmittedReservation = latest.reservationID != nil && value.sequence == latest.chain.sequence + 1
        guard matchesCompleted || matchesSubmittedReservation else {
            throw AgentPassNativeError.invalidSignature("External audit prune receipt position is ahead of or behind durable local trust")
        }
    }

    /// Export this value to an independently monotonic pin when direct pin integration is
    /// unavailable. Merely logging it does not itself prevent coherent rollback.
    public func currentTrustHeadHash() throws -> String {
        try withLock { try verifiedLatest(records: readRecords()).recordHash }
    }

    public func refreshVerifiedBoundary(_ boundary: NativeAuditRetentionBoundary) throws {
        try withLock {
            let latest = try verifiedLatest(records: readRecords())
            guard latest.reservationID == nil else {
                guard latest.boundary == boundary else { throw AgentPassNativeError.invalidSignature("Audit prune reservation freezes the verified boundary") }
                return
            }
            guard !Self.boundaryRegresses(boundary, from: latest.boundary) else {
                throw AgentPassNativeError.invalidSignature("Verified audit boundary regressed")
            }
            if latest.boundary != boundary { _ = try append(boundary: boundary, chain: latest.chain, reservation: nil, previous: latest) }
        }
    }

    public func currentAuditPruneTrustSnapshot() throws -> NativeAuditPruneTrustSnapshot {
        try withLock { try snapshot(verifiedLatest(records: readRecords())) }
    }

    public func acquireAuditPruneMutationReservation(operationID: String, expected: NativeAuditPruneMutationReservation?) throws -> NativeAuditPruneMutationReservation {
        try withLock {
            guard Self.slug(operationID) else { throw AgentPassNativeError.invalidConfiguration("Audit prune operation ID is invalid") }
            let latest = try verifiedLatest(records: readRecords())
            if let reservationID = latest.reservationID, let reservedOperationID = latest.operationID {
                let existing = reservation(latest, reservationID: reservationID, operationID: reservedOperationID)
                guard existing.operationID == operationID, expected == existing else {
                    throw AgentPassNativeError.invalidSignature("Audit prune mutation domain is already reserved")
                }
                return existing
            }
            guard expected == nil else { throw AgentPassNativeError.invalidSignature("Expected audit prune reservation is missing") }
            let id = UUID().uuidString.lowercased()
            let next = try append(boundary: latest.boundary, chain: latest.chain, reservation: (id, operationID), previous: latest)
            return reservation(next, reservationID: id, operationID: operationID)
        }
    }

    public func validateAuditPruneMutationReservation(_ reservation: NativeAuditPruneMutationReservation) throws {
        try withLock {
            let latest = try verifiedLatest(records: readRecords())
            guard latest.reservationID == reservation.reservationID,
                  latest.operationID == reservation.operationID,
                  reservation.snapshotRevision == latest.reservationSnapshotRevision,
                  reservation.boundary == latest.boundary, reservation.chainState == latest.chain else {
                throw AgentPassNativeError.invalidSignature("Audit prune mutation reservation is stale or substituted")
            }
        }
    }

    public func completeAuditPruneMutationReservation(_ reservation: NativeAuditPruneMutationReservation, nextState: NativeAuditPruneChainState) throws {
        try withLock {
            let latest = try verifiedLatest(records: readRecords())
            if latest.reservationID == nil, latest.chain == nextState { return }
            try require(reservation, latest)
            guard nextState.sequence == latest.chain.sequence + 1 else { throw AgentPassNativeError.invalidSignature("Audit prune chain advance is not contiguous") }
            _ = try append(boundary: latest.boundary, chain: nextState, reservation: nil, previous: latest)
        }
    }

    public func cancelAuditPruneMutationReservation(_ reservation: NativeAuditPruneMutationReservation) throws {
        try withLock {
            let latest = try verifiedLatest(records: readRecords())
            if latest.reservationID == nil { return }
            try require(reservation, latest)
            _ = try append(boundary: latest.boundary, chain: latest.chain, reservation: nil, previous: latest)
        }
    }

    private struct Record {
        let revision: Int; let boundary: NativeAuditRetentionBoundary; let chain: NativeAuditPruneChainState
        let reservationID: String?; let operationID: String?; let reservationSnapshotRevision: Int?
        let previousHash: String; let recordHash: String
    }

    private func snapshot(_ record: Record) -> NativeAuditPruneTrustSnapshot {
        NativeAuditPruneTrustSnapshot(revision: record.revision, boundary: record.boundary, chainState: record.chain, activeReservationID: record.reservationID)
    }
    private func reservation(_ record: Record, reservationID: String, operationID: String) -> NativeAuditPruneMutationReservation {
        NativeAuditPruneMutationReservation(reservationID: reservationID, operationID: operationID,
            snapshotRevision: record.reservationSnapshotRevision!, boundary: record.boundary, chainState: record.chain)
    }
    private func require(_ reservation: NativeAuditPruneMutationReservation, _ record: Record) throws {
        guard record.reservationID == reservation.reservationID, record.operationID == reservation.operationID,
              record.reservationSnapshotRevision == reservation.snapshotRevision,
              record.boundary == reservation.boundary, record.chain == reservation.chainState else {
            throw AgentPassNativeError.invalidSignature("Audit prune mutation reservation is stale or substituted")
        }
    }

    private func append(boundary: NativeAuditRetentionBoundary, chain: NativeAuditPruneChainState, reservation: (String, String)?, previous: Record?) throws -> Record {
        let revision = (previous?.revision ?? -1) + 1
        let snapshotRevision = reservation == nil ? nil : previous!.revision
        var object = Self.object(revision: revision, tenant: tenant, boundary: boundary, chain: chain,
            reservationID: reservation?.0, operationID: reservation?.1, reservationSnapshotRevision: snapshotRevision,
            previousHash: previous?.recordHash ?? NativeAuditLog.zeroHash)
        let hash = Self.hash(try Self.canonical(object)); object["record_hash"] = hash
        let data = try Self.canonical(object)
        let name = String(format: "record-%020d.json", revision)
        try writeImmutable(name: name, data: data)
        if let walHeadPin {
            do { try walHeadPin.advanceAuditPruneTrustHead(expected: previous?.recordHash, newHead: hash) }
            catch {
                let observed = try walHeadPin.currentAuditPruneTrustHead()
                guard observed == hash else {
                    if observed == previous?.recordHash || (observed == nil && previous == nil) {
                        guard unlinkat(rootFD, name, 0) == 0, fsync(rootFD) == 0 else { throw Self.posixError() }
                    }
                    throw error
                }
            }
            guard try walHeadPin.currentAuditPruneTrustHead() == hash else {
                throw AgentPassNativeError.invalidSignature("Audit prune external pin did not durably advance")
            }
        }
        try replaceTip(revision: revision, recordHash: hash)
        return try Self.decode(data, expectedTenant: tenant)
    }

    private func verifiedLatest(records: [Record]) throws -> Record {
        guard let last = records.last else { throw AgentPassNativeError.invalidSignature("Audit prune trust state is empty") }
        let tip = try readTipIfPresent()
        if let walHeadPin {
            let pinned = try walHeadPin.currentAuditPruneTrustHead()
            if pinned == nil, last.revision == 0, tip == nil {
                try walHeadPin.advanceAuditPruneTrustHead(expected: nil, newHead: last.recordHash)
                try replaceTip(revision: last.revision, recordHash: last.recordHash)
                return last
            }
            if pinned == records.dropLast().last?.recordHash,
               tip?.0 == last.revision - 1, tip?.1 == pinned {
                let name = String(format: "record-%020d.json", last.revision)
                guard unlinkat(rootFD, name, 0) == 0, fsync(rootFD) == 0, let previous = records.dropLast().last else {
                    throw AgentPassNativeError.invalidSignature("Audit prune unpinned crash tail could not be discarded")
                }
                return previous
            }
            guard pinned == last.recordHash else { throw AgentPassNativeError.invalidSignature("Audit prune trust WAL disagrees with its external monotonic pin") }
            let recoverableMissingInitialTip = last.revision == 0 && tip == nil
            let recoverableOneAhead = tip?.0 == last.revision - 1 && records.dropLast().last?.recordHash == tip?.1
            if recoverableMissingInitialTip || recoverableOneAhead {
                try replaceTip(revision: last.revision, recordHash: last.recordHash)
                return last
            }
        }
        guard tip?.0 == last.revision, tip?.1 == last.recordHash else {
            throw AgentPassNativeError.invalidSignature("Audit prune trust tip rollback or incomplete update detected")
        }
        return last
    }

    private func readRecords() throws -> [Record] {
        try validateRootIdentity()
        try cleanSafeTemporaryEntries()
        let names = try descriptorEntryNames()
        let records = names.filter { $0.wholeMatch(of: /^record-[0-9]{20}\.json$/) != nil }.sorted()
        let allowed = Set(records + (names.contains("tip.json") ? ["tip.json"] : []))
        guard Set(names) == allowed else { throw AgentPassNativeError.invalidSignature("Audit prune trust directory contains an unknown entry") }
        var values: [Record] = []
        for (index, name) in records.enumerated() {
            guard name == String(format: "record-%020d.json", index) else { throw AgentPassNativeError.invalidSignature("Audit prune trust record sequence has a gap") }
            let data = try readPrivate(name: name, maximum: 128 * 1024)
            let value = try Self.decode(data, expectedTenant: tenant)
            guard value.revision == index, value.previousHash == (values.last?.recordHash ?? NativeAuditLog.zeroHash) else {
                throw AgentPassNativeError.invalidSignature("Audit prune trust hash chain is invalid")
            }
            values.append(value)
        }
        return values
    }

    private func readTipIfPresent() throws -> (Int, String)? {
        var info = stat()
        if fstatat(rootFD, "tip.json", &info, AT_SYMLINK_NOFOLLOW) != 0 {
            if errno == ENOENT { return nil }
            throw Self.posixError()
        }
        let data = try readPrivate(name: "tip.json", maximum: 4096)
        guard let object = try JSONSerialization.jsonObject(with: data) as? [String: Any], Set(object.keys) == ["version","tenant","revision","record_hash"],
              try Self.canonical(object) == data, Self.exactInt(object["version"]) == 1, object["tenant"] as? String == tenant,
              let revision = Self.exactInt(object["revision"]), let hash = object["record_hash"] as? String else {
            throw AgentPassNativeError.invalidSignature("Audit prune trust tip is invalid")
        }
        return (revision, hash)
    }

    private func writeImmutable(name: String, data: Data) throws {
        let fd = openat(rootFD, name, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o400)
        guard fd >= 0 else { throw Self.posixError() }
        do { try Self.writeAll(fd, data); guard fsync(fd) == 0, close(fd) == 0, fsync(rootFD) == 0 else { throw Self.posixError() } }
        catch { close(fd); unlinkat(rootFD, name, 0); throw error }
    }

    private func replaceTip(revision: Int, recordHash: String) throws {
        let data = try Self.canonical(["version":1,"tenant":tenant,"revision":revision,"record_hash":recordHash])
        let temp = ".tip-\(UUID().uuidString.lowercased())"
        let fd = openat(rootFD, temp, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
        guard fd >= 0 else { throw Self.posixError() }
        do {
            try Self.writeAll(fd, data); guard fsync(fd) == 0, close(fd) == 0 else { throw Self.posixError() }
            guard renameat(rootFD, temp, rootFD, "tip.json") == 0, fsync(rootFD) == 0 else { throw Self.posixError() }
        } catch { close(fd); unlinkat(rootFD, temp, 0); throw error }
    }

    private func readPrivate(name: String, maximum: Int) throws -> Data {
        try validateRootIdentity()
        let fd = openat(rootFD, name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC); guard fd >= 0 else { throw Self.posixError() }
        defer { close(fd) }; var info = stat()
        guard fstat(fd, &info) == 0, (info.st_mode & S_IFMT) == S_IFREG, info.st_uid == geteuid(), info.st_mode & 0o077 == 0,
              info.st_nlink == 1, info.st_size > 0, info.st_size <= maximum else { throw AgentPassNativeError.invalidSignature("Audit prune trust file is unsafe") }
        var data = Data(count: Int(info.st_size)); let count = data.withUnsafeMutableBytes { Darwin.read(fd, $0.baseAddress, $0.count) }
        guard count == data.count else { throw Self.posixError() }; return data
    }

    private static func object(revision: Int, tenant: String, boundary: NativeAuditRetentionBoundary, chain: NativeAuditPruneChainState, reservationID: String?, operationID: String?, reservationSnapshotRevision: Int?, previousHash: String) -> [String: Any] {
        ["version":1,"tenant":tenant,"revision":revision,"boundary":boundaryObject(boundary),"chain_state":chainObject(chain),
         "reservation_id":reservationID ?? NSNull(),"operation_id":operationID ?? NSNull(),"reservation_snapshot_revision":reservationSnapshotRevision ?? NSNull(),"previous_record_hash":previousHash]
    }
    private static func decode(_ data: Data, expectedTenant: String) throws -> Record {
        guard let object = try JSONSerialization.jsonObject(with: data) as? [String: Any], try canonical(object) == data,
              Set(object.keys) == ["version","tenant","revision","boundary","chain_state","reservation_id","operation_id","reservation_snapshot_revision","previous_record_hash","record_hash"],
              exactInt(object["version"]) == 1, object["tenant"] as? String == expectedTenant,
              let revision = exactInt(object["revision"]), revision >= 0, let boundaryObject = object["boundary"] as? [String:Any],
              let chainObject = object["chain_state"] as? [String:Any], let previous = object["previous_record_hash"] as? String,
              let hash = object["record_hash"] as? String else { throw AgentPassNativeError.invalidSignature("Audit prune trust record is invalid") }
        var unsigned = object; unsigned.removeValue(forKey: "record_hash")
        guard hash == self.hash(try canonical(unsigned)) else { throw AgentPassNativeError.invalidSignature("Audit prune trust record hash is invalid") }
        let reservationID = object["reservation_id"] as? String; let operationID = object["operation_id"] as? String
        let snapshotRevision = exactInt(object["reservation_snapshot_revision"])
        guard (reservationID == nil) == (operationID == nil), (reservationID == nil) == (snapshotRevision == nil) else { throw AgentPassNativeError.invalidSignature("Audit prune trust reservation is incomplete") }
        return Record(revision: revision, boundary: try boundary(boundaryObject), chain: try chain(chainObject), reservationID: reservationID, operationID: operationID, reservationSnapshotRevision: snapshotRevision, previousHash: previous, recordHash: hash)
    }
    private static func boundaryObject(_ v: NativeAuditRetentionBoundary) -> [String:Any] { ["lifecycle_head_hash":v.lifecycleHeadHash,"audit_key_transition_receipt_hash":v.auditKeyTransitionReceiptHash,"anchor_event_index":v.anchorEventIndex,"anchor_event_hash":v.anchorEventHash,"checkpoint_index":v.checkpointIndex,"checkpoint_hash":v.checkpointHash,"checkpoint_receipt_hash":v.checkpointReceiptHash] }
    private static func boundary(_ o:[String:Any]) throws -> NativeAuditRetentionBoundary { guard Set(o.keys)==["lifecycle_head_hash","audit_key_transition_receipt_hash","anchor_event_index","anchor_event_hash","checkpoint_index","checkpoint_hash","checkpoint_receipt_hash"], let l=o["lifecycle_head_hash"] as? String, let t=o["audit_key_transition_receipt_hash"] as? String, let ei=exactInt(o["anchor_event_index"]), let eh=o["anchor_event_hash"] as? String, let ci=exactInt(o["checkpoint_index"]), let ch=o["checkpoint_hash"] as? String, let cr=o["checkpoint_receipt_hash"] as? String else { throw AgentPassNativeError.invalidSignature("Audit prune trust boundary is invalid") }; return .init(lifecycleHeadHash:l,auditKeyTransitionReceiptHash:t,anchorEventIndex:ei,anchorEventHash:eh,checkpointIndex:ci,checkpointHash:ch,checkpointReceiptHash:cr) }
    private static func chainObject(_ v: NativeAuditPruneChainState)->[String:Any] { ["sequence":v.sequence,"authorization_hash":v.authorizationHash,"receipt_hash":v.receiptHash,"manifest_hash":v.manifestHash,"last_event_index":v.lastEventIndex,"last_checkpoint_index":v.lastCheckpointIndex,"last_receipt_index":v.lastReceiptIndex,"last_event_hash":v.lastEventHash,"last_checkpoint_hash":v.lastCheckpointHash,"last_archive_receipt_hash":v.lastArchiveReceiptHash] }
    private static func chain(_ o:[String:Any]) throws -> NativeAuditPruneChainState { guard Set(o.keys)==["sequence","authorization_hash","receipt_hash","manifest_hash","last_event_index","last_checkpoint_index","last_receipt_index","last_event_hash","last_checkpoint_hash","last_archive_receipt_hash"], let s=exactInt(o["sequence"]), let a=o["authorization_hash"] as? String, let r=o["receipt_hash"] as? String, let m=o["manifest_hash"] as? String, let ei=exactInt(o["last_event_index"]), let ci=exactInt(o["last_checkpoint_index"]), let ri=exactInt(o["last_receipt_index"]), let eh=o["last_event_hash"] as? String, let ch=o["last_checkpoint_hash"] as? String, let rh=o["last_archive_receipt_hash"] as? String else { throw AgentPassNativeError.invalidSignature("Audit prune chain state is invalid") }; return .init(sequence:s,authorizationHash:a,receiptHash:r,manifestHash:m,lastEventIndex:ei,lastCheckpointIndex:ci,lastReceiptIndex:ri,lastEventHash:eh,lastCheckpointHash:ch,lastArchiveReceiptHash:rh) }
    private static func boundaryRegresses(_ candidate: NativeAuditRetentionBoundary, from old: NativeAuditRetentionBoundary) -> Bool { candidate.anchorEventIndex < old.anchorEventIndex || candidate.checkpointIndex < old.checkpointIndex || (candidate.lifecycleHeadHash != old.lifecycleHeadHash && candidate.auditKeyTransitionReceiptHash == old.auditKeyTransitionReceiptHash) }
    private static func canonical(_ object:[String:Any]) throws -> Data { try JSONSerialization.data(withJSONObject: object, options:[.sortedKeys,.withoutEscapingSlashes]) }
    private static func exactInt(_ value: Any?) -> Int? {
        guard let number = value as? NSNumber, String(cString: number.objCType) == "q" else { return nil }
        return number.intValue
    }
    private static func hash(_ data:Data)->String { SHA256.hash(data:data).map{String(format:"%02x",$0)}.joined() }
    private static func slug(_ value:String)->Bool { value.range(of:"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$",options:.regularExpression) != nil }
    private static func writeAll(_ fd:Int32,_ data:Data)throws { try data.withUnsafeBytes { b in var o=0; while o<b.count { let n=Darwin.write(fd,b.baseAddress!.advanced(by:o),b.count-o); guard n>0 else{throw posixError()}; o += n } } }
    private func validateRootIdentity() throws {
        var descriptorInfo = stat(), pathInfo = stat()
        guard fstat(rootFD, &descriptorInfo) == 0, lstat(rootPath, &pathInfo) == 0,
              descriptorInfo.st_dev == rootDevice, descriptorInfo.st_ino == rootInode,
              pathInfo.st_dev == rootDevice, pathInfo.st_ino == rootInode,
              (descriptorInfo.st_mode & S_IFMT) == S_IFDIR, descriptorInfo.st_uid == geteuid(),
              descriptorInfo.st_mode & 0o777 == 0o700 else {
            throw AgentPassNativeError.invalidSignature("Audit prune trust root identity changed")
        }
    }
    private func descriptorEntryNames() throws -> [String] {
        let copied = dup(rootFD); guard copied >= 0, let directory = fdopendir(copied) else { if copied >= 0 { close(copied) }; throw Self.posixError() }
        defer { closedir(directory) }
        rewinddir(directory)
        var names: [String] = []
        while let entry = readdir(directory) {
            let name = withUnsafePointer(to: &entry.pointee.d_name) { $0.withMemoryRebound(to: CChar.self, capacity: Int(NAME_MAX) + 1) { String(cString: $0) } }
            if name != "." && name != ".." { names.append(name) }
        }
        return names
    }
    private func cleanSafeTemporaryEntries() throws {
        try validateRootIdentity()
        for name in try descriptorEntryNames() where name.hasPrefix(".tip-") {
            guard name.wholeMatch(of: /^\.tip-[0-9a-f-]{36}$/) != nil else { throw AgentPassNativeError.invalidSignature("Audit prune trust temporary entry is invalid") }
            var info = stat()
            guard fstatat(rootFD,name,&info,AT_SYMLINK_NOFOLLOW)==0,(info.st_mode&S_IFMT)==S_IFREG,info.st_uid==geteuid(),info.st_mode&0o777==0o600,info.st_nlink==1,
                  unlinkat(rootFD,name,0)==0,fsync(rootFD)==0 else { throw AgentPassNativeError.invalidSignature("Audit prune trust temporary entry is unsafe") }
        }
    }
    private func withLock<T>(_ body:() throws->T)throws->T { lock.lock(); defer{lock.unlock()}; try validateRootIdentity(); return try body() }
    private static func posixError()->Error { POSIXError(POSIXErrorCode(rawValue:errno) ?? .EIO) }
}

public enum NativeAuditPruneEvidencePublisher {
    public static func publish(_ data: Data, path: String) throws {
        guard !data.isEmpty, path.hasPrefix("/") else { throw AgentPassNativeError.invalidConfiguration("Audit prune evidence path is invalid") }
        let url = URL(fileURLWithPath:path).standardizedFileURL
        guard url.path == path else { throw AgentPassNativeError.invalidConfiguration("Audit prune evidence path must be canonical") }
        let parent = url.deletingLastPathComponent().path
        guard URL(fileURLWithPath: parent).resolvingSymlinksInPath().path == parent else { throw AgentPassNativeError.invalidSignature("Audit prune evidence parent contains a symbolic link") }
        let directory = open(parent, O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC); guard directory >= 0 else { throw POSIXError(.EIO) }
        defer { close(directory) }
        var descriptorInfo = stat(), pathInfo = stat()
        guard fstat(directory,&descriptorInfo)==0,lstat(parent,&pathInfo)==0,
              descriptorInfo.st_dev==pathInfo.st_dev,descriptorInfo.st_ino==pathInfo.st_ino,
              (descriptorInfo.st_mode&S_IFMT)==S_IFDIR,descriptorInfo.st_uid==geteuid(),descriptorInfo.st_mode&0o022==0 else {
            throw AgentPassNativeError.invalidSignature("Audit prune evidence parent identity is unsafe")
        }
        var existing = stat()
        if fstatat(directory,url.lastPathComponent,&existing,AT_SYMLINK_NOFOLLOW)==0 {
            guard (existing.st_mode&S_IFMT)==S_IFREG,existing.st_uid==geteuid(),existing.st_mode&0o077==0,existing.st_nlink==1 else {
                throw AgentPassNativeError.invalidSignature("Existing audit prune evidence file is unsafe")
            }
        } else if errno != ENOENT { throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO) }
        let temp = ".prune-evidence-\(UUID().uuidString.lowercased())"
        let fd = openat(directory,temp,O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0o600); guard fd >= 0 else { throw POSIXError(.EIO) }
        do { try data.withUnsafeBytes { b in var o=0; while o<b.count { let n=Darwin.write(fd,b.baseAddress!.advanced(by:o),b.count-o); guard n>0 else{throw POSIXError(.EIO)}; o += n } }; guard fsync(fd)==0,close(fd)==0,renameat(directory,temp,directory,url.lastPathComponent)==0,fsync(directory)==0 else{throw POSIXError(.EIO)} }
        catch { close(fd); unlinkat(directory,temp,0); throw error }
    }
}
