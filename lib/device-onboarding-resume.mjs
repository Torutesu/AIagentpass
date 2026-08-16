import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

export const DEVICE_ONBOARDING_RESUME_VERSION = 1;
export const DEVICE_ONBOARDING_RESUME_FORMAT = "device-onboarding-resume.v1";
export const DEVICE_ONBOARDING_RESUME_SOURCE = "agentpass-device-onboarding";
export const DEVICE_ONBOARDING_RESUME_STATES = Object.freeze([
  "prepared",
  "invitation_issued",
  "delivered",
  "enrollment_uncertain",
  "receipt_verified",
  "trust_installed",
  "control_acknowledged",
  "failed"
]);

const STATE_RANK = new Map(DEVICE_ONBOARDING_RESUME_STATES.map((state, index) => [state, index]));
const ZERO_HASH = "0".repeat(64);
const SHA256 = /^[0-9a-f]{64}$/u;
const ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u;
const RELEASE_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u;
const RFC3339_UTC = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u;
const MAX_DOCUMENT_BYTES = 512 * 1024;
const MAX_JSON_DEPTH = 32;
const MAX_LOCK_AGE_MS = 30_000;
const RECORD_KEYS = Object.freeze([
  "format", "version", "source", "release_id", "organization_id", "device_id", "resume_id",
  "state", "revision", "created_at", "updated_at", "previous_hash", "record_hash", "recovery_descriptor", "evidence", "failure"
]);
const JOURNAL_KEYS = Object.freeze(["format", "version", "source", "resume_id", "head_revision", "head_hash", "entries"]);
const ANCHOR_KEYS = Object.freeze(["format", "version", "source", "resume_id", "highest_revision", "head_hash"]);
const EVIDENCE_KEYS = Object.freeze(["invitation", "delivery", "attempt", "enrollment", "trust", "control"]);
const INVITATION_KEYS = Object.freeze(["invitation_id", "invitation_hash", "issued_at"]);
const DELIVERY_KEYS = Object.freeze(["delivery_id", "delivery_hash", "delivered_at"]);
const ATTEMPT_KEYS = Object.freeze(["attempt_id", "attempt_hash", "uncertain_at"]);
const ENROLLMENT_KEYS = Object.freeze([
  "enrollment_id", "receipt_id", "receipt_statement_hash", "authority_record_id", "authority_evidence_hash", "observed_at"
]);
const TRUST_KEYS = Object.freeze(["trust_receipt_id", "trust_evidence_hash", "installed_at"]);
const CONTROL_KEYS = Object.freeze(["ack_id", "ack_evidence_hash", "acknowledged_at"]);
const FAILURE_KEYS = Object.freeze(["code", "failed_at", "detail_hash"]);
const BINDING_KEYS = Object.freeze(["source", "release_id", "organization_id", "device_id"]);
const AUTHORITY_RESULT_KEYS = Object.freeze([
  "status", "binding", "authority_record_id", "enrollment_id", "receipt_id", "receipt_statement_hash",
  "authority_evidence_hash", "observed_at"
]);
const RECOVERY_DESCRIPTOR_KEYS = Object.freeze([
  "enrollment_id", "label", "platform", "api_base_url", "candidate_binding", "challenge_digest",
  "request_digest", "verification_key_id", "verification_algorithm", "verification_public_key"
]);
const CANDIDATE_BINDING_KEYS = Object.freeze([
  "version", "enrollment_id", "organization_id", "device_id", "candidate_id", "artifact_sha256",
  "source_commit", "team_id", "device_key_fingerprint", "expires_at"
]);
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const SOURCE_COMMIT = /^[0-9a-f]{40}$/u;
const TEAM_ID = /^[A-Z0-9]{10}$/u;
const FINGERPRINT = /^SHA256:[A-Za-z0-9_-]{43}$/u;

export class DeviceOnboardingResumeError extends Error {
  constructor(code, message, cause) {
    super(message, cause === undefined ? undefined : { cause });
    this.name = "DeviceOnboardingResumeError";
    this.code = code;
  }
}

export class DeviceOnboardingResumeStore {
  constructor(filePath, options = {}) {
    if (typeof filePath !== "string" || !path.isAbsolute(filePath)) fail("INVALID_PATH", "Resume state path must be absolute");
    if (!isPlainOptions(options)) fail("INVALID_OPTIONS", "Resume store options must be an object");
    this.filePath = filePath;
    this.journalPath = `${filePath}.journal`;
    this.anchorPath = `${filePath}.anchor`;
    this.lockPath = `${filePath}.lock`;
    this.directory = path.dirname(filePath);
    this.clock = options.clock ?? (() => new Date().toISOString());
    this.idFactory = options.id_factory ?? (() => crypto.randomUUID());
    this.fault = options.fault;
    this.staleLockMs = options.stale_lock_ms ?? MAX_LOCK_AGE_MS;
    if (typeof this.clock !== "function" || typeof this.idFactory !== "function") fail("INVALID_OPTIONS", "Clock and ID factory must be functions");
    if (!Number.isInteger(this.staleLockMs) || this.staleLockMs < 1_000 || this.staleLockMs > 24 * 60 * 60 * 1_000) {
      fail("INVALID_OPTIONS", "Stale lock limit is out of bounds");
    }
    validateDirectory(this.directory);
  }

  create_prepared(input = {}) {
    assertInputShape(input, ["release_id", "organization_id", "device_id"], ["release_id", "organization_id", "device_id", "resume_id", "created_at", "recovery_descriptor"]);
    const releaseId = validateReleaseId(input.release_id);
    const organizationId = validatePublicId(input.organization_id, "organization_id");
    const deviceId = validatePublicId(input.device_id, "device_id");
    const resumeId = input.resume_id === undefined ? validatePublicId(this.idFactory(), "resume_id") : validatePublicId(input.resume_id, "resume_id");
    return this._withLock(() => {
      if (hasAnyStorage(this)) fail("ALREADY_EXISTS", "Resume state already exists");
      const now = validateTime(input.created_at ?? this.clock(), "created_at");
      const record = makeRecord({
        release_id: releaseId,
        organization_id: organizationId,
        device_id: deviceId,
        resume_id: resumeId,
        state: "prepared",
        revision: 1,
        created_at: now,
        updated_at: now,
        previous_hash: ZERO_HASH,
        recovery_descriptor: input.recovery_descriptor === undefined ? null : normalizeRecoveryDescriptor(input.recovery_descriptor, { release_id: releaseId, organization_id: organizationId, device_id: deviceId }),
        evidence: emptyEvidence(),
        failure: null
      });
      return this._commitFresh(record);
    });
  }

  read() {
    return this._withLock(() => this._loadUnlocked(true));
  }

  issue_invitation(input = {}) {
    assertInputKeys(input, ["invitation_id", "invitation_hash", "issued_at"]);
    return this._transition("prepared", (current) => {
      const issuedAt = nextTime(input.issued_at, current.updated_at, "issued_at");
      const evidence = { ...current.evidence, invitation: {
        invitation_id: validatePublicId(input.invitation_id, "invitation_id"),
        invitation_hash: validateHash(input.invitation_hash, "invitation_hash"),
        issued_at: issuedAt
      }};
      return this._nextRecord(current, "invitation_issued", issuedAt, evidence, null);
    });
  }

  record_delivery(input = {}) {
    assertInputKeys(input, ["delivery_id", "delivery_hash", "delivered_at"]);
    return this._transition("invitation_issued", (current) => {
      const deliveredAt = nextTime(input.delivered_at, current.updated_at, "delivered_at");
      const evidence = { ...current.evidence, delivery: {
        delivery_id: validatePublicId(input.delivery_id, "delivery_id"),
        delivery_hash: validateHash(input.delivery_hash, "delivery_hash"),
        delivered_at: deliveredAt
      }};
      return this._nextRecord(current, "delivered", deliveredAt, evidence, null);
    });
  }

  mark_enrollment_uncertain(input = {}) {
    assertInputKeys(input, ["attempt_id", "attempt_hash", "uncertain_at"]);
    return this._transition("delivered", (current) => {
      const uncertainAt = nextTime(input.uncertain_at, current.updated_at, "uncertain_at");
      const evidence = { ...current.evidence, attempt: {
        attempt_id: validatePublicId(input.attempt_id, "attempt_id"),
        attempt_hash: validateHash(input.attempt_hash, "attempt_hash"),
        uncertain_at: uncertainAt
      }};
      return this._nextRecord(current, "enrollment_uncertain", uncertainAt, evidence, null);
    });
  }

  async reconcile_enrollment(input = {}) {
    assertInputKeys(input, ["lookup"]);
    if (typeof input.lookup !== "function") fail("INVALID_LOOKUP", "Authoritative lookup must be an injected function");
    const lease = this._acquireLock();
    try {
      const current = this._loadUnlocked(true);
      if (current.state !== "enrollment_uncertain") fail("INVALID_TRANSITION", "Only uncertain enrollment can be reconciled");
      let result;
      try {
        result = await input.lookup({
          record: publicRecord(current),
          binding: {
            source: current.source,
            release_id: current.release_id,
            organization_id: current.organization_id,
            device_id: current.device_id
          }
        });
      } catch (error) {
        throw new DeviceOnboardingResumeError("AUTHORITATIVE_LOOKUP_FAILED", "Authoritative lookup failed; enrollment remains uncertain", error);
      }
      const normalized = validateAuthorityResult(result);
      if (normalized.status === "not_found") return publicRecord(current);
      const detailHash = hashCanonical(normalized);
      if (normalized.status === "duplicate") {
        return this._commitLocked(this._failureRecord(current, "duplicate_enrollment", detailHash, normalized.observed_at));
      }
      if (normalized.status === "conflict") {
        return this._commitLocked(this._failureRecord(current, "authority_conflict", detailHash, normalized.observed_at));
      }
      if (!sameBinding(current, normalized.binding)) {
        return this._commitLocked(this._failureRecord(current, "authority_conflict", detailHash, normalized.observed_at));
      }
      const evidence = { ...current.evidence, enrollment: {
        enrollment_id: normalized.enrollment_id,
        receipt_id: normalized.receipt_id,
        receipt_statement_hash: normalized.receipt_statement_hash,
        authority_record_id: normalized.authority_record_id,
        authority_evidence_hash: normalized.authority_evidence_hash,
        observed_at: normalized.observed_at
      }};
      const next = this._nextRecord(current, "receipt_verified", normalized.observed_at, evidence, null);
      return this._commitLocked(next);
    } finally {
      this._releaseLock(lease);
    }
  }

  install_trust(input = {}) {
    assertInputKeys(input, ["trust_receipt_id", "trust_evidence_hash", "installed_at"]);
    return this._transition("receipt_verified", (current) => {
      const installedAt = nextTime(input.installed_at, current.updated_at, "installed_at");
      const evidence = { ...current.evidence, trust: {
        trust_receipt_id: validatePublicId(input.trust_receipt_id, "trust_receipt_id"),
        trust_evidence_hash: validateHash(input.trust_evidence_hash, "trust_evidence_hash"),
        installed_at: installedAt
      }};
      return this._nextRecord(current, "trust_installed", installedAt, evidence, null);
    });
  }

  acknowledge_control(input = {}) {
    assertInputKeys(input, ["ack_id", "ack_evidence_hash", "acknowledged_at"]);
    return this._transition("trust_installed", (current) => {
      const acknowledgedAt = nextTime(input.acknowledged_at, current.updated_at, "acknowledged_at");
      const evidence = { ...current.evidence, control: {
        ack_id: validatePublicId(input.ack_id, "ack_id"),
        ack_evidence_hash: validateHash(input.ack_evidence_hash, "ack_evidence_hash"),
        acknowledged_at: acknowledgedAt
      }};
      return this._nextRecord(current, "control_acknowledged", acknowledgedAt, evidence, null);
    });
  }

  _transition(expectedState, build) {
    return this._withLock(() => {
      const current = this._loadUnlocked(true);
      if (current.state !== expectedState) fail("INVALID_TRANSITION", `Expected ${expectedState}, found ${current.state}`);
      return this._commitLocked(build(current));
    });
  }

  _commitFresh(record) {
    const journal = makeJournal(record, [record]);
    this._writeCanonical(this.journalPath, journal);
    this._fault("after_journal");
    this._writeCanonical(this.filePath, record);
    this._fault("after_state");
    this._writeCanonical(this.anchorPath, makeAnchor(record));
    this._fault("after_anchor");
    return publicRecord(record);
  }

  _commitLocked(record) {
    assertRecord(record);
    const loaded = this._loadUnlocked(true);
    if (record.resume_id !== loaded.resume_id || record.revision !== loaded.revision + 1 || record.previous_hash !== loaded.record_hash) {
      fail("CONCURRENT_MODIFICATION", "Resume state changed while it was being updated");
    }
    const journal = makeJournal(record, [...loaded._entries, record]);
    this._writeCanonical(this.journalPath, journal);
    this._fault("after_journal");
    this._writeCanonical(this.filePath, record);
    this._fault("after_state");
    this._writeCanonical(this.anchorPath, makeAnchor(record));
    this._fault("after_anchor");
    return publicRecord(record);
  }

  _nextRecord(current, state, time, evidence, failure) {
    if (state !== "failed" && STATE_RANK.get(state) <= STATE_RANK.get(current.state)) fail("INVALID_TRANSITION", "Resume state must advance monotonically");
    const record = makeRecord({
      ...current,
      state,
      revision: current.revision + 1,
      updated_at: time,
      previous_hash: current.record_hash,
      evidence,
      failure
    });
    return record;
  }

  _failureRecord(current, code, detailHash, time) {
    return this._nextRecord(current, "failed", time, current.evidence, { code, failed_at: time, detail_hash: detailHash });
  }

  _loadUnlocked(repair) {
    const stateExists = safeExists(this.filePath);
    const journalExists = safeExists(this.journalPath);
    const anchorExists = safeExists(this.anchorPath);
    if (!stateExists && !journalExists && !anchorExists) fail("NOT_INITIALIZED", "Resume state is not initialized");
    if (!journalExists) fail("DURABILITY_FAILURE", "Resume journal is missing");
    const journal = readCanonical(this.journalPath, "journal");
    assertJournal(journal);
    const entries = journal.entries.map((entry) => {
      assertRecord(entry);
      return entry;
    });
    verifyChain(entries, journal);
    const latest = entries.at(-1);
    if (!stateExists) {
      if (!repair) fail("DURABILITY_FAILURE", "Resume state snapshot is missing");
      this._writeCanonical(this.filePath, latest);
    } else {
      const state = readCanonical(this.filePath, "state");
      assertRecord(state);
      if (canonicalJson(state) !== canonicalJson(latest)) {
        const stateIsPriorJournalEntry = entries.some((entry) => canonicalJson(entry) === canonicalJson(state));
        if (!stateIsPriorJournalEntry) fail("ROLLBACK_DETECTED", "Resume state and journal heads disagree");
        if (!repair) fail("DURABILITY_FAILURE", "Resume state snapshot is behind journal head");
        this._writeCanonical(this.filePath, latest);
      }
    }
    if (!anchorExists) {
      if (!repair) fail("DURABILITY_FAILURE", "Resume anchor is missing");
      this._writeCanonical(this.anchorPath, makeAnchor(latest));
    } else {
      const anchor = readCanonical(this.anchorPath, "anchor");
      assertAnchor(anchor, latest);
      if (anchor.highest_revision < latest.revision) {
        if (!repair) fail("DURABILITY_FAILURE", "Resume anchor is behind journal head");
        this._writeCanonical(this.anchorPath, makeAnchor(latest));
      }
    }
    return { ...publicRecord(latest), _entries: entries };
  }

  _withLock(operation) {
    const lease = this._acquireLock();
    try { return operation(); } finally { this._releaseLock(lease); }
  }

  _acquireLock() {
    validateDirectory(this.directory);
    const flags = fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | (fs.constants.O_NOFOLLOW ?? 0);
    try {
      const descriptor = fs.openSync(this.lockPath, flags, 0o600);
      try {
        fs.writeFileSync(descriptor, `${JSON.stringify({ pid: process.pid, acquired_at: new Date().toISOString() })}\n`, "utf8");
        fs.fsyncSync(descriptor);
      } finally { fs.closeSync(descriptor); }
      validateRegularOwnedFile(this.lockPath, "lock");
      return { pid: process.pid };
    } catch (error) {
      if (error?.code !== "EEXIST") throw wrapIo("LOCK_ACQUIRE_FAILED", "Could not acquire resume lock", error);
      const lock = readLock(this.lockPath);
      if (!lock || lock.pid === process.pid || lock.acquired_at === null || Date.now() - lock.acquired_at < this.staleLockMs || processAlive(lock.pid)) {
        fail("LOCK_HELD", "Another resume operation owns the lock");
      }
      validateRegularOwnedFile(this.lockPath, "lock");
      try { fs.unlinkSync(this.lockPath); } catch (unlinkError) { throw wrapIo("LOCK_ACQUIRE_FAILED", "Could not recover stale resume lock", unlinkError); }
      return this._acquireLock();
    }
  }

  _releaseLock(lease) {
    if (!lease) return;
    try {
      const lock = readLock(this.lockPath);
      if (lock?.pid === lease.pid) fs.unlinkSync(this.lockPath);
    } catch (error) {
      if (error?.code !== "ENOENT") throw wrapIo("LOCK_RELEASE_FAILED", "Could not release resume lock", error);
    }
  }

  _writeCanonical(target, value) {
    const content = `${canonicalJson(value)}\n`;
    if (Buffer.byteLength(content, "utf8") > MAX_DOCUMENT_BYTES) fail("BOUNDED_VALUE", "Resume document exceeds size limit");
    validateDirectory(this.directory);
    if (safeExists(target)) validateRegularOwnedFile(target, path.basename(target));
    const temporary = path.join(this.directory, `.${path.basename(target)}.tmp.${process.pid}.${crypto.randomUUID()}`);
    let descriptor;
    try {
      const flags = fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | (fs.constants.O_NOFOLLOW ?? 0);
      descriptor = fs.openSync(temporary, flags, 0o600);
      fs.writeFileSync(descriptor, content, "utf8");
      fs.fchmodSync(descriptor, 0o600);
      fs.fsyncSync(descriptor);
      fs.closeSync(descriptor);
      descriptor = undefined;
      fs.renameSync(temporary, target);
      fsyncDirectory(this.directory);
      validateRegularOwnedFile(target, path.basename(target));
    } catch (error) {
      if (descriptor !== undefined) try { fs.closeSync(descriptor); } catch {}
      throw wrapIo("PERSISTENCE_FAILED", `Could not atomically write ${target}`, error);
    } finally {
      try { if (safeExists(temporary)) fs.unlinkSync(temporary); } catch {}
    }
  }

  _fault(stage) {
    if (this.fault === undefined) return;
    if (typeof this.fault !== "function") fail("INVALID_OPTIONS", "Fault hook must be a function");
    this.fault(stage);
  }
}

export function createDeviceOnboardingResumeStore(filePath, options = {}) {
  return new DeviceOnboardingResumeStore(filePath, options);
}

function makeRecord(fields) {
  const record = {
    format: DEVICE_ONBOARDING_RESUME_FORMAT,
    version: DEVICE_ONBOARDING_RESUME_VERSION,
    source: DEVICE_ONBOARDING_RESUME_SOURCE,
    release_id: fields.release_id,
    organization_id: fields.organization_id,
    device_id: fields.device_id,
    resume_id: fields.resume_id,
    state: fields.state,
    revision: fields.revision,
    created_at: fields.created_at,
    updated_at: fields.updated_at,
    previous_hash: fields.previous_hash,
    record_hash: null,
    recovery_descriptor: fields.recovery_descriptor,
    evidence: fields.evidence,
    failure: fields.failure
  };
  record.record_hash = hashRecord(record);
  assertRecord(record);
  assertNoSecretFields(record);
  return record;
}

function makeJournal(record, entries) {
  return { format: "onboarding-runtime-journal.v1", version: DEVICE_ONBOARDING_RESUME_VERSION, source: DEVICE_ONBOARDING_RESUME_SOURCE, resume_id: record.resume_id, head_revision: record.revision, head_hash: record.record_hash, entries };
}

function makeAnchor(record) {
  return { format: "onboarding-runtime-anchor.v1", version: DEVICE_ONBOARDING_RESUME_VERSION, source: DEVICE_ONBOARDING_RESUME_SOURCE, resume_id: record.resume_id, highest_revision: record.revision, head_hash: record.record_hash };
}

function emptyEvidence() {
  return { invitation: null, delivery: null, attempt: null, enrollment: null, trust: null, control: null };
}

function publicRecord(record) {
  const copy = { ...record };
  delete copy._entries;
  return JSON.parse(JSON.stringify(copy));
}

function assertRecord(record) {
  assertExactObject(record, RECORD_KEYS, "record");
  if (record.format !== DEVICE_ONBOARDING_RESUME_FORMAT || record.version !== DEVICE_ONBOARDING_RESUME_VERSION) fail("UNSUPPORTED_VERSION", "Unsupported or downgraded resume record");
  if (record.source !== DEVICE_ONBOARDING_RESUME_SOURCE) fail("BINDING_FAILURE", "Resume source binding is invalid");
  validateReleaseId(record.release_id);
  validatePublicId(record.organization_id, "organization_id");
  validatePublicId(record.device_id, "device_id");
  validatePublicId(record.resume_id, "resume_id");
  if (!DEVICE_ONBOARDING_RESUME_STATES.includes(record.state)) fail("INVALID_STATE", "Unknown resume state");
  if (!Number.isSafeInteger(record.revision) || record.revision < 1 || record.revision > 1_000_000) fail("BOUNDED_VALUE", "Resume revision is invalid");
  validateTime(record.created_at, "created_at");
  validateTime(record.updated_at, "updated_at");
  if (Date.parse(record.updated_at) < Date.parse(record.created_at)) fail("INVALID_TIME", "Resume timestamps are not monotonic");
  validateHash(record.previous_hash, "previous_hash");
  validateHash(record.record_hash, "record_hash");
  if (record.recovery_descriptor !== null) normalizeRecoveryDescriptor(record.recovery_descriptor, record);
  assertEvidence(record.evidence);
  if (record.failure === null) {
    if (record.state === "failed") fail("INVALID_RECORD", "Failed state requires failure evidence");
  } else {
    assertExactObject(record.failure, FAILURE_KEYS, "failure");
    if (!["duplicate_enrollment", "authority_conflict"].includes(record.failure.code)) fail("INVALID_RECORD", "Failure code is not permitted");
    validateTime(record.failure.failed_at, "failed_at");
    validateHash(record.failure.detail_hash, "detail_hash");
    if (record.state !== "failed") fail("INVALID_RECORD", "Failure evidence is only valid in failed state");
  }
  const required = {
    prepared: [],
    invitation_issued: ["invitation"],
    delivered: ["invitation", "delivery"],
    enrollment_uncertain: ["invitation", "delivery", "attempt"],
    receipt_verified: ["invitation", "delivery", "attempt", "enrollment"],
    trust_installed: ["invitation", "delivery", "attempt", "enrollment", "trust"],
    control_acknowledged: ["invitation", "delivery", "attempt", "enrollment", "trust", "control"],
    failed: ["invitation", "delivery", "attempt"]
  }[record.state];
  for (const key of required) if (record.evidence[key] === null) fail("INVALID_RECORD", `${key} evidence is missing for ${record.state}`);
  if (record.state === "prepared" && Object.values(record.evidence).some(Boolean)) fail("INVALID_RECORD", "Prepared state contains evidence");
  if (record.state === "invitation_issued" && Object.values(record.evidence).filter(Boolean).length !== 1) fail("INVALID_RECORD", "Invitation state contains unexpected evidence");
  if (record.state === "delivered" && Object.values(record.evidence).filter(Boolean).length !== 2) fail("INVALID_RECORD", "Delivered state contains unexpected evidence");
  if (record.state === "enrollment_uncertain" && Object.values(record.evidence).filter(Boolean).length !== 3) fail("INVALID_RECORD", "Uncertain state contains unexpected evidence");
  if (record.state === "failed" && record.evidence.enrollment !== null) fail("INVALID_RECORD", "Failed enrollment cannot contain receipt evidence");
  assertNoSecretFields(record);
}

function assertEvidence(evidence) {
  assertExactObject(evidence, EVIDENCE_KEYS, "evidence");
  if (evidence.invitation !== null) { assertExactObject(evidence.invitation, INVITATION_KEYS, "invitation evidence"); validatePublicId(evidence.invitation.invitation_id, "invitation_id"); validateHash(evidence.invitation.invitation_hash, "invitation_hash"); validateTime(evidence.invitation.issued_at, "issued_at"); }
  if (evidence.delivery !== null) { assertExactObject(evidence.delivery, DELIVERY_KEYS, "delivery evidence"); validatePublicId(evidence.delivery.delivery_id, "delivery_id"); validateHash(evidence.delivery.delivery_hash, "delivery_hash"); validateTime(evidence.delivery.delivered_at, "delivered_at"); }
  if (evidence.attempt !== null) { assertExactObject(evidence.attempt, ATTEMPT_KEYS, "attempt evidence"); validatePublicId(evidence.attempt.attempt_id, "attempt_id"); validateHash(evidence.attempt.attempt_hash, "attempt_hash"); validateTime(evidence.attempt.uncertain_at, "uncertain_at"); }
  if (evidence.enrollment !== null) { assertExactObject(evidence.enrollment, ENROLLMENT_KEYS, "enrollment evidence"); validatePublicId(evidence.enrollment.enrollment_id, "enrollment_id"); validatePublicId(evidence.enrollment.receipt_id, "receipt_id"); validateHash(evidence.enrollment.receipt_statement_hash, "receipt_statement_hash"); validatePublicId(evidence.enrollment.authority_record_id, "authority_record_id"); validateHash(evidence.enrollment.authority_evidence_hash, "authority_evidence_hash"); validateTime(evidence.enrollment.observed_at, "observed_at"); }
  if (evidence.trust !== null) { assertExactObject(evidence.trust, TRUST_KEYS, "trust evidence"); validatePublicId(evidence.trust.trust_receipt_id, "trust_receipt_id"); validateHash(evidence.trust.trust_evidence_hash, "trust_evidence_hash"); validateTime(evidence.trust.installed_at, "installed_at"); }
  if (evidence.control !== null) { assertExactObject(evidence.control, CONTROL_KEYS, "control evidence"); validatePublicId(evidence.control.ack_id, "ack_id"); validateHash(evidence.control.ack_evidence_hash, "ack_evidence_hash"); validateTime(evidence.control.acknowledged_at, "acknowledged_at"); }
}

function assertJournal(journal) {
  assertExactObject(journal, JOURNAL_KEYS, "journal");
  if (journal.format !== "onboarding-runtime-journal.v1" || journal.version !== DEVICE_ONBOARDING_RESUME_VERSION || journal.source !== DEVICE_ONBOARDING_RESUME_SOURCE) fail("UNSUPPORTED_VERSION", "Unsupported journal");
  validatePublicId(journal.resume_id, "resume_id");
  if (!Number.isSafeInteger(journal.head_revision) || journal.head_revision < 1) fail("INVALID_JOURNAL", "Invalid journal head revision");
  validateHash(journal.head_hash, "head_hash");
  if (!Array.isArray(journal.entries) || journal.entries.length < 1 || journal.entries.length > 1_000_000) fail("INVALID_JOURNAL", "Invalid journal entries");
}

function assertAnchor(anchor, latest) {
  assertExactObject(anchor, ANCHOR_KEYS, "anchor");
  if (anchor.format !== "onboarding-runtime-anchor.v1" || anchor.version !== DEVICE_ONBOARDING_RESUME_VERSION || anchor.source !== DEVICE_ONBOARDING_RESUME_SOURCE) fail("UNSUPPORTED_VERSION", "Unsupported anchor");
  if (anchor.resume_id !== latest.resume_id || !Number.isSafeInteger(anchor.highest_revision) || anchor.highest_revision < 1) fail("ROLLBACK_DETECTED", "Anchor binding is invalid");
  validateHash(anchor.head_hash, "anchor head hash");
  if (anchor.highest_revision > latest.revision || (anchor.highest_revision === latest.revision && anchor.head_hash !== latest.record_hash)) fail("ROLLBACK_DETECTED", "Resume anchor detects rollback");
}

function verifyChain(entries, journal) {
  for (let index = 0; index < entries.length; index += 1) {
    const record = entries[index];
    if (record.revision !== index + 1 || (index === 0 ? record.previous_hash !== ZERO_HASH : record.previous_hash !== entries[index - 1].record_hash)) fail("ROLLBACK_DETECTED", "Resume journal hash chain is invalid");
    if (index > 0 && (record.resume_id !== entries[0].resume_id || record.release_id !== entries[0].release_id || record.organization_id !== entries[0].organization_id || record.device_id !== entries[0].device_id || canonicalJson(record.recovery_descriptor) !== canonicalJson(entries[0].recovery_descriptor))) fail("BINDING_FAILURE", "Resume journal binding changed");
    if (hashRecord(record) !== record.record_hash) fail("TAMPER_DETECTED", "Resume record hash is invalid");
    if (index > 0 && record.state !== "failed" && STATE_RANK.get(record.state) <= STATE_RANK.get(entries[index - 1].state)) fail("ROLLBACK_DETECTED", "Resume state regressed");
  }
  const latest = entries.at(-1);
  if (journal.resume_id !== latest.resume_id || journal.head_revision !== latest.revision || journal.head_hash !== latest.record_hash) fail("ROLLBACK_DETECTED", "Resume journal head is invalid");
}

function validateAuthorityResult(value) {
  assertExactObject(value, AUTHORITY_RESULT_KEYS, "authority result");
  if (!["found", "not_found", "duplicate", "conflict"].includes(value.status)) fail("INVALID_AUTHORITY_RESULT", "Unknown authority result");
  assertExactObject(value.binding, BINDING_KEYS, "authority binding");
  if (value.binding.source !== DEVICE_ONBOARDING_RESUME_SOURCE) fail("BINDING_FAILURE", "Authority source binding is invalid");
  validateReleaseId(value.binding.release_id); validatePublicId(value.binding.organization_id, "organization_id"); validatePublicId(value.binding.device_id, "device_id");
  validateTime(value.observed_at, "observed_at");
  const nullableIds = ["authority_record_id", "enrollment_id", "receipt_id"];
  const nullableHashes = ["receipt_statement_hash", "authority_evidence_hash"];
  for (const key of nullableIds) if (value[key] !== null) validatePublicId(value[key], key);
  for (const key of nullableHashes) if (value[key] !== null) validateHash(value[key], key);
  if (value.status === "found" && [value.authority_record_id, value.enrollment_id, value.receipt_id, value.receipt_statement_hash, value.authority_evidence_hash].some((item) => item === null)) fail("INVALID_AUTHORITY_RESULT", "Found authority result is incomplete");
  if (value.status !== "found" && [value.authority_record_id, value.enrollment_id, value.receipt_id, value.receipt_statement_hash, value.authority_evidence_hash].some((item) => item !== null)) fail("INVALID_AUTHORITY_RESULT", "Non-found authority result contains enrollment evidence");
  return value;
}

function normalizeRecoveryDescriptor(value, binding) {
  assertExactObject(value, RECOVERY_DESCRIPTOR_KEYS, "recovery descriptor");
  assertExactObject(value.candidate_binding, CANDIDATE_BINDING_KEYS, "recovery candidate binding");
  const candidate = {
    version: value.candidate_binding.version,
    enrollment_id: exactPattern(value.candidate_binding.enrollment_id, UUID, "candidate enrollment_id"),
    organization_id: exactPattern(value.candidate_binding.organization_id, UUID, "candidate organization_id"),
    device_id: exactPattern(value.candidate_binding.device_id, UUID, "candidate device_id"),
    candidate_id: validateReleaseId(value.candidate_binding.candidate_id),
    artifact_sha256: validateHash(value.candidate_binding.artifact_sha256, "candidate artifact_sha256"),
    source_commit: exactPattern(value.candidate_binding.source_commit, SOURCE_COMMIT, "candidate source_commit"),
    team_id: exactPattern(value.candidate_binding.team_id, TEAM_ID, "candidate team_id"),
    device_key_fingerprint: exactPattern(value.candidate_binding.device_key_fingerprint, FINGERPRINT, "candidate device_key_fingerprint"),
    expires_at: validateTime(value.candidate_binding.expires_at, "candidate expires_at")
  };
  if (candidate.version !== 1) fail("UNSUPPORTED_VERSION", "Recovery candidate binding version is unsupported");
  const enrollmentId = exactPattern(value.enrollment_id, UUID, "recovery enrollment_id");
  if (enrollmentId !== candidate.enrollment_id
    || candidate.organization_id !== binding.organization_id
    || candidate.device_id !== binding.device_id
    || candidate.candidate_id !== binding.release_id) fail("BINDING_FAILURE", "Recovery descriptor identity binding is invalid");
  if (typeof value.label !== "string" || value.label.length < 1 || [...value.label].length > 128 || /[\u0000-\u001f\u007f]/u.test(value.label)) fail("BOUNDED_VALUE", "Recovery label is invalid");
  if (value.platform !== "macos") fail("BINDING_FAILURE", "Recovery platform is invalid");
  let api;
  try { api = new URL(value.api_base_url); } catch { fail("BINDING_FAILURE", "Recovery API base URL is invalid"); }
  const hostname = api.hostname.replace(/^\[|\]$/gu, "");
  if (api.protocol !== "https:" || !hostname || hostname !== hostname.toLowerCase() || api.username || api.password || api.search || api.hash || api.pathname !== "/v1") fail("BINDING_FAILURE", "Recovery API base URL is invalid");
  const canonicalApi = `${api.origin}/v1`;
  if (value.api_base_url !== canonicalApi) fail("NONCANONICAL", "Recovery API base URL is not canonical");
  const verificationKeyId = validatePublicId(value.verification_key_id, "verification_key_id");
  if (value.verification_algorithm !== "ed25519") fail("BINDING_FAILURE", "Recovery verification algorithm is invalid");
  if (typeof value.verification_public_key !== "string" || Buffer.byteLength(value.verification_public_key, "utf8") > 8192 || /PRIVATE\s+KEY/iu.test(value.verification_public_key)) fail("SECRET_FIELD", "Recovery verification key is invalid");
  let verificationKey;
  try { verificationKey = crypto.createPublicKey(value.verification_public_key); } catch { fail("BINDING_FAILURE", "Recovery verification key is invalid"); }
  if (verificationKey.type !== "public" || verificationKey.asymmetricKeyType !== "ed25519") fail("BINDING_FAILURE", "Recovery verification key algorithm is invalid");
  const canonicalKey = verificationKey.export({ type: "spki", format: "pem" }).toString();
  if (canonicalKey !== value.verification_public_key) fail("NONCANONICAL", "Recovery verification key is not canonical");
  return Object.freeze({
    enrollment_id: enrollmentId,
    label: value.label,
    platform: "macos",
    api_base_url: canonicalApi,
    candidate_binding: Object.freeze(candidate),
    challenge_digest: validateHash(value.challenge_digest, "challenge_digest"),
    request_digest: validateHash(value.request_digest, "request_digest"),
    verification_key_id: verificationKeyId,
    verification_algorithm: "ed25519",
    verification_public_key: canonicalKey
  });
}

function exactPattern(value, pattern, label) {
  if (typeof value !== "string" || !pattern.test(value)) fail("BOUNDED_VALUE", `${label} is invalid`);
  return value;
}

function sameBinding(record, binding) {
  return record.source === binding.source && record.release_id === binding.release_id && record.organization_id === binding.organization_id && record.device_id === binding.device_id;
}

function hashRecord(record) {
  const preimage = { ...record };
  delete preimage.record_hash;
  return hashCanonical(preimage);
}

function hashCanonical(value) { return crypto.createHash("sha256").update(canonicalJson(value), "utf8").digest("hex"); }

function readCanonical(filePath, label) {
  validateRegularOwnedFile(filePath, label);
  let text;
  try { text = fs.readFileSync(filePath, "utf8"); } catch (error) { throw wrapIo("DURABILITY_FAILURE", `Could not read ${label}`, error); }
  if (Buffer.byteLength(text, "utf8") > MAX_DOCUMENT_BYTES) fail("BOUNDED_VALUE", `${label} exceeds size limit`);
  try {
    const value = parseStrictJson(text);
    if (`${canonicalJson(value)}\n` !== text) fail("NONCANONICAL", `${label} is not canonical JSON`);
    return value;
  } catch (error) {
    if (error instanceof DeviceOnboardingResumeError) throw error;
    throw new DeviceOnboardingResumeError("INVALID_DOCUMENT", `${label} is not valid JSON`, error);
  }
}

function parseStrictJson(text) {
  if (typeof text !== "string" || text.length === 0) throw new Error("empty JSON");
  let cursor = 0;
  const value = parseValue(0);
  while (/[ \t\r]/u.test(text[cursor] ?? "")) cursor += 1;
  if (cursor !== text.length - 1 || text[cursor] !== "\n") throw new Error("trailing JSON");
  cursor += 1;
  return value;

  function parseValue(depth) {
    if (depth > MAX_JSON_DEPTH) throw new Error("JSON too deep");
    skipWhitespace();
    const char = text[cursor];
    if (char === "{") return parseObject(depth + 1);
    if (char === "[") return parseArray(depth + 1);
    if (char === '"') return parseString();
    for (const literal of ["true", "false", "null"]) if (text.startsWith(literal, cursor)) { cursor += literal.length; return literal === "null" ? null : literal === "true"; }
    const number = text.slice(cursor).match(/^-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?/u);
    if (number) { cursor += number[0].length; return JSON.parse(number[0]); }
    throw new Error("invalid JSON value");
  }
  function parseObject(depth) {
    cursor += 1; skipWhitespace(); const object = Object.create(null); const keys = new Set();
    if (text[cursor] === "}") { cursor += 1; return object; }
    while (cursor < text.length) {
      skipWhitespace(); if (text[cursor] !== '"') throw new Error("object key is not a string");
      const key = parseString(); if (keys.has(key)) throw new Error("duplicate object key"); keys.add(key);
      skipWhitespace(); if (text[cursor] !== ":") throw new Error("missing object colon"); cursor += 1;
      object[key] = parseValue(depth); skipWhitespace();
      if (text[cursor] === "}") { cursor += 1; return object; }
      if (text[cursor] !== ",") throw new Error("missing object comma"); cursor += 1;
    }
    throw new Error("unterminated object");
  }
  function parseArray(depth) {
    cursor += 1; skipWhitespace(); const array = [];
    if (text[cursor] === "]") { cursor += 1; return array; }
    while (cursor < text.length) {
      array.push(parseValue(depth)); skipWhitespace();
      if (text[cursor] === "]") { cursor += 1; return array; }
      if (text[cursor] !== ",") throw new Error("missing array comma"); cursor += 1;
    }
    throw new Error("unterminated array");
  }
  function parseString() {
    const start = cursor; cursor += 1;
    while (cursor < text.length) {
      const char = text[cursor];
      if (char === "\\") { cursor += 2; continue; }
      if (char === '"') { cursor += 1; return JSON.parse(text.slice(start, cursor)); }
      if (char < " ") throw new Error("control character in string");
      cursor += 1;
    }
    throw new Error("unterminated string");
  }
  function skipWhitespace() { while (/[ \t\r\n]/u.test(text[cursor] ?? "")) cursor += 1; }
}

function canonicalJson(value) {
  if (value === null) return "null";
  if (typeof value === "string") return JSON.stringify(value);
  if (typeof value === "boolean") return value ? "true" : "false";
  if (typeof value === "number") {
    if (!Number.isFinite(value) || Object.is(value, -0)) throw new Error("noncanonical number");
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (typeof value === "object") return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(",")}}`;
  throw new Error("unsupported JSON value");
}

function assertExactObject(value, expectedKeys, label) {
  if (!value || typeof value !== "object" || Array.isArray(value)) fail("INVALID_SCHEMA", `${label} must be an object`);
  const actual = Object.keys(value).sort(); const expected = [...expectedKeys].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) fail("INVALID_SCHEMA", `${label} contains unknown or missing fields`);
}

function assertInputKeys(value, keys) { assertExactObject(value, keys, "input"); }
function assertInputShape(value, requiredKeys, allowedKeys) {
  if (!value || typeof value !== "object" || Array.isArray(value)) fail("INVALID_SCHEMA", "input must be an object");
  const actual = Object.keys(value);
  if (requiredKeys.some((key) => !Object.hasOwn(value, key)) || actual.some((key) => !allowedKeys.includes(key))) fail("INVALID_SCHEMA", "input contains unknown or missing fields");
}
function validatePublicId(value, label) { if (typeof value !== "string" || !ID.test(value)) fail("BOUNDED_VALUE", `${label} is not a bounded opaque identifier`); return value; }
function validateReleaseId(value) { if (typeof value !== "string" || !RELEASE_ID.test(value)) fail("BOUNDED_VALUE", "release_id is invalid"); return value; }
function validateHash(value, label) { if (typeof value !== "string" || !SHA256.test(value)) fail("BOUNDED_VALUE", `${label} must be a lowercase SHA-256 hash`); return value; }
function validateTime(value, label) { if (typeof value !== "string" || !RFC3339_UTC.test(value) || !Number.isFinite(Date.parse(value)) || new Date(Date.parse(value)).toISOString() !== value) fail("INVALID_TIME", `${label} must be canonical UTC time`); return value; }
function nextTime(value, previous, label) { const time = validateTime(value ?? new Date().toISOString(), label); if (Date.parse(time) < Date.parse(previous)) fail("INVALID_TIME", `${label} regresses durable time`); return time; }
function isPlainOptions(value) { return value !== null && typeof value === "object" && !Array.isArray(value); }

function validateDirectory(directory) {
  let stat;
  try { stat = fs.lstatSync(directory); } catch (error) { throw wrapIo("UNSAFE_PATH", "Resume directory is unavailable", error); }
  if (!stat.isDirectory() || stat.isSymbolicLink()) fail("UNSAFE_PATH", "Resume directory must be a real directory");
  if (typeof process.getuid === "function" && stat.uid !== process.getuid()) fail("UNSAFE_PATH", "Resume directory owner is unexpected");
  if ((stat.mode & 0o022) !== 0) fail("UNSAFE_PATH", "Resume directory is group/world writable");
}

function validateRegularOwnedFile(filePath, label) {
  let stat;
  try { stat = fs.lstatSync(filePath); } catch (error) { throw wrapIo("DURABILITY_FAILURE", `${label} is unavailable`, error); }
  if (!stat.isFile() || stat.isSymbolicLink()) fail("UNSAFE_PATH", `${label} must be a regular non-symlink file`);
  if (typeof process.getuid === "function" && stat.uid !== process.getuid()) fail("UNSAFE_PATH", `${label} owner is unexpected`);
  if ((stat.mode & 0o077) !== 0) fail("UNSAFE_PATH", `${label} permissions are too broad`);
}

function safeExists(filePath) { try { fs.lstatSync(filePath); return true; } catch (error) { if (error?.code === "ENOENT") return false; throw wrapIo("UNSAFE_PATH", "Could not inspect resume path", error); } }
function hasAnyStorage(store) { return [store.filePath, store.journalPath, store.anchorPath].some(safeExists); }

function readLock(filePath) {
  try {
    validateRegularOwnedFile(filePath, "lock");
    const value = JSON.parse(fs.readFileSync(filePath, "utf8"));
    return { pid: Number.isInteger(value.pid) ? value.pid : null, acquired_at: typeof value.acquired_at === "string" ? Date.parse(value.acquired_at) : null };
  } catch (error) {
    if (error?.code === "ENOENT") return null;
    if (error instanceof DeviceOnboardingResumeError) throw error;
    fail("LOCK_HELD", "Resume lock is invalid; refusing to remove it");
  }
}

function processAlive(pid) { if (!Number.isInteger(pid) || pid < 1) return false; try { process.kill(pid, 0); return true; } catch (error) { return error?.code !== "ESRCH"; } }
function fsyncDirectory(directory) { try { const descriptor = fs.openSync(directory, fs.constants.O_RDONLY); try { fs.fsyncSync(descriptor); } finally { fs.closeSync(descriptor); } } catch (error) { if (!["EINVAL", "ENOTSUP", "EOPNOTSUPP", "EBADF"].includes(error?.code)) throw error; } }
function fail(code, message) { throw new DeviceOnboardingResumeError(code, message); }
function wrapIo(code, message, error) { return error instanceof DeviceOnboardingResumeError ? error : new DeviceOnboardingResumeError(code, message, error); }
function assertNoSecretFields(value) {
  const forbiddenKey = /(credential|nonce|bearer|token|private.?key|raw.?receipt.?signature|receipt.?signature|secret)/iu;
  const walk = (item) => {
    if (!item || typeof item !== "object") return;
    for (const [key, child] of Object.entries(item)) {
      if (forbiddenKey.test(key)) fail("SECRET_FIELD", `Forbidden durable field: ${key}`);
      walk(child);
    }
  };
  walk(value);
}
