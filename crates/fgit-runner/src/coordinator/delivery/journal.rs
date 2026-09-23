//! Unix, single-owner, append-only custody journal for check proposals.
//!
//! This is NOT the canonical forge outbox, a workflow restart scheduler, or an
//! authority backend. The operator owns stable private parent paths. File locks
//! are advisory; hostile same-UID mutation and storage that lies about fsync are
//! outside this profile. A trusted minimum pin detects rollback of known data.
use super::*;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;

const HEADER: &[u8; 8] = b"FGCJ0001";
const HEADER_BYTES: u64 = 72;
const FRAME_DOMAIN: &[u8] = b"frankengit/check-custody-frame/v1\0";
const DELIVERED_BYTES: u64 = 4 + 1 + 32 + 32 + 32;
const MAX_EVIDENCE_BYTES: usize = 64 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CheckJournalScope {
    pub tenant: TenantId,
    pub repository: RepositoryId,
    /// Operator-owned journal instance identity, not repository authority.
    pub journal_id: Commitment,
}
impl CheckJournalScope {
    fn bytes(self) -> Vec<u8> {
        let mut bytes = HEADER.to_vec();
        bytes.extend_from_slice(self.tenant.as_bytes());
        bytes.extend_from_slice(self.repository.as_bytes());
        root(&mut bytes, self.journal_id); bytes
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CheckJournalLimits {
    pub journal_bytes: u64,
    /// Includes historical records; no implicit forgetting of idempotency.
    pub records: usize,
    pub evidence_bytes: usize,
}
impl Default for CheckJournalLimits {
    fn default() -> Self {
        Self { journal_bytes: 256 * 1024 * 1024, records: 65_536, evidence_bytes: MAX_EVIDENCE_BYTES }
    }
}
impl CheckJournalLimits {
    fn validate(self) -> Result<(), CheckDeliveryRefusal> {
        if self.journal_bytes < HEADER_BYTES || self.journal_bytes > 4 * 1024 * 1024 * 1024
            || self.records == 0 || self.records > 1_000_000
            || self.evidence_bytes == 0 || self.evidence_bytes > MAX_EVIDENCE_BYTES
        { return Err(CheckDeliveryRefusal::InvalidLimits); }
        Ok(())
    }
}

/// Retain this checkpoint outside the journal when anti-rollback is required.
/// A locally valid older prefix cannot be detected without a trusted witness.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CheckJournalPin { bytes: u64, tail: Commitment }
impl CheckJournalPin {
    pub const fn new(bytes: u64, tail: Commitment) -> Self { Self { bytes, tail } }
    pub const fn byte_len(self) -> u64 { self.bytes }
    pub const fn tail(self) -> Commitment { self.tail }
}

#[derive(Clone, Copy)]
struct Frame { offset: u64, length: usize, previous: Commitment, hash: Commitment }
struct StoredBatch { frame: Frame, delivered: Option<(Commitment, Frame)> }
#[derive(Clone, Debug, Eq, PartialEq)]
struct Binding {
    attempt: AttemptId, head: Commitment, source: GitOid, graph: Commitment,
    trust: TrustDomain, profile: CoordinatorExecutionProfile,
}
impl Binding {
    fn of(batch: &CheckDeliveryBatch) -> Self {
        Self { attempt: batch.attempt, head: batch.head, source: batch.source, graph: batch.graph,
            trust: batch.trust.clone(), profile: batch.profile }
    }
}

/// The held descriptor owns the OS lock. Indexes contain only verified record
/// locations, never a replacement for the on-disk append log. All acknowledgements
/// follow sync_all; readback rechecks record commitments before disclosure.
pub struct FileCheckJournal {
    file: File,
    scope: CheckJournalScope,
    limits: CheckJournalLimits,
    pin: CheckJournalPin,
    records: usize,
    failed: bool,
    batches: BTreeMap<Commitment, StoredBatch>,
    batch_order: BTreeMap<u64, Commitment>,
    pending: VecDeque<Commitment>,
    evidence: BTreeMap<Commitment, Frame>,
    bindings: BTreeMap<WorkflowRunId, Binding>,
    phases: BTreeMap<(WorkflowRunId, String), u8>,
    run_ends: BTreeMap<WorkflowRunId, u64>,
}
impl FileCheckJournal {
    /// Create without replacing any path. The parent must already be a private,
    /// operator-owned directory. Sync its entry before advertising any custody.
    pub fn create(path: &Path, scope: CheckJournalScope, limits: CheckJournalLimits)
        -> Result<Self, CheckDeliveryRefusal>
    {
        limits.validate()?;
        check_parent(path)?;
        let mut file = private_file(path, true)?;
        let header = scope.bytes();
        file.write_all(&header).and_then(|()| file.sync_all()).map_err(storage)?;
        File::open(path.parent().ok_or(CheckDeliveryRefusal::StorageUnavailable)?)
            .and_then(|parent| parent.sync_all()).map_err(storage)?;
        Ok(Self::empty(file, scope, limits))
    }

    /// Rebuild from one known file, not directory listing. Partial/corrupt tails
    /// and missing trusted prefixes fail closed WITHOUT truncation or repair.
    /// A complete append whose response was lost is synchronized before reuse.
    pub fn open(path: &Path, scope: CheckJournalScope, limits: CheckJournalLimits,
        minimum: Option<CheckJournalPin>, live: &dyn Fn() -> bool)
        -> Result<Self, CheckDeliveryRefusal>
    {
        limits.validate()?;
        if !live() { return Err(CheckDeliveryRefusal::Cancelled); }
        check_parent(path)?;
        let mut file = private_file(path, false)?;
        let end = file.metadata().map_err(storage)?.len();
        if end < HEADER_BYTES { return Err(CheckDeliveryRefusal::CorruptJournal); }
        if end > limits.journal_bytes { return Err(CheckDeliveryRefusal::JournalFull); }
        let mut header = [0; HEADER_BYTES as usize];
        file.read_exact(&mut header).map_err(read_error)?;
        if header.as_slice() != scope.bytes().as_slice() { return Err(CheckDeliveryRefusal::ScopeMismatch); }
        let mut journal = Self::empty(file, scope, limits);
        let mut pin_seen = minimum.is_none() || minimum == Some(journal.pin);
        while journal.pin.bytes < end {
            if !live() { return Err(CheckDeliveryRefusal::Cancelled); }
            if journal.records >= limits.records { return Err(CheckDeliveryRefusal::JournalFull); }
            let offset = journal.pin.bytes;
            let mut length = [0; 4];
            journal.file.read_exact(&mut length).map_err(read_error)?;
            let count = u32::from_be_bytes(length) as usize;
            let maximum = (limits.evidence_bytes + 33).max(MAX_BATCH_BYTES + 1);
            if count == 0 || count > maximum { return Err(CheckDeliveryRefusal::CorruptJournal); }
            let next = offset.checked_add(4 + count as u64 + 32).ok_or(CheckDeliveryRefusal::CorruptJournal)?;
            if next > end { return Err(CheckDeliveryRefusal::CorruptJournal); }
            let mut payload = vec![0; count];
            journal.file.read_exact(&mut payload).map_err(read_error)?;
            let mut expected = [0; 32];
            journal.file.read_exact(&mut expected).map_err(read_error)?;
            let hash = frame_hash(journal.pin.tail, &payload);
            if hash.digest().bytes().as_bytes() != expected.as_slice() { return Err(CheckDeliveryRefusal::CorruptJournal); }
            let frame = Frame { offset, length: count, previous: journal.pin.tail, hash };
            journal.replay(&payload, frame)?;
            journal.pin = CheckJournalPin { bytes: next, tail: hash };
            journal.records += 1;
            pin_seen |= minimum == Some(journal.pin);
        }
        if !pin_seen || journal.file.metadata().map_err(storage)?.len() != end {
            return Err(CheckDeliveryRefusal::CorruptJournal);
        }
        journal.check_capacity(0, 0, journal.pending.len())?;
        if !live() { return Err(CheckDeliveryRefusal::Cancelled); }
        journal.file.sync_all().map_err(storage)?;
        // Reopening may be recovery from a lost/failed create response before
        // the parent entry was synced. File sync alone cannot settle that edge.
        File::open(path.parent().ok_or(CheckDeliveryRefusal::StorageUnavailable)?)
            .and_then(|parent| parent.sync_all()).map_err(storage)?;
        Ok(journal)
    }

    fn empty(file: File, scope: CheckJournalScope, limits: CheckJournalLimits) -> Self {
        Self { file, scope, limits, pin: CheckJournalPin { bytes: HEADER_BYTES, tail: Commitment::of_bytes(&scope.bytes()) },
            records: 0, failed: false, batches: BTreeMap::new(), batch_order: BTreeMap::new(), pending: VecDeque::new(),
            evidence: BTreeMap::new(), bindings: BTreeMap::new(), phases: BTreeMap::new(), run_ends: BTreeMap::new() }
    }
    pub const fn pin(&self) -> CheckJournalPin { self.pin }
    pub const fn scope(&self) -> CheckJournalScope { self.scope }
    pub fn pending_batches(&self) -> usize { self.pending.len() }
    pub const fn is_failed(&self) -> bool { self.failed }

    /// Persist the actual referenced evidence BEFORE accepting a proposal.
    /// A matching digest is integrity evidence, not semantic verification or
    /// producer authorization. No invalid or oversized input reaches a write.
    pub fn store_evidence(&mut self, expected: Commitment, bytes: &[u8]) -> Result<(), CheckDeliveryRefusal> {
        self.healthy()?;
        if bytes.is_empty() || bytes.len() > self.limits.evidence_bytes { return Err(CheckDeliveryRefusal::BatchTooLarge); }
        if Commitment::of_bytes(bytes) != expected { return Err(CheckDeliveryRefusal::AcknowledgementMismatch); }
        if self.evidence.contains_key(&expected) {
            if self.read_evidence(expected)? != bytes { return Err(CheckDeliveryRefusal::AcknowledgementMismatch); }
            return Ok(());
        }
        let mut payload = Vec::with_capacity(bytes.len() + 33);
        payload.push(3); root(&mut payload, expected); payload.extend_from_slice(bytes);
        let frame = self.append(&payload, self.pending.len())?;
        self.evidence.insert(expected, frame);
        Ok(())
    }

    pub fn read_evidence(&mut self, id: Commitment) -> Result<Vec<u8>, CheckDeliveryRefusal> {
        self.healthy()?;
        let frame = *self.evidence.get(&id).ok_or(CheckDeliveryRefusal::EvidenceMissing)?;
        let payload = self.read_frame(frame)?;
        if payload.first() != Some(&3) || payload.len() < 34 || Commitment::of_bytes(&payload[33..]) != id {
            self.failed = true; return Err(CheckDeliveryRefusal::CorruptJournal);
        }
        Ok(payload[33..].to_vec())
    }

    /// Read the oldest undelivered batch without removing it. Its evidence
    /// bodies remain retrievable after dropping the originating coordinator.
    pub fn next_batch(&mut self) -> Result<Option<CheckDeliveryBatch>, CheckDeliveryRefusal> {
        self.healthy()?;
        let Some(id) = self.pending.front().copied() else { return Ok(None); };
        let frame = self.batches.get(&id).ok_or(CheckDeliveryRefusal::CorruptJournal)?.frame;
        let payload = self.read_frame(frame)?;
        let decoded = payload.get(1..).filter(|_| payload.first() == Some(&1))
            .and_then(|body| CheckDeliveryBatch::decode(body).ok());
        let Some(batch) = decoded.filter(|batch| batch.id() == id) else {
            self.failed = true; return Err(CheckDeliveryRefusal::CorruptJournal);
        };
        // A valid proposal record cannot conceal damaged evidence elsewhere
        // in the same journal. Verify every referenced body before forwarding.
        for root in batch.facts.iter().filter_map(|fact| fact.receipt_commitment).collect::<BTreeSet<_>>() {
            self.read_evidence(root)?;
        }
        Ok(Some(batch))
    }

    /// Reconcile a lost delivery response from a durable, idempotent destination.
    /// Only the FIFO head can advance; exact repeats of an already recorded
    /// acknowledgement are harmless, conflicting receipts are refused.
    pub fn record_delivery(&mut self, acknowledgement: CheckDeliveryAcknowledgement) -> Result<(), CheckDeliveryRefusal> {
        self.healthy()?;
        let entry = self.batches.get(&acknowledgement.batch).ok_or(CheckDeliveryRefusal::StaleBatch)?;
        if let Some((receipt, frame)) = entry.delivered {
            if receipt != acknowledgement.receipt { return Err(CheckDeliveryRefusal::AcknowledgementMismatch); }
            self.read_frame(frame)?;
            return Ok(());
        }
        if self.pending.front() != Some(&acknowledgement.batch) { return Err(CheckDeliveryRefusal::OutOfOrder); }
        let mut payload = vec![2]; root(&mut payload, acknowledgement.batch); root(&mut payload, acknowledgement.receipt);
        let frame = self.append(&payload, self.pending.len() - 1)?;
        self.batches.get_mut(&acknowledgement.batch).expect("validated batch").delivered = Some((acknowledgement.receipt, frame));
        self.pending.pop_front();
        Ok(())
    }

    /// One synchronous bounded delivery attempt; no worker is spawned. A failed
    /// destination call or failed local acknowledgement append retains custody.
    /// The destination MUST deduplicate by the exact batch id across restarts.
    pub fn forward_next<S: CheckDeliverySink>(&mut self, destination: &mut S, live: &dyn Fn() -> bool)
        -> Result<Option<CheckDeliveryAcknowledgement>, CheckDeliveryRefusal>
    {
        if !live() { return Err(CheckDeliveryRefusal::Cancelled); }
        let Some(batch) = self.next_batch()? else { return Ok(None); };
        if !live() { return Err(CheckDeliveryRefusal::Cancelled); }
        let acknowledgement = destination.accept(&batch)?;
        if acknowledgement.batch != batch.id() { return Err(CheckDeliveryRefusal::AcknowledgementMismatch); }
        self.record_delivery(acknowledgement)?;
        Ok(Some(acknowledgement))
    }

    fn healthy(&self) -> Result<(), CheckDeliveryRefusal> {
        if self.failed { Err(CheckDeliveryRefusal::FailedJournal) } else { Ok(()) }
    }
    fn check_capacity(&self, bytes: u64, records: usize, pending: usize) -> Result<(), CheckDeliveryRefusal> {
        let reserve = (pending as u64).checked_mul(DELIVERED_BYTES).ok_or(CheckDeliveryRefusal::JournalFull)?;
        if self.pin.bytes.checked_add(bytes).and_then(|n| n.checked_add(reserve)).is_none_or(|n| n > self.limits.journal_bytes)
            || self.records.checked_add(records).and_then(|n| n.checked_add(pending)).is_none_or(|n| n > self.limits.records)
        { return Err(CheckDeliveryRefusal::JournalFull); }
        Ok(())
    }
    fn check_batch(&self, batch: &CheckDeliveryBatch) -> Result<(), CheckDeliveryRefusal> {
        if batch.tenant != self.scope.tenant || batch.repository != self.scope.repository { return Err(CheckDeliveryRefusal::ScopeMismatch); }
        if self.bindings.get(&batch.run).is_some_and(|binding| *binding != Binding::of(batch)) {
            return Err(CheckDeliveryRefusal::ScopeMismatch);
        }
        if batch.ordinal.checked_add(batch.facts.len() as u64).is_none()
            || self.run_ends.get(&batch.run).is_some_and(|end| batch.ordinal < *end)
        { return Err(CheckDeliveryRefusal::StaleBatch); }
        // Refuse regrouped/overlapping retries rather than emitting a second
        // copy of the same job phase under a different batch id.
        let mut updated = BTreeMap::new();
        for fact in &batch.facts {
            let key = (batch.run, fact.job_id.clone());
            let previous = updated.get(&key).or_else(|| self.phases.get(&key)).copied().unwrap_or(0);
            let phase = phase(fact.status);
            if !matches!((previous, phase), (0, 1) | (1, 2) | (1, 3) | (2, 3)) { return Err(CheckDeliveryRefusal::StaleBatch); }
            if fact.receipt_commitment.is_some_and(|id| !self.evidence.contains_key(&id)) {
                return Err(CheckDeliveryRefusal::EvidenceMissing);
            }
            updated.insert(key, phase);
        }
        Ok(())
    }
    fn index_batch(&mut self, batch: &CheckDeliveryBatch, frame: Frame) {
        let id = batch.id();
        self.bindings.entry(batch.run).or_insert_with(|| Binding::of(batch));
        self.run_ends.insert(batch.run, batch.ordinal + batch.facts.len() as u64);
        for fact in &batch.facts { self.phases.insert((batch.run, fact.job_id.clone()), phase(fact.status)); }
        self.batch_order.insert(frame.offset, id);
        self.batches.insert(id, StoredBatch { frame, delivered: None }); self.pending.push_back(id);
    }
    fn replay(&mut self, payload: &[u8], frame: Frame) -> Result<(), CheckDeliveryRefusal> {
        match payload.first() {
            Some(1) => {
                let batch = CheckDeliveryBatch::decode(&payload[1..]).map_err(|_| CheckDeliveryRefusal::CorruptJournal)?;
                if self.batches.contains_key(&batch.id()) { return Err(CheckDeliveryRefusal::CorruptJournal); }
                self.check_batch(&batch).map_err(|_| CheckDeliveryRefusal::CorruptJournal)?;
                self.index_batch(&batch, frame);
            }
            Some(2) if payload.len() == 65 => {
                let mut input = Input(&payload[1..]); let id = input.root()?; let receipt = input.root()?;
                if self.pending.front() != Some(&id) { return Err(CheckDeliveryRefusal::CorruptJournal); }
                self.batches.get_mut(&id).ok_or(CheckDeliveryRefusal::CorruptJournal)?.delivered = Some((receipt, frame));
                self.pending.pop_front();
            }
            Some(3) if payload.len() > 33 && payload.len() - 33 <= self.limits.evidence_bytes => {
                let id = Input(&payload[1..33]).root()?;
                if Commitment::of_bytes(&payload[33..]) != id || self.evidence.contains_key(&id) { return Err(CheckDeliveryRefusal::CorruptJournal); }
                self.evidence.insert(id, frame);
            }
            _ => return Err(CheckDeliveryRefusal::CorruptJournal),
        }
        Ok(())
    }
    fn append(&mut self, payload: &[u8], pending_after: usize) -> Result<Frame, CheckDeliveryRefusal> {
        self.healthy()?;
        let bytes = 4 + payload.len() as u64 + 32;
        self.check_capacity(bytes, 1, pending_after)?;
        let frame = Frame { offset: self.pin.bytes, length: payload.len(), previous: self.pin.tail, hash: frame_hash(self.pin.tail, payload) };
        // Poison BEFORE the first potentially mutating I/O. An unwind or error
        // may leave complete, partial or merely visible bytes: only reopen may
        // resolve that ambiguity; this object cannot silently keep appending.
        self.failed = true;
        if self.file.metadata().map_err(storage)?.len() != self.pin.bytes { return Err(CheckDeliveryRefusal::CorruptJournal); }
        self.file.seek(SeekFrom::Start(self.pin.bytes)).map_err(storage)?;
        write_frame(&mut self.file, payload, frame.hash, |file| file.sync_all()).map_err(storage)?;
        self.pin = CheckJournalPin { bytes: self.pin.bytes + bytes, tail: frame.hash };
        self.records += 1; self.failed = false;
        Ok(frame)
    }
    fn read_frame(&mut self, frame: Frame) -> Result<Vec<u8>, CheckDeliveryRefusal> {
        self.healthy()?;
        self.failed = true;
        if self.file.metadata().map_err(storage)?.len() != self.pin.bytes { return Err(CheckDeliveryRefusal::CorruptJournal); }
        self.file.seek(SeekFrom::Start(frame.offset)).map_err(storage)?;
        let mut length = [0; 4]; self.file.read_exact(&mut length).map_err(read_error)?;
        if u32::from_be_bytes(length) as usize != frame.length { return Err(CheckDeliveryRefusal::CorruptJournal); }
        let mut payload = vec![0; frame.length]; self.file.read_exact(&mut payload).map_err(read_error)?;
        let mut hash = [0; 32]; self.file.read_exact(&mut hash).map_err(read_error)?;
        if frame_hash(frame.previous, &payload) != frame.hash || frame.hash.digest().bytes().as_bytes() != hash.as_slice() {
            return Err(CheckDeliveryRefusal::CorruptJournal);
        }
        self.failed = false;
        Ok(payload)
    }
}
impl CheckDeliverySink for FileCheckJournal {
    fn accept(&mut self, batch: &CheckDeliveryBatch) -> Result<CheckDeliveryAcknowledgement, CheckDeliveryRefusal> {
        self.healthy()?;
        if batch.tenant != self.scope.tenant || batch.repository != self.scope.repository { return Err(CheckDeliveryRefusal::ScopeMismatch); }
        if let Some(stored) = self.batches.get(&batch.id()) {
            let frame = stored.frame;
            let payload = self.read_frame(frame)?;
            if &payload[1..] != batch.body() { return Err(CheckDeliveryRefusal::AcknowledgementMismatch); }
            for id in batch.facts.iter().filter_map(|fact| fact.receipt_commitment).collect::<BTreeSet<_>>() {
                self.read_evidence(id)?;
            }
            return Ok(CheckDeliveryAcknowledgement::after_durable_acceptance(batch, frame.hash));
        }
        self.check_batch(batch)?;
        // Evidence is re-read through its committed record, not assumed valid
        // merely because its id occurs in a cached in-memory index.
        for id in batch.facts.iter().filter_map(|fact| fact.receipt_commitment).collect::<BTreeSet<_>>() {
            self.read_evidence(id)?;
        }
        let mut payload = Vec::with_capacity(batch.body.len() + 1);
        payload.push(1); payload.extend_from_slice(batch.body());
        let frame = self.append(&payload, self.pending.len() + 1)?;
        self.index_batch(batch, frame);
        Ok(CheckDeliveryAcknowledgement::after_durable_acceptance(batch, frame.hash))
    }
}

impl WorkflowCoordinator {
    /// Persist the exact evidence bodies and one bounded proposal batch before
    /// transferring custody. The optional trusted receipt must belong to the
    /// pending run. Ordinary runner evidence is obtained from retained receipts.
    /// Missing evidence, cancellation or failed I/O keeps every fact pending;
    /// any already persisted evidence remains idempotently reusable on retry.
    pub fn journal_check_facts(
        &mut self, journal: &mut FileCheckJournal, maximum_facts: usize,
        maximum_bytes: usize, trusted: Option<&TrustedWorkflowReceipt>,
        live: &dyn Fn() -> bool,
    ) -> Result<Option<CheckDeliveryAcknowledgement>, CheckDeliveryRefusal> {
        if !live() { return Err(CheckDeliveryRefusal::Cancelled); }
        let Some(batch) = self.prepare_check_delivery(maximum_facts, maximum_bytes)? else { return Ok(None); };
        if batch.tenant != journal.scope.tenant || batch.repository != journal.scope.repository {
            return Err(CheckDeliveryRefusal::ScopeMismatch);
        }
        for fact in &batch.facts {
            let Some(expected) = fact.receipt_commitment else { continue; };
            if !live() { return Err(CheckDeliveryRefusal::Cancelled); }
            if journal.evidence.contains_key(&expected) { continue; }
            let bytes = match batch.profile {
                CoordinatorExecutionProfile::CommandOnly => {
                    let receipt = self.active_runs.get(&batch.run)
                        .and_then(|run| run.job_receipts.get(&fact.job_id))
                        .ok_or(CheckDeliveryRefusal::EvidenceMissing)?;
                    receipt.verify_evidence().map_err(|_| CheckDeliveryRefusal::InvalidBatch)?;
                    receipt.evidence().frame().to_vec()
                }
                CoordinatorExecutionProfile::TrustedWorkflow { .. } => {
                    trusted.filter(|receipt| receipt.run_id() == batch.run)
                        .and_then(|receipt| receipt.job_frame(&fact.job_id))
                        .ok_or(CheckDeliveryRefusal::EvidenceMissing)?
                }
            };
            journal.store_evidence(expected, &bytes)?;
        }
        if !live() { return Err(CheckDeliveryRefusal::Cancelled); }
        let acknowledgement = journal.accept(&batch)?;
        self.acknowledge_check_delivery(&batch, acknowledgement)?;
        Ok(Some(acknowledgement))
    }
}

fn phase(status: CheckRunStatus) -> u8 {
    match status { CheckRunStatus::Queued => 1, CheckRunStatus::InProgress => 2, CheckRunStatus::Completed => 3 }
}
fn frame_hash(previous: Commitment, payload: &[u8]) -> Commitment {
    let mut bytes = FRAME_DOMAIN.to_vec(); root(&mut bytes, previous);
    bytes.extend_from_slice(&(payload.len() as u32).to_be_bytes()); bytes.extend_from_slice(payload);
    Commitment::of_bytes(&bytes)
}
fn write_frame<W: Write>(writer: &mut W, payload: &[u8], hash: Commitment,
    sync: impl FnOnce(&mut W) -> io::Result<()>) -> io::Result<()>
{
    let length = u32::try_from(payload.len()).map_err(|_| io::Error::other("check record size"))?;
    writer.write_all(&length.to_be_bytes())?; writer.write_all(payload)?;
    writer.write_all(hash.digest().bytes().as_bytes())?;
    sync(writer)
}
fn storage(_: io::Error) -> CheckDeliveryRefusal { CheckDeliveryRefusal::StorageUnavailable }
fn read_error(error: io::Error) -> CheckDeliveryRefusal {
    if error.kind() == io::ErrorKind::UnexpectedEof { CheckDeliveryRefusal::CorruptJournal } else { storage(error) }
}
fn check_parent(path: &Path) -> Result<(), CheckDeliveryRefusal> {
    if !path.is_absolute() { return Err(CheckDeliveryRefusal::StorageUnavailable); }
    let parent = path.parent().ok_or(CheckDeliveryRefusal::StorageUnavailable)?;
    let metadata = fs::symlink_metadata(parent).map_err(storage)?;
    if !metadata.is_dir() || metadata.mode() & 0o077 != 0 { return Err(CheckDeliveryRefusal::StorageUnavailable); }
    Ok(())
}
fn private_file(path: &Path, create: bool) -> Result<File, CheckDeliveryRefusal> {
    if !create {
        let metadata = fs::symlink_metadata(path).map_err(storage)?;
        if !metadata.is_file() || metadata.mode() & 0o077 != 0 || metadata.nlink() != 1 {
            return Err(CheckDeliveryRefusal::StorageUnavailable);
        }
    }
    let file = OpenOptions::new().read(true).write(true).create_new(create).mode(0o600).open(path).map_err(storage)?;
    file.try_lock().map_err(|_| CheckDeliveryRefusal::LockUnavailable)?;
    let actual = file.metadata().map_err(storage)?;
    let named = fs::symlink_metadata(path).map_err(storage)?;
    if !actual.is_file() || !named.is_file() || actual.mode() & 0o077 != 0 || actual.nlink() != 1
        || (actual.dev(), actual.ino()) != (named.dev(), named.ino())
    { return Err(CheckDeliveryRefusal::StorageUnavailable); }
    Ok(file)
}

#[cfg(test)]
mod tests;

/// Durable local execution ownership paired with this custody journal.
pub mod attempt;

/// Launch-fenced execution through the existing journal and workflow engine.
pub mod execution;


/// Non-consuming, snapshot-pinned access to accepted and delivered results.
pub mod history;
