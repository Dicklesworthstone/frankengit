//! One locked, exact local execution attempt; never repository authority.
//!
//! The operator assigns one stable path per attempt. A synced Started record
//! precedes user work. Reopening Started never grants permission to rerun: the
//! previous process may have escaped or completed with a lost response.
use super::{
    AttemptId, CheckDeliveryRefusal, CheckJournalPin, CheckJournalScope, Commitment,
    CoordinatorRefusal, File, FileCheckJournal, Frame, HEADER_BYTES, Input, Path, Read, Seek,
    SeekFrom, TrustedWorkflowReceipt, WorkflowRunId, Write, check_parent, fmt, private_file,
    read_error, root, storage, write_frame,
};

const ATTEMPT_HEADER: &[u8; 8] = b"FGWA0001";
const ATTEMPT_HEADER_BYTES: u64 = 168;
const ATTEMPT_DOMAIN: &[u8] = b"frankengit/trusted-attempt-frame/v1\0";
pub const MAX_ATTEMPT_RECEIPT_BYTES: usize = 64 * 1024 * 1024;

/// Derived by `WorkflowCoordinator::trusted_attempt_binding`, not repository
/// text. Includes the configured custody journal instance and exact request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WorkflowAttemptBinding {
    pub(in crate::coordinator) scope: CheckJournalScope,
    pub(in crate::coordinator) run: WorkflowRunId,
    pub(in crate::coordinator) attempt: AttemptId,
    pub(in crate::coordinator) request: Commitment,
}
impl WorkflowAttemptBinding {
    #[must_use]
    pub const fn run_id(self) -> WorkflowRunId {
        self.run
    }
    #[must_use]
    pub const fn request_commitment(self) -> Commitment {
        self.request
    }
    #[must_use]
    pub const fn journal_scope(self) -> CheckJournalScope {
        self.scope
    }
    fn bytes(self) -> Vec<u8> {
        let mut bytes = ATTEMPT_HEADER.to_vec();
        bytes.extend_from_slice(self.scope.tenant.as_bytes());
        bytes.extend_from_slice(self.scope.repository.as_bytes());
        for id in [
            self.scope.journal_id,
            self.run.commitment(),
            self.attempt.commitment(),
            self.request,
        ] {
            root(&mut bytes, id);
        }
        bytes
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WorkflowAttemptPin {
    bytes: u64,
    tail: Commitment,
}
impl WorkflowAttemptPin {
    #[must_use]
    pub const fn new(bytes: u64, tail: Commitment) -> Self {
        Self { bytes, tail }
    }
    #[must_use]
    pub const fn byte_len(self) -> u64 {
        self.bytes
    }
    #[must_use]
    pub const fn tail(self) -> Commitment {
        self.tail
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WorkflowAttemptStatus {
    Prepared,
    Started,
    Completed,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WorkflowAttemptRefusal {
    Custody(CheckDeliveryRefusal),
    Execution(Box<CoordinatorRefusal>),
    IdentityMismatch,
    ReconciliationRequired,
    WrongState,
}
impl fmt::Display for WorkflowAttemptRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "durable workflow attempt refused: {self:?}")
    }
}
impl std::error::Error for WorkflowAttemptRefusal {}
impl From<CheckDeliveryRefusal> for WorkflowAttemptRefusal {
    fn from(error: CheckDeliveryRefusal) -> Self {
        Self::Custody(error)
    }
}
impl From<CoordinatorRefusal> for WorkflowAttemptRefusal {
    fn from(error: CoordinatorRefusal) -> Self {
        Self::Execution(Box::new(error))
    }
}

/// Immutable bytes of the existing LOCAL observation, plus its custody pin.
/// Not a reconstructed scheduler, CheckReceipt, canonical check, or green gate.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecordedWorkflowReceipt {
    binding: WorkflowAttemptBinding,
    frame: Vec<u8>,
    journal: CheckJournalPin,
    containment: bool,
}
impl RecordedWorkflowReceipt {
    #[must_use]
    pub const fn binding(&self) -> WorkflowAttemptBinding {
        self.binding
    }
    #[must_use]
    pub fn frame(&self) -> &[u8] {
        &self.frame
    }
    #[must_use]
    pub fn commitment(&self) -> Commitment {
        Commitment::of_bytes(&self.frame)
    }
    #[must_use]
    pub const fn journal_pin(&self) -> CheckJournalPin {
        self.journal
    }
    #[must_use]
    pub const fn requires_containment(&self) -> bool {
        self.containment
    }
}

pub struct FileWorkflowAttempt {
    file: File,
    binding: WorkflowAttemptBinding,
    pin: WorkflowAttemptPin,
    started: Option<CheckJournalPin>,
    completed: Option<Frame>,
    failed: bool,
}
impl FileWorkflowAttempt {
    /// Create a new private file without adopting or overwriting an old path.
    /// Retain its descriptor/OS lock throughout execution and final settlement.
    pub fn create(
        path: &Path,
        binding: WorkflowAttemptBinding,
    ) -> Result<Self, WorkflowAttemptRefusal> {
        check_parent(path)?;
        let mut file = private_file(path, true)?;
        let header = binding.bytes();
        file.write_all(&header)
            .and_then(|()| file.sync_all())
            .map_err(storage)?;
        sync_parent(path)?;
        Ok(Self::empty(file, &binding))
    }

    /// Reopen one known attempt. Never recreate missing files, repair a torn
    /// tail, infer process reaping, or downgrade Started to Prepared. Supply an
    /// independently retained minimum pin when rollback detection is required.
    pub fn open(
        path: &Path,
        binding: WorkflowAttemptBinding,
        minimum: Option<WorkflowAttemptPin>,
        live: &dyn Fn() -> bool,
    ) -> Result<Self, WorkflowAttemptRefusal> {
        if !live() {
            return Err(CheckDeliveryRefusal::Cancelled.into());
        }
        check_parent(path)?;
        let mut file = private_file(path, false)?;
        let end = file.metadata().map_err(storage)?.len();
        if !(ATTEMPT_HEADER_BYTES..=ATTEMPT_HEADER_BYTES + 155 + MAX_ATTEMPT_RECEIPT_BYTES as u64)
            .contains(&end)
        {
            return Err(CheckDeliveryRefusal::CorruptJournal.into());
        }
        let mut header = [0; ATTEMPT_HEADER_BYTES as usize];
        file.read_exact(&mut header).map_err(read_error)?;
        if header.as_slice() != binding.bytes().as_slice() {
            return Err(WorkflowAttemptRefusal::IdentityMismatch);
        }
        let mut owner = Self::empty(file, &binding);
        let mut witnessed = minimum.is_none() || minimum == Some(owner.pin);
        while owner.pin.bytes < end {
            if !live() {
                return Err(CheckDeliveryRefusal::Cancelled.into());
            }
            if owner.completed.is_some() {
                return Err(CheckDeliveryRefusal::CorruptJournal.into());
            }
            let mut count = [0; 4];
            owner.file.read_exact(&mut count).map_err(read_error)?;
            let length = u32::from_be_bytes(count) as usize;
            if (owner.started.is_none() && length != 41)
                || (owner.started.is_some()
                    && !(43..=42 + MAX_ATTEMPT_RECEIPT_BYTES).contains(&length))
                || owner.pin.bytes + 36 + length as u64 > end
            {
                return Err(CheckDeliveryRefusal::CorruptJournal.into());
            }
            let mut payload = vec![0; length];
            owner.file.read_exact(&mut payload).map_err(read_error)?;
            let mut claimed = [0; 32];
            owner.file.read_exact(&mut claimed).map_err(read_error)?;
            let hash = attempt_hash(owner.pin.tail, &payload);
            if hash.digest().bytes().as_bytes() != claimed.as_slice() {
                return Err(CheckDeliveryRefusal::CorruptJournal.into());
            }
            let frame = Frame {
                offset: owner.pin.bytes,
                length,
                previous: owner.pin.tail,
                hash,
            };
            match (owner.started, payload[0]) {
                (None, 1) => owner.started = Some(decode_pin(&payload[1..41])?),
                (Some(start), 2) => {
                    let final_pin = decode_pin(&payload[1..41])?;
                    if payload[41] > 1 || final_pin.byte_len() < start.byte_len() {
                        return Err(CheckDeliveryRefusal::CorruptJournal.into());
                    }
                    owner.completed = Some(frame);
                }
                _ => return Err(CheckDeliveryRefusal::CorruptJournal.into()),
            }
            owner.pin = WorkflowAttemptPin {
                bytes: owner.pin.bytes + 36 + length as u64,
                tail: hash,
            };
            witnessed |= minimum == Some(owner.pin);
        }
        if !witnessed || owner.file.metadata().map_err(storage)?.len() != end {
            return Err(CheckDeliveryRefusal::CorruptJournal.into());
        }
        if !live() {
            return Err(CheckDeliveryRefusal::Cancelled.into());
        }
        owner.file.sync_all().map_err(storage)?;
        sync_parent(path)?;
        Ok(owner)
    }
    fn empty(file: File, binding: &WorkflowAttemptBinding) -> Self {
        Self {
            file,
            binding: *binding,
            pin: WorkflowAttemptPin {
                bytes: ATTEMPT_HEADER_BYTES,
                tail: Commitment::of_bytes(&binding.bytes()),
            },
            started: None,
            completed: None,
            failed: false,
        }
    }
    #[must_use]
    pub const fn binding(&self) -> WorkflowAttemptBinding {
        self.binding
    }
    #[must_use]
    pub const fn pin(&self) -> WorkflowAttemptPin {
        self.pin
    }
    #[must_use]
    pub const fn status(&self) -> WorkflowAttemptStatus {
        if self.completed.is_some() {
            WorkflowAttemptStatus::Completed
        } else if self.started.is_some() {
            WorkflowAttemptStatus::Started
        } else {
            WorkflowAttemptStatus::Prepared
        }
    }
    #[must_use]
    pub const fn is_failed(&self) -> bool {
        self.failed
    }
    #[must_use]
    pub const fn starting_journal_pin(&self) -> Option<CheckJournalPin> {
        self.started
    }

    /// Re-read and verify the actual saved observation; no cached success bit.
    pub fn completed_receipt(
        &mut self,
    ) -> Result<Option<RecordedWorkflowReceipt>, WorkflowAttemptRefusal> {
        self.healthy()?;
        let Some(frame) = self.completed else {
            return Ok(None);
        };
        self.failed = true;
        if self.file.metadata().map_err(storage)?.len() != self.pin.bytes {
            return Err(CheckDeliveryRefusal::CorruptJournal.into());
        }
        self.file
            .seek(SeekFrom::Start(frame.offset))
            .map_err(storage)?;
        let mut length = [0; 4];
        self.file.read_exact(&mut length).map_err(read_error)?;
        if u32::from_be_bytes(length) as usize != frame.length {
            return Err(CheckDeliveryRefusal::CorruptJournal.into());
        }
        let mut payload = vec![0; frame.length];
        self.file.read_exact(&mut payload).map_err(read_error)?;
        let mut hash = [0; 32];
        self.file.read_exact(&mut hash).map_err(read_error)?;
        if payload.first() != Some(&2)
            || payload.len() <= 42
            || payload[41] > 1
            || attempt_hash(frame.previous, &payload) != frame.hash
            || frame.hash.digest().bytes().as_bytes() != hash.as_slice()
        {
            return Err(CheckDeliveryRefusal::CorruptJournal.into());
        }
        let journal = decode_pin(&payload[1..41])?;
        self.failed = false;
        Ok(Some(RecordedWorkflowReceipt {
            binding: self.binding,
            frame: payload[42..].to_vec(),
            journal,
            containment: payload[41] == 1,
        }))
    }
    pub(in crate::coordinator) fn start(
        &mut self,
        journal: CheckJournalPin,
    ) -> Result<(), WorkflowAttemptRefusal> {
        self.healthy()?;
        if self.status() != WorkflowAttemptStatus::Prepared {
            return Err(WorkflowAttemptRefusal::ReconciliationRequired);
        }
        let payload = pin_payload(1, journal);
        self.append(&payload)?;
        self.started = Some(journal);
        Ok(())
    }
    pub(in crate::coordinator) fn finish(
        &mut self,
        receipt: &TrustedWorkflowReceipt,
        journal: CheckJournalPin,
    ) -> Result<(), WorkflowAttemptRefusal> {
        self.finish_bytes(
            &receipt.frame(),
            receipt
                .report()
                .jobs
                .iter()
                .any(crate::workflow::JobReport::requires_containment),
            journal,
        )
    }
    fn finish_bytes(
        &mut self,
        receipt: &[u8],
        containment: bool,
        journal: CheckJournalPin,
    ) -> Result<(), WorkflowAttemptRefusal> {
        self.healthy()?;
        if self.status() != WorkflowAttemptStatus::Started {
            return Err(WorkflowAttemptRefusal::WrongState);
        }
        if receipt.is_empty() || receipt.len() > MAX_ATTEMPT_RECEIPT_BYTES {
            return Err(CheckDeliveryRefusal::BatchTooLarge.into());
        }
        if self
            .started
            .is_some_and(|pin| journal.byte_len() < pin.byte_len())
        {
            return Err(WorkflowAttemptRefusal::IdentityMismatch);
        }
        let mut payload = pin_payload(2, journal);
        payload.push(u8::from(containment));
        payload.extend_from_slice(receipt);
        let frame = self.append(&payload)?;
        self.completed = Some(frame);
        Ok(())
    }
    fn healthy(&self) -> Result<(), WorkflowAttemptRefusal> {
        if self.failed {
            Err(CheckDeliveryRefusal::FailedJournal.into())
        } else {
            Ok(())
        }
    }
    fn append(&mut self, payload: &[u8]) -> Result<Frame, WorkflowAttemptRefusal> {
        self.healthy()?;
        let frame = Frame {
            offset: self.pin.bytes,
            length: payload.len(),
            previous: self.pin.tail,
            hash: attempt_hash(self.pin.tail, payload),
        };
        self.failed = true;
        if self.file.metadata().map_err(storage)?.len() != self.pin.bytes {
            return Err(CheckDeliveryRefusal::CorruptJournal.into());
        }
        self.file
            .seek(SeekFrom::Start(self.pin.bytes))
            .map_err(storage)?;
        write_frame(&mut self.file, payload, frame.hash, |file| file.sync_all())
            .map_err(storage)?;
        self.pin = WorkflowAttemptPin {
            bytes: self.pin.bytes + 36 + payload.len() as u64,
            tail: frame.hash,
        };
        self.failed = false;
        Ok(frame)
    }
}
fn sync_parent(path: &Path) -> Result<(), CheckDeliveryRefusal> {
    File::open(
        path.parent()
            .ok_or(CheckDeliveryRefusal::StorageUnavailable)?,
    )
    .and_then(|parent| parent.sync_all())
    .map_err(storage)
}
fn pin_payload(tag: u8, pin: CheckJournalPin) -> Vec<u8> {
    let mut bytes = vec![tag];
    bytes.extend_from_slice(&pin.byte_len().to_be_bytes());
    root(&mut bytes, pin.tail());
    bytes
}
fn decode_pin(bytes: &[u8]) -> Result<CheckJournalPin, CheckDeliveryRefusal> {
    let mut input = Input(bytes);
    Ok(CheckJournalPin::new(input.u64()?, input.root()?))
}
fn attempt_hash(previous: Commitment, payload: &[u8]) -> Commitment {
    let mut bytes = ATTEMPT_DOMAIN.to_vec();
    root(&mut bytes, previous);
    bytes.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    bytes.extend_from_slice(payload);
    Commitment::of_bytes(&bytes)
}

impl FileCheckJournal {
    /// Confirm a witness is an actual verified prefix, including after later
    /// delivery acknowledgements. A larger length alone never proves ancestry.
    pub fn verify_checkpoint(&mut self, pin: CheckJournalPin) -> Result<(), CheckDeliveryRefusal> {
        self.healthy()?;
        if pin == CheckJournalPin::new(HEADER_BYTES, Commitment::of_bytes(&self.scope.bytes())) {
            self.failed = true;
            if self.file.metadata().map_err(storage)?.len() != self.pin.bytes {
                return Err(CheckDeliveryRefusal::CorruptJournal);
            }
            self.file.seek(SeekFrom::Start(0)).map_err(storage)?;
            let mut header = [0; HEADER_BYTES as usize];
            self.file.read_exact(&mut header).map_err(read_error)?;
            if header.as_slice() != self.scope.bytes().as_slice() {
                return Err(CheckDeliveryRefusal::CorruptJournal);
            }
            self.failed = false;
            return Ok(());
        }
        let frame = self
            .evidence
            .values()
            .copied()
            .chain(self.batches.values().map(|batch| batch.frame))
            .chain(
                self.batches
                    .values()
                    .filter_map(|batch| batch.delivered.map(|(_, frame)| frame)),
            )
            .find(|frame| {
                frame.offset + 36 + frame.length as u64 == pin.byte_len()
                    && frame.hash == pin.tail()
            })
            .ok_or(CheckDeliveryRefusal::CorruptJournal)?;
        self.read_frame(frame)?;
        Ok(())
    }
    pub(in crate::coordinator) fn preflight_execution(
        &self,
        bytes: u64,
        records: usize,
        evidence_bytes: usize,
    ) -> Result<(), CheckDeliveryRefusal> {
        self.healthy()?;
        if evidence_bytes > self.limits.evidence_bytes {
            return Err(CheckDeliveryRefusal::BatchTooLarge);
        }
        self.check_capacity(bytes, records, self.pending.len())
    }
}

#[cfg(test)]
mod tests;
