//! Exclusive, cleanup-only custody of an existing responsibility journal.
//! The general reader remains strict. This owner privately validates an old
//! anchored prefix and retains any suffix until the ordinary authority reader
//! proves the one exact ACK that may complete it. It never truncates a file.

use std::{
    fs::{File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    path::Path,
};

use fgit_agent::{
    IntentRun, IntentRunCommitment,
    effect_journal::{
        EffectJournalPersistenceRefusal, EffectJournalPosition, MAX_EFFECT_JOURNAL_BYTES,
        MAX_EFFECT_JOURNAL_FRAME_BYTES, RecoveredEffectJournal,
    },
    ref_publication::{PreparedRefTransactionAcknowledgement, RefTransactionAcknowledgementSink},
};

use super::file::{AgentJournalHostRefusal, checked_directory, journal_path};

type Checkpoint = Box<dyn Fn() -> Result<(), EffectJournalPersistenceRefusal>>;

pub struct FileRefTransactionSettlement {
    file: File,
    run: IntentRunCommitment,
    before: EffectJournalPosition,
    bytes: Vec<u8>,
    checkpoint: Checkpoint,
    failed: bool,
}

impl FileRefTransactionSettlement {
    /// The returned prefix is private input to cleanup, not a complete inventory
    /// of the file. The owner must keep this lock through observation and `persist`
    /// and may expose an inventory only after that operation succeeds.
    pub fn open(
        directory: &Path,
        run: &IntentRun,
        expected_tail: EffectJournalPosition,
        checkpoint: Checkpoint,
    ) -> Result<(Self, RecoveredEffectJournal), AgentJournalHostRefusal> {
        checkpoint().map_err(host_refusal)?;
        if expected_tail.bytes > MAX_EFFECT_JOURNAL_BYTES as u64 {
            return Err(AgentJournalHostRefusal::Limit);
        }
        let directory = checked_directory(directory)?;
        let path = journal_path(&directory, run);
        let metadata =
            std::fs::symlink_metadata(&path).map_err(|_| AgentJournalHostRefusal::Read)?;
        if !metadata.is_file() || metadata.file_type().is_symlink() {
            return Err(AgentJournalHostRefusal::Path);
        }
        // No create/truncate permission: recovery cannot replace an uncertain
        // journal or reset the original issuing broker's resource ledger.
        let mut file = OpenOptions::new()
            .read(true)
            .append(true)
            .open(path)
            .map_err(|_| AgentJournalHostRefusal::Read)?;
        file.try_lock().map_err(|_| AgentJournalHostRefusal::Busy)?;
        let metadata = file.metadata().map_err(|_| AgentJournalHostRefusal::Read)?;
        if !metadata.is_file() {
            return Err(AgentJournalHostRefusal::Path);
        }
        let length = metadata.len();
        if length < expected_tail.bytes {
            return Err(AgentJournalHostRefusal::Binding);
        }
        if length > MAX_EFFECT_JOURNAL_BYTES as u64
            || length - expected_tail.bytes > (MAX_EFFECT_JOURNAL_FRAME_BYTES + 4) as u64
        {
            return Err(AgentJournalHostRefusal::Limit);
        }
        let bytes = read_exact_snapshot(&mut file, length, &*checkpoint).map_err(host_refusal)?;
        let prefix = RecoveredEffectJournal::decode(
            run,
            &bytes[..expected_tail.bytes as usize],
            Some(expected_tail),
        )
        .map_err(AgentJournalHostRefusal::Codec)?;
        let run = run
            .commitment()
            .map_err(|_| AgentJournalHostRefusal::Binding)?;
        checkpoint().map_err(host_refusal)?;
        Ok((
            Self {
                file,
                run,
                before: expected_tail,
                bytes,
                checkpoint,
                failed: false,
            },
            prefix,
        ))
    }

    fn persist(
        &mut self,
        prepared: &PreparedRefTransactionAcknowledgement,
    ) -> Result<EffectJournalPosition, EffectJournalPersistenceRefusal> {
        (self.checkpoint)()?;
        let frame = prepared.frame();
        let after = prepared.after_position();
        if prepared.run_commitment() != self.run
            || prepared.before_position() != self.before
            || self.before.bytes.checked_add(frame.len() as u64) != Some(after.bytes)
            || self
                .before
                .entries
                .checked_add(u64::from(!frame.is_empty()))
                != Some(after.entries)
            || (frame.is_empty() && after != self.before)
        {
            return Err(EffectJournalPersistenceRefusal::Binding);
        }
        if after.bytes > MAX_EFFECT_JOURNAL_BYTES as u64
            || frame.len() > MAX_EFFECT_JOURNAL_FRAME_BYTES + 4
        {
            return Err(EffectJournalPersistenceRefusal::Limit);
        }
        let suffix = &self.bytes[self.before.bytes as usize..];
        if !frame.starts_with(suffix) {
            return Err(EffectJournalPersistenceRefusal::Binding);
        }
        // The lock spans the authority await. Recheck exact bytes too, so a
        // changed file cannot be blessed merely because its length is stable.
        let current =
            read_exact_snapshot(&mut self.file, self.bytes.len() as u64, &*self.checkpoint)?;
        if current != self.bytes {
            return Err(EffectJournalPersistenceRefusal::Binding);
        }
        (self.checkpoint)()?;
        self.file
            .write_all(&frame[suffix.len()..])
            .and_then(|()| self.file.sync_all())
            .map_err(|_| EffectJournalPersistenceRefusal::OutcomeUnknown)?;
        // Even a complete pre-existing ACK or an already-ACKed input takes
        // this sync and checkpoint. Cancellation retains debt, never success.
        (self.checkpoint)()?;
        if self
            .file
            .metadata()
            .map_err(|_| EffectJournalPersistenceRefusal::OutcomeUnknown)?
            .len()
            != after.bytes
        {
            return Err(EffectJournalPersistenceRefusal::Binding);
        }
        Ok(after)
    }
}

impl RefTransactionAcknowledgementSink for FileRefTransactionSettlement {
    fn persist_acknowledgement(
        &mut self,
        prepared: &PreparedRefTransactionAcknowledgement,
    ) -> Result<EffectJournalPosition, EffectJournalPersistenceRefusal> {
        if self.failed {
            return Err(EffectJournalPersistenceRefusal::Unavailable);
        }
        let result = self.persist(prepared);
        if result.is_err() {
            self.failed = true;
        }
        result
    }
}

fn read_exact_snapshot(
    file: &mut File,
    length: u64,
    checkpoint: &dyn Fn() -> Result<(), EffectJournalPersistenceRefusal>,
) -> Result<Vec<u8>, EffectJournalPersistenceRefusal> {
    if length > MAX_EFFECT_JOURNAL_BYTES as u64 {
        return Err(EffectJournalPersistenceRefusal::Limit);
    }
    checkpoint()?;
    if file
        .metadata()
        .map_err(|_| EffectJournalPersistenceRefusal::Unavailable)?
        .len()
        != length
    {
        return Err(EffectJournalPersistenceRefusal::Binding);
    }
    file.seek(SeekFrom::Start(0))
        .map_err(|_| EffectJournalPersistenceRefusal::Unavailable)?;
    let mut bytes = Vec::with_capacity(length as usize);
    let mut bounded = (&mut *file).take(length + 1);
    let mut scratch = [0; 16 * 1024];
    loop {
        checkpoint()?;
        let count = bounded
            .read(&mut scratch)
            .map_err(|_| EffectJournalPersistenceRefusal::Unavailable)?;
        if count == 0 {
            break;
        }
        if bytes.len() + count > length as usize {
            return Err(EffectJournalPersistenceRefusal::Binding);
        }
        bytes.extend_from_slice(&scratch[..count]);
    }
    if bytes.len() as u64 != length
        || file
            .metadata()
            .map_err(|_| EffectJournalPersistenceRefusal::Unavailable)?
            .len()
            != length
    {
        return Err(EffectJournalPersistenceRefusal::Binding);
    }
    checkpoint()?;
    Ok(bytes)
}

const fn host_refusal(reason: EffectJournalPersistenceRefusal) -> AgentJournalHostRefusal {
    match reason {
        EffectJournalPersistenceRefusal::Cancelled => AgentJournalHostRefusal::Cancelled,
        EffectJournalPersistenceRefusal::Limit => AgentJournalHostRefusal::Limit,
        EffectJournalPersistenceRefusal::Binding => AgentJournalHostRefusal::Binding,
        EffectJournalPersistenceRefusal::Unavailable => AgentJournalHostRefusal::Read,
        EffectJournalPersistenceRefusal::OutcomeUnknown => AgentJournalHostRefusal::OutcomeUnknown,
    }
}
