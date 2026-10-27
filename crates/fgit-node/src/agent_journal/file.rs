//! Synchronous local-file mechanics shared by the native runtime wrapper and
//! its actual-file conformance tests. No repository authority is stored here.

use std::{
    fmt,
    fs::{File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
};

use fgit_agent::{
    EffectJournalEntry, IntentRun, IntentRunCommitment,
    effect_journal::{
        EffectJournalCodecRefusal, EffectJournalEncoder, EffectJournalPersistenceRefusal,
        EffectJournalPosition, EffectJournalSink, MAX_EFFECT_JOURNAL_BYTES, RecoveredEffectJournal,
    },
};

/// Typed native-host refusal; backend payloads and task text are never included.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AgentJournalHostRefusal {
    /// The runtime owner stopped or exhausted its budget.
    Cancelled,
    /// The path was not an explicit regular local file in an existing directory.
    Path,
    /// Another live process or obligation retains writer custody.
    Busy,
    /// This run already has a journal; creating it again would reset its ledger.
    Exists,
    /// A runtime/run/codec binding disagreed.
    Binding,
    /// The whole-journal byte bound was exceeded.
    Limit,
    /// A read failed without causing a mutation.
    Read,
    /// A write or durability barrier failed and its visibility is uncertain.
    OutcomeUnknown,
    /// Bytes failed the exact profile, chain, anchor, or semantic replay checks.
    Codec(EffectJournalCodecRefusal),
    /// The saved run could not be bounded, pinned or independently authenticated.
    RunCheckpoint(fgit_agent::run_checkpoint::RunCheckpointRefusal),
}

impl fmt::Display for AgentJournalHostRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "native agent journal refused: {self:?}")
    }
}
impl core::error::Error for AgentJournalHostRefusal {}

type Checkpoint = Box<dyn Fn() -> Result<(), EffectJournalPersistenceRefusal>>;

pub(super) struct FileEffectJournal {
    file: File,
    encoder: EffectJournalEncoder,
    acknowledged: EffectJournalPosition,
    failed: bool,
    checkpoint: Checkpoint,
}

impl fmt::Debug for FileEffectJournal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FileEffectJournal")
            .field("acknowledged", &self.acknowledged)
            .field("failed", &self.failed)
            .finish_non_exhaustive()
    }
}

pub(super) fn journal_path(directory: &Path, run: &IntentRun) -> PathBuf {
    // Numeric run IDs cannot be reused with a different body in this store.
    // The exact complete commitment is verified in the file header.
    let name = format!("{:032x}.fg-agent-journal", run.run_id().value());
    directory.join(name)
}

pub(super) fn checked_directory(directory: &Path) -> Result<PathBuf, AgentJournalHostRefusal> {
    if !directory.is_absolute() {
        return Err(AgentJournalHostRefusal::Path);
    }
    let metadata =
        std::fs::symlink_metadata(directory).map_err(|_| AgentJournalHostRefusal::Path)?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(AgentJournalHostRefusal::Path);
    }
    directory
        .canonicalize()
        .map_err(|_| AgentJournalHostRefusal::Path)
}

impl FileEffectJournal {
    pub(super) fn create(
        directory: &Path,
        run: &IntentRun,
        checkpoint: Checkpoint,
    ) -> Result<Self, AgentJournalHostRefusal> {
        checkpoint().map_err(|_| AgentJournalHostRefusal::Cancelled)?;
        let (encoder, header) =
            EffectJournalEncoder::new(run).map_err(AgentJournalHostRefusal::Codec)?;
        let directory = checked_directory(directory)?;
        let directory_handle = File::open(&directory).map_err(|_| AgentJournalHostRefusal::Path)?;
        // Establish directory-sync support before creating a visible journal.
        directory_handle
            .sync_all()
            .map_err(|_| AgentJournalHostRefusal::OutcomeUnknown)?;
        checkpoint().map_err(|_| AgentJournalHostRefusal::Cancelled)?;
        let path = journal_path(&directory, run);
        let mut options = OpenOptions::new();
        options.read(true).append(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(path).map_err(|error| {
            if error.kind() == std::io::ErrorKind::AlreadyExists {
                AgentJournalHostRefusal::Exists
            } else {
                AgentJournalHostRefusal::OutcomeUnknown
            }
        })?;
        file.try_lock().map_err(|_| AgentJournalHostRefusal::Busy)?;
        file.write_all(&header)
            .and_then(|()| file.sync_all())
            .and_then(|()| directory_handle.sync_all())
            .map_err(|_| AgentJournalHostRefusal::OutcomeUnknown)?;
        checkpoint().map_err(|_| AgentJournalHostRefusal::Cancelled)?;
        Ok(Self {
            acknowledged: encoder.position(),
            encoder,
            file,
            failed: false,
            checkpoint,
        })
    }
}

impl EffectJournalSink for FileEffectJournal {
    fn run_commitment(&self) -> IntentRunCommitment {
        self.encoder.run_commitment()
    }
    fn position(&self) -> EffectJournalPosition {
        self.acknowledged
    }
    fn append(
        &mut self,
        entry: &EffectJournalEntry,
    ) -> Result<(), EffectJournalPersistenceRefusal> {
        if self.failed {
            return Err(EffectJournalPersistenceRefusal::Unavailable);
        }
        let operation = (|| {
            (self.checkpoint)()?;
            let observed = self
                .file
                .metadata()
                .map_err(|_| EffectJournalPersistenceRefusal::Unavailable)?
                .len();
            if observed != self.acknowledged.bytes {
                return Err(EffectJournalPersistenceRefusal::Binding);
            }
            let frame = self
                .encoder
                .encode(entry)
                .map_err(|refusal| match refusal {
                    EffectJournalCodecRefusal::Limit => EffectJournalPersistenceRefusal::Limit,
                    _ => EffectJournalPersistenceRefusal::Binding,
                })?;
            self.file
                .write_all(&frame)
                .and_then(|()| self.file.sync_all())
                .map_err(|_| EffectJournalPersistenceRefusal::OutcomeUnknown)?;
            // If cancellation raced the sync, callers receive an ambiguous
            // refusal and no new grant, even though these bytes may be durable.
            (self.checkpoint)()?;
            self.acknowledged = self.encoder.position();
            Ok(())
        })();
        if operation.is_err() {
            self.failed = true;
        }
        operation
    }
}

pub(super) fn recover(
    directory: &Path,
    run: &IntentRun,
    expected_tail: Option<EffectJournalPosition>,
    checkpoint: &dyn Fn() -> Result<(), AgentJournalHostRefusal>,
) -> Result<RecoveredEffectJournal, AgentJournalHostRefusal> {
    checkpoint()?;
    let directory = checked_directory(directory)?;
    let path = journal_path(&directory, run);
    let metadata = std::fs::symlink_metadata(&path).map_err(|_| AgentJournalHostRefusal::Read)?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(AgentJournalHostRefusal::Path);
    }
    let file = File::open(path).map_err(|_| AgentJournalHostRefusal::Read)?;
    file.try_lock().map_err(|_| AgentJournalHostRefusal::Busy)?;
    let length = file
        .metadata()
        .map_err(|_| AgentJournalHostRefusal::Read)?
        .len();
    if length > MAX_EFFECT_JOURNAL_BYTES as u64 {
        return Err(AgentJournalHostRefusal::Limit);
    }
    let mut bytes = Vec::with_capacity(length as usize);
    let mut bounded = (&file).take(MAX_EFFECT_JOURNAL_BYTES as u64 + 1);
    let mut buffer = [0; 16 * 1024];
    loop {
        checkpoint()?;
        let n = bounded
            .read(&mut buffer)
            .map_err(|_| AgentJournalHostRefusal::Read)?;
        if n == 0 {
            break;
        }
        if bytes.len() + n > MAX_EFFECT_JOURNAL_BYTES {
            return Err(AgentJournalHostRefusal::Limit);
        }
        bytes.extend_from_slice(&buffer[..n]);
    }
    if bytes.len() as u64 != length
        || file
            .metadata()
            .map_err(|_| AgentJournalHostRefusal::Read)?
            .len()
            != length
    {
        return Err(AgentJournalHostRefusal::Binding);
    }
    let recovered = RecoveredEffectJournal::decode(run, &bytes, expected_tail)
        .map_err(AgentJournalHostRefusal::Codec)?;
    checkpoint()?;
    Ok(recovered)
}
