//! Verified native replica publication. The archive is durable before its exact
//! original approval becomes the published recovery root. No Drop deletes files.

use std::fs::{self, File, Metadata};
use std::io::{ErrorKind, Seek, SeekFrom};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use fgit_crypto::{DigestHasher, Sha256Hasher};

use super::super::super::{hex, quote};
use super::super::approval::{MAX_ENVELOPE_BYTES, VerifiedApproval};
use super::super::archive::stream::Seal;
use super::super::attest::filesystem::{Stage, StagePublication};
use super::super::profile::Deadline;
use super::super::recovery_io::{BUFFER_BYTES, Control, ReadFailure, Source, SourceFailure};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum PublicationCheckpoint {
    DestinationChecked,
    ArchiveStaged,
    ArchiveVisible,
    ArchiveDurable,
    ApprovalVisible,
    Completed,
}

#[derive(Clone, Copy, Debug, Default, Eq, Ord, PartialEq, PartialOrd)]
pub(super) enum PublicationState {
    #[default]
    NotStarted,
    Staging,
    ArchivePublicationUnknown,
    ArchiveVisible,
    ArchiveDurable,
    ApprovalPublicationUnknown,
    ApprovalVisible,
    Durable,
}

impl PublicationState {
    pub(super) const fn label(self) -> &'static str {
        match self {
            Self::NotStarted => "not_started",
            Self::Staging => "staging",
            Self::ArchivePublicationUnknown => "archive_publication_unknown",
            Self::ArchiveVisible => "archive_visible",
            Self::ArchiveDurable => "archive_durable",
            Self::ApprovalPublicationUnknown => "approval_publication_unknown",
            Self::ApprovalVisible => "approval_visible",
            Self::Durable => "durable",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct ReplicaCandidate {
    pub(super) input: PathBuf,
    pub(super) approval: PathBuf,
}

impl ReplicaCandidate {
    pub(super) fn json(&self) -> String {
        format!(
            "{{\"input\":{},\"approval\":{}}}",
            quote(&self.input.to_string_lossy()),
            quote(&self.approval.to_string_lossy()),
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct PublishedReplica {
    pub(super) candidate: ReplicaCandidate,
    pub(super) archive_created: bool,
    pub(super) approval_created: bool,
}

impl PublishedReplica {
    pub(super) fn json_fields(&self) -> String {
        format!(
            concat!(
                "\"publication_state\":\"durable\",\"candidate\":{},",
                "\"archive_created\":{},\"approval_created\":{},",
                "\"archive_readback_verified\":true,\"body_before_approval\":true,",
                "\"files_and_directory_synced\":true"
            ),
            self.candidate.json(),
            self.archive_created,
            self.approval_created,
        )
    }
}

#[derive(Debug)]
pub(super) struct PublicationFailure {
    pub(super) state: PublicationState,
    pub(super) candidate: Option<ReplicaCandidate>,
    pub(super) completed: Option<PublishedReplica>,
    pub(super) error: String,
}

impl PublicationFailure {
    pub(super) fn message(&self) -> String {
        format!(
            "{}; publication_state={}; candidate={}{}",
            self.error,
            self.state.label(),
            self.candidate
                .as_ref()
                .map_or_else(|| "null".into(), ReplicaCandidate::json),
            self.completed
                .as_ref()
                .map_or_else(String::new, |receipt| format!(
                    "; replication_complete=true; completed_replica={{{}}}",
                    receipt.json_fields()
                )),
        )
    }
}

#[derive(Default)]
struct Progress {
    state: PublicationState,
    candidate: Option<ReplicaCandidate>,
    completed: Option<PublishedReplica>,
}

impl Progress {
    fn advance(&mut self, next: PublicationState) {
        // A previously visible approval must not disappear from the report
        // while its missing original body is being safely recreated.
        self.state = self.state.max(next);
    }
}

/// The caller must complete native verification before invoking this publisher.
/// Source is the ORIGINAL retained descriptor used by that verifier, not a path
/// reopened after receiving a JSON report. Every payload read uses its original
/// Control; small approval reads have the independent existing control bound.
pub(super) fn publish_verified(
    directory: &Path,
    source: &mut Source,
    envelope: &[u8],
    approval: &VerifiedApproval,
    control: &Control<'_>,
    deadline: Deadline,
    guard: &mut impl FnMut() -> Result<(), String>,
    checkpoint: &mut impl FnMut(PublicationCheckpoint) -> Result<(), String>,
) -> Result<PublishedReplica, PublicationFailure> {
    let mut progress = Progress::default();
    let result = publish_inner(
        directory,
        source,
        envelope,
        approval,
        control,
        deadline,
        guard,
        checkpoint,
        &mut progress,
    );
    result.map_err(|error| PublicationFailure {
        state: progress.state,
        candidate: progress.candidate,
        completed: progress.completed,
        error,
    })
}

fn publish_inner(
    requested: &Path,
    source: &mut Source,
    envelope: &[u8],
    approval: &VerifiedApproval,
    control: &Control<'_>,
    deadline: Deadline,
    guard: &mut impl FnMut() -> Result<(), String>,
    checkpoint: &mut impl FnMut(PublicationCheckpoint) -> Result<(), String>,
    progress: &mut Progress,
) -> Result<PublishedReplica, String> {
    control.check()?;
    approval.check_current()?;
    guard()?;
    if envelope.is_empty() || envelope.len() > MAX_ENVELOPE_BYTES {
        return Err("replica approval exceeds the original bounded envelope profile".into());
    }
    let mut hash = Sha256Hasher::new();
    hash.update(envelope);
    let approval_digest = hash.finish();
    if approval_digest != approval.approval_digest() {
        return Err(
            "replica approval bytes differ from the original authenticated envelope".into(),
        );
    }
    let original = approval.artifact_seal();
    source.check().map_err(SourceFailure::message)?;
    if source.length() != original.bytes {
        return Err("replica source length differs from its original signed approval".into());
    }
    let directory = Directory::open(requested)?;
    let candidate = ReplicaCandidate {
        input: directory.child(&format!(
            "archive-sha256-{}.fgbackup",
            hex(&original.digest)
        ))?,
        approval: directory.child(&format!(
            "checkpoint-sha256-{}.approval.json",
            hex(&approval_digest)
        ))?,
    };
    progress.candidate = Some(candidate.clone());
    gate(&directory, control, guard)?;
    let mut prior_approval = directory.existing(&candidate.approval, envelope.len() as u64)?;
    if let Some(existing) = prior_approval.as_mut() {
        progress.advance(PublicationState::ApprovalVisible);
        compare_approval(existing, envelope, control)?;
    }
    checkpoint(PublicationCheckpoint::DestinationChecked)?;
    gate(&directory, control, guard)?;

    let mut body = directory.existing(&candidate.input, original.bytes)?;
    let archive_created = if body.is_some() {
        progress.advance(PublicationState::ArchiveVisible);
        control.reserve(original.bytes)?;
        false
    } else {
        // Preserve enough work for source copy AND the final published readback
        // before creating any private output. Reservation does not charge reads.
        control.reserve(
            original
                .bytes
                .checked_mul(2)
                .ok_or("replica read reservation overflow")?,
        )?;
        let mut stage = Stage::reserve_reusable(&candidate.input, deadline)?;
        progress.advance(PublicationState::Staging);
        let staged = (|| {
            gate(&directory, control, guard)?;
            scan_body(source, original, Some(stage.file()), control)?;
            stage.synchronize_content(original.bytes, deadline)?;
            stage.check_frozen_content()?;
            checkpoint(PublicationCheckpoint::ArchiveStaged)?;
            gate(&directory, control, guard)?;
            stage.check_frozen_content()?;
            progress.advance(PublicationState::ArchivePublicationUnknown);
            let publication = stage.publish_or_existing(|| gate(&directory, control, guard))?;
            progress.advance(PublicationState::ArchiveVisible);
            stage.cleanup_unpublished()?;
            Ok(publication == StagePublication::Created)
        })();
        match staged {
            Ok(created) => created,
            Err(error) => return Err(with_stage_cleanup(&mut stage, error)),
        }
    };
    if body.is_none() {
        body = directory.existing(&candidate.input, original.bytes)?;
    }
    let mut body = body.ok_or("published replica archive disappeared")?;
    checkpoint(PublicationCheckpoint::ArchiveVisible)?;
    gate(&directory, control, guard)?;
    scan_body(&mut body, original, None, control)?;
    synchronize(&body, &directory, control, guard)?;
    progress.advance(PublicationState::ArchiveDurable);
    checkpoint(PublicationCheckpoint::ArchiveDurable)?;
    gate(&directory, control, guard)?;
    body.check().map_err(SourceFailure::message)?;

    let approval_created = if let Some(existing) = prior_approval.as_mut() {
        compare_approval(existing, envelope, control)?;
        false
    } else {
        let mut stage = Stage::reserve_reusable(&candidate.approval, deadline)?;
        let staged = (|| {
            stage.write_verified(envelope, deadline)?;
            gate(&directory, control, guard)?;
            body.check().map_err(SourceFailure::message)?;
            stage.check_frozen_content()?;
            progress.advance(PublicationState::ApprovalPublicationUnknown);
            let publication = stage.publish_or_existing(|| {
                gate(&directory, control, guard)?;
                body.check().map_err(SourceFailure::message)?;
                control.check()
            })?;
            progress.advance(PublicationState::ApprovalVisible);
            stage.cleanup_unpublished()?;
            Ok(publication == StagePublication::Created)
        })();
        match staged {
            Ok(created) => created,
            Err(error) => return Err(with_stage_cleanup(&mut stage, error)),
        }
    };
    checkpoint(PublicationCheckpoint::ApprovalVisible)?;
    gate(&directory, control, guard)?;
    // Even an exact existing approval is rechecked after the body work and all
    // observers. Concurrent publication may supply only the exact original bytes.
    let mut final_approval = directory
        .existing(&candidate.approval, envelope.len() as u64)?
        .ok_or("published replica approval disappeared")?;
    compare_approval(&mut final_approval, envelope, control)?;
    body.check().map_err(SourceFailure::message)?;
    synchronize(&final_approval, &directory, control, guard)?;
    body.check().map_err(SourceFailure::message)?;
    gate(&directory, control, guard)?;
    progress.advance(PublicationState::Durable);
    let receipt = PublishedReplica {
        candidate,
        archive_created,
        approval_created,
    };
    progress.completed = Some(receipt.clone());
    // No late expiry/cancellation can undo known completion. A failed observer
    // carries the typed completed replica through PublicationFailure instead.
    checkpoint(PublicationCheckpoint::Completed)?;
    Ok(receipt)
}

fn with_stage_cleanup(stage: &mut Stage, error: String) -> String {
    match stage.cleanup_unpublished() {
        Ok(()) => error,
        Err(cleanup) => format!("{error}; owned replica staging cleanup incomplete: {cleanup}"),
    }
}

fn gate(
    directory: &Directory,
    control: &Control<'_>,
    guard: &mut impl FnMut() -> Result<(), String>,
) -> Result<(), String> {
    control.check()?;
    guard()?;
    directory.check()?;
    control.check()
}

fn synchronize(
    source: &Source,
    directory: &Directory,
    control: &Control<'_>,
    guard: &mut impl FnMut() -> Result<(), String>,
) -> Result<(), String> {
    gate(directory, control, guard)?;
    source.check().map_err(SourceFailure::message)?;
    source
        .file
        .sync_all()
        .map_err(|error| format!("replica file synchronization: {error}"))?;
    directory.sync()?;
    source.check().map_err(SourceFailure::message)?;
    gate(directory, control, guard)
}

fn read_payload(
    control: &Control<'_>,
    input: &mut File,
    buffer: &mut [u8],
) -> Result<usize, String> {
    loop {
        match control.read(input, buffer) {
            Err(ReadFailure::Io(error)) if error.kind() == ErrorKind::Interrupted => {}
            result => return result.map_err(ReadFailure::message),
        }
    }
}

fn scan_body(
    source: &mut Source,
    original: Seal,
    mut output: Option<&mut File>,
    control: &Control<'_>,
) -> Result<(), String> {
    control.reserve(original.bytes)?;
    source.check().map_err(SourceFailure::message)?;
    if source.length() != original.bytes {
        return Err("replica archive length disagrees with the original signed length".into());
    }
    source
        .file
        .seek(SeekFrom::Start(0))
        .map_err(|error| format!("replica archive seek: {error}"))?;
    let mut hash = Sha256Hasher::new();
    let mut buffer = [0; BUFFER_BYTES];
    let mut at = 0_u64;
    while at < original.bytes {
        let maximum = (original.bytes - at).min(buffer.len() as u64) as usize;
        let count = read_payload(control, &mut source.file, &mut buffer[..maximum])?;
        if count == 0 {
            return Err("replica archive became short during copy or readback".into());
        }
        hash.update(&buffer[..count]);
        if let Some(target) = output.as_mut() {
            control.write_all(*target, &buffer[..count])?;
        }
        at += count as u64;
    }
    if read_payload(control, &mut source.file, &mut buffer[..1])? != 0
        || hash.finish() != original.digest
    {
        return Err("replica archive differs from its original signed checksum or length".into());
    }
    source.check().map_err(SourceFailure::message)?;
    control.check()
}

fn compare_approval(
    source: &mut Source,
    expected: &[u8],
    control: &Control<'_>,
) -> Result<(), String> {
    source.check().map_err(SourceFailure::message)?;
    source
        .file
        .seek(SeekFrom::Start(0))
        .map_err(|error| format!("replica approval seek: {error}"))?;
    let mut buffer = [0; 1024];
    let mut at = 0_usize;
    loop {
        let count = control.metadata_read(&mut source.file, &mut buffer)?;
        if count == 0 {
            break;
        }
        if expected.get(at..at + count) != Some(&buffer[..count]) {
            return Err(
                "existing replica approval conflicts with the exact original envelope".into(),
            );
        }
        at += count;
    }
    if at != expected.len() {
        return Err("replica approval became short".into());
    }
    source.check().map_err(SourceFailure::message)?;
    control.check()
}

struct Directory {
    requested: PathBuf,
    path: PathBuf,
    file: File,
    identity: Metadata,
}

impl Directory {
    fn open(requested: &Path) -> Result<Self, String> {
        let named = fs::symlink_metadata(requested)
            .map_err(|error| format!("replica directory: {error}"))?;
        if !named.is_dir() || named.mode() & 0o077 != 0 {
            return Err(
                "replica publication requires an existing owner-private directory, not a symlink"
                    .into(),
            );
        }
        let path = fs::canonicalize(requested)
            .map_err(|error| format!("replica directory resolution: {error}"))?;
        let file = rustix::fs::open(
            &path,
            rustix::fs::OFlags::RDONLY
                | rustix::fs::OFlags::CLOEXEC
                | rustix::fs::OFlags::DIRECTORY
                | rustix::fs::OFlags::NOFOLLOW
                | rustix::fs::OFlags::NONBLOCK,
            rustix::fs::Mode::empty(),
        )
        .map(File::from)
        .map_err(|error| format!("replica directory open: {error}"))?;
        let directory = Self {
            requested: requested.to_path_buf(),
            path,
            file,
            identity: named,
        };
        directory.check()?;
        Ok(directory)
    }

    fn check(&self) -> Result<(), String> {
        let opened = self.file.metadata().map_err(|error| error.to_string())?;
        let named = fs::symlink_metadata(&self.path).map_err(|error| error.to_string())?;
        let requested = fs::symlink_metadata(&self.requested).map_err(|error| error.to_string())?;
        for current in [&opened, &named, &requested] {
            if !current.is_dir()
                || current.mode() & 0o077 != 0
                || current.dev() != self.identity.dev()
                || current.ino() != self.identity.ino()
                || current.uid() != self.identity.uid()
                || current.mode() != self.identity.mode()
            {
                return Err(
                    "replica directory identity, private mode, or ownership changed".into(),
                );
            }
        }
        Ok(())
    }

    fn child(&self, name: &str) -> Result<PathBuf, String> {
        let path = self.path.join(name);
        if path.to_str().is_none_or(|text| text.len() > 8192) {
            return Err("content-addressed replica path exceeds the native path-byte bound".into());
        }
        Ok(path)
    }

    fn existing(&self, path: &Path, bytes: u64) -> Result<Option<Source>, String> {
        self.check()?;
        let named = match fs::symlink_metadata(path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(format!("replica existing-file inspection: {error}")),
        };
        if !named.is_file()
            || named.len() != bytes
            || named.mode() & 0o077 != 0
            || named.uid() != self.identity.uid()
            || named.nlink() != 1
        {
            return Err(
                "existing replica must be an exact-length owner-private singly linked regular file"
                    .into(),
            );
        }
        let source = Source::open(path, bytes).map_err(SourceFailure::message)?;
        let opened = source.file.metadata().map_err(|error| error.to_string())?;
        if !same_file(&named, &opened) {
            return Err("existing replica changed while its descriptor was captured".into());
        }
        self.check()?;
        source.check().map_err(SourceFailure::message)?;
        Ok(Some(source))
    }

    fn sync(&self) -> Result<(), String> {
        self.check()?;
        self.file
            .sync_all()
            .map_err(|error| format!("replica directory synchronization: {error}"))?;
        self.check()
    }
}

fn same_file(left: &Metadata, right: &Metadata) -> bool {
    left.is_file()
        && right.is_file()
        && left.dev() == right.dev()
        && left.ino() == right.ino()
        && left.uid() == right.uid()
        && left.mode() == right.mode()
        && left.len() == right.len()
        && left.nlink() == right.nlink()
        && left.mtime() == right.mtime()
        && left.mtime_nsec() == right.mtime_nsec()
        && left.ctime() == right.ctime()
        && left.ctime_nsec() == right.ctime_nsec()
}
